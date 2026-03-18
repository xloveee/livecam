use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use str0m::media::{KeyframeRequest, MediaData, Mid, Rid};
use str0m::net::{Protocol, Receive};
use str0m::{Event, IceConnectionState, Input, Output, Rtc};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::sleep;

/// Unique identifier for a peer session (broadcaster or viewer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(u64);

static NEXT_PEER_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl PeerId {
    pub fn next() -> Self {
        Self(NEXT_PEER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    pub fn parse(s: &str) -> Option<Self> {
        let num = s.strip_prefix("peer-")?;
        num.parse::<u64>().ok().map(PeerId)
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer-{}", self.0)
    }
}

/// Role of a peer: broadcaster sends media, viewer receives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    Broadcaster,
    Viewer,
}

/// A new Rtc instance to be added to the run loop, sent from the HTTP handler.
pub struct NewPeer {
    pub peer_id: PeerId,
    pub rtc: Rtc,
    pub role: PeerRole,
    pub room_id: String,
}

/// Request to change a viewer's simulcast quality, sent from the HTTP handler.
pub struct QualityChange {
    pub peer_id: PeerId,
    pub room_id: String,
    pub rid: Option<Rid>,
}

/// Request to disconnect a viewer, sent from the HTTP handler.
pub struct PeerDisconnect {
    pub peer_id: PeerId,
    pub room_id: String,
}

/// Per-room metadata visible to both API handlers and the SFU loop.
#[derive(Debug, Clone)]
pub struct RoomInfo {
    pub viewer_count: u32,
    pub max_viewers: u32,
    pub password: Option<String>,
    pub is_live: bool,
}

impl Default for RoomInfo {
    fn default() -> Self {
        Self {
            viewer_count: 0,
            max_viewers: 0,
            password: None,
            is_live: false,
        }
    }
}

/// Thread-safe map of room_id -> RoomInfo, shared between API and SFU.
pub type RoomStateMap = Arc<Mutex<HashMap<String, RoomInfo>>>;

pub fn new_room_state() -> RoomStateMap {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Tracks an incoming media track on the broadcaster.
struct TrackIn {
    mid: Mid,
    kind: str0m::media::MediaKind,
}

/// Tracks an outgoing media track on a viewer, mapped to a broadcaster's incoming track.
struct TrackOut {
    source_peer: PeerId,
    source_mid: Mid,
    kind: str0m::media::MediaKind,
    local_mid: Option<Mid>,
}

/// Per-peer session state.
struct Peer {
    id: PeerId,
    rtc: Rtc,
    role: PeerRole,
    room_id: String,
    tracks_in: Vec<TrackIn>,
    tracks_out: Vec<TrackOut>,
    chosen_rid: Option<Rid>,
    last_media_at: Option<Instant>,
}

impl Peer {
    fn new(id: PeerId, rtc: Rtc, role: PeerRole, room_id: String) -> Self {
        Self {
            id,
            rtc,
            role,
            room_id,
            tracks_in: Vec::new(),
            tracks_out: Vec::new(),
            chosen_rid: None,
            last_media_at: None,
        }
    }
}

/// Events produced by polling a peer that need to be forwarded to other peers.
enum Propagated {
    Noop,
    TrackOpen {
        source_peer: PeerId,
        room_id: String,
        mid: Mid,
        kind: str0m::media::MediaKind,
    },
    Media {
        source_peer: PeerId,
        room_id: String,
        data: MediaData,
    },
    Keyframe {
        request: KeyframeRequest,
        target_peer: PeerId,
        source_mid: Mid,
    },
}

/// The main SFU run loop. Drives all Rtc instances, demuxes UDP, forwards media.
///
/// `socket`         — single multiplexed UDP socket for all WebRTC traffic
/// `candidate_addr` — public address advertised in ICE candidates
/// `new_peer_rx`    — channel receiving new Rtc instances from the HTTP handlers
/// `quality_rx`     — channel receiving quality change requests from the HTTP handlers
/// `disconnect_rx`  — channel receiving explicit viewer disconnect requests
/// `room_state`     — shared map of room metadata (viewer counts, caps)
pub async fn run_sfu_loop(
    socket: UdpSocket,
    candidate_addr: SocketAddr,
    mut new_peer_rx: mpsc::UnboundedReceiver<NewPeer>,
    mut quality_rx: mpsc::UnboundedReceiver<QualityChange>,
    mut disconnect_rx: mpsc::UnboundedReceiver<PeerDisconnect>,
    room_state: RoomStateMap,
) {
    let mut peers: Vec<Peer> = Vec::new();
    let mut propagation_queue: VecDeque<Propagated> = VecDeque::new();
    let mut buf = vec![0u8; 2000];
    let mut last_housekeeping = Instant::now();
    let mut media_fwd_count: u64 = 0;
    let mut last_media_log = Instant::now();

    tracing::info!("SFU run loop started on {}", socket.local_addr().unwrap());

    loop {
        // ── Periodic housekeeping (~250ms) ────────────────────────
        // Heavy work stays off the per-packet fast path.
        if last_housekeeping.elapsed() >= Duration::from_millis(250) {
            last_housekeeping = Instant::now();

            let mut dead_rooms: Vec<String> = Vec::new();
            for peer in peers.iter() {
                if !peer.rtc.is_alive() && peer.role == PeerRole::Broadcaster {
                    dead_rooms.push(peer.room_id.clone());
                }
            }
            if !dead_rooms.is_empty() {
                for peer in peers.iter_mut() {
                    if peer.role == PeerRole::Viewer && dead_rooms.contains(&peer.room_id) {
                        tracing::info!("{}: kicking viewer (broadcaster left room '{}')", peer.id, peer.room_id);
                        peer.rtc.disconnect();
                    }
                }
            }

            for peer in peers.iter_mut() {
                if !peer.rtc.is_alive() {
                    loop {
                        match peer.rtc.poll_output() {
                            Ok(Output::Transmit(t)) => {
                                if let Err(e) = socket.try_send_to(&t.contents, t.destination) {
                                    tracing::warn!("{}: final UDP send error: {}", peer.id, e);
                                }
                            }
                            _ => break,
                        }
                    }
                }
            }

            peers.retain(|p| p.rtc.is_alive());

            // Recompute viewer counts and broadcaster liveness.
            let now = Instant::now();
            let media_timeout = Duration::from_secs(3);
            let mut viewer_counts: HashMap<&str, u32> = HashMap::new();
            let mut live_rooms: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for peer in peers.iter() {
                match peer.role {
                    PeerRole::Viewer => { *viewer_counts.entry(&peer.room_id).or_insert(0) += 1; }
                    PeerRole::Broadcaster => {
                        let sending = peer.last_media_at
                            .map(|t| now.duration_since(t) < media_timeout)
                            .unwrap_or(false);
                        if sending {
                            live_rooms.insert(&peer.room_id);
                        }
                    }
                }
            }
            if let Ok(mut state) = room_state.lock() {
                for info in state.values_mut() {
                    info.viewer_count = 0;
                    info.is_live = false;
                }
                for (room_id, count) in viewer_counts {
                    state.entry(room_id.to_owned())
                        .or_default()
                        .viewer_count = count;
                }
                for room_id in live_rooms {
                    state.entry(room_id.to_owned())
                        .or_default()
                        .is_live = true;
                }
            }
        }

        // ── Accept new peers from HTTP handlers ───────────────────
        while let Ok(new) = new_peer_rx.try_recv() {
            let peer_id = new.peer_id;
            let room_id = new.room_id.clone();
            let role = new.role;
            let mut peer = Peer::new(peer_id, new.rtc, role, new.room_id);

            if role == PeerRole::Broadcaster {
                peer.last_media_at = Some(Instant::now());
                for old in peers.iter_mut().filter(|p| {
                    p.role == PeerRole::Broadcaster && p.room_id == room_id
                }) {
                    tracing::info!("{}: evicting stale broadcaster from room '{}'", old.id, room_id);
                    old.rtc.disconnect();
                }
            }

            if role == PeerRole::Viewer {
                for bcast in peers.iter().filter(|p| {
                    p.role == PeerRole::Broadcaster && p.room_id == room_id
                }) {
                    for track_in in &bcast.tracks_in {
                        peer.tracks_out.push(TrackOut {
                            source_peer: bcast.id,
                            source_mid: track_in.mid,
                            kind: track_in.kind,
                            local_mid: None,
                        });
                    }
                }
            }

            tracing::info!("{} joined room '{}' as {:?}", peer_id, room_id, role);
            peers.push(peer);
        }

        // ── Process control channels ──────────────────────────────
        while let Ok(qc) = quality_rx.try_recv() {
            if let Some(peer) = peers.iter_mut().find(|p| {
                p.id == qc.peer_id && p.room_id == qc.room_id && p.role == PeerRole::Viewer
            }) {
                tracing::info!("{}: quality changed to {:?}", peer.id, qc.rid);
                peer.chosen_rid = qc.rid;
            }
        }

        while let Ok(dc) = disconnect_rx.try_recv() {
            if let Some(peer) = peers.iter_mut().find(|p| {
                p.id == dc.peer_id && p.room_id == dc.room_id && p.role == PeerRole::Viewer
            }) {
                tracing::info!("{}: explicit disconnect from room '{}'", peer.id, peer.room_id);
                peer.rtc.disconnect();
            }
        }

        // ── Batch-read all available UDP packets ─────────────────
        let mut read_something = false;
        loop {
            match socket.try_recv_from(&mut buf) {
                Ok((n, source)) => {
                    read_something = true;
                    let now = Instant::now();
                    if let Ok(receive) = Receive::new(Protocol::Udp, source, candidate_addr, &buf[..n]) {
                        let input = Input::Receive(now, receive);
                        if let Some(peer) = peers.iter_mut().find(|p| p.rtc.accepts(&input)) {
                            if let Err(e) = peer.rtc.handle_input(input) {
                                tracing::warn!("{}: handle_input error: {:?}", peer.id, e);
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }

        // ── Drive time forward on all peers (once per batch) ─────
        let now = Instant::now();
        for peer in peers.iter_mut() {
            if peer.rtc.is_alive() {
                let _ = peer.rtc.handle_input(Input::Timeout(now));
            }
        }

        // ── Poll + propagate + flush in a tight loop ─────────────
        // After batch-reading, poll all peers to collect events,
        // then drain the propagation queue, flushing each write's
        // resulting Transmit packets immediately before the next.
        let mut next_timeout = Instant::now() + Duration::from_millis(100);

        loop {
            for peer in peers.iter_mut() {
                if !peer.rtc.is_alive() { continue; }
                loop {
                    match peer.rtc.poll_output() {
                        Ok(Output::Timeout(t)) => {
                            next_timeout = next_timeout.min(t);
                            break;
                        }
                        Ok(Output::Transmit(t)) => {
                            if let Err(e) = socket.try_send_to(&t.contents, t.destination) {
                                tracing::warn!("{}: UDP send error: {}", peer.id, e);
                            }
                        }
                        Ok(Output::Event(event)) => {
                            let ev = handle_peer_event(peer, event);
                            if !matches!(ev, Propagated::Noop) {
                                propagation_queue.push_back(ev);
                            }
                        }
                        Err(e) => {
                            tracing::error!("{}: poll error: {:?}", peer.id, e);
                            peer.rtc.disconnect();
                            break;
                        }
                    }
                }
            }

            if propagation_queue.is_empty() {
                break;
            }

            while let Some(prop) = propagation_queue.pop_front() {
                if matches!(&prop, Propagated::Media { .. }) {
                    media_fwd_count += 1;
                }
                propagate(prop, &mut peers);
            }
        }

        if last_media_log.elapsed() >= Duration::from_secs(5) {
            if media_fwd_count > 0 {
                tracing::info!("SFU media: {} events forwarded in 5s (~{}/s)", media_fwd_count, media_fwd_count / 5);
            }
            media_fwd_count = 0;
            last_media_log = Instant::now();
        }

        // ── Yield to tokio only when idle ────────────────────────
        if !read_something {
            let wait = next_timeout.saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1));
            tokio::select! {
                _ = socket.readable() => {}
                _ = sleep(wait) => {}
            }
        }
    }
}

/// Process a single event from a peer's Rtc instance.
fn handle_peer_event(peer: &mut Peer, event: Event) -> Propagated {
    match event {
        Event::IceConnectionStateChange(state) => {
            tracing::info!("{}: ICE state -> {:?}", peer.id, state);
            if state == IceConnectionState::Disconnected {
                peer.rtc.disconnect();
            }
            Propagated::Noop
        }

        Event::MediaAdded(ev) => {
            tracing::info!("{}: media added mid={} kind={:?} dir={:?}", peer.id, ev.mid, ev.kind, ev.direction);
            if peer.role == PeerRole::Broadcaster {
                peer.tracks_in.push(TrackIn { mid: ev.mid, kind: ev.kind });
                return Propagated::TrackOpen {
                    source_peer: peer.id,
                    room_id: peer.room_id.clone(),
                    mid: ev.mid,
                    kind: ev.kind,
                };
            }
            if peer.role == PeerRole::Viewer {
                // The viewer's SDP offer contained recvonly m-lines. str0m fires MediaAdded
                // for each one. Match it to an unmapped TrackOut of the same media kind so
                // the SFU knows where to write incoming broadcaster media.
                if let Some(track_out) = peer.tracks_out.iter_mut().find(|t| {
                    t.local_mid.is_none() && t.kind == ev.kind
                }) {
                    tracing::info!("{}: mapped viewer mid={} -> broadcaster mid={}", peer.id, ev.mid, track_out.source_mid);
                    track_out.local_mid = Some(ev.mid);
                }
            }
            Propagated::Noop
        }

        Event::MediaData(data) => {
            if peer.role == PeerRole::Broadcaster {
                peer.last_media_at = Some(Instant::now());
                return Propagated::Media {
                    source_peer: peer.id,
                    room_id: peer.room_id.clone(),
                    data,
                };
            }
            Propagated::Noop
        }

        Event::KeyframeRequest(req) => {
            if peer.role == PeerRole::Viewer {
                if let Some(track_out) = peer.tracks_out.iter().find(|t| t.local_mid == Some(req.mid)) {
                    return Propagated::Keyframe {
                        request: req,
                        target_peer: track_out.source_peer,
                        source_mid: track_out.source_mid,
                    };
                }
            }
            Propagated::Noop
        }

        _ => Propagated::Noop,
    }
}

/// Forward a propagated event to all relevant peers.
/// Takes ownership so frame data can be moved (zero-copy) to the last viewer.
fn propagate(prop: Propagated, peers: &mut [Peer]) {
    match prop {
        Propagated::TrackOpen { source_peer, room_id, mid, kind } => {
            for peer in peers.iter_mut() {
                if peer.role != PeerRole::Viewer || peer.room_id != room_id {
                    continue;
                }
                let already_mapped = peer.tracks_out.iter().any(|t| {
                    t.source_peer == source_peer && t.source_mid == mid
                });
                if !already_mapped {
                    peer.tracks_out.push(TrackOut {
                        source_peer,
                        source_mid: mid,
                        kind,
                        local_mid: None,
                    });
                }
            }
        }

        Propagated::Media { source_peer, room_id, mut data } => {
            let viewer_count = peers.iter().filter(|p| {
                p.role == PeerRole::Viewer && p.room_id == room_id && p.id != source_peer
            }).count();

            let mut written = 0u32;
            for peer in peers.iter_mut() {
                if peer.role != PeerRole::Viewer
                    || peer.room_id != room_id
                    || peer.id == source_peer
                {
                    continue;
                }

                if let Some(ref actual_rid) = data.rid {
                    let default_rid: Rid = "h".into();
                    let target = peer.chosen_rid.as_ref().unwrap_or(&default_rid);
                    if target != actual_rid {
                        continue;
                    }
                }

                let local_mid = peer.tracks_out.iter()
                    .find(|t| t.source_peer == source_peer && t.source_mid == data.mid)
                    .and_then(|t| t.local_mid);

                let Some(mid) = local_mid else {
                    continue;
                };

                let Some(mut writer) = peer.rtc.writer(mid) else {
                    continue;
                };

                let Some(pt) = writer.match_params(data.params) else {
                    continue;
                };

                if let Some(orientation) = data.ext_vals.video_orientation {
                    writer = writer.video_orientation(orientation);
                }

                written += 1;
                let frame = if written >= viewer_count as u32 {
                    std::mem::take(&mut data.data)
                } else {
                    data.data.clone()
                };

                if let Err(e) = writer.write(pt, data.network_time, data.time, frame) {
                    tracing::warn!("{}: write error: {:?}", peer.id, e);
                    peer.rtc.disconnect();
                }
            }
        }

        Propagated::Keyframe { target_peer, source_mid, request, .. } => {
            if let Some(broadcaster) = peers.iter_mut().find(|p| p.id == target_peer) {
                if let Some(mut writer) = broadcaster.rtc.writer(source_mid) {
                    let _ = writer.request_keyframe(request.rid, request.kind);
                }
            }
        }

        Propagated::Noop => {}
    }
}
