use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use str0m::format::Codec;
use str0m::media::{KeyframeRequest, KeyframeRequestKind, MediaData, Mid, Rid};
use str0m::net::{Protocol, Receive};
use str0m::{Event, IceConnectionState, Input, Output, Rtc};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::hls::HlsSink;

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
    /// Shown on the watch page when the room is not live (broadcaster-set).
    pub offline_banner: String,
}

impl Default for RoomInfo {
    fn default() -> Self {
        Self {
            viewer_count: 0,
            max_viewers: 0,
            password: None,
            is_live: false,
            offline_banner: String::new(),
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

/// Simulcast quality levels in descending order.
const QUALITY_LEVELS: &[&str] = &["h", "m", "l"];
const AQ_BAD_THRESHOLD: u8 = 1;
const AQ_GOOD_THRESHOLD: u8 = 6;
const AQ_COOLDOWN: Duration = Duration::from_secs(8);
const AQ_UPGRADE_COOLDOWN: Duration = Duration::from_secs(30);
const AQ_LOSS_BAD: f32 = 0.03;
const AQ_LOSS_GOOD: f32 = 0.01;
const AQ_NACK_BAD: u64 = 5;
const AQ_NACK_GOOD: u64 = 2;

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
    logged_mids: Vec<Mid>,
    aq_bad_count: u8,
    aq_good_count: u8,
    aq_last_change: Option<Instant>,
    aq_manual: bool,
    write_error_count: u32,
    last_video_write: Instant,
}

const WRITE_ERROR_DISCONNECT_THRESHOLD: u32 = 50;

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
            logged_mids: Vec::new(),
            aq_bad_count: 0,
            aq_good_count: 0,
            aq_last_change: None,
            aq_manual: false,
            write_error_count: 0,
            last_video_write: Instant::now(),
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
    hls_dir: Option<PathBuf>,
) {
    let mut peers: Vec<Peer> = Vec::new();
    let mut propagation_queue: VecDeque<Propagated> = VecDeque::new();
    let mut buf = vec![0u8; 2000];
    let mut last_housekeeping = Instant::now();
    let mut media_fwd_count: u64 = 0;
    let mut last_media_log = Instant::now();
    let mut hls_sinks: HashMap<String, HlsSink> = HashMap::new();
    let mut addr_cache: HashMap<SocketAddr, usize> = HashMap::new();
    let mut last_keyframe_per_peer: HashMap<PeerId, Instant> = HashMap::new();
    let mut room_viewer_cache: HashMap<String, usize> = HashMap::new();

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
                for room in &dead_rooms {
                    if let Some(sink) = hls_sinks.remove(room) {
                        sink.stop();
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
            addr_cache.clear();

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

            room_viewer_cache.clear();
            for (&room_id, &count) in &viewer_counts {
                room_viewer_cache.insert(room_id.to_owned(), count as usize);
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
                if let Some(old_sink) = hls_sinks.remove(&room_id) {
                    old_sink.stop();
                }
                if let Some(ref dir) = hls_dir {
                    match HlsSink::start(&room_id, dir) {
                        Ok(sink) => { hls_sinks.insert(room_id.clone(), sink); }
                        Err(e) => tracing::warn!("HLS sink failed for '{}': {}", room_id, e),
                    }
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
            let mut keyframe_needed: Option<(PeerId, Rid)> = None;

            if let Some(peer) = peers.iter_mut().find(|p| {
                p.id == qc.peer_id && p.room_id == qc.room_id && p.role == PeerRole::Viewer
            }) {
                tracing::info!("{}: manual quality -> {:?}", peer.id, qc.rid);
                peer.chosen_rid = qc.rid.clone();
                peer.aq_manual = qc.rid.is_some();
                peer.aq_bad_count = 0;
                peer.aq_good_count = 0;

                let target_rid: Rid = match qc.rid {
                    Some(rid) => rid,
                    None => "h".into(),
                };
                if let Some(track_out) = peer.tracks_out.iter().find(|t| {
                    t.kind == str0m::media::MediaKind::Video
                }) {
                    keyframe_needed = Some((track_out.source_peer, target_rid));
                }
            }

            if let Some((broadcaster_id, rid)) = keyframe_needed {
                if let Some(broadcaster) = peers.iter_mut().find(|p| p.id == broadcaster_id) {
                    if let Some(track_in) = broadcaster.tracks_in.iter().find(|t| {
                        t.kind == str0m::media::MediaKind::Video
                    }) {
                        if let Some(mut writer) = broadcaster.rtc.writer(track_in.mid) {
                            let _ = writer.request_keyframe(
                                Some(rid),
                                KeyframeRequestKind::Pli,
                            );
                        }
                    }
                }
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

                        // Fast path: check address cache
                        if let Some(&idx) = addr_cache.get(&source) {
                            if idx < peers.len() && peers[idx].rtc.accepts(&input) {
                                if let Err(e) = peers[idx].rtc.handle_input(input) {
                                    tracing::warn!("{}: handle_input error: {:?}", peers[idx].id, e);
                                }
                                continue;
                            }
                        }

                        // Slow path: linear scan, then update cache
                        for (i, peer) in peers.iter_mut().enumerate() {
                            if peer.rtc.accepts(&input) {
                                addr_cache.insert(source, i);
                                if let Err(e) = peer.rtc.handle_input(input) {
                                    tracing::warn!("{}: handle_input error: {:?}", peer.id, e);
                                }
                                break;
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
                if let Propagated::Keyframe { target_peer, .. } = &prop {
                    let now = Instant::now();
                    if let Some(last) = last_keyframe_per_peer.get(target_peer) {
                        if now.duration_since(*last) < Duration::from_millis(500) {
                            continue;
                        }
                    }
                    last_keyframe_per_peer.insert(*target_peer, now);
                }
                propagate(prop, &mut peers, &mut hls_sinks, &room_viewer_cache);
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
                if let Some(track_out) = peer.tracks_out.iter_mut().find(|t| {
                    t.local_mid.is_none() && t.kind == ev.kind
                }) {
                    tracing::info!("{}: mapped viewer mid={} -> broadcaster mid={}", peer.id, ev.mid, track_out.source_mid);
                    track_out.local_mid = Some(ev.mid);

                    if ev.kind == str0m::media::MediaKind::Video {
                        if let Some(tx) = peer.rtc.direct_api().stream_tx_by_mid(ev.mid, None) {
                            tx.set_rtx_cache(1024, Duration::from_secs(2), Some(0.15));
                            tracing::info!("{}: RTX cache tuned for video mid={}", peer.id, ev.mid);
                        }
                    } else if ev.kind == str0m::media::MediaKind::Audio {
                        if let Some(tx) = peer.rtc.direct_api().stream_tx_by_mid(ev.mid, None) {
                            tx.set_rtx_cache(1, Duration::from_millis(1), Some(0.0));
                            tracing::info!("{}: audio RTX disabled mid={}", peer.id, ev.mid);
                        }
                    }
                }
            }
            Propagated::Noop
        }

        Event::MediaData(data) => {
            if peer.role == PeerRole::Broadcaster {
                if !peer.logged_mids.contains(&data.mid) {
                    let codec = data.params.spec().codec;
                    tracing::info!(
                        "{} room='{}': first media mid={} codec={:?} keyframe={}",
                        peer.id, peer.room_id, data.mid, codec, data.is_keyframe()
                    );
                    peer.logged_mids.push(data.mid);
                }
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

        Event::MediaEgressStats(stats) => {
            if peer.role != PeerRole::Viewer {
                return Propagated::Noop;
            }

            let is_video = peer.tracks_out.iter().any(|t| {
                t.local_mid == Some(stats.mid) && t.kind == str0m::media::MediaKind::Video
            });
            if !is_video || peer.aq_manual {
                return Propagated::Noop;
            }

            if peer.chosen_rid.is_some() {
                let stale = stats.timestamp.saturating_duration_since(peer.last_video_write);
                if stale > Duration::from_secs(3) {
                    tracing::warn!(
                        "{}: video stale {:.1}s on {:?}, resetting to default layer",
                        peer.id, stale.as_secs_f32(), peer.chosen_rid
                    );
                    peer.chosen_rid = None;
                    peer.aq_bad_count = 0;
                    peer.aq_good_count = 0;
                    peer.aq_last_change = Some(stats.timestamp);
                    if let Some(track_out) = peer.tracks_out.iter().find(|t| {
                        t.kind == str0m::media::MediaKind::Video
                    }) {
                        return Propagated::Keyframe {
                            request: KeyframeRequest {
                                mid: track_out.local_mid.unwrap_or(track_out.source_mid),
                                rid: Some("h".into()),
                                kind: KeyframeRequestKind::Pli,
                            },
                            target_peer: track_out.source_peer,
                            source_mid: track_out.source_mid,
                        };
                    }
                }
            }

            let loss = stats.loss.unwrap_or(0.0);
            let is_bad = loss > AQ_LOSS_BAD || stats.nacks > AQ_NACK_BAD;
            let is_good = loss < AQ_LOSS_GOOD && stats.nacks <= AQ_NACK_GOOD;

            let current_idx = peer.chosen_rid.as_ref()
                .and_then(|r| QUALITY_LEVELS.iter().position(|&q| q == &**r))
                .unwrap_or(0);

            if is_bad {
                peer.aq_good_count = 0;
                peer.aq_bad_count = peer.aq_bad_count.saturating_add(1);
            } else if is_good {
                peer.aq_bad_count = 0;
                peer.aq_good_count = peer.aq_good_count.saturating_add(1);
            } else {
                peer.aq_bad_count = peer.aq_bad_count.saturating_sub(1);
                peer.aq_good_count = 0;
            }

            let now = stats.timestamp;

            let new_idx = if peer.aq_bad_count >= AQ_BAD_THRESHOLD
                && current_idx < QUALITY_LEVELS.len() - 1
            {
                let can_downgrade = peer.aq_last_change
                    .map(|t| now.saturating_duration_since(t) >= AQ_COOLDOWN)
                    .unwrap_or(true);
                if can_downgrade {
                    peer.aq_bad_count = 0;
                    Some(current_idx + 1)
                } else {
                    None
                }
            } else if peer.aq_good_count >= AQ_GOOD_THRESHOLD && current_idx > 0 {
                let can_upgrade = peer.aq_last_change
                    .map(|t| now.saturating_duration_since(t) >= AQ_UPGRADE_COOLDOWN)
                    .unwrap_or(true);
                if can_upgrade {
                    peer.aq_good_count = 0;
                    Some(current_idx - 1)
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(idx) = new_idx {
                let new_rid: Rid = QUALITY_LEVELS[idx].into();
                tracing::info!(
                    "{}: auto-quality {:?} -> {} (loss={:.1}% nacks={})",
                    peer.id, peer.chosen_rid, &*new_rid, loss * 100.0, stats.nacks
                );
                peer.chosen_rid = Some(new_rid.clone());
                peer.aq_last_change = Some(now);

                if let Some(track_out) = peer.tracks_out.iter().find(|t| {
                    t.kind == str0m::media::MediaKind::Video
                }) {
                    return Propagated::Keyframe {
                        request: KeyframeRequest {
                            mid: track_out.local_mid.unwrap_or(track_out.source_mid),
                            rid: Some(new_rid),
                            kind: KeyframeRequestKind::Pli,
                        },
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
fn propagate(
    prop: Propagated,
    peers: &mut [Peer],
    hls_sinks: &mut HashMap<String, HlsSink>,
    room_viewer_cache: &HashMap<String, usize>,
) {
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
            if data.params.spec().codec == Codec::H264 {
                if let Some(sink) = hls_sinks.get_mut(&room_id) {
                    let pts = data.time.numer();
                    let is_kf = data.is_keyframe();
                    if !sink.write_video(pts, is_kf, &data.data) {
                        hls_sinks.remove(&room_id);
                    }
                }
            }

            let viewer_count = room_viewer_cache.get(&room_id).copied().unwrap_or(0);

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

                let (local_mid, is_video) = peer.tracks_out.iter()
                    .find(|t| t.source_peer == source_peer && t.source_mid == data.mid)
                    .map(|t| (t.local_mid, t.kind == str0m::media::MediaKind::Video))
                    .unwrap_or((None, false));

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

                match writer.write(pt, data.network_time, data.time, frame) {
                    Ok(()) => {
                        peer.write_error_count = 0;
                        if is_video { peer.last_video_write = Instant::now(); }
                    }
                    Err(e) => {
                        peer.write_error_count += 1;
                        if peer.write_error_count >= WRITE_ERROR_DISCONNECT_THRESHOLD {
                            tracing::warn!("{}: {} consecutive write errors, disconnecting: {:?}", peer.id, peer.write_error_count, e);
                            peer.rtc.disconnect();
                        }
                    }
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
