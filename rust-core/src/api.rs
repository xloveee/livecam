use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use str0m::change::SdpOffer;
use str0m::{Candidate, RtcConfig};
use tokio::sync::mpsc;

use crate::config::whep_ice_addrs;
use crate::room_persist::{self, PersistPath, ROOM_PASSWORD_MAX_LEN};
use crate::sfu::{
    CameraLayout, NewPeer, PeerDisconnect, PeerId, PeerRole, QualityChange, RoomStateMap, SceneLayer,
    SceneLayout,
};

/// Shared state injected into axum handlers.
pub struct AppState {
    pub new_peer_tx: mpsc::UnboundedSender<NewPeer>,
    pub quality_tx: mpsc::UnboundedSender<QualityChange>,
    pub disconnect_tx: mpsc::UnboundedSender<PeerDisconnect>,
    pub room_state: RoomStateMap,
    pub udp_candidate_addr: SocketAddr,
    pub ice_candidate_addrs: Vec<SocketAddr>,
    pub internal_secret: String,
    pub persist_path: PersistPath,
}

pub fn valid_http_room_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

pub fn safe_hls_room_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn secrets_equal(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() || ab.is_empty() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..ab.len() {
        diff |= ab[i] ^ bb[i];
    }
    diff == 0
}

fn authorize(state: &AppState, headers: &HeaderMap) -> bool {
    let got = headers
        .get("X-SFU-Internal")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    secrets_equal(got, &state.internal_secret)
}


fn add_host_candidates(rtc: &mut str0m::Rtc, addrs: &[SocketAddr]) -> Result<(), String> {
    if addrs.is_empty() {
        return Err("no ICE host candidates configured".into());
    }
    for addr in addrs {
        let candidate = Candidate::host(*addr, "udp")
            .map_err(|e| format!("Failed to create host candidate {}: {:?}", addr, e))?;
        rtc.add_local_candidate(candidate);
    }
    Ok(())
}

/// str0m requires `s=-` (JSEP). ffmpeg WHIP emits `s=FFmpegPublishSession`.
fn normalize_sdp_session_name(sdp: &str) -> String {
    let mut out = String::with_capacity(sdp.len());
    for line in sdp.split_inclusive(['\n']) {
        let content = line.trim_end_matches(['\r', '\n']);
        if let Some(name) = content.strip_prefix("s=") {
            if name != "-" {
                out.push_str("s=-");
                out.push_str(&line[content.len()..]);
                continue;
            }
        }
        out.push_str(line);
    }
    out
}

/// WHIP Ingest Handler — receives SDP Offer from the Broadcaster (proxied via Go).
/// Creates an Rtc, negotiates SDP, and ships the instance to the SFU run loop.
pub async fn whip_handler(
    State(state): State<Arc<AppState>>,
    Path(stream_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if !authorize(&state, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            [("Content-Type", "text/plain")],
            "unauthorized".to_string(),
        );
    }
    if !valid_http_room_id(&stream_id) {
        return (
            StatusCode::BAD_REQUEST,
            [("Content-Type", "text/plain")],
            "invalid room id".to_string(),
        );
    }
    let is_live = state
        .room_state
        .lock()
        .ok()
        .and_then(|s| s.get(&stream_id).map(|info| info.is_live))
        .unwrap_or(false);
    if is_live {
        return (
            StatusCode::CONFLICT,
            [("Content-Type", "text/plain")],
            "room already has a live publisher".to_string(),
        );
    }
    let sdp_raw = normalize_sdp_session_name(&String::from_utf8_lossy(&body));
    tracing::info!("WHIP offer for stream '{}'", stream_id);

    let offer = match SdpOffer::from_sdp_string(&sdp_raw) {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("Failed to parse SDP offer: {:?}", e);
            return (
                StatusCode::BAD_REQUEST,
                [("Content-Type", "text/plain")],
                "Malformed SDP Offer".to_string(),
            );
        }
    };

    let mut rtc = RtcConfig::new()
        .set_ice_lite(true)
        .set_reordering_size_audio(0)
        .clear_codecs()
        .enable_h264(true)
        .enable_vp8(true)
        .enable_opus(true)
        .build(Instant::now());

    if let Err(e) = add_host_candidates(&mut rtc, &state.ice_candidate_addrs) {
        tracing::error!("{}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("Content-Type", "text/plain")],
            "Internal candidate error".to_string(),
        );
    }

    let answer = match rtc.sdp_api().accept_offer(offer) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Failed to accept WHIP offer: {:?}", e);
            return (
                StatusCode::BAD_REQUEST,
                [("Content-Type", "text/plain")],
                "Invalid SDP Offer".to_string(),
            );
        }
    };

    let answer_sdp = answer.to_sdp_string();

    let new_peer = NewPeer {
        peer_id: PeerId::next(),
        rtc,
        role: PeerRole::Broadcaster,
        room_id: stream_id,
    };

    if state.new_peer_tx.send(new_peer).is_err() {
        tracing::error!("SFU run loop has shut down");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("Content-Type", "text/plain")],
            "SFU unavailable".to_string(),
        );
    }

    (
        StatusCode::CREATED,
        [("Content-Type", "application/sdp")],
        answer_sdp,
    )
}

/// WHEP Egress Handler — receives SDP Offer from a Viewer (proxied via Go).
/// Creates an Rtc, negotiates SDP, and ships the instance to the SFU run loop.
/// Returns X-Session-Id header so the client can reference this peer for quality changes.
pub async fn whep_handler(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    if !authorize(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    if !valid_http_room_id(&room_id) {
        return (StatusCode::BAD_REQUEST, "invalid room id").into_response();
    }
    let sdp_raw = String::from_utf8_lossy(&body);
    let offer_cands: Vec<&str> = sdp_raw
        .lines()
        .filter(|l| l.starts_with("a=candidate:") || l.starts_with("a=ice-ufrag") || l.starts_with("a=ice-pwd"))
        .collect();
    tracing::info!("WHEP offer for room '{}' cands={:?}", room_id, offer_cands);

    let is_live = state.room_state.lock()
        .ok()
        .and_then(|s| s.get(&room_id).map(|info| info.is_live))
        .unwrap_or(false);

    if !is_live {
        tracing::info!("WHEP rejected for room '{}': not live", room_id);
        return (
            StatusCode::NOT_FOUND,
            [("Content-Type", "text/plain")],
            "Room is not live",
        ).into_response();
    }

    let offer = match SdpOffer::from_sdp_string(&sdp_raw) {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("Failed to parse SDP offer: {:?}", e);
            return (
                StatusCode::BAD_REQUEST,
                [("Content-Type", "text/plain")],
                "Malformed SDP Offer",
            ).into_response();
        }
    };

    let mut rtc = RtcConfig::new()
        .set_ice_lite(true)
        .set_reordering_size_audio(0)
        .set_send_buffer_video(500)
        .set_stats_interval(Some(std::time::Duration::from_secs(2)))
        .clear_codecs()
        .enable_h264(true)
        .enable_vp8(true)
        .enable_opus(true)
        .build(Instant::now());

    let whep_addrs = whep_ice_addrs(&sdp_raw, &state.ice_candidate_addrs);
    tracing::info!("WHEP ICE hosts for room '{}': {:?}", room_id, whep_addrs);
    if let Err(e) = add_host_candidates(&mut rtc, &whep_addrs) {
        tracing::error!("{}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("Content-Type", "text/plain")],
            "Internal candidate error",
        ).into_response();
    }

    let answer = match rtc.sdp_api().accept_offer(offer) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Failed to accept WHEP offer: {:?}", e);
            return (
                StatusCode::BAD_REQUEST,
                [("Content-Type", "text/plain")],
                "Invalid SDP Offer",
            ).into_response();
        }
    };

    let answer_sdp = answer.to_sdp_string();

    let peer_id = PeerId::next();
    let new_peer = NewPeer {
        peer_id,
        rtc,
        role: PeerRole::Viewer,
        room_id,
    };

    if state.new_peer_tx.send(new_peer).is_err() {
        tracing::error!("SFU run loop has shut down");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("Content-Type", "text/plain")],
            "SFU unavailable",
        ).into_response();
    }

    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", "application/sdp".parse().unwrap());
    headers.insert("X-Session-Id", peer_id.to_string().parse().unwrap());

    (StatusCode::CREATED, headers, answer_sdp).into_response()
}

#[derive(Deserialize)]
pub struct QualityRequest {
    pub rid: Option<String>,
}

/// Quality change handler — receives a rid selection from a viewer.
/// Expects X-Session-Id header to identify the peer.
pub async fn quality_handler(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<QualityRequest>,
 ) -> impl IntoResponse {
    if !authorize(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !valid_http_room_id(&room_id) {
        return (StatusCode::BAD_REQUEST, "invalid room id");
    }
    let session_id = match headers.get("X-Session-Id").and_then(|v| v.to_str().ok()) {
        Some(id) => id.to_owned(),
        None => {
            return (StatusCode::BAD_REQUEST, "Missing X-Session-Id header");
        }
    };

    let peer_id = match PeerId::parse(&session_id) {
        Some(id) => id,
        None => {
            return (StatusCode::BAD_REQUEST, "Invalid X-Session-Id");
        }
    };

    let rid = body.rid.as_deref().map(|s| s.into());

    let qc = QualityChange {
        peer_id,
        room_id: room_id.clone(),
        rid,
    };

    if state.quality_tx.send(qc).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "SFU unavailable");
    }

    tracing::info!("Quality change: {} room '{}' -> {:?}", session_id, room_id, body.rid);
    (StatusCode::OK, "ok")
}

/// Explicit viewer disconnect handler — called via DELETE /whep/{roomId}.
/// Expects X-Session-Id header to identify the peer.
pub async fn disconnect_handler(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let session_id = match headers.get("X-Session-Id").and_then(|v| v.to_str().ok()) {
        Some(id) => id.to_owned(),
        None => {
            return (StatusCode::BAD_REQUEST, "Missing X-Session-Id header");
        }
    };

    let peer_id = match PeerId::parse(&session_id) {
        Some(id) => id,
        None => {
            return (StatusCode::BAD_REQUEST, "Invalid X-Session-Id");
        }
    };

    let dc = PeerDisconnect {
        peer_id,
        room_id: room_id.clone(),
    };

    if state.disconnect_tx.send(dc).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "SFU unavailable");
    }

    tracing::info!("Viewer disconnect: {} room '{}'", session_id, room_id);
    (StatusCode::OK, "ok")
}

#[derive(Serialize)]
pub struct RoomInfoResponse {
    pub viewer_count: u32,
    pub max_viewers: u32,
    pub has_password: bool,
    pub is_live: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub camera: Option<CameraLayout>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scene: Option<SceneLayout>,
}

/// Returns current viewer count, max viewer cap, and password state for a room.
/// The `password` field is included for internal Go proxy queries.
/// The Go proxy strips it before forwarding to external clients.
pub async fn room_info_handler(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !authorize(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(RoomInfoResponse {
            viewer_count: 0,
            max_viewers: 0,
            has_password: false,
            is_live: false,
            camera: None,
            scene: None,
        })).into_response();
    }
    if !valid_http_room_id(&room_id) {
        return (StatusCode::BAD_REQUEST, Json(RoomInfoResponse {
            viewer_count: 0,
            max_viewers: 0,
            has_password: false,
            is_live: false,
            camera: None,
            scene: None,
        })).into_response();
    }
    let info = state.room_state.lock()
        .ok()
        .and_then(|s| s.get(&room_id).cloned());

    let Some(info) = info else {
        // H25: unknown room is not a public room (leftover HLS must not skip invite).
        return StatusCode::NOT_FOUND.into_response();
    };

    let resp = RoomInfoResponse {
        viewer_count: info.viewer_count,
        max_viewers: info.max_viewers,
        has_password: info.password_hash.is_some(),
        is_live: info.is_live,
        camera: info.camera,
        scene: info.scene,
    };

    (StatusCode::OK, Json(resp)).into_response()
}

#[derive(Deserialize)]
pub struct ViewerLimitRequest {
    pub max_viewers: u32,
}

/// Sets the maximum viewer count for a room. Called by the broadcaster.
pub async fn viewer_limit_handler(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ViewerLimitRequest>,
) -> impl IntoResponse {
    if !authorize(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !valid_http_room_id(&room_id) {
        return (StatusCode::BAD_REQUEST, "invalid room id");
    }
    if let Ok(mut s) = state.room_state.lock() {
        s.entry(room_id.clone()).or_default().max_viewers = body.max_viewers;
    }
    room_persist::persist_snapshot(&state.room_state, &state.persist_path);

    tracing::info!("Viewer limit for room '{}' set to {}", room_id, body.max_viewers);
    (StatusCode::OK, "ok")
}

#[derive(Deserialize)]
pub struct RoomPasswordRequest {
    pub password: String,
}

/// Sets or clears the room password. Empty string clears the password.
pub async fn room_password_handler(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<RoomPasswordRequest>,
) -> impl IntoResponse {
    if !authorize(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !valid_http_room_id(&room_id) {
        return (StatusCode::BAD_REQUEST, "invalid room id");
    }
    if body.password.len() > ROOM_PASSWORD_MAX_LEN {
        return (StatusCode::BAD_REQUEST, "password too long");
    }
    let hash = if body.password.is_empty() {
        None
    } else {
        Some(room_persist::hash_room_password(&body.password))
    };
    let active = hash.is_some();

    if let Ok(mut s) = state.room_state.lock() {
        s.entry(room_id.clone()).or_default().password_hash = hash;
    }
    room_persist::persist_snapshot(&state.room_state, &state.persist_path);

    tracing::info!("Room password for '{}': {}", room_id, if active { "set" } else { "cleared" });
    (StatusCode::OK, "ok")
}

#[derive(Deserialize)]
pub struct CameraLayoutRequest {
    #[serde(default)]
    pub x: f32,
    #[serde(default)]
    pub y: f32,
    #[serde(default)]
    pub w: f32,
    #[serde(default)]
    pub h: f32,
    #[serde(default)]
    pub visible: bool,
    #[serde(default)]
    pub plate_w: u32,
    #[serde(default)]
    pub plate_h: u32,
    #[serde(default)]
    pub layers: Vec<SceneLayer>,
}

fn clamp_norm(v: f32) -> f32 {
    v.clamp(-1.0, 2.0)
}

fn clamp_scene_layer(mut layer: SceneLayer) -> SceneLayer {
    layer.x = clamp_norm(layer.x);
    layer.y = clamp_norm(layer.y);
    layer.w = layer.w.clamp(0.0, 2.0);
    layer.h = layer.h.clamp(0.0, 2.0);
    layer.visible = layer.visible && layer.w > 0.0 && layer.h > 0.0;
    layer
}

fn camera_from_scene(scene: &SceneLayout) -> Option<CameraLayout> {
    let cam = scene.layers.iter().find(|l| {
        l.visible && (l.kind == "camera-face" || l.kind == "camera-extra")
    }).or_else(|| {
        scene.layers.iter().find(|l| l.visible && l.kind != "screen")
    });
    cam.map(|c| CameraLayout {
        x: c.x,
        y: c.y,
        w: c.w,
        h: c.h,
        visible: c.visible,
    })
}

/// Studio scene (every video layer x/y/w/h + track index) for WHEP composite.
/// Old `{x,y,w,h,visible}` camera-only bodies still work.
pub async fn room_camera_handler(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CameraLayoutRequest>,
) -> impl IntoResponse {
    if !authorize(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    if !valid_http_room_id(&room_id) {
        return (StatusCode::BAD_REQUEST, "invalid room id").into_response();
    }
    let scene = if !body.layers.is_empty() {
        SceneLayout {
            plate_w: if body.plate_w > 0 { body.plate_w } else { 1280 },
            plate_h: if body.plate_h > 0 { body.plate_h } else { 720 },
            layers: body.layers.into_iter().map(clamp_scene_layer).collect(),
        }
    } else {
        let visible = body.visible && body.w > 0.0 && body.h > 0.0;
        SceneLayout {
            plate_w: 1280,
            plate_h: 720,
            layers: vec![clamp_scene_layer(SceneLayer {
                id: "camera".into(),
                kind: "camera-face".into(),
                x: body.x,
                y: body.y,
                w: body.w,
                h: body.h,
                visible,
                track: 0,
                z: 1,
            })],
        }
    };
    let cam = camera_from_scene(&scene).unwrap_or(CameraLayout {
        x: body.x.clamp(-1.0, 2.0),
        y: body.y.clamp(-1.0, 2.0),
        w: body.w.clamp(0.0, 2.0),
        h: body.h.clamp(0.0, 2.0),
        visible: false,
    });
    if let Ok(mut s) = state.room_state.lock() {
        let info = s.entry(room_id.clone()).or_default();
        info.camera = Some(cam.clone());
        info.scene = Some(scene.clone());
    }
    tracing::info!(
        "Room scene for '{}': plate={}x{} layers={} camera visible={} {:.3},{:.3} {:.3}x{:.3}",
        room_id,
        scene.plate_w,
        scene.plate_h,
        scene.layers.len(),
        cam.visible,
        cam.x,
        cam.y,
        cam.w,
        cam.h
    );
    (StatusCode::OK, "ok").into_response()
}

#[derive(Serialize)]
pub struct ActiveRoomResponse {
    pub room_id: Option<String>,
    pub has_password: bool,
}

/// Returns the first currently-live room, or null if no broadcast is active.
pub async fn active_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !authorize(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(ActiveRoomResponse { room_id: None, has_password: false })).into_response();
    }
    let active = state.room_state.lock()
        .ok()
        .and_then(|s| {
            s.iter()
                .find(|(_, info)| info.is_live)
                .map(|(id, info)| (id.clone(), info.password_hash.is_some()))
        });

    let resp = match active {
        Some((id, has_pw)) => ActiveRoomResponse { room_id: Some(id), has_password: has_pw },
        None => ActiveRoomResponse { room_id: None, has_password: false },
    };

    (StatusCode::OK, Json(resp)).into_response()
}

#[cfg(test)]
mod tests {
    use super::normalize_sdp_session_name;

    #[test]
    fn ffmpeg_session_name_becomes_dash() {
        let raw = "v=0\r\no=FFmpeg 1 2 IN IP4 127.0.0.1\r\ns=FFmpegPublishSession\r\nt=0 0\r\n";
        let got = normalize_sdp_session_name(raw);
        assert!(got.contains("s=-\r\n"));
        assert!(!got.contains("FFmpegPublishSession"));
    }
}


#[derive(Deserialize)]
pub struct CheckRoomPasswordRequest {
    pub password: String,
}

#[derive(Serialize)]
pub struct CheckRoomPasswordResponse {
    pub ok: bool,
}

pub async fn check_room_password_handler(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CheckRoomPasswordRequest>,
) -> impl IntoResponse {
    if !authorize(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(CheckRoomPasswordResponse { ok: false })).into_response();
    }
    if !valid_http_room_id(&room_id) {
        return (StatusCode::BAD_REQUEST, Json(CheckRoomPasswordResponse { ok: false })).into_response();
    }
    if body.password.len() > ROOM_PASSWORD_MAX_LEN {
        return (StatusCode::BAD_REQUEST, Json(CheckRoomPasswordResponse { ok: false })).into_response();
    }
    let stored = state
        .room_state
        .lock()
        .ok()
        .and_then(|s| s.get(&room_id).and_then(|i| i.password_hash.clone()));
    let ok = match stored {
        Some(hash) => {
            room_persist::constant_eq_hex(&hash, &room_persist::hash_room_password(&body.password))
        }
        None => body.password.is_empty(),
    };
    (StatusCode::OK, Json(CheckRoomPasswordResponse { ok })).into_response()
}

#[cfg(test)]
mod auth_tests {
    use super::{safe_hls_room_id, valid_http_room_id};

    #[test]
    fn http_room_id_is_32_alnum() {
        assert!(valid_http_room_id("abcdefghijklmnopqrstuvwxyz012345"));
        assert!(!valid_http_room_id("room1"));
        assert!(!valid_http_room_id("../etc/passwd"));
    }

    #[test]
    fn linger_room_id_rejects_path_escape() {
        assert!(safe_hls_room_id("roomlinger"));
        assert!(!safe_hls_room_id("../etc"));
        assert!(!safe_hls_room_id("a/b"));
    }
}
