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
use str0m::{Candidate, Rtc};
use tokio::sync::mpsc;

use crate::sfu::{NewPeer, PeerDisconnect, PeerId, PeerRole, QualityChange, RoomStateMap};

/// Shared state injected into axum handlers.
pub struct AppState {
    pub new_peer_tx: mpsc::UnboundedSender<NewPeer>,
    pub quality_tx: mpsc::UnboundedSender<QualityChange>,
    pub disconnect_tx: mpsc::UnboundedSender<PeerDisconnect>,
    pub room_state: RoomStateMap,
    pub udp_candidate_addr: SocketAddr,
}

/// WHIP Ingest Handler — receives SDP Offer from the Broadcaster (proxied via Go).
/// Creates an Rtc, negotiates SDP, and ships the instance to the SFU run loop.
pub async fn whip_handler(
    State(state): State<Arc<AppState>>,
    Path(stream_id): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    let sdp_raw = String::from_utf8_lossy(&body);
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

    let mut rtc = Rtc::new(Instant::now());

    let candidate = match Candidate::host(state.udp_candidate_addr, "udp") {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to create host candidate: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("Content-Type", "text/plain")],
                "Internal candidate error".to_string(),
            );
        }
    };
    rtc.add_local_candidate(candidate);

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
    body: Bytes,
) -> axum::response::Response {
    let sdp_raw = String::from_utf8_lossy(&body);
    tracing::info!("WHEP offer for room '{}'", room_id);

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

    let mut rtc = Rtc::new(Instant::now());

    let candidate = match Candidate::host(state.udp_candidate_addr, "udp") {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to create host candidate: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("Content-Type", "text/plain")],
                "Internal candidate error",
            ).into_response();
        }
    };
    rtc.add_local_candidate(candidate);

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
    pub password: Option<String>,
}

/// Returns current viewer count, max viewer cap, and password state for a room.
/// The `password` field is included for internal Go proxy queries.
/// The Go proxy strips it before forwarding to external clients.
pub async fn room_info_handler(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<String>,
) -> impl IntoResponse {
    let info = state.room_state.lock()
        .ok()
        .and_then(|s| s.get(&room_id).cloned());

    let resp = match info {
        Some(info) => RoomInfoResponse {
            viewer_count: info.viewer_count,
            max_viewers: info.max_viewers,
            has_password: info.password.is_some(),
            is_live: info.is_live,
            password: info.password,
        },
        None => RoomInfoResponse {
            viewer_count: 0,
            max_viewers: 0,
            has_password: false,
            is_live: false,
            password: None,
        },
    };

    (StatusCode::OK, Json(resp))
}

#[derive(Deserialize)]
pub struct ViewerLimitRequest {
    pub max_viewers: u32,
}

/// Sets the maximum viewer count for a room. Called by the broadcaster.
pub async fn viewer_limit_handler(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<String>,
    Json(body): Json<ViewerLimitRequest>,
) -> impl IntoResponse {
    if let Ok(mut s) = state.room_state.lock() {
        s.entry(room_id.clone()).or_default().max_viewers = body.max_viewers;
    }

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
    Json(body): Json<RoomPasswordRequest>,
) -> impl IntoResponse {
    let pw = if body.password.is_empty() { None } else { Some(body.password.clone()) };
    let active = pw.is_some();

    if let Ok(mut s) = state.room_state.lock() {
        s.entry(room_id.clone()).or_default().password = pw;
    }

    tracing::info!("Room password for '{}': {}", room_id, if active { "set" } else { "cleared" });
    (StatusCode::OK, "ok")
}

#[derive(Serialize)]
pub struct ActiveRoomResponse {
    pub room_id: Option<String>,
    pub has_password: bool,
}

/// Returns the first currently-live room, or null if no broadcast is active.
pub async fn active_handler(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let active = state.room_state.lock()
        .ok()
        .and_then(|s| {
            s.iter()
                .find(|(_, info)| info.is_live)
                .map(|(id, info)| (id.clone(), info.password.is_some()))
        });

    let resp = match active {
        Some((id, has_pw)) => ActiveRoomResponse { room_id: Some(id), has_password: has_pw },
        None => ActiveRoomResponse { room_id: None, has_password: false },
    };

    (StatusCode::OK, Json(resp))
}
