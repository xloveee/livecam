use std::sync::Arc;

use axum::{http::StatusCode, routing::{get, post}, Router};
use tokio::sync::mpsc;

mod api;
mod config;
mod hls;
mod sfu;
mod room_persist;
mod stun_loopback;

use api::AppState;
use config::Config;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    str0m::crypto::from_feature_flags().install_process_default();

    let cfg = Config::from_env();
    if cfg.internal_secret.len() < 16 {
        panic!("SFU_INTERNAL_SECRET must be at least 16 bytes");
    }
    tracing::info!("HTTP API on {}", cfg.http_bind);
    tracing::info!("UDP bind addrs {:?}", cfg.media_bind_addrs());
    tracing::info!("ICE candidate {}", cfg.udp_candidate_addr());
    tracing::info!("ICE host candidates {:?}", cfg.ice_candidate_addrs());

    let mut udp_sockets = Vec::new();
    for addr in cfg.media_bind_addrs() {
        let sock = tokio::net::UdpSocket::bind(addr)
            .await
            .unwrap_or_else(|e| panic!("failed to bind UDP socket {addr}: {e}"));
        let sndbuf: i32 = 2 * 1024 * 1024;
        let rcvbuf: i32 = 2 * 1024 * 1024;
        let sock_ref = socket2::SockRef::from(&sock);
        if let Err(e) = sock_ref.set_send_buffer_size(sndbuf as usize) {
            tracing::warn!("SO_SNDBUF set failed on {addr}: {e}");
        }
        if let Err(e) = sock_ref.set_recv_buffer_size(rcvbuf as usize) {
            tracing::warn!("SO_RCVBUF set failed on {addr}: {e}");
        }
        tracing::info!(
            "UDP {addr} buffers: send={}KB recv={}KB",
            sock_ref.send_buffer_size().unwrap_or(0) / 1024,
            sock_ref.recv_buffer_size().unwrap_or(0) / 1024,
        );
        udp_sockets.push(sock);
    }
    if udp_sockets.is_empty() {
        panic!("no UDP media sockets bound");
    }

    let stun_addr: std::net::SocketAddr = "127.0.0.1:3478".parse().unwrap();
    match tokio::net::UdpSocket::bind(stun_addr).await {
        Ok(stun_sock) => {
            tokio::spawn(stun_loopback::run(stun_sock));
        }
        Err(e) => tracing::warn!("loopback STUN bind {stun_addr}: {e}"),
    }

    let (new_peer_tx, new_peer_rx) = mpsc::unbounded_channel();
    let (quality_tx, quality_rx) = mpsc::unbounded_channel();
    let (disconnect_tx, disconnect_rx) = mpsc::unbounded_channel();
    let room_state = sfu::new_room_state();
    let persist_file = room_persist::default_persist_path(&cfg.hls_dir);
    room_persist::load_into(&room_state, &persist_file);
    let persist_path = room_persist::new_persist_path(Some(persist_file));

    let udp_candidate_addr = cfg.udp_candidate_addr();
    let ice_candidate_addrs = cfg.ice_candidate_addrs();
    if let Some(ref dir) = cfg.hls_dir {
        tracing::info!("HLS output enabled -> {:?}", dir);
    }
    tokio::spawn(sfu::run_sfu_loop(
        udp_sockets, udp_candidate_addr, ice_candidate_addrs.clone(),
        new_peer_rx, quality_rx, disconnect_rx, room_state.clone(),
        cfg.hls_dir.clone(),
    ));

    let state = Arc::new(AppState {
        new_peer_tx,
        quality_tx,
        disconnect_tx,
        room_state,
        udp_candidate_addr,
        ice_candidate_addrs,
        internal_secret: cfg.internal_secret.clone(),
        persist_path,
    });

    let app = Router::new()
        .route("/whip/:stream_id", post(api::whip_handler))
        .route("/whep/:room_id", post(api::whep_handler).delete(api::disconnect_handler))
        .route("/quality/:room_id", post(api::quality_handler))
        .route("/room_info/:room_id", get(api::room_info_handler))
        .route("/viewer_limit/:room_id", post(api::viewer_limit_handler))
        .route("/room_password/:room_id", post(api::room_password_handler))
        .route("/room_camera/:room_id", post(api::room_camera_handler))
        .route("/check_room_password/:room_id", post(api::check_room_password_handler))
        .route("/active", get(api::active_handler))
        .route("/health", get(|| async { (StatusCode::OK, "ok") }))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(cfg.http_bind)
        .await
        .expect("failed to bind HTTP listener");

    tracing::info!("Rust Core SFU ready");
    axum::serve(listener, app).await.unwrap();
}
