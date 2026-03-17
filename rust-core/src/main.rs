use std::sync::Arc;

use axum::{http::StatusCode, routing::{get, post}, Router};
use tokio::sync::mpsc;

mod api;
mod archive;
mod config;
mod sfu;

use api::AppState;
use config::Config;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    str0m::crypto::from_feature_flags().install_process_default();

    let cfg = Config::from_env();
    tracing::info!("HTTP API on {}", cfg.http_bind);
    tracing::info!("UDP bind on {}", cfg.udp_bind_addr());
    tracing::info!("ICE candidate {}", cfg.udp_candidate_addr());

    let std_socket = {
        let s = std::net::UdpSocket::bind(cfg.udp_bind_addr())
            .expect("failed to bind UDP socket");
        s.set_nonblocking(true).expect("failed to set non-blocking");
        let _ = s.set_recv_buffer_size(2 * 1024 * 1024);
        let _ = s.set_send_buffer_size(2 * 1024 * 1024);
        s
    };
    let udp_socket = tokio::net::UdpSocket::from_std(std_socket)
        .expect("failed to wrap UDP socket");

    let (new_peer_tx, new_peer_rx) = mpsc::unbounded_channel();
    let (quality_tx, quality_rx) = mpsc::unbounded_channel();
    let (disconnect_tx, disconnect_rx) = mpsc::unbounded_channel();
    let room_state = sfu::new_room_state();

    let udp_candidate_addr = cfg.udp_candidate_addr();
    tokio::spawn(sfu::run_sfu_loop(
        udp_socket, udp_candidate_addr, new_peer_rx, quality_rx, disconnect_rx, room_state.clone(), cfg.archive_dir,
    ));

    let state = Arc::new(AppState {
        new_peer_tx,
        quality_tx,
        disconnect_tx,
        room_state,
        udp_candidate_addr,
    });

    let app = Router::new()
        .route("/whip/:stream_id", post(api::whip_handler))
        .route("/whep/:room_id", post(api::whep_handler).delete(api::disconnect_handler))
        .route("/quality/:room_id", post(api::quality_handler))
        .route("/room_info/:room_id", get(api::room_info_handler))
        .route("/viewer_limit/:room_id", post(api::viewer_limit_handler))
        .route("/room_password/:room_id", post(api::room_password_handler))
        .route("/active", get(api::active_handler))
        .route("/health", get(|| async { (StatusCode::OK, "ok") }))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(cfg.http_bind)
        .await
        .expect("failed to bind HTTP listener");

    tracing::info!("Rust Core SFU ready");
    axum::serve(listener, app).await.unwrap();
}
