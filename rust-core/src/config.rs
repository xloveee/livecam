use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Central configuration for the Rust Core SFU.
/// Loaded from environment variables with sensible defaults.
pub struct Config {
    /// Address for the internal HTTP API (WHIP/WHEP), only reachable by the Go proxy.
    pub http_bind: SocketAddr,
    /// Local IP to bind the UDP media socket to (typically 0.0.0.0).
    pub bind_ip: IpAddr,
    /// Public IP address advertised in ICE candidates to remote peers.
    pub public_ip: IpAddr,
    /// UDP port the SFU media socket binds to for all WebRTC traffic.
    pub udp_port: u16,
    /// Directory for VOD archive recordings.
    pub archive_dir: String,
}

impl Config {
    pub fn from_env() -> Self {
        let http_host: IpAddr = std::env::var("SFU_HTTP_HOST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

        let http_port: u16 = std::env::var("SFU_HTTP_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8080);

        let bind_ip: IpAddr = std::env::var("SFU_BIND_IP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

        let public_ip: IpAddr = std::env::var("SFU_PUBLIC_IP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

        let udp_port: u16 = std::env::var("SFU_UDP_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50000);

        let archive_dir = std::env::var("SFU_ARCHIVE_DIR")
            .unwrap_or_else(|_| "archive".to_string());

        Self {
            http_bind: SocketAddr::new(http_host, http_port),
            bind_ip,
            public_ip,
            udp_port,
            archive_dir,
        }
    }

    /// The local socket address to bind the UDP media socket to.
    pub fn udp_bind_addr(&self) -> SocketAddr {
        SocketAddr::new(self.bind_ip, self.udp_port)
    }

    /// The public address advertised in ICE candidates to remote peers.
    pub fn udp_candidate_addr(&self) -> SocketAddr {
        SocketAddr::new(self.public_ip, self.udp_port)
    }
}
