use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

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
    /// Directory for HLS segment output. None disables HLS.
    pub hls_dir: Option<PathBuf>,
    pub internal_secret: String,
    /// Host IPs advertised as ICE candidates (`SFU_PUBLIC_IP` plus extras).
    ///
    /// Chrome on the same Mac does not gather `127.0.0.1`, so a loopback-only
    /// candidate makes STUN replies come from the LAN IP and ICE never
    /// nominates. Extra IPv4s come from `SFU_EXTRA_IPS` and outbound discovery.
    pub ice_host_ips: Vec<IpAddr>,
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

        let hls_dir = std::env::var("HLS_DIR").ok()
            .or_else(|| Some("hls".to_owned()))
            .map(PathBuf::from);

        // Always advertise loopback + LAN (and extras). Binding only loopback
        // made Firefox / LAN-origin WHEP stay Checking: those browsers pair
        // host-LAN to host-LAN and never send STUN to 127.0.0.1. Sockets are
        // opened per advertised IP in main.rs (not 0.0.0.0) so dest is known.
        let mut ice_host_ips = collect_ice_host_ips(public_ip);
        push_unique_ip(&mut ice_host_ips, bind_ip);
        // Loopback first: Chrome on http://127.0.0.1 prefers it (LNA).
        ice_host_ips.sort_by_key(|ip| !ip.is_loopback());
        if ice_host_ips.is_empty() {
            ice_host_ips.push(if bind_ip.is_unspecified() {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                bind_ip
            });
        }

        Self {
            http_bind: SocketAddr::new(http_host, http_port),
            bind_ip,
            public_ip,
            udp_port,
            hls_dir,
            ice_host_ips,
            internal_secret: std::env::var("SFU_INTERNAL_SECRET").unwrap_or_default(),
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

    /// All host addresses advertised in ICE (LAN extras included).
    pub fn ice_candidate_addrs(&self) -> Vec<SocketAddr> {
        self.ice_host_ips
            .iter()
            .map(|ip| SocketAddr::new(*ip, self.udp_port))
            .collect()
    }

    /// UDP sockets to open. Specific IPs (loopback + LAN), never a wildcard
    /// plus a specific IP on the same port (that fails with EADDRINUSE).
    /// Each socket's local_addr is the ICE dest for packets it receives.
    pub fn media_bind_addrs(&self) -> Vec<SocketAddr> {
        let primary = self.udp_bind_addr();
        if primary.ip().is_unspecified() {
            return vec![primary];
        }
        let mut addrs = self.ice_candidate_addrs();
        if !addrs.iter().any(|a| a.ip() == primary.ip()) {
            addrs.insert(0, primary);
        }
        addrs.retain(|a| !a.ip().is_unspecified());
        if addrs.is_empty() {
            vec![primary]
        } else {
            addrs
        }
    }
}

/// Host IPs for ICE: `SFU_PUBLIC_IP`, then `SFU_EXTRA_IPS`, then the
/// primary outbound IPv4. Non-loopback addresses are listed first so
/// Chrome prefers a LAN pair over `127.0.0.1`.
fn collect_ice_host_ips(public_ip: IpAddr) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    if let Ok(extra) = std::env::var("SFU_EXTRA_IPS") {
        for part in extra.split(',') {
            if let Ok(ip) = part.trim().parse::<IpAddr>() {
                push_unique_ip(&mut ips, ip);
            }
        }
    }
    if let Some(ip) = discover_outbound_ipv4() {
        push_unique_ip(&mut ips, ip);
    }
    push_unique_ip(&mut ips, public_ip);
    // Chrome on http://127.0.0.1 may STUN to loopback; same-host LAN
    // publish still needs the outbound IPv4 advertised above.
    push_unique_ip(&mut ips, IpAddr::V4(Ipv4Addr::LOCALHOST));
    ips.sort_by_key(|ip| ip.is_loopback());
    ips
}

fn push_unique_ip(ips: &mut Vec<IpAddr>, ip: IpAddr) {
    if ip.is_unspecified() || ip.is_multicast() {
        return;
    }
    if !ips.contains(&ip) {
        ips.push(ip);
    }
}

fn discover_outbound_ipv4() -> Option<IpAddr> {
    let sock = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.connect((Ipv4Addr::new(8, 8, 8, 8), 80)).ok()?;
    let ip = sock.local_addr().ok()?.ip();
    if ip.is_unspecified() || ip.is_loopback() {
        None
    } else {
        Some(ip)
    }
}

/// True when the SDP lists a host/srflx candidate on loopback.
///
/// Firefox gathers only mDNS (`.local`) host candidates and will not
/// complete a 127.0.0.1 pair from its LAN-bound socket. Chrome on
/// `http://127.0.0.1` includes a loopback host and needs that pair.
pub fn sdp_has_loopback_ice_host(sdp: &str) -> bool {
    for line in sdp.lines() {
        let line = line.trim();
        let body = line.strip_prefix("a=").unwrap_or(line);
        if !body.starts_with("candidate:") {
            continue;
        }
        let parts: Vec<&str> = body.split_whitespace().collect();
        // candidate:<foundation> <comp> <proto> <prio> <addr> <port> typ <type>
        if parts.len() < 8 {
            continue;
        }
        let addr = parts[4];
        let typ = parts[7];
        if typ != "host" && typ != "srflx" && typ != "relay" {
            continue;
        }
        if addr == "127.0.0.1" || addr == "::1" || addr.starts_with("127.") {
            return true;
        }
    }
    false
}

/// Host addresses to put in a WHEP answer.
///
/// Always include 127.0.0.1:50000. A page on `http://127.0.0.1` cannot
/// STUN a LAN-only answer (Local Network Access). Chrome offers that
/// already list a loopback host still get loopback-only so they do not
/// nominate the LAN pair. mDNS-only Firefox offers get loopback plus
/// LAN — do not drop loopback.
pub fn whep_ice_addrs(offer_sdp: &str, addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    if sdp_has_loopback_ice_host(offer_sdp) {
        let loopbacks: Vec<SocketAddr> = addrs
            .iter()
            .copied()
            .filter(|a| a.ip().is_loopback())
            .collect();
        if !loopbacks.is_empty() {
            return loopbacks;
        }
        return addrs.to_vec();
    }
    let mut out: Vec<SocketAddr> = addrs
        .iter()
        .copied()
        .filter(|a| a.ip().is_loopback())
        .collect();
    for addr in addrs.iter().copied().filter(|a| !a.ip().is_loopback()) {
        out.push(addr);
    }
    if out.is_empty() {
        addrs.to_vec()
    } else {
        out
    }
}

/// Destination address str0m should treat an inbound UDP packet as
/// arriving on. Same-host Chrome sends from the LAN IP; matching that
/// IP to a host candidate makes ICE-lite reply on the pair Chrome nominated.
pub fn pick_ice_recv_dest(source: SocketAddr, addrs: &[SocketAddr]) -> SocketAddr {
    if let Some(&addr) = addrs.iter().find(|a| a.ip() == source.ip()) {
        return addr;
    }
    if let Some(&addr) = addrs.iter().find(|a| !a.ip().is_loopback()) {
        return addr;
    }
    addrs
        .first()
        .copied()
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recv_dest_matches_same_host_lan() {
        let lan: SocketAddr = "192.168.1.224:50000".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let addrs = vec![lan, loopback];
        let src: SocketAddr = "192.168.1.224:63975".parse().unwrap();
        assert_eq!(pick_ice_recv_dest(src, &addrs), lan);
    }

    #[test]
    fn recv_dest_prefers_lan_for_unknown_source() {
        let lan: SocketAddr = "192.168.1.224:50000".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let src: SocketAddr = "203.0.113.9:40000".parse().unwrap();
        assert_eq!(pick_ice_recv_dest(src, &[loopback, lan]), lan);
    }

    #[test]
    fn ice_hosts_include_loopback_and_public() {
        let ips = collect_ice_host_ips(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(ips.iter().any(|ip| ip.is_loopback()));
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn media_binds_are_specific_when_bind_is_loopback() {
        let cfg = Config {
            http_bind: "127.0.0.1:8080".parse().unwrap(),
            bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            public_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            udp_port: 50000,
            hls_dir: None,
            ice_host_ips: vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "192.168.1.224".parse().unwrap(),
            ],
            internal_secret: String::new(),
        };
        let binds = cfg.media_bind_addrs();
        assert!(binds.iter().any(|a| a.ip().is_loopback()));
        assert!(binds.iter().any(|a| a.ip().to_string() == "192.168.1.224"));
        assert!(binds.iter().all(|a| !a.ip().is_unspecified()));
    }

    #[test]
    fn firefox_mdns_offer_has_no_loopback_host() {
        let sdp = "a=candidate:0 1 UDP 2122252543 62826850-3658-4956-be34-e916d460e3d9.local 61931 typ host\r\n";
        assert!(!sdp_has_loopback_ice_host(sdp));
    }

    #[test]
    fn chrome_loopback_offer_is_detected() {
        let sdp = "a=candidate:1 1 udp 2122260223 127.0.0.1 54321 typ host generation 0\r\n";
        assert!(sdp_has_loopback_ice_host(sdp));
    }

    #[test]
    fn whep_includes_loopback_for_mdns_only_offer() {
        let lan: SocketAddr = "192.168.1.224:50000".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let offer = "a=candidate:0 1 UDP 2122252543 abcdef.local 61931 typ host\n";
        let out = whep_ice_addrs(offer, &[loopback, lan]);
        assert!(out.contains(&loopback), "mDNS-only WHEP must keep 127.0.0.1");
        assert!(out.contains(&lan));
        assert_eq!(out[0], loopback);
    }

    #[test]
    fn whep_keeps_loopback_when_offer_has_it() {
        let lan: SocketAddr = "192.168.1.224:50000".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let offer = "a=candidate:1 1 udp 2122260223 127.0.0.1 9 typ host\n";
        let out = whep_ice_addrs(offer, &[loopback, lan]);
        assert_eq!(out, vec![loopback]);
    }

    #[test]
    fn whep_keeps_loopback_if_that_is_the_only_bind() {
        let loopback: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let offer = "a=candidate:0 1 UDP 1 foo.local 9 typ host\n";
        let out = whep_ice_addrs(offer, &[loopback]);
        assert_eq!(out, vec![loopback]);
    }
}
