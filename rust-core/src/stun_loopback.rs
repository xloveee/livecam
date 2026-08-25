//! Loopback STUN/TURN so Firefox can ICE without same-host LAN hairpin.
//!
//! On this Mac, UDP 192.168.1.224 → 192.168.1.224:50000 is not delivered
//! (LAN hairpin). Chrome sends to 127.0.0.1:50000 and works. Firefox will
//! not pair a LAN host with 127.0.0.1, so we give it a TURN relay on
//! 127.0.0.1:3478 (LAN→loopback *does* arrive) that forwards to :50000.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const MAGIC: u32 = 0x2112A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ALLOCATE_REQUEST: u16 = 0x0003;
const ALLOCATE_SUCCESS: u16 = 0x0103;
const ALLOCATE_ERROR: u16 = 0x0113;
const REFRESH_REQUEST: u16 = 0x0004;
const REFRESH_SUCCESS: u16 = 0x0104;
const CREATE_PERM_REQUEST: u16 = 0x0008;
const CREATE_PERM_SUCCESS: u16 = 0x0108;
const CHANNEL_BIND_REQUEST: u16 = 0x0009;
const CHANNEL_BIND_SUCCESS: u16 = 0x0109;

const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_XOR_PEER: u16 = 0x0012;
const ATTR_DATA: u16 = 0x0013;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;
const ATTR_XOR_RELAYED: u16 = 0x0016;
const ATTR_XOR_MAPPED: u16 = 0x0020;

const REALM: &str = "livecam";
const NONCE: &str = "livecam-nonce-1";
const MEDIA: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 50000);
const ALLOC_TTL: std::time::Duration = std::time::Duration::from_secs(600);

static CREDS: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();

pub fn enabled() -> bool {
    matches!(
        std::env::var("SFU_LOOPBACK_TURN").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn creds() -> &'static (String, String) {
    CREDS.get_or_init(|| {
        let mut buf = [0u8; 16];
        getrandom::fill(&mut buf).expect("loopback TURN entropy");
        let user = hex::encode(&buf[..8]);
        let pass = hex::encode(&buf[8..]);
        tracing::info!("loopback TURN creds (process-local): user={user}");
        (user, pass)
    })
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        const H: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            out.push(H[(b >> 4) as usize] as char);
            out.push(H[(b & 0xf) as usize] as char);
        }
        out
    }
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    str0m::crypto::from_feature_flags()
        .sha1_hmac_provider
        .sha1_hmac(key, &[data])
}

/// TURN long-term key = MD5(username:realm:password).
fn turn_key(user: &str, realm: &str, pass: &str) -> [u8; 16] {
    md5_bytes(format!("{user}:{realm}:{pass}").as_bytes())
}

pub async fn run(sock: UdpSocket) {
    let local = sock.local_addr().ok();
    tracing::info!("loopback STUN/TURN listening on {:?}", local);
    let sock = std::sync::Arc::new(sock);
    let mut allocs: HashMap<SocketAddr, Alloc> = HashMap::new();
    let mut buf = [0u8; 2048];
    let (from_media_tx, mut from_media_rx) = mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();

    loop {
        tokio::select! {
            rec = sock.recv_from(&mut buf) => {
                let (n, src) = match rec {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("loopback STUN recv: {e}");
                        continue;
                    }
                };
                expire_allocs(&mut allocs);
                let pkt = &buf[..n];
                if n >= 4 && pkt[0] & 0xC0 == 0x40 {
                    if let Some(alloc) = allocs.get(&src) {
                        let ch = u16::from_be_bytes([pkt[0], pkt[1]]);
                        let len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
                        if 4 + len <= n {
                            if let Some(dest) = alloc.channels.get(&ch).copied().or(Some(MEDIA)) {
                                let _ = alloc.relay.send_to(&pkt[4..4 + len], dest).await;
                            }
                        }
                    }
                    continue;
                }
                if let Some(resp) = handle_stun(pkt, src, &mut allocs, &from_media_tx).await {
                    if let Err(e) = sock.send_to(&resp, src).await {
                        tracing::warn!("loopback STUN send {src}: {e}");
                    }
                }
            }
            Some((client, payload)) = from_media_rx.recv() => {
                if let Some(alloc) = allocs.get(&client) {
                    if let Some((&ch, _)) = alloc.channels.iter().find(|(_, p)| **p == MEDIA) {
                        let mut out = Vec::with_capacity(4 + payload.len() + 3);
                        out.extend_from_slice(&ch.to_be_bytes());
                        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                        out.extend_from_slice(&payload);
                        while out.len() % 4 != 0 {
                            out.push(0);
                        }
                        let _ = sock.send_to(&out, client).await;
                    } else {
                        // Firefox often uses Send/Data indications before ChannelBind.
                        let tid = [0u8; 12];
                        let mut body = xor_mapped(ATTR_XOR_PEER, MEDIA.port(), &tid);
                        body.extend(tlv(ATTR_DATA, &payload));
                        let msg = encode_raw(0x0017, &tid, &body, None);
                        let _ = sock.send_to(&msg, client).await;
                    }
                }
            }
        }
    }
}

struct Alloc {
    relay: std::sync::Arc<UdpSocket>,
    channels: HashMap<u16, SocketAddr>,
    expires: std::time::Instant,
}

async fn handle_stun(
    req: &[u8],
    src: SocketAddr,
    allocs: &mut HashMap<SocketAddr, Alloc>,
    from_media_tx: &mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
) -> Option<Vec<u8>> {
    if req.len() < 20 {
        return None;
    }
    let typ = u16::from_be_bytes([req[0], req[1]]);
    let magic = u32::from_be_bytes([req[4], req[5], req[6], req[7]]);
    if magic != MAGIC {
        return None;
    }
    let tid = req[8..20].to_vec();

    match typ {
        BINDING_REQUEST => {
            tracing::info!("loopback STUN binding <- {src}");
            Some(encode_success(
                BINDING_SUCCESS,
                &tid,
                &[xor_mapped(ATTR_XOR_MAPPED, loopback_port(src.port()), &tid)],
                None,
            ))
        }
        ALLOCATE_REQUEST => {
            if !has_integrity(req) {
                return Some(allocate_401(&tid));
            }
            if allocs.get(&src).is_none() {
                match UdpSocket::bind("127.0.0.1:0").await {
                    Ok(relay) => {
                        let relay_addr = relay.local_addr().ok()?;
                        let relay = std::sync::Arc::new(relay);
                        let r2 = relay.clone();
                        let tx = from_media_tx.clone();
                        tokio::spawn(async move {
                            let mut b = [0u8; 2048];
                            loop {
                                match r2.recv_from(&mut b).await {
                                    Ok((n, _)) => {
                                        if tx.send((src, b[..n].to_vec())).is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                        tracing::info!("TURN allocate {src} relay {relay_addr}");
                        allocs.insert(
                            src,
                            Alloc {
                                relay,
                                channels: HashMap::new(),
                                expires: std::time::Instant::now() + ALLOC_TTL,
                            },
                        );
                        let port = relay_addr.port();
                        Some(encode_success(
                            ALLOCATE_SUCCESS,
                            &tid,
                            &[
                                xor_mapped(ATTR_XOR_RELAYED, port, &tid),
                                xor_mapped(ATTR_XOR_MAPPED, loopback_port(src.port()), &tid),
                                lifetime(600),
                            ],
                            Some(&turn_key(&creds().0, REALM, &creds().1)),
                        ))
                    }
                    Err(e) => {
                        tracing::warn!("TURN relay bind: {e}");
                        None
                    }
                }
            } else {
                let port = allocs.get(&src)?.relay.local_addr().ok()?.port();
                Some(encode_success(
                    ALLOCATE_SUCCESS,
                    &tid,
                    &[
                        xor_mapped(ATTR_XOR_RELAYED, port, &tid),
                        xor_mapped(ATTR_XOR_MAPPED, loopback_port(src.port()), &tid),
                        lifetime(600),
                    ],
                    Some(&turn_key(&creds().0, REALM, &creds().1)),
                ))
            }
        }
        REFRESH_REQUEST => Some(encode_success(
            REFRESH_SUCCESS,
            &tid,
            &[lifetime(600)],
            Some(&turn_key(&creds().0, REALM, &creds().1)),
        )),
        CREATE_PERM_REQUEST => Some(encode_success(
            CREATE_PERM_SUCCESS,
            &tid,
            &[],
            Some(&turn_key(&creds().0, REALM, &creds().1)),
        )),
        CHANNEL_BIND_REQUEST => {
            let ch = attr_u16(req, ATTR_CHANNEL_NUMBER).unwrap_or(0x4000);
            let peer = xor_peer_addr(req, &tid).unwrap_or(MEDIA);
            // H15: only relay to the SFU media port on loopback.
            if peer != MEDIA {
                tracing::warn!("TURN channel bind rejected peer {peer}");
                return None;
            }
            if let Some(a) = allocs.get_mut(&src) {
                a.channels.insert(ch, MEDIA);
                tracing::info!("TURN channel {ch:#x} {src} -> {MEDIA}");
            }
            Some(encode_success(
                CHANNEL_BIND_SUCCESS,
                &tid,
                &[],
                Some(&turn_key(&creds().0, REALM, &creds().1)),
            ))
        }
        _ => {
            if typ == 0x0016 {
                // Send indication
                if let (Some(data), Some(alloc)) = (attr_bytes(req, ATTR_DATA), allocs.get(&src)) {
                    let dest = xor_peer_addr(req, &tid).unwrap_or(MEDIA);
                    if dest == MEDIA {
                        let _ = alloc.relay.send_to(data, MEDIA).await;
                    }
                }
            }
            None
        }
    }
}

fn loopback_port(port: u16) -> u16 {
    port
}

fn expire_allocs(allocs: &mut HashMap<SocketAddr, Alloc>) {
    let now = std::time::Instant::now();
    allocs.retain(|_, a| a.expires > now);
}

fn has_integrity(req: &[u8]) -> bool {
    let Some((start, len)) = find_attr_range(req, ATTR_MESSAGE_INTEGRITY) else {
        return false;
    };
    if len != 20 || start + 4 + len > req.len() {
        return false;
    }
    let provided = &req[start + 4..start + 4 + 20];
    // MESSAGE-INTEGRITY covers bytes up to but not including the MI attr,
    // with header length adjusted as if MI is the last attr.
    if req.len() < 20 {
        return false;
    }
    let mut adjusted = req[..start].to_vec();
    if adjusted.len() < 20 {
        return false;
    }
    let mi_total = 24u16; // type+len+20
    let body_len = (adjusted.len() as u16).saturating_sub(20) + mi_total;
    adjusted[2] = (body_len >> 8) as u8;
    adjusted[3] = (body_len & 0xff) as u8;
    let key = turn_key(&creds().0, REALM, &creds().1);
    let expect = hmac_sha1(&key, &adjusted);
    constant_eq(provided, &expect)
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    d == 0
}

fn find_attr_range(msg: &[u8], want: u16) -> Option<(usize, usize)> {
    if msg.len() < 20 {
        return None;
    }
    let mut i = 20usize;
    let end = msg.len().min(20 + u16::from_be_bytes([msg[2], msg[3]]) as usize);
    while i + 4 <= end {
        let typ = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let len = u16::from_be_bytes([msg[i + 2], msg[i + 3]]) as usize;
        let val_end = i + 4 + len;
        if val_end > end {
            break;
        }
        if typ == want {
            return Some((i, len));
        }
        i = val_end + (4 - len % 4) % 4;
    }
    None
}

fn allocate_401(tid: &[u8]) -> Vec<u8> {
    let mut attrs = Vec::new();
    // ERROR-CODE 401
    let reason = b"Unauthorized";
    let mut body = vec![0, 0, 4, 1];
    body.extend_from_slice(reason);
    attrs.extend(tlv(ATTR_ERROR_CODE, &body));
    attrs.extend(tlv(ATTR_REALM, REALM.as_bytes()));
    attrs.extend(tlv(ATTR_NONCE, NONCE.as_bytes()));
    encode_raw(ALLOCATE_ERROR, tid, &attrs, None)
}

fn encode_success(typ: u16, tid: &[u8], attrs: &[Vec<u8>], key: Option<&[u8]>) -> Vec<u8> {
    let mut body = Vec::new();
    for a in attrs {
        body.extend_from_slice(a);
    }
    encode_raw(typ, tid, &body, key)
}

fn encode_raw(typ: u16, tid: &[u8], body: &[u8], key: Option<&[u8]>) -> Vec<u8> {
    let mi_len = if key.is_some() { 24 } else { 0 };
    let mut msg = vec![0u8; 20 + body.len() + mi_len];
    msg[0..2].copy_from_slice(&typ.to_be_bytes());
    msg[2..4].copy_from_slice(&((body.len() + mi_len) as u16).to_be_bytes());
    msg[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    msg[8..20].copy_from_slice(tid);
    msg[20..20 + body.len()].copy_from_slice(body);
    if let Some(k) = key {
        let mac = hmac_sha1(k, &msg[..20 + body.len()]);
        let off = 20 + body.len();
        msg[off..off + 2].copy_from_slice(&ATTR_MESSAGE_INTEGRITY.to_be_bytes());
        msg[off + 2..off + 4].copy_from_slice(&20u16.to_be_bytes());
        msg[off + 4..off + 24].copy_from_slice(&mac);
    }
    msg
}

fn xor_mapped(attr: u16, port: u16, tid: &[u8]) -> Vec<u8> {
    let xport = port ^ 0x2112;
    let ip = Ipv4Addr::LOCALHOST.octets();
    let magic = MAGIC.to_be_bytes();
    let xip = [
        ip[0] ^ magic[0],
        ip[1] ^ magic[1],
        ip[2] ^ magic[2],
        ip[3] ^ magic[3],
    ];
    let mut v = vec![0, 0x01];
    v.extend_from_slice(&xport.to_be_bytes());
    v.extend_from_slice(&xip);
    let _ = tid;
    tlv(attr, &v)
}

fn lifetime(secs: u32) -> Vec<u8> {
    tlv(ATTR_LIFETIME, &secs.to_be_bytes())
}

fn tlv(typ: u16, val: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(4 + val.len() + 3);
    o.extend_from_slice(&typ.to_be_bytes());
    o.extend_from_slice(&(val.len() as u16).to_be_bytes());
    o.extend_from_slice(val);
    while o.len() % 4 != 0 {
        o.push(0);
    }
    o
}

fn find_attr(msg: &[u8], want: u16) -> Option<&[u8]> {
    if msg.len() < 20 {
        return None;
    }
    let mut i = 20;
    let end = 20 + u16::from_be_bytes([msg[2], msg[3]]) as usize;
    let end = end.min(msg.len());
    while i + 4 <= end {
        let typ = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let len = u16::from_be_bytes([msg[i + 2], msg[i + 3]]) as usize;
        if i + 4 + len > msg.len() {
            break;
        }
        if typ == want {
            return Some(&msg[i + 4..i + 4 + len]);
        }
        i += 4 + ((len + 3) & !3);
    }
    None
}

fn attr_u16(msg: &[u8], typ: u16) -> Option<u16> {
    let v = find_attr(msg, typ)?;
    if v.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([v[0], v[1]]))
}

fn attr_bytes(msg: &[u8], typ: u16) -> Option<&[u8]> {
    find_attr(msg, typ)
}

fn xor_peer_addr(msg: &[u8], tid: &[u8]) -> Option<SocketAddr> {
    let v = find_attr(msg, ATTR_XOR_PEER)?;
    if v.len() < 8 || v[1] != 0x01 {
        return None;
    }
    let port = u16::from_be_bytes([v[2], v[3]]) ^ 0x2112;
    let magic = MAGIC.to_be_bytes();
    let ip = Ipv4Addr::new(
        v[4] ^ magic[0],
        v[5] ^ magic[1],
        v[6] ^ magic[2],
        v[7] ^ magic[3],
    );
    let _ = tid;
    Some(SocketAddr::new(ip.into(), port))
}

fn md5_bytes(input: &[u8]) -> [u8; 16] {
    // RFC 1321
    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }
    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & z) | (y & !z)
    }
    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }
    fn i(x: u32, y: u32, z: u32) -> u32 {
        y ^ (x | !z)
    }
    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64) * 8;
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xEFCDAB89;
    let mut c0: u32 = 0x98BADCFE;
    let mut d0: u32 = 0x10325476;
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for n in 0..64 {
            let (fval, gval) = if n < 16 {
                (f(b, c, d), n)
            } else if n < 32 {
                (g(b, c, d), (5 * n + 1) % 16)
            } else if n < 48 {
                (h(b, c, d), (3 * n + 5) % 16)
            } else {
                (i(b, c, d), (7 * n) % 16)
            };
            let tmp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(fval)
                    .wrapping_add(K[n])
                    .wrapping_add(m[gval])
                    .rotate_left(S[n]),
            );
            a = tmp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// Binding success with XOR-MAPPED-ADDRESS 127.0.0.1:<src.port>.
pub fn binding_success_loopback(req: &[u8], src: SocketAddr) -> Option<Vec<u8>> {
    if req.len() < 20 {
        return None;
    }
    let typ = u16::from_be_bytes([req[0], req[1]]);
    if typ != BINDING_REQUEST {
        return None;
    }
    let magic = u32::from_be_bytes([req[4], req[5], req[6], req[7]]);
    if magic != MAGIC {
        return None;
    }
    let tid = &req[8..20];
    Some(encode_success(
        BINDING_SUCCESS,
        tid,
        &[xor_mapped(ATTR_XOR_MAPPED, src.port(), tid)],
        None,
    ))
}

#[cfg(test)]
mod h15_tests {
    #[test]
    fn loopback_turn_disabled_by_default() {
        std::env::remove_var("SFU_LOOPBACK_TURN");
        assert!(!super::enabled());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    #[test]
    fn encodes_loopback_mapped_port() {
        let mut req = vec![0u8; 20];
        req[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
        req[4..8].copy_from_slice(&MAGIC.to_be_bytes());
        req[8..20].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 224), 61931));
        let resp = binding_success_loopback(&req, src).expect("resp");
        assert_eq!(&resp[0..2], &BINDING_SUCCESS.to_be_bytes());
        let xport = u16::from_be_bytes([resp[26], resp[27]]) ^ 0x2112;
        assert_eq!(xport, 61931);
    }

    #[test]
    fn md5_rfc_vector() {
        let d = md5_bytes(b"");
        assert_eq!(
            d,
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec,
                0xf8, 0x42, 0x7e
            ]
        );
    }
}
