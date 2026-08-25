//! H25: persist room password hashes + viewer caps across rust restarts.
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::sfu::RoomStateMap;

pub const ROOM_PASSWORD_MAX_LEN: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedRoom {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_viewers: u32,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub grant_epoch: u64,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedStore {
    #[serde(default)]
    pub rooms: HashMap<String, PersistedRoom>,
}

pub type PersistPath = Arc<Mutex<Option<PathBuf>>>;

pub fn new_persist_path(path: Option<PathBuf>) -> PersistPath {
    Arc::new(Mutex::new(path))
}

pub fn hash_room_password(password: &str) -> String {
    hex::encode(&sha256(password.as_bytes()))
}

pub fn constant_eq_hex(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in ab.iter().zip(bb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn default_persist_path(hls_dir: &Option<PathBuf>) -> PathBuf {
    if let Ok(p) = std::env::var("ROOM_STATE_PATH") {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    if let Some(dir) = hls_dir {
        if let Some(parent) = dir.parent() {
            return parent.join("data").join("room_state.json");
        }
    }
    PathBuf::from("data/room_state.json")
}

pub fn load_into(room_state: &RoomStateMap, path: &Path) -> usize {
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(e) => {
            tracing::warn!("H25 room state load {}: {e}", path.display());
            return 0;
        }
    };
    let store: PersistedStore = match serde_json::from_str(&raw) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("H25 room state parse {}: {e}", path.display());
            return 0;
        }
    };
    let Ok(mut map) = room_state.lock() else {
        return 0;
    };
    let mut n = 0;
    for (id, pr) in store.rooms {
        if pr.password_hash.is_none() && pr.max_viewers == 0 && pr.grant_epoch == 0 {
            continue;
        }
        let entry = map.entry(id).or_default();
        entry.password_hash = pr.password_hash;
        entry.max_viewers = pr.max_viewers;
        entry.grant_epoch = pr.grant_epoch;
        entry.is_live = false;
        n += 1;
    }
    tracing::info!("H25 loaded {n} room(s) from {}", path.display());
    n
}

pub fn save_from(room_state: &RoomStateMap, path: &Path) {
    let Ok(map) = room_state.lock() else {
        return;
    };
    let mut store = PersistedStore::default();
    for (id, info) in map.iter() {
        if info.password_hash.is_none() && info.max_viewers == 0 && info.grant_epoch == 0 {
            continue;
        }
        store.rooms.insert(
            id.clone(),
            PersistedRoom {
                password_hash: info.password_hash.clone(),
                max_viewers: info.max_viewers,
                grant_epoch: info.grant_epoch,
            },
        );
    }
    drop(map);
    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            tracing::warn!("H25 mkdir {}: {e}", parent.display());
            return;
        }
    }
    let Ok(json) = serde_json::to_string_pretty(&store) else {
        return;
    };
    let tmp = path.with_extension("json.tmp");
    match fs::File::create(&tmp) {
        Ok(mut f) => {
            if f.write_all(json.as_bytes()).is_err() {
                let _ = fs::remove_file(&tmp);
                return;
            }
            if f.sync_all().is_err() {
                let _ = fs::remove_file(&tmp);
                return;
            }
        }
        Err(e) => {
            tracing::warn!("H25 write {}: {e}", tmp.display());
            return;
        }
    }
    if let Err(e) = fs::rename(&tmp, path) {
        tracing::warn!("H25 rename {}: {e}", path.display());
        let _ = fs::remove_file(&tmp);
    }
}

pub fn persist_snapshot(room_state: &RoomStateMap, persist: &PersistPath) {
    let path = match persist.lock() {
        Ok(g) => g.clone(),
        Err(_) => None,
    };
    if let Some(path) = path {
        save_from(room_state, &path);
    }
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0xf) as usize] as char);
        }
        out
    }
}

/// Minimal SHA-256 (FIPS 180-4) so we stay inside the vendored crate set.
fn sha256(msg: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (msg.len() as u64) * 8;
    let mut data = msg.to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in data.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sfu::new_room_state;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn sha256_empty_vector() {
        assert_eq!(
            hex::encode(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash_is_stable_and_not_plaintext() {
        let h = hash_room_password("secret");
        assert_eq!(h.len(), 64);
        assert_ne!(h, "secret");
        assert_eq!(h, hash_room_password("secret"));
        assert!(!constant_eq_hex(&h, &hash_room_password("other")));
    }

    #[test]
    fn round_trip_persist() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("room-persist-{nanos}"));
        let path = dir.join("room_state.json");
        let state = new_room_state();
        {
            let mut map = state.lock().unwrap();
            let e = map.entry("abcdefghijklmnopqrstuvwxyz012345".into()).or_default();
            e.password_hash = Some(hash_room_password("invite"));
            e.max_viewers = 12;
            e.grant_epoch = 3;
            e.is_live = true;
        }
        save_from(&state, &path);
        let state2 = new_room_state();
        assert_eq!(load_into(&state2, &path), 1);
        let map = state2.lock().unwrap();
        let info = map.get("abcdefghijklmnopqrstuvwxyz012345").unwrap();
        assert_eq!(
            info.password_hash.as_deref(),
            Some(hash_room_password("invite").as_str())
        );
        assert_eq!(info.max_viewers, 12);
        assert_eq!(info.grant_epoch, 3);
        assert!(!info.is_live);
        let _ = fs::remove_dir_all(dir);
    }
}
