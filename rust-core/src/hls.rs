use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

const TS_PACKET_SIZE: usize = 188;
const PAT_PID: u16 = 0x0000;
const PMT_PID: u16 = 0x0100;
const VIDEO_PID: u16 = 0x0101;
const AUDIO_PID: u16 = 0x0102;
const SEGMENT_DURATION_SECS: f64 = 2.0;
const MAX_PLAYLIST_ENTRIES: usize = 5;

/// Looped AAC-LC ADTS (file-source pass-through). Remux only — not Opus.
#[derive(Clone)]
struct AdtsLoop {
    frames: Vec<Vec<u8>>,
    ticks_per_frame: u64,
    idx: usize,
    next_pts: Option<u64>,
}

/// Per-room HLS: `master.m3u8` from the first non-`l` H.264 layer
/// (`"h"`, `"m"`, or unspecified), `pip.m3u8` from simulcast rid `"l"`.
///
/// No transcode. Single-layer publish (no `"l"` rid) never writes
/// `pip.m3u8` — Preview is unavailable until the broadcaster sends
/// a low simulcast layer.
pub struct RoomHls {
    room_id: String,
    master: HlsSink,
    pip: HlsSink,
    pip_alive: bool,
    pip_seen: bool,
    /// First non-`l` rid packed into master (`"h"`, `"m"`, or `""` for unspecified).
    master_rid: Option<String>,
}

impl RoomHls {
    pub fn start(room_id: &str, hls_root: &Path) -> Result<Self, String> {
        let hls_dir = hls_root.join(room_id);
        fs::create_dir_all(&hls_dir)
            .map_err(|e| format!("failed to create HLS dir {:?}: {}", hls_dir, e))?;
        // A new publisher must not inherit Preview from the previous one.
        // Compatible (master) stays on disk until the first new keyframe overwrites it.
        clear_leftover_pip(&hls_dir);

        Ok(Self {
            room_id: room_id.to_owned(),
            master: HlsSink::start_named(room_id, hls_root, "master.m3u8", "seg")?,
            pip: HlsSink::start_named(room_id, hls_root, "pip.m3u8", "pip")?,
            pip_alive: true,
            pip_seen: false,
            master_rid: None,
        })
    }

    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    /// Remux the screen / primary video mid only.
    /// - `rid` h/m/l → always pack (Chrome screen simulcast)
    /// - no rid on video index 0 → pack (Firefox screen / camera-only)
    /// - no rid on later video mids → skip (facecam is WHEP-only)
    pub fn accepts_frame(video_index: Option<usize>, rid: Option<&str>) -> bool {
        if matches!(rid, Some("h") | Some("m") | Some("l")) {
            return true;
        }
        video_index == Some(0)
    }

    /// Pack a frame into the playlist that matches `rid`.
    /// - first non-`"l"` (`None` / `"h"` / `"m"` / unknown) → `master.m3u8`
    /// - `"l"` → `pip.m3u8`
    ///
    /// Returns false only if the master sink failed (room HLS is dead).
    pub fn write_video(
        &mut self,
        rid: Option<&str>,
        pts_90khz: u64,
        is_keyframe: bool,
        annex_b: &[u8],
    ) -> bool {
        match rid {
            Some("l") => {
                if !self.pip_seen {
                    self.pip_seen = true;
                    tracing::info!(
                        "HLS pip layer (rid l) first frame for room '{}' keyframe={} bytes={}",
                        self.room_id,
                        is_keyframe,
                        annex_b.len()
                    );
                }
                if self.pip_alive && !self.pip.write_video(pts_90khz, is_keyframe, annex_b) {
                    self.pip_alive = false;
                    tracing::warn!("HLS pip sink failed for room '{}'", self.room_id);
                }
                true
            }
            other => {
                let layer = other.unwrap_or("");
                match self.master_rid.as_deref() {
                    None => {
                        self.master_rid = Some(layer.to_owned());
                        tracing::info!(
                            "HLS master layer rid={:?} for room '{}'",
                            if layer.is_empty() { None } else { Some(layer) },
                            self.room_id
                        );
                    }
                    Some(chosen) if chosen != layer => return true,
                    Some(_) => {}
                }
                self.master.write_video(pts_90khz, is_keyframe, annex_b)
            }
        }
    }

    #[allow(dead_code)]
    pub fn has_pip(&self) -> bool {
        self.pip_seen
    }

    /// Finalize open segments and log. Leaves playlists/segments on disk so
    /// Compatible can keep playing while a replacement WHIP starts or ICE
    /// has only just dropped.
    pub fn stop(self) {
        self.pip.stop();
        self.master.stop();
    }
}

fn clear_leftover_pip(hls_dir: &Path) {
    let _ = fs::remove_file(hls_dir.join("pip.m3u8"));
    if let Ok(entries) = fs::read_dir(hls_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("pip") && name.ends_with(".ts") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

/// Pure-Rust HLS segmenter. Wraps raw H.264 Annex B frames into MPEG-TS
/// segments and writes a rolling m3u8 playlist. No ffmpeg, no external deps.
struct HlsSink {
    room_id: String,
    hls_dir: PathBuf,
    playlist_name: String,
    segment_prefix: String,
    segment_index: u32,
    current_segment: Option<File>,
    segment_start_pts: u64,
    last_pts: u64,
    continuity_counter_pat: u8,
    continuity_counter_pmt: u8,
    continuity_counter_vid: u8,
    continuity_counter_aud: u8,
    /// Looped ADTS from room `audio.adts` (file-source AAC pass-through). None = video-only.
    aac: Option<AdtsLoop>,
    segment_durations: Vec<f64>,
    started_at: Instant,
    bytes_written: u64,
    has_keyframe: bool,
    /// Last seen SPS / PPS (Annex B, with start codes). Repeated at each new .ts.
    sps: Option<Vec<u8>>,
    pps: Option<Vec<u8>>,
    pes_scratch: Vec<u8>,
    ts_scratch: Vec<u8>,
    playlist_scratch: String,
}

impl HlsSink {
    fn start_named(
        room_id: &str,
        hls_root: &Path,
        playlist_name: &str,
        segment_prefix: &str,
    ) -> Result<Self, String> {
        let hls_dir = hls_root.join(room_id);
        fs::create_dir_all(&hls_dir)
            .map_err(|e| format!("failed to create HLS dir {:?}: {}", hls_dir, e))?;

        let aac = load_adts_loop(&hls_dir);
        if aac.is_some() {
            tracing::info!(
                "HLS sink '{}' for room '{}' remuxing AAC from audio.adts",
                playlist_name, room_id
            );
        }

        tracing::info!(
            "HLS sink started for room '{}' -> {:?} ({})",
            room_id, hls_dir, playlist_name
        );

        Ok(Self {
            room_id: room_id.to_owned(),
            hls_dir,
            playlist_name: playlist_name.to_owned(),
            segment_prefix: segment_prefix.to_owned(),
            segment_index: 0,
            current_segment: None,
            segment_start_pts: 0,
            last_pts: 0,
            continuity_counter_pat: 0,
            continuity_counter_pmt: 0,
            continuity_counter_vid: 0,
            continuity_counter_aud: 0,
            aac,
            segment_durations: Vec::new(),
            started_at: Instant::now(),
            bytes_written: 0,
            has_keyframe: false,
            sps: None,
            pps: None,
            pes_scratch: Vec::with_capacity(4096),
            ts_scratch: Vec::with_capacity(188 * 64),
            playlist_scratch: String::with_capacity(512),
        })
    }

    /// Write a video frame. `pts_90khz` is the presentation timestamp in 90kHz units.
    /// `is_keyframe` indicates an IDR frame (segment boundary candidate).
    /// `annex_b` is the raw H.264 Annex B data (with start codes).
    pub fn write_video(&mut self, pts_90khz: u64, is_keyframe: bool, annex_b: &[u8]) -> bool {
        if annex_b.is_empty() {
            return true;
        }

        self.cache_parameter_sets(annex_b);

        if is_keyframe {
            if self.current_segment.is_some() {
                let duration = (pts_90khz.saturating_sub(self.segment_start_pts)) as f64 / 90_000.0;
                if duration >= SEGMENT_DURATION_SECS * 0.5 {
                    self.finalize_segment(duration);
                }
            }
            if self.current_segment.is_none() {
                // Do not open a player-visible .ts until we can start it with
                // SPS/PPS + IDR. Chrome often sends those only on the first IDR.
                if !self.has_parameter_sets() && !access_unit_has_sps_pps(annex_b) {
                    return true;
                }
                if !self.open_segment(pts_90khz) {
                    return false;
                }
            }
            self.has_keyframe = true;
        }

        if !self.has_keyframe {
            return true;
        }

        self.last_pts = pts_90khz;
        let opened_new = is_keyframe && self.current_segment.is_some();
        let mut prefixed = Vec::new();
        let payload = if opened_new {
            self.ensure_sps_pps(annex_b, &mut prefixed)
        } else {
            annex_b
        };
        let ok = self.write_pes(pts_90khz, is_keyframe, payload);
        if ok {
            self.mux_audio_up_to(pts_90khz);
        }
        if ok && opened_new {
            // Publish as soon as the first IDR lands so pip.m3u8 / master.m3u8
            // exist before the 2s segment closes.
            let oldest = self.window_start();
            self.evict_outside_window(oldest);
            self.write_playlist(oldest);
            if let Some(ref mut f) = self.current_segment {
                let _ = f.flush();
            }
        }
        ok
    }

    fn has_parameter_sets(&self) -> bool {
        self.sps.is_some() && self.pps.is_some()
    }

    fn cache_parameter_sets(&mut self, annex_b: &[u8]) {
        for_each_annex_b_nal(annex_b, |nal| match nal_type(nal) {
            7 => self.sps = Some(nal.to_vec()),
            8 => self.pps = Some(nal.to_vec()),
            _ => {}
        });
    }

    /// SPS + PPS then the access unit, so each new .ts is independently decodable.
    fn ensure_sps_pps<'a>(&self, annex_b: &'a [u8], buf: &'a mut Vec<u8>) -> &'a [u8] {
        if access_unit_has_sps_pps(annex_b) {
            return annex_b;
        }
        let (Some(sps), Some(pps)) = (self.sps.as_deref(), self.pps.as_deref()) else {
            return annex_b;
        };
        buf.clear();
        buf.extend_from_slice(sps);
        buf.extend_from_slice(pps);
        buf.extend_from_slice(annex_b);
        buf
    }

    fn window_start(&self) -> usize {
        if self.segment_durations.len() > MAX_PLAYLIST_ENTRIES {
            self.segment_index as usize - MAX_PLAYLIST_ENTRIES
        } else {
            0
        }
    }

    fn stop(mut self) {
        if self.current_segment.is_some() {
            let duration = (self.last_pts.saturating_sub(self.segment_start_pts)) as f64 / 90_000.0;
            self.finalize_segment(duration.max(0.1));
        }
        let elapsed = self.started_at.elapsed();
        tracing::info!(
            "HLS sink stopped for room '{}' ({}): wrote {} bytes in {:.0}s (playlists kept)",
            self.room_id, self.playlist_name, self.bytes_written, elapsed.as_secs_f64()
        );
    }

    fn open_segment(&mut self, pts: u64) -> bool {
        self.playlist_scratch.clear();
        let _ = write!(
            self.playlist_scratch,
            "{}{:03}.ts",
            self.segment_prefix, self.segment_index
        );
        let path = self.hls_dir.join(self.playlist_scratch.as_str());
        match File::create(&path) {
            Ok(mut f) => {
                self.write_pat_pmt(&mut f);
                self.current_segment = Some(f);
                self.segment_start_pts = pts;
                true
            }
            Err(e) => {
                tracing::warn!("HLS: failed to create segment {:?}: {}", path, e);
                false
            }
        }
    }

    fn finalize_segment(&mut self, duration: f64) {
        if let Some(ref mut f) = self.current_segment {
            let _ = f.flush();
        }
        self.current_segment = None;
        self.segment_durations.push(duration);

        self.segment_index += 1;
        let oldest = self.window_start();
        self.evict_outside_window(oldest);
        self.write_playlist(oldest);
    }

    fn evict_outside_window(&self, first_index: usize) {
        let last_index = if self.current_segment.is_some() {
            self.segment_index
        } else {
            self.segment_index.saturating_sub(1)
        };
        let prefix = self.segment_prefix.as_str();
        if let Ok(entries) = fs::read_dir(&self.hls_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.starts_with(prefix) || !name.ends_with(".ts") {
                    continue;
                }
                let mid = &name[prefix.len()..name.len() - 3];
                let Ok(idx) = mid.parse::<u32>() else {
                    continue;
                };
                if (idx as usize) < first_index || idx > last_index {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }

    fn write_playlist(&mut self, first_index: usize) {
        let mut max_dur = self
            .segment_durations
            .iter()
            .skip(first_index)
            .cloned()
            .fold(0.0_f64, f64::max);
        if self.current_segment.is_some() {
            max_dur = max_dur.max(SEGMENT_DURATION_SECS);
        }
        // Live target is ~2s. Floor at 2 so an early open-segment playlist
        // is never TARGETDURATION 1 with EXTINF 2.000.
        let target_duration = max_dur.ceil().max(2.0) as u32;

        self.playlist_scratch.clear();
        let _ = write!(
            self.playlist_scratch,
            "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:{}\n#EXT-X-MEDIA-SEQUENCE:{}\n",
            target_duration, first_index
        );

        for (i, dur) in self.segment_durations.iter().enumerate().skip(first_index) {
            let _ = write!(
                self.playlist_scratch,
                "#EXTINF:{:.3},\n{}{:03}.ts\n",
                dur, self.segment_prefix, i
            );
        }

        if self.current_segment.is_some() {
            let open_dur = (self.last_pts.saturating_sub(self.segment_start_pts)) as f64 / 90_000.0;
            let open_dur = if open_dur > 0.05 { open_dur } else { SEGMENT_DURATION_SECS };
            let _ = write!(
                self.playlist_scratch,
                "#EXTINF:{:.3},\n{}{:03}.ts\n",
                open_dur, self.segment_prefix, self.segment_index
            );
        }

        let path = self.hls_dir.join(&self.playlist_name);
        if let Err(e) = fs::write(&path, self.playlist_scratch.as_bytes()) {
            tracing::warn!("HLS: failed to write playlist {:?}: {}", path, e);
        }
    }

    fn mux_audio_up_to(&mut self, pts_90khz: u64) {
        if self.current_segment.is_none() || self.aac.is_none() {
            return;
        }
        let mut aac = self.aac.take().unwrap();
        if aac.next_pts.is_none() {
            aac.next_pts = Some(pts_90khz);
        }
        let ticks = aac.ticks_per_frame;
        if ticks == 0 {
            self.aac = Some(aac);
            return;
        }
        let mut safety = 0u32;
        loop {
            let pts = aac.next_pts.unwrap();
            if pts > pts_90khz {
                break;
            }
            // Video PTS jumped (new publisher / wrap). Snap instead of flooding.
            if pts_90khz.saturating_sub(pts) > 180_000 {
                aac.next_pts = Some(pts_90khz);
                break;
            }
            if !self.write_audio_pes(pts, &aac.frames[aac.idx]) {
                self.aac = Some(aac);
                return;
            }
            aac.idx = (aac.idx + 1) % aac.frames.len();
            aac.next_pts = Some(pts + ticks);
            safety += 1;
            if safety > 200 {
                break;
            }
        }
        self.aac = Some(aac);
    }

    fn write_pes(&mut self, pts_90khz: u64, is_rap: bool, annex_b: &[u8]) -> bool {
        self.write_media_pes(VIDEO_PID, pts_90khz, is_rap, 0xE0, annex_b)
    }

    fn write_audio_pes(&mut self, pts_90khz: u64, adts: &[u8]) -> bool {
        self.write_media_pes(AUDIO_PID, pts_90khz, false, 0xC0, adts)
    }

    fn write_media_pes(
        &mut self,
        pid: u16,
        pts_90khz: u64,
        is_rap: bool,
        stream_id: u8,
        es: &[u8],
    ) -> bool {
        if self.current_segment.is_none() {
            return true;
        }

        let pes_header = build_pes_header(pts_90khz, es.len(), stream_id);
        self.pes_scratch.clear();
        self.pes_scratch.extend_from_slice(&pes_header);
        self.pes_scratch.extend_from_slice(es);
        self.ts_scratch.clear();

        let mut offset = 0;
        let mut first = true;
        while offset < self.pes_scratch.len() {
            let mut pkt = [0u8; TS_PACKET_SIZE];
            pkt[0] = 0x47; // sync byte
            let pusi: u8 = if first { 0x40 } else { 0x00 };
            pkt[1] = pusi | ((pid >> 8) as u8 & 0x1F);
            pkt[2] = pid as u8;

            let cc = if pid == AUDIO_PID {
                let c = self.continuity_counter_aud & 0x0F;
                self.continuity_counter_aud = self.continuity_counter_aud.wrapping_add(1);
                c
            } else {
                let c = self.continuity_counter_vid & 0x0F;
                self.continuity_counter_vid = self.continuity_counter_vid.wrapping_add(1);
                c
            };

            let remaining = self.pes_scratch.len() - offset;

            if first && is_rap {
                // adaptation: flags + 6-byte PCR (RAI + PCR)
                let adapt_len = 7u8;
                pkt[3] = 0x30 | cc; // adaptation + payload
                pkt[4] = adapt_len;
                pkt[5] = 0x50; // random access + PCR
                write_pcr(&mut pkt[6..12], pts_90khz);
                let space = TS_PACKET_SIZE - 4 - 1 - adapt_len as usize;
                let chunk = remaining.min(space);
                pkt[12..12 + chunk].copy_from_slice(&self.pes_scratch[offset..offset + chunk]);
                offset += chunk;
            } else {
                let header_size = 4;
                let space = TS_PACKET_SIZE - header_size;
                if remaining < space {
                    let stuff_len = space - remaining;
                    pkt[3] = 0x30 | cc; // adaptation + payload
                    if stuff_len == 1 {
                        pkt[4] = 0;
                        pkt[5..5 + remaining].copy_from_slice(&self.pes_scratch[offset..offset + remaining]);
                    } else {
                        pkt[4] = (stuff_len - 1) as u8;
                        pkt[5] = 0x00;
                        pkt[6..4 + stuff_len].fill(0xFF);
                        pkt[4 + stuff_len..4 + stuff_len + remaining]
                            .copy_from_slice(&self.pes_scratch[offset..offset + remaining]);
                    }
                    offset += remaining;
                } else {
                    pkt[3] = 0x10 | cc; // payload only
                    pkt[4..4 + space].copy_from_slice(&self.pes_scratch[offset..offset + space]);
                    offset += space;
                }
            }
            first = false;

            self.ts_scratch.extend_from_slice(&pkt);
        }

        let file = match self.current_segment {
            Some(ref mut f) => f,
            None => return true,
        };
        if file.write_all(&self.ts_scratch).is_err() {
            tracing::warn!("HLS: write error for room '{}'", self.room_id);
            return false;
        }
        self.bytes_written += self.ts_scratch.len() as u64;
        true
    }

    fn write_pat_pmt(&mut self, file: &mut File) {
        let pat = build_pat(&mut self.continuity_counter_pat);
        let pmt = build_pmt(&mut self.continuity_counter_pmt, self.aac.is_some());
        let _ = file.write_all(&pat);
        let _ = file.write_all(&pmt);
        self.bytes_written += (TS_PACKET_SIZE * 2) as u64;
    }
}

impl Drop for HlsSink {
    fn drop(&mut self) {
        if self.current_segment.is_some() {
            let duration = (self.last_pts.saturating_sub(self.segment_start_pts)) as f64 / 90_000.0;
            self.finalize_segment(duration.max(0.1));
        }
        // Never delete the room dir here. Evict and ICE-disconnect must leave
        // Compatible playlists for viewers still on the watch page.
    }
}

fn build_pes_header(pts_90khz: u64, payload_len: usize, stream_id: u8) -> Vec<u8> {
    let pes_len = payload_len + 8; // 3 header + 5 PTS
    let pes_len_field = if pes_len > 0xFFFF { 0u16 } else { pes_len as u16 };
    let pts = pts_90khz & 0x1FFFFFFFF;

    let mut hdr = Vec::with_capacity(14);
    hdr.extend_from_slice(&[0x00, 0x00, 0x01]); // start code
    hdr.push(stream_id);
    hdr.push((pes_len_field >> 8) as u8);
    hdr.push(pes_len_field as u8);
    hdr.push(0x80); // marker bits
    hdr.push(0x80); // PTS present
    hdr.push(5);    // PES header data length

    // PTS encoding (5 bytes)
    hdr.push(0x21 | (((pts >> 30) as u8 & 0x07) << 1));
    hdr.push(((pts >> 22) & 0xFF) as u8);
    hdr.push((((pts >> 15) as u8 & 0x7F) << 1) | 0x01);
    hdr.push(((pts >> 7) & 0xFF) as u8);
    hdr.push((((pts as u8) & 0x7F) << 1) | 0x01);

    hdr
}

fn build_pat(cc: &mut u8) -> [u8; TS_PACKET_SIZE] {
    let mut pkt = [0xFFu8; TS_PACKET_SIZE];
    pkt[0] = 0x47;
    pkt[1] = 0x40 | ((PAT_PID >> 8) as u8 & 0x1F);
    pkt[2] = PAT_PID as u8;
    pkt[3] = 0x10 | (*cc & 0x0F);
    *cc = cc.wrapping_add(1);

    // pointer field
    pkt[4] = 0x00;

    // PAT section
    let section = [
        0x00,       // table id
        0xB0, 0x0D, // section syntax + length (13 bytes)
        0x00, 0x01, // transport stream id
        0xC1,       // version 0, current
        0x00, 0x00, // section number, last section number
        0x00, 0x01, // program number 1
        0xE0 | ((PMT_PID >> 8) as u8 & 0x1F), PMT_PID as u8,
    ];
    pkt[5..5 + section.len()].copy_from_slice(&section);
    let crc = crc32_mpeg2(&pkt[5..5 + section.len()]);
    let crc_pos = 5 + section.len();
    pkt[crc_pos..crc_pos + 4].copy_from_slice(&crc.to_be_bytes());

    pkt
}

fn build_pmt(cc: &mut u8, include_audio: bool) -> [u8; TS_PACKET_SIZE] {
    let mut pkt = [0xFFu8; TS_PACKET_SIZE];
    pkt[0] = 0x47;
    pkt[1] = 0x40 | ((PMT_PID >> 8) as u8 & 0x1F);
    pkt[2] = PMT_PID as u8;
    pkt[3] = 0x10 | (*cc & 0x0F);
    *cc = cc.wrapping_add(1);

    pkt[4] = 0x00;

    // section_length covers from after the length field through CRC.
    // video-only = 18; +5 bytes for one AAC ES = 23.
    let section_len: u16 = if include_audio { 23 } else { 18 };
    let mut section = vec![
        0x02, // table id (PMT)
        0xB0 | ((section_len >> 8) as u8 & 0x0F),
        section_len as u8,
        0x00,
        0x01, // program number
        0xC1, // version 0, current
        0x00,
        0x00, // section/last section
        0xE0 | ((VIDEO_PID >> 8) as u8 & 0x1F),
        VIDEO_PID as u8, // PCR PID
        0xF0,
        0x00, // program info length (0)
        0x1B, // stream type: H.264
        0xE0 | ((VIDEO_PID >> 8) as u8 & 0x1F),
        VIDEO_PID as u8,
        0xF0,
        0x00, // ES info length (0)
    ];
    if include_audio {
        section.extend_from_slice(&[
            0x0F, // stream type: AAC ADTS
            0xE0 | ((AUDIO_PID >> 8) as u8 & 0x1F),
            AUDIO_PID as u8,
            0xF0,
            0x00,
        ]);
    }
    pkt[5..5 + section.len()].copy_from_slice(&section);
    let crc = crc32_mpeg2(&pkt[5..5 + section.len()]);
    let crc_pos = 5 + section.len();
    pkt[crc_pos..crc_pos + 4].copy_from_slice(&crc.to_be_bytes());

    pkt
}

fn write_pcr(buf: &mut [u8], pts_90khz: u64) {
    let base = pts_90khz & 0x1_FFFF_FFFF;
    buf[0] = (base >> 25) as u8;
    buf[1] = (base >> 17) as u8;
    buf[2] = (base >> 9) as u8;
    buf[3] = (base >> 1) as u8;
    buf[4] = (((base & 1) as u8) << 7) | 0x7E;
    buf[5] = 0;
}

pub(crate) fn nal_type(nal: &[u8]) -> u8 {
    let skip = if nal.len() >= 4 && nal[0..4] == [0, 0, 0, 1] {
        4
    } else if nal.len() >= 3 && nal[0..3] == [0, 0, 1] {
        3
    } else {
        return 0;
    };
    nal.get(skip).copied().unwrap_or(0) & 0x1f
}

pub(crate) fn for_each_annex_b_nal(data: &[u8], mut f: impl FnMut(&[u8])) {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        if i + 4 <= data.len() && data[i..i + 4] == [0, 0, 0, 1] {
            starts.push(i);
            i += 4;
        } else if data[i..i + 3] == [0, 0, 1] {
            starts.push(i);
            i += 3;
        } else {
            i += 1;
        }
    }
    for (n, &s) in starts.iter().enumerate() {
        let e = starts.get(n + 1).copied().unwrap_or(data.len());
        if e > s {
            f(&data[s..e]);
        }
    }
}

pub(crate) fn access_unit_has_sps_pps(data: &[u8]) -> bool {
    let mut sps = false;
    let mut pps = false;
    for_each_annex_b_nal(data, |nal| match nal_type(nal) {
        7 => sps = true,
        8 => pps = true,
        _ => {}
    });
    sps && pps
}

/// Last SPS and PPS seen in an Annex-B access unit (with start codes).
pub(crate) fn extract_sps_pps(data: &[u8]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let mut sps = None;
    let mut pps = None;
    for_each_annex_b_nal(data, |nal| match nal_type(nal) {
        7 => sps = Some(nal.to_vec()),
        8 => pps = Some(nal.to_vec()),
        _ => {}
    });
    (sps, pps)
}

/// Prepend cached SPS/PPS when this access unit is an IDR without them.
pub(crate) fn prepend_sps_pps(sps: &[u8], pps: &[u8], annex_b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(sps.len() + pps.len() + annex_b.len());
    out.extend_from_slice(sps);
    out.extend_from_slice(pps);
    out.extend_from_slice(annex_b);
    out
}

fn load_adts_loop(hls_dir: &Path) -> Option<AdtsLoop> {
    let path = hls_dir.join("audio.adts");
    let bytes = fs::read(&path).ok()?;
    let frames = split_adts(&bytes);
    if frames.is_empty() {
        return None;
    }
    let sr = adts_sample_rate(&frames[0])?;
    if sr == 0 {
        return None;
    }
    let ticks_per_frame = 1024u64 * 90_000 / u64::from(sr);
    if ticks_per_frame == 0 {
        return None;
    }
    Some(AdtsLoop {
        frames,
        ticks_per_frame,
        idx: 0,
        next_pts: None,
    })
}

fn split_adts(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 7 <= data.len() {
        if data[i] != 0xFF || data[i + 1] & 0xF0 != 0xF0 {
            i += 1;
            continue;
        }
        let len = (((data[i + 3] & 0x03) as usize) << 11)
            | ((data[i + 4] as usize) << 3)
            | ((data[i + 5] as usize) >> 5);
        if len < 7 || i + len > data.len() {
            i += 1;
            continue;
        }
        out.push(data[i..i + len].to_vec());
        i += len;
    }
    out
}

fn adts_sample_rate(frame: &[u8]) -> Option<u32> {
    if frame.len() < 7 {
        return None;
    }
    let idx = (frame[2] >> 2) & 0x0F;
    const RATES: [u32; 13] = [
        96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350,
    ];
    RATES.get(idx as usize).copied()
}

#[cfg(test)]
fn ts_has_pid(ts: &[u8], pid: u16) -> bool {
    let mut i = 0;
    while i + 4 <= ts.len() {
        if ts[i] == 0x47 {
            let p = ((ts[i + 1] as u16 & 0x1F) << 8) | ts[i + 2] as u16;
            if p == pid {
                return true;
            }
            i += TS_PACKET_SIZE;
        } else {
            i += 1;
        }
    }
    false
}

fn crc32_mpeg2(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= (byte as u32) << 24;
        for _ in 0..8 {
            if crc & 0x80000000 != 0 {
                crc = (crc << 1) ^ 0x04C11DB7;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPS: &[u8] = &[0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xC0, 0x1E];
    const PPS: &[u8] = &[0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x38, 0x80];
    const IDR_NAL: &[u8] = &[0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00];
    /// First-keyframe test access unit: SPS + PPS + IDR so a .ts can open.
    const IDR: &[u8] = &[
        0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xC0, 0x1E, // SPS
        0x00, 0x00, 0x00, 0x01, 0x68, 0xCE, 0x38, 0x80, // PPS
        0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00, // IDR
    ];
    const TWO_SECS_90KHZ: u64 = 180_000;

    fn tmp_root(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!(
            "livecam-hls-{}-{}-{}",
            name,
            std::process::id(),
            nanos
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn write_closed_segment(room: &mut RoomHls, rid: Option<&str>) {
        assert!(room.write_video(rid, 0, true, IDR));
        assert!(room.write_video(rid, TWO_SECS_90KHZ, true, IDR));
    }

    #[test]
    fn two_video_mids_pack_primary_or_simulcast_rids() {
        assert!(RoomHls::accepts_frame(Some(0), None));
        assert!(RoomHls::accepts_frame(Some(0), Some("h")));
        assert!(RoomHls::accepts_frame(Some(1), Some("h")));
        assert!(RoomHls::accepts_frame(Some(1), Some("l")));
        assert!(!RoomHls::accepts_frame(Some(1), None));
        assert!(!RoomHls::accepts_frame(Some(1), Some("cam")));
        assert!(!RoomHls::accepts_frame(None, None));
    }

    #[test]
    fn single_layer_writes_master_not_pip() {
        let root = tmp_root("single");
        let mut room = RoomHls::start("room1", &root).unwrap();
        write_closed_segment(&mut room, None);

        let dir = root.join("room1");
        let master = fs::read_to_string(dir.join("master.m3u8")).unwrap();
        assert!(master.contains("seg000.ts"));
        assert!(dir.join("seg000.ts").exists());
        assert!(!dir.join("pip.m3u8").exists());
        assert!(!dir.join("pip000.ts").exists());

        room.stop();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn first_keyframe_writes_playlist_before_segment_close() {
        let root = tmp_root("early");
        let mut room = RoomHls::start("room3", &root).unwrap();
        assert!(room.write_video(Some("h"), 0, true, IDR));
        assert!(room.write_video(Some("l"), 0, true, IDR));

        let dir = root.join("room3");
        let master = fs::read_to_string(dir.join("master.m3u8")).unwrap();
        let pip = fs::read_to_string(dir.join("pip.m3u8")).unwrap();
        assert!(master.contains("seg000.ts"), "{master}");
        assert!(pip.contains("pip000.ts"), "{pip}");

        room.stop();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn mid_layer_only_writes_master_not_pip() {
        let root = tmp_root("midonly");
        let mut room = RoomHls::start("roomm", &root).unwrap();
        write_closed_segment(&mut room, Some("m"));

        let dir = root.join("roomm");
        let master = fs::read_to_string(dir.join("master.m3u8")).unwrap();
        assert!(master.contains("seg000.ts"));
        assert!(!dir.join("pip.m3u8").exists());

        room.stop();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn stop_keeps_playlists() {
        let root = tmp_root("linger");
        let mut room = RoomHls::start("roomlinger", &root).unwrap();
        write_closed_segment(&mut room, Some("h"));
        write_closed_segment(&mut room, Some("l"));
        let dir = root.join("roomlinger");
        assert!(dir.join("master.m3u8").exists());
        assert!(dir.join("pip.m3u8").exists());
        room.stop();
        assert!(
            dir.join("master.m3u8").exists(),
            "stop must not delete Compatible playlists"
        );
        assert!(dir.join("pip.m3u8").exists());
        assert!(dir.join("seg000.ts").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn start_does_not_invent_or_keep_stale_pip() {
        let root = tmp_root("nopip");
        let dir = root.join("roomx");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("pip.m3u8"), "#EXTM3U\n").unwrap();
        fs::write(dir.join("pip000.ts"), b"x").unwrap();
        fs::write(dir.join("master.m3u8"), "#EXTM3U\nold\n").unwrap();
        let room = RoomHls::start("roomx", &root).unwrap();
        assert!(!dir.join("pip.m3u8").exists(), "must not inherit stale pip");
        assert!(!dir.join("pip000.ts").exists());
        assert!(dir.join("master.m3u8").exists(), "keep Compatible across restart");
        room.stop();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn two_second_segments_use_targetduration_two() {
        let root = tmp_root("tdur");
        let mut room = RoomHls::start("roomtd", &root).unwrap();
        assert!(room.write_video(Some("h"), 0, true, IDR));
        assert!(room.write_video(Some("h"), TWO_SECS_90KHZ, true, IDR));
        assert!(room.write_video(Some("h"), TWO_SECS_90KHZ * 2, true, IDR));

        let master = fs::read_to_string(root.join("roomtd").join("master.m3u8")).unwrap();
        assert!(
            master.contains("#EXT-X-TARGETDURATION:2")
                || master.contains("#EXT-X-TARGETDURATION:3"),
            "{master}"
        );
        assert!(master.contains("#EXTINF:2.000,"), "{master}");
        assert!(
            !master.contains("#EXT-X-TARGETDURATION:241"),
            "{master}"
        );

        room.stop();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sliding_window_evicts_old_and_stale_segments() {
        let root = tmp_root("window");
        let dir = root.join("roomw");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("seg099.ts"), b"stale").unwrap();
        let mut room = RoomHls::start("roomw", &root).unwrap();
        for i in 0..8u64 {
            assert!(room.write_video(Some("h"), i * TWO_SECS_90KHZ, true, IDR));
        }
        assert!(
            !dir.join("seg099.ts").exists(),
            "stale high-index leftover must be evicted"
        );
        assert!(!dir.join("seg000.ts").exists(), "old window entry evicted");
        assert!(dir.join("seg007.ts").exists() || dir.join("seg006.ts").exists());
        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|n| n.ends_with(".ts"))
            .collect();
        assert!(
            names.len() <= MAX_PLAYLIST_ENTRIES + 1,
            "live window too large: {names:?}"
        );

        room.stop();
        let _ = fs::remove_dir_all(&root);
    }

    fn ts_has_nal(ts: &[u8], ty: u8) -> bool {
        let mut i = 0;
        while i + 5 < ts.len() {
            if ts[i..i + 4] == [0, 0, 0, 1] && (ts[i + 4] & 0x1f) == ty {
                return true;
            }
            if i + 4 < ts.len() && ts[i..i + 3] == [0, 0, 1] && (ts[i + 3] & 0x1f) == ty {
                return true;
            }
            i += 1;
        }
        false
    }

    #[test]
    fn extract_and_prepend_sps_pps() {
        let mut au = Vec::new();
        au.extend_from_slice(SPS);
        au.extend_from_slice(PPS);
        au.extend_from_slice(IDR_NAL);
        let (sps, pps) = extract_sps_pps(&au);
        assert!(sps.as_deref() == Some(SPS));
        assert!(pps.as_deref() == Some(PPS));
        assert!(!access_unit_has_sps_pps(IDR_NAL));
        let prefixed = prepend_sps_pps(sps.as_deref().unwrap(), pps.as_deref().unwrap(), IDR_NAL);
        assert!(access_unit_has_sps_pps(&prefixed));
        assert!(prefixed.starts_with(SPS));
    }

    #[test]
    fn later_idr_segment_repeats_sps_pps() {
        let root = tmp_root("sps");
        let mut room = RoomHls::start("roomsps", &root).unwrap();
        let mut first = Vec::new();
        first.extend_from_slice(SPS);
        first.extend_from_slice(PPS);
        first.extend_from_slice(IDR);
        assert!(room.write_video(Some("h"), 0, true, &first));
        assert!(room.write_video(Some("h"), TWO_SECS_90KHZ, true, IDR_NAL));
        assert!(room.write_video(Some("h"), TWO_SECS_90KHZ * 2, true, IDR_NAL));

        let seg1 = fs::read(root.join("roomsps").join("seg001.ts")).unwrap();
        assert!(ts_has_nal(&seg1, 7), "segment must start with SPS");
        assert!(ts_has_nal(&seg1, 8), "segment must include PPS");
        assert!(ts_has_nal(&seg1, 5), "segment must include IDR");

        room.stop();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn file_source_adts_is_remuxed_into_ts() {
        let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test/fixtures");
        let adts_path = fixtures.join("loop.aac");
        let adts = fs::read(&adts_path).expect("test/fixtures/loop.aac (ffmpeg -c:a copy -f adts)");
        assert!(!split_adts(&adts).is_empty(), "loop.aac must contain ADTS frames");

        let root = tmp_root("aac");
        let dir = root.join("roomaac");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("audio.adts"), &adts).unwrap();

        let mut room = RoomHls::start("roomaac", &root).unwrap();
        assert!(room.write_video(Some("h"), 0, true, IDR));
        assert!(room.write_video(Some("h"), TWO_SECS_90KHZ, true, IDR));
        assert!(room.write_video(Some("l"), 0, true, IDR));
        assert!(room.write_video(Some("l"), TWO_SECS_90KHZ, true, IDR));

        let seg = fs::read(dir.join("seg000.ts")).unwrap();
        let pip = fs::read(dir.join("pip000.ts")).unwrap();
        assert!(ts_has_pid(&seg, AUDIO_PID), "master .ts must have AAC PID 0x102");
        assert!(ts_has_pid(&pip, AUDIO_PID), "pip .ts must have AAC PID 0x102");
        assert!(ts_has_pid(&seg, VIDEO_PID), "master .ts must keep video");

        room.stop();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn simulcast_low_layer_writes_pip() {
        let root = tmp_root("simul");
        let mut room = RoomHls::start("room2", &root).unwrap();
        write_closed_segment(&mut room, Some("h"));
        write_closed_segment(&mut room, Some("m"));
        write_closed_segment(&mut room, Some("l"));

        let dir = root.join("room2");
        let master = fs::read_to_string(dir.join("master.m3u8")).unwrap();
        let pip = fs::read_to_string(dir.join("pip.m3u8")).unwrap();
        assert!(master.contains("seg000.ts"));
        assert!(!master.contains("pip000.ts"));
        assert!(pip.contains("pip000.ts"));
        assert!(!pip.contains("seg000.ts"));
        assert!(dir.join("pip000.ts").exists());
        // Mid layer is not packed.
        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        assert!(!names.iter().any(|n| n.starts_with("m") && n.ends_with(".ts")));

        room.stop();
        let _ = fs::remove_dir_all(&root);
    }

    fn nal_units(data: &[u8]) -> Vec<&[u8]> {
        let mut starts = Vec::new();
        let mut i = 0;
        while i + 3 <= data.len() {
            if i + 4 <= data.len() && data[i..i + 4] == [0, 0, 0, 1] {
                starts.push(i);
                i += 4;
            } else if data[i..i + 3] == [0, 0, 1] {
                starts.push(i);
                i += 3;
            } else {
                i += 1;
            }
        }
        let mut out = Vec::new();
        for (n, &s) in starts.iter().enumerate() {
            let e = starts.get(n + 1).copied().unwrap_or(data.len());
            if e > s {
                out.push(&data[s..e]);
            }
        }
        out
    }

    fn nal_type(nal: &[u8]) -> u8 {
        let skip = if nal.len() >= 4 && nal[0..4] == [0, 0, 0, 1] {
            4
        } else if nal.len() >= 3 && nal[0..3] == [0, 0, 1] {
            3
        } else {
            return 0;
        };
        nal.get(skip).copied().unwrap_or(0) & 0x1f
    }

    /// SPS/PPS (and SEI) plus the first IDR. Empty if the bitstream has no IDR.
    fn first_idr_access_unit(data: &[u8]) -> Option<Vec<u8>> {
        let mut prefix = Vec::new();
        for nal in nal_units(data) {
            match nal_type(nal) {
                6 | 7 | 8 => prefix.extend_from_slice(nal),
                5 => {
                    let mut au = prefix;
                    au.extend_from_slice(nal);
                    return Some(au);
                }
                _ => {}
            }
        }
        None
    }

    fn ffmpeg_annex_b(mp4: &Path) -> Option<Vec<u8>> {
        let out = std::env::temp_dir().join(format!(
            "livecam-loop-{}-{}.h264",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let status = std::process::Command::new("ffmpeg")
            .args(["-y", "-hide_banner", "-loglevel", "error", "-i"])
            .arg(mp4)
            .args([
                "-c:v",
                "copy",
                "-bsf:v",
                "h264_mp4toannexb",
                "-an",
                "-f",
                "h264",
            ])
            .arg(&out)
            .status()
            .ok()?;
        if !status.success() {
            let _ = fs::remove_file(&out);
            return None;
        }
        let bytes = fs::read(&out).ok();
        let _ = fs::remove_file(&out);
        bytes
    }

    fn load_h264_sample() -> Option<Vec<u8>> {
        let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test/fixtures");
        let annex = fixtures.join("loop.h264");
        if annex.is_file() {
            return fs::read(&annex).ok();
        }
        let mp4 = fixtures.join("loop.mp4");
        if mp4.is_file() {
            return ffmpeg_annex_b(&mp4);
        }
        None
    }

    #[test]
    fn fixture_h264_l_layer_writes_pip() {
        let annex = load_h264_sample().expect(
            "need test/fixtures/loop.mp4 (or loop.h264) plus ffmpeg to prove rid-l remux",
        );
        let idr = first_idr_access_unit(&annex).expect("fixture must contain an IDR NAL");
        assert!(
            idr.len() > 16,
            "IDR access unit too small to be a real sample ({})",
            idr.len()
        );

        let persist = std::env::var_os("HLS_PIP_SAMPLE_DIR").map(PathBuf::from);
        let root = persist.clone().unwrap_or_else(|| tmp_root("fixture-l"));
        if persist.is_some() {
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
        }

        let mut room = RoomHls::start("pipdemo", &root).unwrap();
        assert!(room.write_video(Some("h"), 0, true, &idr));
        assert!(room.write_video(Some("h"), TWO_SECS_90KHZ, true, &idr));
        assert!(room.write_video(Some("m"), 0, true, &idr));
        assert!(room.write_video(Some("m"), TWO_SECS_90KHZ, true, &idr));
        assert!(room.write_video(Some("l"), 0, true, &idr));
        assert!(room.write_video(Some("l"), TWO_SECS_90KHZ, true, &idr));

        let dir = root.join("pipdemo");
        let pip = fs::read_to_string(dir.join("pip.m3u8")).expect("pip.m3u8 from rid l");
        let master = fs::read_to_string(dir.join("master.m3u8")).expect("master.m3u8 from rid h");
        assert!(pip.contains("pip000.ts"), "{pip}");
        assert!(!pip.contains("seg000.ts"), "{pip}");
        assert!(master.contains("seg000.ts"), "{master}");
        assert!(!master.contains("pip000.ts"), "{master}");
        assert!(dir.join("pip000.ts").exists());
        assert!(dir.join("seg000.ts").exists());

        if persist.is_some() {
            // Leave playlists on disk for the headless proof script. Do not call
            // stop() — master owns the room dir and would delete it.
            std::mem::forget(room);
            eprintln!("HLS pip sample kept at {}", dir.display());
        } else {
            room.stop();
            let _ = fs::remove_dir_all(&root);
        }
    }
}
