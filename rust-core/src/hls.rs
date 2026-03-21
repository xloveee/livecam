use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

const TS_PACKET_SIZE: usize = 188;
const PAT_PID: u16 = 0x0000;
const PMT_PID: u16 = 0x0100;
const VIDEO_PID: u16 = 0x0101;
const SEGMENT_DURATION_SECS: f64 = 2.0;
const MAX_PLAYLIST_ENTRIES: usize = 5;

/// Pure-Rust HLS segmenter. Wraps raw H.264 Annex B frames into MPEG-TS
/// segments and writes a rolling m3u8 playlist. No ffmpeg, no external deps.
pub struct HlsSink {
    room_id: String,
    hls_dir: PathBuf,
    segment_index: u32,
    current_segment: Option<File>,
    segment_start_pts: u64,
    last_pts: u64,
    continuity_counter_pat: u8,
    continuity_counter_pmt: u8,
    continuity_counter_vid: u8,
    segment_durations: Vec<f64>,
    started_at: Instant,
    bytes_written: u64,
    has_keyframe: bool,
}

impl HlsSink {
    pub fn start(room_id: &str, hls_root: &Path) -> Result<Self, String> {
        let hls_dir = hls_root.join(room_id);
        fs::create_dir_all(&hls_dir)
            .map_err(|e| format!("failed to create HLS dir {:?}: {}", hls_dir, e))?;

        tracing::info!("HLS sink started for room '{}' -> {:?}", room_id, hls_dir);

        Ok(Self {
            room_id: room_id.to_owned(),
            hls_dir,
            segment_index: 0,
            current_segment: None,
            segment_start_pts: 0,
            last_pts: 0,
            continuity_counter_pat: 0,
            continuity_counter_pmt: 0,
            continuity_counter_vid: 0,
            segment_durations: Vec::new(),
            started_at: Instant::now(),
            bytes_written: 0,
            has_keyframe: false,
        })
    }

    /// Write a video frame. `pts_90khz` is the presentation timestamp in 90kHz units.
    /// `is_keyframe` indicates an IDR frame (segment boundary candidate).
    /// `annex_b` is the raw H.264 Annex B data (with start codes).
    pub fn write_video(&mut self, pts_90khz: u64, is_keyframe: bool, annex_b: &[u8]) -> bool {
        if annex_b.is_empty() {
            return true;
        }

        if is_keyframe {
            if self.current_segment.is_some() {
                let duration = (pts_90khz.saturating_sub(self.segment_start_pts)) as f64 / 90_000.0;
                if duration >= SEGMENT_DURATION_SECS * 0.5 {
                    self.finalize_segment(duration);
                }
            }
            if self.current_segment.is_none() {
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
        self.write_pes(pts_90khz, is_keyframe, annex_b)
    }

    pub fn stop(mut self) {
        if self.current_segment.is_some() {
            let duration = (self.last_pts.saturating_sub(self.segment_start_pts)) as f64 / 90_000.0;
            self.finalize_segment(duration.max(0.1));
        }
        let elapsed = self.started_at.elapsed();
        tracing::info!(
            "HLS sink stopped for room '{}': wrote {} bytes in {:.0}s",
            self.room_id, self.bytes_written, elapsed.as_secs_f64()
        );
        if let Err(e) = fs::remove_dir_all(&self.hls_dir) {
            tracing::warn!("Failed to clean up HLS dir {:?}: {}", self.hls_dir, e);
        }
    }

    fn open_segment(&mut self, pts: u64) -> bool {
        let path = self.hls_dir.join(format!("seg{:03}.ts", self.segment_index));
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
        self.current_segment = None;
        self.segment_durations.push(duration);

        let oldest = if self.segment_durations.len() > MAX_PLAYLIST_ENTRIES {
            self.segment_index as usize - MAX_PLAYLIST_ENTRIES
        } else {
            0
        };
        for i in 0..oldest {
            let old_path = self.hls_dir.join(format!("seg{:03}.ts", i));
            let _ = fs::remove_file(old_path);
        }

        self.write_playlist(oldest);
        self.segment_index += 1;
    }

    fn write_playlist(&self, first_index: usize) {
        let target_duration = self.segment_durations.iter()
            .skip(first_index)
            .cloned()
            .fold(0.0_f64, f64::max)
            .ceil() as u32;
        let target_duration = target_duration.max(1);

        let mut m3u8 = String::with_capacity(512);
        m3u8.push_str("#EXTM3U\n");
        m3u8.push_str("#EXT-X-VERSION:3\n");
        m3u8.push_str(&format!("#EXT-X-TARGETDURATION:{}\n", target_duration));
        m3u8.push_str(&format!("#EXT-X-MEDIA-SEQUENCE:{}\n", first_index));

        for (i, dur) in self.segment_durations.iter().enumerate().skip(first_index) {
            m3u8.push_str(&format!("#EXTINF:{:.3},\n", dur));
            m3u8.push_str(&format!("seg{:03}.ts\n", i));
        }

        let path = self.hls_dir.join("master.m3u8");
        if let Err(e) = fs::write(&path, m3u8.as_bytes()) {
            tracing::warn!("HLS: failed to write playlist {:?}: {}", path, e);
        }
    }

    fn write_pes(&mut self, pts_90khz: u64, is_rap: bool, annex_b: &[u8]) -> bool {
        let file = match self.current_segment {
            Some(ref mut f) => f,
            None => return true,
        };

        let pes_header = build_pes_header(pts_90khz, annex_b.len());
        let payload: Vec<u8> = [&pes_header[..], annex_b].concat();

        let mut offset = 0;
        let mut first = true;
        while offset < payload.len() {
            let mut pkt = [0u8; TS_PACKET_SIZE];
            pkt[0] = 0x47; // sync byte
            let pusi: u8 = if first { 0x40 } else { 0x00 };
            pkt[1] = pusi | ((VIDEO_PID >> 8) as u8 & 0x1F);
            pkt[2] = VIDEO_PID as u8;

            let cc = self.continuity_counter_vid & 0x0F;
            self.continuity_counter_vid = self.continuity_counter_vid.wrapping_add(1);

            let remaining = payload.len() - offset;

            if first && is_rap {
                let adapt_len = 2u8;
                pkt[3] = 0x30 | cc; // adaptation + payload
                pkt[4] = adapt_len;
                pkt[5] = 0x40; // random access indicator
                let space = TS_PACKET_SIZE - 4 - 1 - adapt_len as usize;
                let chunk = remaining.min(space);
                pkt[6..6 + chunk].copy_from_slice(&payload[offset..offset + chunk]);
                offset += chunk;
            } else {
                let header_size = 4;
                let space = TS_PACKET_SIZE - header_size;
                if remaining < space {
                    let stuff_len = space - remaining;
                    pkt[3] = 0x30 | cc; // adaptation + payload
                    if stuff_len == 1 {
                        pkt[4] = 0;
                        pkt[5..5 + remaining].copy_from_slice(&payload[offset..offset + remaining]);
                    } else {
                        pkt[4] = (stuff_len - 1) as u8;
                        pkt[5] = 0x00;
                        for b in &mut pkt[6..4 + stuff_len] {
                            *b = 0xFF;
                        }
                        pkt[4 + stuff_len..4 + stuff_len + remaining]
                            .copy_from_slice(&payload[offset..offset + remaining]);
                    }
                    offset += remaining;
                } else {
                    pkt[3] = 0x10 | cc; // payload only
                    pkt[4..4 + space].copy_from_slice(&payload[offset..offset + space]);
                    offset += space;
                }
            }
            first = false;

            if let Err(_) = file.write_all(&pkt) {
                tracing::warn!("HLS: write error for room '{}'", self.room_id);
                return false;
            }
            self.bytes_written += TS_PACKET_SIZE as u64;
        }

        true
    }

    fn write_pat_pmt(&mut self, file: &mut File) {
        let pat = build_pat(&mut self.continuity_counter_pat);
        let pmt = build_pmt(&mut self.continuity_counter_pmt);
        let _ = file.write_all(&pat);
        let _ = file.write_all(&pmt);
        self.bytes_written += (TS_PACKET_SIZE * 2) as u64;
    }
}

impl Drop for HlsSink {
    fn drop(&mut self) {
        // Clean up any leftover segments
        let _ = fs::remove_dir_all(&self.hls_dir);
    }
}

fn build_pes_header(pts_90khz: u64, payload_len: usize) -> Vec<u8> {
    let pes_len = payload_len + 8; // 3 header + 5 PTS
    let pes_len_field = if pes_len > 0xFFFF { 0u16 } else { pes_len as u16 };
    let pts = pts_90khz & 0x1FFFFFFFF;

    let mut hdr = Vec::with_capacity(14);
    hdr.extend_from_slice(&[0x00, 0x00, 0x01]); // start code
    hdr.push(0xE0); // stream id (video)
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

fn build_pmt(cc: &mut u8) -> [u8; TS_PACKET_SIZE] {
    let mut pkt = [0xFFu8; TS_PACKET_SIZE];
    pkt[0] = 0x47;
    pkt[1] = 0x40 | ((PMT_PID >> 8) as u8 & 0x1F);
    pkt[2] = PMT_PID as u8;
    pkt[3] = 0x10 | (*cc & 0x0F);
    *cc = cc.wrapping_add(1);

    pkt[4] = 0x00;

    let section = [
        0x02,       // table id (PMT)
        0xB0, 0x12, // section syntax + length (18 bytes)
        0x00, 0x01, // program number
        0xC1,       // version 0, current
        0x00, 0x00, // section/last section
        0xE0 | ((VIDEO_PID >> 8) as u8 & 0x1F), VIDEO_PID as u8, // PCR PID
        0xF0, 0x00, // program info length (0)
        0x1B,       // stream type: H.264
        0xE0 | ((VIDEO_PID >> 8) as u8 & 0x1F), VIDEO_PID as u8,
        0xF0, 0x00, // ES info length (0)
    ];
    pkt[5..5 + section.len()].copy_from_slice(&section);
    let crc = crc32_mpeg2(&pkt[5..5 + section.len()]);
    let crc_pos = 5 + section.len();
    pkt[crc_pos..crc_pos + 4].copy_from_slice(&crc.to_be_bytes());

    pkt
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
