use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::SystemTime;

/// Manages per-room VOD recordings by writing raw media samples to disk.
///
/// Each room gets its own file. Recording starts automatically when the first
/// media packet arrives for a room, and stops when `stop_recording` is called
/// (e.g., when the broadcaster disconnects).
pub struct ArchiveModule {
    archive_dir: PathBuf,
    recordings: HashMap<String, File>,
}

impl ArchiveModule {
    pub fn new(archive_dir: &str) -> Self {
        let dir = PathBuf::from(archive_dir);
        if !dir.exists() {
            if let Err(e) = std::fs::create_dir_all(&dir) {
                tracing::error!("Failed to create archive directory '{}': {}", dir.display(), e);
            }
        }
        Self {
            archive_dir: dir,
            recordings: HashMap::new(),
        }
    }

    /// Write a media sample for a given room. Lazily opens the file on the first packet.
    pub fn write_sample(&mut self, room_id: &str, data: &[u8]) {
        let file = self.recordings.entry(room_id.to_owned()).or_insert_with(|| {
            let filename = generate_filename(room_id);
            let path = self.archive_dir.join(&filename);
            tracing::info!("Recording started: {}", path.display());
            File::create(&path).unwrap_or_else(|e| {
                panic!("Cannot create archive file '{}': {}", path.display(), e);
            })
        });

        if let Err(e) = file.write_all(data) {
            tracing::error!("Archive write error for room '{}': {}", room_id, e);
        }
    }

    /// Stop and finalize recording for a room. The file is flushed and closed.
    pub fn stop_recording(&mut self, room_id: &str) {
        if let Some(mut file) = self.recordings.remove(room_id) {
            let _ = file.flush();
            tracing::info!("Recording stopped for room '{}'", room_id);
        }
    }

    pub fn is_recording(&self, room_id: &str) -> bool {
        self.recordings.contains_key(room_id)
    }
}

fn generate_filename(room_id: &str) -> String {
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}_{}.raw", sanitize_room_id(room_id), ts)
}

fn sanitize_room_id(room_id: &str) -> String {
    room_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}
