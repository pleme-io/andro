use blake3::Hash;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Tracks file state for incremental sync — what was synced and when.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncManifest {
    pub entries: HashMap<String, ManifestEntry>,
    pub last_sync: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub remote_path: String,
    pub local_path: PathBuf,
    pub blake3_hash: String,
    pub size: u64,
    pub modified: DateTime<Utc>,
    pub synced_at: DateTime<Utc>,
}

impl SyncManifest {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            last_sync: None,
        }
    }

    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(Self::new)
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, json)
    }

    pub fn record(&mut self, remote: &str, local: &Path, hash: Hash, size: u64) {
        let now = Utc::now();
        self.entries.insert(
            remote.to_string(),
            ManifestEntry {
                remote_path: remote.to_string(),
                local_path: local.to_path_buf(),
                blake3_hash: hash.to_hex().to_string(),
                size,
                modified: now,
                synced_at: now,
            },
        );
        self.last_sync = Some(now);
    }

    /// Check if a file needs syncing by comparing BLAKE3 hash.
    pub fn needs_sync(&self, remote: &str, current_hash: &str) -> bool {
        match self.entries.get(remote) {
            Some(entry) => entry.blake3_hash != current_hash,
            None => true,
        }
    }
}

impl Default for SyncManifest {
    fn default() -> Self {
        Self::new()
    }
}
