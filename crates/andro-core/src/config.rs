use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Root configuration for andro.
/// Loaded from `~/.config/andro/andro.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AndroConfig {
    /// ADB server host (default: 127.0.0.1)
    pub adb_host: String,

    /// ADB server port (default: 5037)
    pub adb_port: u16,

    /// Default device serial (if set, used when --device is omitted)
    pub default_device: Option<String>,

    /// Named device groups for parallel operations.
    pub groups: HashMap<String, Vec<String>>,

    /// Sync configuration.
    pub sync: SyncConfig,

    /// Log configuration.
    pub log: LogConfig,
}

impl Default for AndroConfig {
    fn default() -> Self {
        Self {
            adb_host: "127.0.0.1".into(),
            adb_port: 5037,
            default_device: None,
            groups: HashMap::new(),
            sync: SyncConfig::default(),
            log: LogConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SyncConfig {
    /// Default local backup directory.
    pub backup_dir: PathBuf,

    /// Exclude patterns for sync operations.
    pub exclude: Vec<String>,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            backup_dir: dirs::home_dir()
                .unwrap_or_default()
                .join(".local/share/andro/backups"),
            exclude: vec![".thumbnails".into(), ".trashed-*".into()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// Path to log database.
    pub db_path: PathBuf,

    /// Maximum log retention in days.
    pub retention_days: u32,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            db_path: dirs::data_dir()
                .unwrap_or_default()
                .join("andro/logs.db"),
            retention_days: 30,
        }
    }
}

impl AndroConfig {
    /// Load config from standard paths: $ANDRO_CONFIG or ~/.config/andro/andro.yaml
    pub fn load() -> Self {
        if let Ok(path) = std::env::var("ANDRO_CONFIG") {
            let path = PathBuf::from(path);
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(config) = serde_yaml_ng::from_str(&content) {
                    return config;
                }
            }
        }

        let xdg = dirs::config_dir()
            .unwrap_or_default()
            .join("andro/andro.yaml");
        if let Ok(content) = std::fs::read_to_string(&xdg) {
            if let Ok(config) = serde_yaml_ng::from_str(&content) {
                return config;
            }
        }

        Self::default()
    }
}
