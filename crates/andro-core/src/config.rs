use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddrV4;
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

    /// Parse ADB server address from config fields.
    pub fn server_addr(&self) -> SocketAddrV4 {
        format!("{}:{}", self.adb_host, self.adb_port)
            .parse()
            .unwrap_or_else(|_| "127.0.0.1:5037".parse().unwrap())
    }
}

/// Known Android device USB vendor IDs.
/// Shared across andro-farm (USB discovery) and andro-hw (fastboot).
pub const ANDROID_VENDOR_IDS: &[u16] = &[
    0x18D1, // Google
    0x04E8, // Samsung
    0x22B8, // Motorola
    0x2717, // Xiaomi
    0x2A70, // OnePlus
    0x05C6, // Qualcomm
    0x1949, // Lab126 (Amazon)
    0x0BB4, // HTC
    0x12D1, // Huawei
    0x2B4C, // Nothing
    0x1004, // LG
    0x0FCE, // Sony
    0x2A96, // Google (Tensor)
    0x0E8D, // MediaTek
    0x1532, // Razer
    0x2916, // Google (AOSP)
];
