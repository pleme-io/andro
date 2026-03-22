//! Device settings snapshot, diff, and restore via ADB.
//!
//! Captures `system`, `secure`, and `global` settings namespaces using
//! `adb shell settings list`, stores them as typed snapshots, and can
//! compute diffs or restore a previous snapshot.

use andro_core::error::Result;
use andro_core::traits::AdbTransport;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Settings namespace (system, secure, global).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Namespace {
    System,
    Secure,
    Global,
}

impl Namespace {
    /// All namespaces in order.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::System, Self::Secure, Self::Global]
    }
}

impl std::fmt::Display for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::System => write!(f, "system"),
            Self::Secure => write!(f, "secure"),
            Self::Global => write!(f, "global"),
        }
    }
}

/// A complete snapshot of device settings at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsSnapshot {
    pub device: String,
    pub timestamp: DateTime<Utc>,
    pub system: BTreeMap<String, String>,
    pub secure: BTreeMap<String, String>,
    pub global: BTreeMap<String, String>,
}

/// The kind of change detected between two snapshots.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
}

/// A single setting that changed between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingChange {
    pub namespace: Namespace,
    pub key: String,
    pub kind: ChangeKind,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

/// Manager for device settings operations.
pub struct SettingsManager;

impl SettingsManager {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Capture a full settings snapshot from the device.
    ///
    /// Runs `settings list system`, `settings list secure`, and
    /// `settings list global` and parses the key=value output.
    pub fn snapshot(
        &self,
        serial: &str,
        adb: &mut dyn AdbTransport,
    ) -> Result<SettingsSnapshot> {
        let system = self.list_namespace(serial, Namespace::System, adb)?;
        let secure = self.list_namespace(serial, Namespace::Secure, adb)?;
        let global = self.list_namespace(serial, Namespace::Global, adb)?;

        Ok(SettingsSnapshot {
            device: serial.to_string(),
            timestamp: Utc::now(),
            system,
            secure,
            global,
        })
    }

    /// Compute the diff between two snapshots.
    ///
    /// Returns a list of changes (added, removed, modified) across all
    /// namespaces.
    #[must_use]
    pub fn diff(
        &self,
        old: &SettingsSnapshot,
        new: &SettingsSnapshot,
    ) -> Vec<SettingChange> {
        let mut changes = Vec::new();
        Self::diff_maps(Namespace::System, &old.system, &new.system, &mut changes);
        Self::diff_maps(Namespace::Secure, &old.secure, &new.secure, &mut changes);
        Self::diff_maps(Namespace::Global, &old.global, &new.global, &mut changes);
        changes
    }

    /// Restore a snapshot by writing each setting back to the device.
    ///
    /// Uses `settings put <namespace> <key> <value>` for each entry.
    pub fn restore(
        &self,
        serial: &str,
        snapshot: &SettingsSnapshot,
        adb: &mut dyn AdbTransport,
    ) -> Result<u64> {
        let mut count: u64 = 0;
        for (ns, map) in [
            (Namespace::System, &snapshot.system),
            (Namespace::Secure, &snapshot.secure),
            (Namespace::Global, &snapshot.global),
        ] {
            for (key, value) in map {
                let cmd = format!("settings put {ns} {key} {value}");
                adb.shell(serial, &cmd)?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// List settings for a single namespace.
    fn list_namespace(
        &self,
        serial: &str,
        namespace: Namespace,
        adb: &mut dyn AdbTransport,
    ) -> Result<BTreeMap<String, String>> {
        let cmd = format!("settings list {namespace}");
        let output = adb.shell(serial, &cmd)?;
        Ok(Self::parse_settings(&output.stdout))
    }

    /// Parse `key=value` lines from `settings list` output.
    fn parse_settings(text: &str) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((key, value)) = trimmed.split_once('=') {
                map.insert(key.to_string(), value.to_string());
            }
        }
        map
    }

    /// Compute changes between two maps for a single namespace.
    fn diff_maps(
        namespace: Namespace,
        old: &BTreeMap<String, String>,
        new: &BTreeMap<String, String>,
        changes: &mut Vec<SettingChange>,
    ) {
        // Collect all keys from both maps.
        let mut all_keys: std::collections::BTreeSet<&String> = old.keys().collect();
        all_keys.extend(new.keys());

        for key in all_keys {
            match (old.get(key), new.get(key)) {
                (Some(ov), Some(nv)) if ov != nv => {
                    changes.push(SettingChange {
                        namespace,
                        key: key.clone(),
                        kind: ChangeKind::Modified,
                        old_value: Some(ov.clone()),
                        new_value: Some(nv.clone()),
                    });
                }
                (Some(_), Some(_)) => {} // unchanged
                (None, Some(nv)) => {
                    changes.push(SettingChange {
                        namespace,
                        key: key.clone(),
                        kind: ChangeKind::Added,
                        old_value: None,
                        new_value: Some(nv.clone()),
                    });
                }
                (Some(ov), None) => {
                    changes.push(SettingChange {
                        namespace,
                        key: key.clone(),
                        kind: ChangeKind::Removed,
                        old_value: Some(ov.clone()),
                        new_value: None,
                    });
                }
                (None, None) => unreachable!(),
            }
        }
    }
}

impl Default for SettingsManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use andro_core::mocks::MockAdbTransport;

    fn mock_adb() -> MockAdbTransport {
        MockAdbTransport::new()
            .with_shell_response(
                "settings list system",
                "volume_music=7\nscreen_brightness=128\n",
            )
            .with_shell_response(
                "settings list secure",
                "android_id=abc123\nlocation_mode=3\n",
            )
            .with_shell_response(
                "settings list global",
                "airplane_mode_on=0\nwifi_on=1\n",
            )
    }

    #[test]
    fn snapshot_captures_all_namespaces() {
        let mut adb = mock_adb();
        let mgr = SettingsManager::new();
        let snap = mgr.snapshot("TEST", &mut adb).unwrap();
        assert_eq!(snap.system.len(), 2);
        assert_eq!(snap.secure.len(), 2);
        assert_eq!(snap.global.len(), 2);
        assert_eq!(snap.system.get("volume_music").unwrap(), "7");
        assert_eq!(snap.secure.get("android_id").unwrap(), "abc123");
        assert_eq!(snap.global.get("wifi_on").unwrap(), "1");
    }

    #[test]
    fn diff_detects_modifications() {
        let mgr = SettingsManager::new();
        let mut old = SettingsSnapshot {
            device: "D1".to_string(),
            timestamp: Utc::now(),
            system: BTreeMap::from([
                ("brightness".to_string(), "100".to_string()),
            ]),
            secure: BTreeMap::new(),
            global: BTreeMap::new(),
        };
        let mut new_snap = old.clone();
        new_snap.system.insert("brightness".to_string(), "200".to_string());

        let changes = mgr.diff(&old, &new_snap);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::Modified);
        assert_eq!(changes[0].old_value.as_deref(), Some("100"));
        assert_eq!(changes[0].new_value.as_deref(), Some("200"));
    }

    #[test]
    fn diff_detects_additions_and_removals() {
        let mgr = SettingsManager::new();
        let old = SettingsSnapshot {
            device: "D1".to_string(),
            timestamp: Utc::now(),
            system: BTreeMap::from([("old_key".to_string(), "val".to_string())]),
            secure: BTreeMap::new(),
            global: BTreeMap::new(),
        };
        let new_snap = SettingsSnapshot {
            device: "D1".to_string(),
            timestamp: Utc::now(),
            system: BTreeMap::from([("new_key".to_string(), "val2".to_string())]),
            secure: BTreeMap::new(),
            global: BTreeMap::new(),
        };

        let changes = mgr.diff(&old, &new_snap);
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().any(|c| c.kind == ChangeKind::Removed));
        assert!(changes.iter().any(|c| c.kind == ChangeKind::Added));
    }

    #[test]
    fn diff_empty_when_identical() {
        let mgr = SettingsManager::new();
        let snap = SettingsSnapshot {
            device: "D1".to_string(),
            timestamp: Utc::now(),
            system: BTreeMap::from([("a".to_string(), "1".to_string())]),
            secure: BTreeMap::new(),
            global: BTreeMap::new(),
        };
        let changes = mgr.diff(&snap, &snap);
        assert!(changes.is_empty());
    }

    #[test]
    fn restore_writes_settings() {
        let mut adb = MockAdbTransport::new();
        // Restore does shell calls for each setting — mock accepts any command.
        let mgr = SettingsManager::new();
        let snap = SettingsSnapshot {
            device: "D1".to_string(),
            timestamp: Utc::now(),
            system: BTreeMap::from([("brightness".to_string(), "128".to_string())]),
            secure: BTreeMap::new(),
            global: BTreeMap::from([("wifi_on".to_string(), "1".to_string())]),
        };
        let count = mgr.restore("D1", &snap, &mut adb).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn parse_settings_handles_edge_cases() {
        let text = "key1=value1\n\nkey2=val=ue2\n  \nkey3=\n";
        let map = SettingsManager::parse_settings(text);
        assert_eq!(map.get("key1").unwrap(), "value1");
        assert_eq!(map.get("key2").unwrap(), "val=ue2");
        assert_eq!(map.get("key3").unwrap(), "");
    }
}
