use andro_core::Result;
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A device in the inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryEntry {
    pub serial: String,
    pub model: Option<String>,
    pub manufacturer: Option<String>,
    pub android_version: Option<String>,
    pub api_level: Option<String>,
    pub group: Option<String>,
    pub last_seen: DateTime<Utc>,
    pub status: String,
}

/// SQLite-backed device inventory.
pub struct DeviceInventory {
    conn: Connection,
}

impl DeviceInventory {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS devices (
                serial TEXT PRIMARY KEY,
                model TEXT,
                manufacturer TEXT,
                android_version TEXT,
                api_level TEXT,
                device_group TEXT,
                last_seen TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'unknown'
            );",
        )
        .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;

        Ok(Self { conn })
    }

    /// Upsert a device entry.
    pub fn upsert(&self, entry: &InventoryEntry) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO devices (serial, model, manufacturer, android_version, api_level, device_group, last_seen, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(serial) DO UPDATE SET
                   model = excluded.model,
                   manufacturer = excluded.manufacturer,
                   android_version = excluded.android_version,
                   api_level = excluded.api_level,
                   last_seen = excluded.last_seen,
                   status = excluded.status",
                params![
                    entry.serial,
                    entry.model,
                    entry.manufacturer,
                    entry.android_version,
                    entry.api_level,
                    entry.group,
                    entry.last_seen.to_rfc3339(),
                    entry.status,
                ],
            )
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        Ok(())
    }

    /// List all devices in inventory.
    pub fn list(&self) -> Result<Vec<InventoryEntry>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT serial, model, manufacturer, android_version, api_level, device_group, last_seen, status
                 FROM devices ORDER BY last_seen DESC",
            )
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;

        let entries = stmt
            .query_map([], |row| {
                let last_seen_str: String = row.get(6)?;
                let last_seen = DateTime::parse_from_rfc3339(&last_seen_str)
                    .unwrap_or_default()
                    .with_timezone(&Utc);
                Ok(InventoryEntry {
                    serial: row.get(0)?,
                    model: row.get(1)?,
                    manufacturer: row.get(2)?,
                    android_version: row.get(3)?,
                    api_level: row.get(4)?,
                    group: row.get(5)?,
                    last_seen,
                    status: row.get(7)?,
                })
            })
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(entries)
    }

    /// Count devices in inventory.
    pub fn count(&self) -> Result<u64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        Ok(count as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("andro_farm_test_{}.db", std::process::id()))
    }

    #[test]
    fn upsert_and_list() {
        let db_path = temp_db();
        let inv = DeviceInventory::open(&db_path).unwrap();

        let entry = InventoryEntry {
            serial: "TEST123".into(),
            model: Some("Pixel 7".into()),
            manufacturer: Some("Google".into()),
            android_version: Some("14".into()),
            api_level: Some("34".into()),
            group: Some("test-phones".into()),
            last_seen: Utc::now(),
            status: "online".into(),
        };

        inv.upsert(&entry).unwrap();
        let devices = inv.list().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].serial, "TEST123");
        assert_eq!(devices[0].model.as_deref(), Some("Pixel 7"));

        let count = inv.count().unwrap();
        assert_eq!(count, 1);

        let _ = std::fs::remove_file(&db_path);
    }

    fn unique_db() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "andro_farm_mock_{}_{}_{}.db",
            std::process::id(),
            id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn upsert_creates_entry_and_fields_match() {
        let db_path = unique_db();
        let inv = DeviceInventory::open(&db_path).unwrap();

        let entry = InventoryEntry {
            serial: "MOCK_S1".into(),
            model: Some("Pixel 8 Pro".into()),
            manufacturer: Some("Google".into()),
            android_version: Some("15".into()),
            api_level: Some("35".into()),
            group: Some("lab-rack-1".into()),
            last_seen: Utc::now(),
            status: "online".into(),
        };
        inv.upsert(&entry).unwrap();

        let devices = inv.list().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].serial, "MOCK_S1");
        assert_eq!(devices[0].model.as_deref(), Some("Pixel 8 Pro"));
        assert_eq!(devices[0].manufacturer.as_deref(), Some("Google"));
        assert_eq!(devices[0].android_version.as_deref(), Some("15"));
        assert_eq!(devices[0].api_level.as_deref(), Some("35"));
        assert_eq!(devices[0].status, "online");

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn list_orders_most_recent_first() {
        let db_path = unique_db();
        let inv = DeviceInventory::open(&db_path).unwrap();

        let older = InventoryEntry {
            serial: "OLD_DEV".into(),
            model: Some("Pixel 6".into()),
            manufacturer: None,
            android_version: None,
            api_level: None,
            group: None,
            last_seen: DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            status: "offline".into(),
        };
        let newer = InventoryEntry {
            serial: "NEW_DEV".into(),
            model: Some("Pixel 9".into()),
            manufacturer: None,
            android_version: None,
            api_level: None,
            group: None,
            last_seen: DateTime::parse_from_rfc3339("2026-03-22T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            status: "online".into(),
        };

        inv.upsert(&older).unwrap();
        inv.upsert(&newer).unwrap();

        let devices = inv.list().unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].serial, "NEW_DEV");
        assert_eq!(devices[1].serial, "OLD_DEV");

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn count_after_multiple_upserts() {
        let db_path = unique_db();
        let inv = DeviceInventory::open(&db_path).unwrap();

        for i in 0..5 {
            let entry = InventoryEntry {
                serial: format!("DEV_{i}"),
                model: Some(format!("Model_{i}")),
                manufacturer: None,
                android_version: None,
                api_level: None,
                group: None,
                last_seen: Utc::now(),
                status: "online".into(),
            };
            inv.upsert(&entry).unwrap();
        }

        assert_eq!(inv.count().unwrap(), 5);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn upsert_updates_existing_entry_same_serial() {
        let db_path = unique_db();
        let inv = DeviceInventory::open(&db_path).unwrap();

        let original = InventoryEntry {
            serial: "SAME_SERIAL".into(),
            model: Some("Pixel 7".into()),
            manufacturer: Some("Google".into()),
            android_version: Some("13".into()),
            api_level: Some("33".into()),
            group: None,
            last_seen: Utc::now(),
            status: "offline".into(),
        };
        inv.upsert(&original).unwrap();

        let updated = InventoryEntry {
            serial: "SAME_SERIAL".into(),
            model: Some("Pixel 7".into()),
            manufacturer: Some("Google".into()),
            android_version: Some("14".into()),
            api_level: Some("34".into()),
            group: None,
            last_seen: Utc::now(),
            status: "online".into(),
        };
        inv.upsert(&updated).unwrap();

        assert_eq!(inv.count().unwrap(), 1);
        let devices = inv.list().unwrap();
        assert_eq!(devices[0].android_version.as_deref(), Some("14"));
        assert_eq!(devices[0].api_level.as_deref(), Some("34"));
        assert_eq!(devices[0].status, "online");

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn list_returns_empty_for_new_database() {
        let db_path = unique_db();
        let inv = DeviceInventory::open(&db_path).unwrap();

        let devices = inv.list().unwrap();
        assert!(devices.is_empty());
        assert_eq!(inv.count().unwrap(), 0);

        let _ = std::fs::remove_file(&db_path);
    }
}
