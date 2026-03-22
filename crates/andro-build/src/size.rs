use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Size report for an APK build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeReport {
    pub file_size: u64,
    pub dex_size: u64,
    pub resource_size: u64,
    pub native_size: u64,
    pub asset_size: u64,
    pub version: Option<String>,
    pub git_sha: Option<String>,
}

/// Tracks APK sizes over time in SQLite.
pub struct SizeTracker {
    conn: Connection,
}

impl SizeTracker {
    pub fn open(path: &Path) -> andro_core::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sizes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_size INTEGER NOT NULL,
                dex_size INTEGER NOT NULL,
                resource_size INTEGER NOT NULL,
                native_size INTEGER NOT NULL,
                asset_size INTEGER NOT NULL,
                version TEXT,
                git_sha TEXT,
                recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
        .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;

        Ok(Self { conn })
    }

    /// Record a size report.
    pub fn record(&self, report: &SizeReport) -> andro_core::Result<()> {
        self.conn
            .execute(
                "INSERT INTO sizes (file_size, dex_size, resource_size, native_size, asset_size, version, git_sha)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    report.file_size as i64,
                    report.dex_size as i64,
                    report.resource_size as i64,
                    report.native_size as i64,
                    report.asset_size as i64,
                    report.version,
                    report.git_sha,
                ],
            )
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        Ok(())
    }

    /// Get the last N size reports.
    pub fn history(&self, limit: usize) -> andro_core::Result<Vec<SizeReport>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT file_size, dex_size, resource_size, native_size, asset_size, version, git_sha
                 FROM sizes ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;

        let reports = stmt
            .query_map(params![limit as i64], |row| {
                Ok(SizeReport {
                    file_size: row.get::<_, i64>(0)? as u64,
                    dex_size: row.get::<_, i64>(1)? as u64,
                    resource_size: row.get::<_, i64>(2)? as u64,
                    native_size: row.get::<_, i64>(3)? as u64,
                    asset_size: row.get::<_, i64>(4)? as u64,
                    version: row.get(5)?,
                    git_sha: row.get(6)?,
                })
            })
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(reports)
    }
}
