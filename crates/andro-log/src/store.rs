use crate::parser::LogEntry;
use andro_core::Result;
use rusqlite::{Connection, params};
use std::path::Path;

/// SQLite-backed log storage with FTS5 full-text search.
pub struct LogStore {
    conn: Connection,
}

impl LogStore {
    /// Open or create log database at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                pid INTEGER,
                tid INTEGER,
                level TEXT NOT NULL,
                tag TEXT NOT NULL,
                message TEXT NOT NULL,
                raw TEXT NOT NULL,
                inserted_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(
                tag, message, content=logs, content_rowid=id
            );

            CREATE TRIGGER IF NOT EXISTS logs_ai AFTER INSERT ON logs BEGIN
                INSERT INTO logs_fts(rowid, tag, message) VALUES (new.id, new.tag, new.message);
            END;

            CREATE INDEX IF NOT EXISTS idx_logs_tag ON logs(tag);
            CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level);
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);",
        )
        .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;

        Ok(Self { conn })
    }

    /// Insert a log entry.
    pub fn insert(&self, entry: &LogEntry) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO logs (timestamp, pid, tid, level, tag, message, raw)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    entry.timestamp.map(|t| t.to_string()),
                    entry.pid,
                    entry.tid,
                    entry.level.as_char().to_string(),
                    entry.tag,
                    entry.message,
                    entry.raw,
                ],
            )
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        Ok(())
    }

    /// Full-text search across tag and message.
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<LogEntry>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT l.timestamp, l.pid, l.tid, l.level, l.tag, l.message, l.raw
                 FROM logs_fts f
                 JOIN logs l ON f.rowid = l.id
                 WHERE logs_fts MATCH ?1
                 ORDER BY l.id DESC
                 LIMIT ?2",
            )
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;

        let entries = stmt
            .query_map(params![query, limit as i64], |row| {
                let ts_str: Option<String> = row.get(0)?;
                let level_str: String = row.get(3)?;
                Ok(LogEntry {
                    timestamp: ts_str.and_then(|s| {
                        chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S%.f").ok()
                    }),
                    pid: row.get(1)?,
                    tid: row.get(2)?,
                    level: crate::parser::LogLevel::from_char(
                        level_str.chars().next().unwrap_or('V'),
                    ),
                    tag: row.get(4)?,
                    message: row.get(5)?,
                    raw: row.get(6)?,
                })
            })
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(entries)
    }

    /// Count total log entries.
    pub fn count(&self) -> Result<u64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM logs", [], |row| row.get(0))
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        Ok(count as u64)
    }

    /// Prune entries older than N days.
    pub fn prune(&self, retention_days: u32) -> Result<u64> {
        let deleted = self
            .conn
            .execute(
                "DELETE FROM logs WHERE inserted_at < datetime('now', ?1)",
                params![format!("-{retention_days} days")],
            )
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        Ok(deleted as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{LogLevel, LogParser};
    use std::path::PathBuf;

    fn temp_db() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "andro_log_test_{}_{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        path
    }

    #[test]
    fn insert_and_search() {
        let db_path = temp_db();
        let store = LogStore::open(&db_path).unwrap();

        let entry = LogParser::parse_line("03-22 14:30:45.123  1234  5678 E AndroidRuntime: FATAL EXCEPTION: main").unwrap();
        store.insert(&entry).unwrap();

        let results = store.search("FATAL", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tag, "AndroidRuntime");

        let count = store.count().unwrap();
        assert_eq!(count, 1);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn empty_search() {
        let db_path = temp_db();
        let store = LogStore::open(&db_path).unwrap();

        let results = store.search("nonexistent", 10).unwrap();
        assert!(results.is_empty());

        let _ = std::fs::remove_file(&db_path);
    }
}
