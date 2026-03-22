use crate::parser::LogEntry;
use andro_core::traits::StorageBackend;
use andro_core::types::Row;
use andro_core::Result;
use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;

// ── Schema SQL ──────────────────────────────────────────────────────

const SCHEMA_SQL: &str = "CREATE TABLE IF NOT EXISTS logs (
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
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);";

// ── SqliteBackend ───────────────────────────────────────────────────

/// Production `StorageBackend` backed by `rusqlite`.
///
/// Wraps `Connection` in a `Mutex` to satisfy `Send + Sync` required by
/// the `StorageBackend` trait.
pub struct SqliteBackend {
    conn: Mutex<Connection>,
}

impl SqliteBackend {
    /// Open or create the SQLite database and apply the schema.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        conn.execute_batch(SCHEMA_SQL)
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        Ok(Self { conn: Mutex::new(conn) })
    }
}

impl StorageBackend for SqliteBackend {
    fn execute(&self, sql: &str, params: &[&str]) -> Result<usize> {
        let conn = self.conn.lock()
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        let p: Vec<&dyn rusqlite::types::ToSql> = params
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let count = conn
            .execute(sql, p.as_slice())
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        Ok(count)
    }

    fn execute_batch(&self, sql: &str) -> Result<()> {
        let conn = self.conn.lock()
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        conn.execute_batch(sql)
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        Ok(())
    }

    fn query_rows(&self, sql: &str, params: &[&str]) -> Result<Vec<Row>> {
        let conn = self.conn.lock()
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        let p: Vec<&dyn rusqlite::types::ToSql> = params
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        let col_names: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();
        let rows = stmt
            .query_map(p.as_slice(), |row| {
                let mut values = std::collections::HashMap::new();
                for (i, name) in col_names.iter().enumerate() {
                    let val: rusqlite::Result<String> = row.get(i);
                    let json_val = match val {
                        Ok(s) => serde_json::Value::String(s),
                        Err(_) => serde_json::Value::Null,
                    };
                    values.insert(name.clone(), json_val);
                }
                Ok(Row { values })
            })
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    fn count(&self, table: &str) -> Result<u64> {
        let conn = self.conn.lock()
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        let sql = format!("SELECT COUNT(*) FROM {table}");
        let count: i64 = conn
            .query_row(&sql, [], |row| row.get(0))
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        Ok(count as u64)
    }

    fn prune(&self, table: &str, ts_col: &str, days: u32) -> Result<u64> {
        let conn = self.conn.lock()
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        let sql = format!("DELETE FROM {table} WHERE {ts_col} < datetime('now', ?1)");
        let deleted = conn
            .execute(&sql, params![format!("-{days} days")])
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        Ok(deleted as u64)
    }
}

// ── LogStore ────────────────────────────────────────────────────────

/// SQLite-backed log storage with FTS5 full-text search.
///
/// Uses `SqliteBackend` by default. For testing, construct via
/// `new_with_backend()` with a `MockStorageBackend`.
pub struct LogStore {
    conn: Connection,
}

impl LogStore {
    /// Open or create log database at the given path.
    ///
    /// This is the standard production constructor using direct SQLite access
    /// for optimal query performance (FTS5, typed params).
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;

        conn.execute_batch(SCHEMA_SQL)
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

// ── Backend-aware LogStore ──────────────────────────────────────────

/// A `LogStore` variant that delegates storage to a `StorageBackend` trait
/// object. Use this for testing with `MockStorageBackend`.
pub struct BackendLogStore {
    backend: Box<dyn StorageBackend>,
}

impl BackendLogStore {
    /// Create a log store backed by any `StorageBackend`.
    ///
    /// For production, pass a `SqliteBackend`. For testing, pass a
    /// `MockStorageBackend`.
    pub fn new_with_backend(backend: Box<dyn StorageBackend>) -> Result<Self> {
        backend.execute_batch(SCHEMA_SQL)?;
        Ok(Self { backend })
    }

    /// Insert a log entry via the backend.
    pub fn insert(&self, entry: &LogEntry) -> Result<()> {
        let ts = entry.timestamp.map(|t| t.to_string()).unwrap_or_default();
        let pid = entry.pid.map(|p| p.to_string()).unwrap_or_default();
        let tid = entry.tid.map(|t| t.to_string()).unwrap_or_default();
        let level = entry.level.as_char().to_string();
        self.backend.execute(
            "INSERT INTO logs (timestamp, pid, tid, level, tag, message, raw) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[&ts, &pid, &tid, &level, &entry.tag, &entry.message, &entry.raw],
        )?;
        Ok(())
    }

    /// Count total log entries via the backend.
    pub fn count(&self) -> Result<u64> {
        self.backend.count("logs")
    }

    /// Prune entries older than N days via the backend.
    pub fn prune(&self, retention_days: u32) -> Result<u64> {
        self.backend.prune("logs", "inserted_at", retention_days)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{LogLevel, LogParser};
    use andro_core::mocks::MockStorageBackend;
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

    // ── Backend-based tests ─────────────────────────────────────────

    #[test]
    fn backend_log_store_insert_with_mock() {
        let backend = MockStorageBackend::new();
        let store = BackendLogStore::new_with_backend(Box::new(backend)).unwrap();

        let entry = LogEntry {
            timestamp: None,
            pid: Some(1234),
            tid: Some(5678),
            level: LogLevel::Error,
            tag: "TestTag".to_string(),
            message: "test message".to_string(),
            raw: "raw line".to_string(),
        };
        // MockStorageBackend always returns Ok(1) for execute
        assert!(store.insert(&entry).is_ok());
    }

    #[test]
    fn backend_log_store_count_with_mock() {
        let backend = MockStorageBackend::new();
        let store = BackendLogStore::new_with_backend(Box::new(backend)).unwrap();
        // MockStorageBackend always returns 0 for count
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn backend_log_store_prune_with_mock() {
        let backend = MockStorageBackend::new();
        let store = BackendLogStore::new_with_backend(Box::new(backend)).unwrap();
        // MockStorageBackend always returns 0 for prune
        let pruned = store.prune(30).unwrap();
        assert_eq!(pruned, 0);
    }

    #[test]
    fn sqlite_backend_implements_trait() {
        // Verify SqliteBackend is Send + Sync (required by trait)
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SqliteBackend>();
    }

    #[test]
    fn sqlite_backend_open_and_count() {
        let db_path = temp_db();
        let backend = SqliteBackend::open(&db_path).unwrap();
        let count = backend.count("logs").unwrap();
        assert_eq!(count, 0);
        let _ = std::fs::remove_file(&db_path);
    }
}
