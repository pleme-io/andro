use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

/// Android log level.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum LogLevel {
    Verbose,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
    Silent,
}

impl LogLevel {
    pub fn from_char(c: char) -> Self {
        match c {
            'V' => Self::Verbose,
            'D' => Self::Debug,
            'I' => Self::Info,
            'W' => Self::Warn,
            'E' => Self::Error,
            'F' => Self::Fatal,
            'S' => Self::Silent,
            _ => Self::Verbose,
        }
    }

    pub fn as_char(self) -> char {
        match self {
            Self::Verbose => 'V',
            Self::Debug => 'D',
            Self::Info => 'I',
            Self::Warn => 'W',
            Self::Error => 'E',
            Self::Fatal => 'F',
            Self::Silent => 'S',
        }
    }
}

/// A parsed logcat line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: Option<NaiveDateTime>,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub level: LogLevel,
    pub tag: String,
    pub message: String,
    pub raw: String,
}

/// Parses logcat output in threadtime format.
pub struct LogParser;

impl LogParser {
    /// Parse a single logcat line in threadtime format:
    /// `MM-DD HH:MM:SS.mmm  PID  TID LEVEL TAG: MESSAGE`
    pub fn parse_line(line: &str) -> Option<LogEntry> {
        let raw = line.to_string();

        // Minimum: "01-01 00:00:00.000  1234  5678 D Tag: msg"
        if line.len() < 33 {
            return Some(LogEntry {
                timestamp: None,
                pid: None,
                tid: None,
                level: LogLevel::Verbose,
                tag: String::new(),
                message: line.to_string(),
                raw,
            });
        }

        // Parse timestamp: MM-DD HH:MM:SS.mmm
        let date_str = &line[..18];
        let year = chrono::Utc::now().format("%Y").to_string();
        let timestamp = NaiveDateTime::parse_from_str(
            &format!("{year}-{date_str}"),
            "%Y-%m-%d %H:%M:%S%.3f",
        )
        .ok();

        // Parse PID, TID, level — fields are whitespace-separated
        let rest = &line[18..];
        let tokens: Vec<&str> = rest.split_whitespace().collect();
        let parts = tokens;
        if parts.len() < 4 {
            return Some(LogEntry {
                timestamp,
                pid: None,
                tid: None,
                level: LogLevel::Verbose,
                tag: String::new(),
                message: rest.to_string(),
                raw,
            });
        }

        let pid = parts[0].parse().ok();
        let tid = parts[1].parse().ok();
        let level = parts[2]
            .chars()
            .next()
            .map(LogLevel::from_char)
            .unwrap_or(LogLevel::Verbose);

        // Rejoin remaining parts as "tag: message"
        let tag_msg = parts[3..].join(" ");
        let (tag, message) = if let Some(colon_pos) = tag_msg.find(": ") {
            (
                tag_msg[..colon_pos].to_string(),
                tag_msg[colon_pos + 2..].to_string(),
            )
        } else {
            (tag_msg.clone(), String::new())
        };

        Some(LogEntry {
            timestamp,
            pid,
            tid,
            level,
            tag,
            message,
            raw,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_threadtime_line() {
        let line = "03-22 14:30:45.123  1234  5678 D MyApp: Hello world";
        let entry = LogParser::parse_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Debug);
        assert_eq!(entry.tag, "MyApp");
        assert_eq!(entry.message, "Hello world");
        assert_eq!(entry.pid, Some(1234));
        assert_eq!(entry.tid, Some(5678));
    }

    #[test]
    fn parse_error_level() {
        let line = "03-22 14:30:45.123  1234  5678 E CrashTag: FATAL EXCEPTION";
        let entry = LogParser::parse_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Error);
        assert_eq!(entry.tag, "CrashTag");
    }

    #[test]
    fn level_roundtrip() {
        for c in ['V', 'D', 'I', 'W', 'E', 'F', 'S'] {
            let level = LogLevel::from_char(c);
            assert_eq!(level.as_char(), c);
        }
    }
}
