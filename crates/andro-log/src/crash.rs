use crate::parser::{LogEntry, LogLevel};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

static FATAL_EXCEPTION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"FATAL EXCEPTION: (.+)").unwrap());

static ANR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"ANR in (.+?) \((.+?)\)").unwrap());

/// Extracted crash report from logcat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReport {
    pub thread: String,
    pub exception: String,
    pub stacktrace: Vec<String>,
    pub pid: Option<u32>,
    pub tag: String,
}

/// Extracted ANR report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnrReport {
    pub process: String,
    pub reason: String,
    pub pid: Option<u32>,
}

/// Detects crashes and ANRs in log entry streams.
pub struct CrashDetector {
    buffer: Vec<LogEntry>,
    in_crash: bool,
}

impl CrashDetector {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            in_crash: false,
        }
    }

    /// Process a log entry. Returns a crash report if one is completed.
    pub fn feed(&mut self, entry: &LogEntry) -> Option<CrashReport> {
        // Detect start of crash
        if entry.level >= LogLevel::Error && FATAL_EXCEPTION_RE.is_match(&entry.message) {
            self.in_crash = true;
            self.buffer.clear();
            self.buffer.push(entry.clone());
            return None;
        }

        // Accumulate crash stacktrace
        if self.in_crash {
            if entry.tag == "AndroidRuntime" || entry.message.starts_with("\tat ") || entry.message.starts_with("at ") || entry.message.starts_with("Caused by:") {
                self.buffer.push(entry.clone());
                return None;
            }
            // Crash ended — emit report
            self.in_crash = false;
            return self.extract_crash();
        }

        None
    }

    /// Check if a log entry indicates an ANR.
    pub fn detect_anr(entry: &LogEntry) -> Option<AnrReport> {
        if let Some(caps) = ANR_RE.captures(&entry.message) {
            let process = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
            let reason = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();
            return Some(AnrReport {
                process,
                reason,
                pid: entry.pid,
            });
        }
        None
    }

    fn extract_crash(&self) -> Option<CrashReport> {
        if self.buffer.is_empty() {
            return None;
        }

        let first = &self.buffer[0];
        let thread = FATAL_EXCEPTION_RE
            .captures(&first.message)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "main".to_string());

        let exception = self
            .buffer
            .iter()
            .find(|e| !e.message.starts_with("FATAL") && !e.message.starts_with("\tat "))
            .map(|e| e.message.clone())
            .unwrap_or_default();

        let stacktrace: Vec<String> = self
            .buffer
            .iter()
            .filter(|e| {
                e.message.starts_with("\tat ")
                    || e.message.starts_with("at ")
                    || e.message.starts_with("Caused by:")
            })
            .map(|e| e.message.clone())
            .collect();

        Some(CrashReport {
            thread,
            exception,
            stacktrace,
            pid: first.pid,
            tag: first.tag.clone(),
        })
    }
}

impl Default for CrashDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::LogParser;

    #[test]
    fn detect_fatal_exception() {
        let mut detector = CrashDetector::new();
        let e1 = LogParser::parse_line("03-22 14:30:45.123  1234  5678 E AndroidRuntime: FATAL EXCEPTION: main").unwrap();
        let e2 = LogParser::parse_line("03-22 14:30:45.124  1234  5678 E AndroidRuntime: java.lang.NullPointerException").unwrap();
        let e3 = LogParser::parse_line("03-22 14:30:45.125  1234  5678 E AndroidRuntime: at com.example.MyClass.method(MyClass.java:42)").unwrap();
        let e4 = LogParser::parse_line("03-22 14:30:45.200  1234  5678 I SomeOther: unrelated log").unwrap();

        assert!(detector.feed(&e1).is_none());
        assert!(detector.feed(&e2).is_none());
        assert!(detector.feed(&e3).is_none());

        let crash = detector.feed(&e4);
        assert!(crash.is_some());
        let crash = crash.unwrap();
        assert_eq!(crash.thread, "main");
        assert!(!crash.stacktrace.is_empty());
    }

    #[test]
    fn detect_anr() {
        let entry = LogParser::parse_line("03-22 14:30:45.123  1234  5678 E ActivityManager: ANR in com.example.app (com.example.app/.MainActivity)").unwrap();
        let anr = CrashDetector::detect_anr(&entry);
        assert!(anr.is_some());
        let anr = anr.unwrap();
        assert_eq!(anr.process, "com.example.app");
    }
}
