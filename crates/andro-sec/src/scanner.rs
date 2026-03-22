use crate::rules::SecurityRule;
use andro_core::traits::ArchiveReader;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use zip::ZipArchive;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub file: Option<String>,
    pub line: Option<usize>,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub apk_path: String,
    pub findings: Vec<ScanFinding>,
    pub total_files_scanned: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

impl ScanResult {
    pub fn new(apk_path: &str) -> Self {
        Self {
            apk_path: apk_path.to_string(),
            findings: Vec::new(),
            total_files_scanned: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
        }
    }

    pub fn add_finding(&mut self, finding: ScanFinding) {
        match finding.severity {
            Severity::Critical => self.critical_count += 1,
            Severity::High => self.high_count += 1,
            Severity::Medium => self.medium_count += 1,
            Severity::Low => self.low_count += 1,
            Severity::Info => self.info_count += 1,
        }
        self.findings.push(finding);
    }
}

/// Scans APK files for security issues.
pub struct ApkScanner {
    rules: Vec<SecurityRule>,
}

impl ApkScanner {
    pub fn new() -> Self {
        Self {
            rules: SecurityRule::default_rules(),
        }
    }

    pub fn with_rules(rules: Vec<SecurityRule>) -> Self {
        Self { rules }
    }

    /// Scan an APK for security issues.
    pub fn scan(&self, path: &Path) -> andro_core::Result<ScanResult> {
        let mut result = ScanResult::new(&path.display().to_string());

        let file = std::fs::File::open(path)?;
        let mut archive = ZipArchive::new(file)
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)
                .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
            let name = entry.name().to_string();
            result.total_files_scanned += 1;

            // Read text-based files for pattern matching
            if name.ends_with(".xml") || name.ends_with(".json") || name.ends_with(".properties") {
                let mut content = String::new();
                if entry.read_to_string(&mut content).is_ok() {
                    for rule in &self.rules {
                        if let Some(finding) = rule.check(&name, &content) {
                            result.add_finding(finding);
                        }
                    }
                }
            }

            // Check for debug flags
            if name == "AndroidManifest.xml" {
                // Binary XML — can't read directly without decoder
                // Flag as info if no decoder available
                result.add_finding(ScanFinding {
                    rule_id: "MANIFEST_BINARY".into(),
                    severity: Severity::Info,
                    title: "Binary manifest detected".into(),
                    description: "AndroidManifest.xml is in binary format. Full analysis requires AXML decoder.".into(),
                    file: Some(name.clone()),
                    line: None,
                    evidence: None,
                });
            }
        }

        // Sort findings by severity (critical first)
        result.findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        Ok(result)
    }

    /// Scan APK data using a trait-based archive reader.
    ///
    /// Accepts any `ArchiveReader` implementation, enabling mock-based testing
    /// without real ZIP files. Text-based entries (`.xml`, `.json`, `.properties`)
    /// are read via the reader and checked against all rules.
    pub fn scan_with(
        &self,
        label: &str,
        data: &[u8],
        reader: &dyn ArchiveReader,
    ) -> andro_core::Result<ScanResult> {
        let mut result = ScanResult::new(label);
        let entries = reader.list_entries(data)?;

        for entry in &entries {
            let name = &entry.path;
            result.total_files_scanned += 1;

            // Read text-based files for pattern matching
            if name.ends_with(".xml") || name.ends_with(".json") || name.ends_with(".properties") {
                if let Ok(bytes) = reader.read_entry(data, name) {
                    if let Ok(content) = String::from_utf8(bytes) {
                        for rule in &self.rules {
                            if let Some(finding) = rule.check(name, &content) {
                                result.add_finding(finding);
                            }
                        }
                    }
                }
            }

            // Check for binary manifest
            if name == "AndroidManifest.xml" {
                result.add_finding(ScanFinding {
                    rule_id: "MANIFEST_BINARY".into(),
                    severity: Severity::Info,
                    title: "Binary manifest detected".into(),
                    description: "AndroidManifest.xml is in binary format. Full analysis requires AXML decoder.".into(),
                    file: Some(name.clone()),
                    line: None,
                    evidence: None,
                });
            }
        }

        // Sort findings by severity (critical first)
        result.findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        Ok(result)
    }
}

impl Default for ApkScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use andro_core::mocks::MockArchiveReader;

    #[test]
    fn scan_with_detects_aws_key() {
        let reader = MockArchiveReader::new()
            .with_entry("res/values/strings.xml", b"aws_key=AKIAIOSFODNN7EXAMPLE");
        let scanner = ApkScanner::new();
        let result = scanner.scan_with("test.apk", &[], &reader).unwrap();
        assert!(result.findings.iter().any(|f| f.rule_id == "AWS_KEY"));
        assert_eq!(result.critical_count, 1);
    }

    #[test]
    fn scan_with_detects_http_url() {
        let reader = MockArchiveReader::new()
            .with_entry("res/xml/network_config.xml", b"url=http://api.example.com/v1");
        let scanner = ApkScanner::new();
        let result = scanner.scan_with("test.apk", &[], &reader).unwrap();
        assert!(result.findings.iter().any(|f| f.rule_id == "HTTP_URL"));
        assert_eq!(result.medium_count, 1);
    }

    #[test]
    fn scan_with_no_findings_on_clean_apk() {
        let reader = MockArchiveReader::new()
            .with_entry("classes.dex", &[0u8; 64])
            .with_entry("res/layout/main.xml", b"<LinearLayout/>");
        let scanner = ApkScanner::new();
        let result = scanner.scan_with("clean.apk", &[], &reader).unwrap();
        // No critical/high/medium/low findings (only info-level manifest check is absent here)
        assert_eq!(result.critical_count, 0);
        assert_eq!(result.high_count, 0);
        assert_eq!(result.total_files_scanned, 2);
    }

    #[test]
    fn scan_with_manifest_binary_info() {
        let reader = MockArchiveReader::new()
            .with_entry("AndroidManifest.xml", &[0u8; 32]);
        let scanner = ApkScanner::new();
        let result = scanner.scan_with("app.apk", &[], &reader).unwrap();
        assert!(result.findings.iter().any(|f| f.rule_id == "MANIFEST_BINARY"));
        assert_eq!(result.info_count, 1);
    }

    #[test]
    fn scan_with_multiple_findings() {
        let reader = MockArchiveReader::new()
            .with_entry("config.properties",
                b"api_key = \"AKIAIOSFODNN7EXAMPLE\"\nendpoint = http://api.example.com\ndebug = true")
            .with_entry("AndroidManifest.xml", b"<manifest/>");
        let scanner = ApkScanner::new();
        let result = scanner.scan_with("multi.apk", &[], &reader).unwrap();
        // AWS_KEY (critical) + HTTP_URL (medium) + DEBUG_FLAG (medium) + MANIFEST_BINARY (info)
        assert!(result.findings.len() >= 4, "expected >= 4, got {}: {:?}",
            result.findings.len(),
            result.findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>());
        // Findings sorted by severity (critical/high first)
        let severities: Vec<_> = result.findings.iter().map(|f| f.severity).collect();
        for w in severities.windows(2) {
            assert!(w[0] >= w[1]);
        }
    }
}
