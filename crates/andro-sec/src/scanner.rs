use crate::rules::SecurityRule;
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
}

impl Default for ApkScanner {
    fn default() -> Self {
        Self::new()
    }
}
