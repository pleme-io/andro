use serde::{Deserialize, Serialize};
use std::path::Path;
use zip::ZipArchive;

/// Parsed APK metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkInfo {
    pub file_size: u64,
    pub entry_count: usize,
    pub dex_count: usize,
    pub dex_total_size: u64,
    pub resource_size: u64,
    pub native_lib_size: u64,
    pub asset_size: u64,
    pub signature_size: u64,
    pub has_manifest: bool,
    pub native_abis: Vec<String>,
    pub dex_files: Vec<DexFileInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexFileInfo {
    pub name: String,
    pub size: u64,
}

/// Diff between two APKs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkDiff {
    pub base_size: u64,
    pub target_size: u64,
    pub size_delta: i64,
    pub size_percent: f64,
    pub dex_delta: i64,
    pub resource_delta: i64,
    pub native_delta: i64,
    pub added_entries: Vec<String>,
    pub removed_entries: Vec<String>,
}

/// Analyzes APK/AAB files (which are ZIP archives).
pub struct ApkAnalyzer;

impl ApkAnalyzer {
    /// Analyze an APK file and return structured info.
    pub fn analyze(path: &Path) -> andro_core::Result<ApkInfo> {
        let file = std::fs::File::open(path)?;
        let file_size = file.metadata()?.len();
        let mut archive = ZipArchive::new(file)
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;

        let entry_count = archive.len();
        let mut dex_count = 0;
        let mut dex_total_size = 0u64;
        let mut resource_size = 0u64;
        let mut native_lib_size = 0u64;
        let mut asset_size = 0u64;
        let mut signature_size = 0u64;
        let mut has_manifest = false;
        let mut native_abis = std::collections::HashSet::new();
        let mut dex_files = Vec::new();

        for i in 0..archive.len() {
            let entry = archive.by_index(i)
                .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
            let name = entry.name().to_string();
            let size = entry.size();

            if name.ends_with(".dex") {
                dex_count += 1;
                dex_total_size += size;
                dex_files.push(DexFileInfo {
                    name: name.clone(),
                    size,
                });
            } else if name.starts_with("res/") || name == "resources.arsc" {
                resource_size += size;
            } else if name.starts_with("lib/") {
                native_lib_size += size;
                // Extract ABI from lib/<abi>/libname.so
                let parts: Vec<&str> = name.split('/').collect();
                if parts.len() >= 2 {
                    native_abis.insert(parts[1].to_string());
                }
            } else if name.starts_with("assets/") {
                asset_size += size;
            } else if name.starts_with("META-INF/") {
                signature_size += size;
            }

            if name == "AndroidManifest.xml" {
                has_manifest = true;
            }
        }

        Ok(ApkInfo {
            file_size,
            entry_count,
            dex_count,
            dex_total_size,
            resource_size,
            native_lib_size,
            asset_size,
            signature_size,
            has_manifest,
            native_abis: native_abis.into_iter().collect(),
            dex_files,
        })
    }

    /// Diff two APK files.
    pub fn diff(base_path: &Path, target_path: &Path) -> andro_core::Result<ApkDiff> {
        let base = Self::analyze(base_path)?;
        let target = Self::analyze(target_path)?;

        let base_entries = Self::entry_names(base_path)?;
        let target_entries = Self::entry_names(target_path)?;

        let added: Vec<String> = target_entries
            .iter()
            .filter(|e| !base_entries.contains(e.as_str()))
            .cloned()
            .collect();
        let removed: Vec<String> = base_entries
            .iter()
            .filter(|e| !target_entries.contains(e.as_str()))
            .cloned()
            .collect();

        let size_delta = target.file_size as i64 - base.file_size as i64;
        let size_percent = if base.file_size > 0 {
            (size_delta as f64 / base.file_size as f64) * 100.0
        } else {
            0.0
        };

        Ok(ApkDiff {
            base_size: base.file_size,
            target_size: target.file_size,
            size_delta,
            size_percent,
            dex_delta: target.dex_total_size as i64 - base.dex_total_size as i64,
            resource_delta: target.resource_size as i64 - base.resource_size as i64,
            native_delta: target.native_lib_size as i64 - base.native_lib_size as i64,
            added_entries: added,
            removed_entries: removed,
        })
    }

    fn entry_names(path: &Path) -> andro_core::Result<std::collections::HashSet<String>> {
        let file = std::fs::File::open(path)?;
        let mut archive = ZipArchive::new(file)
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        let mut names = std::collections::HashSet::new();
        for i in 0..archive.len() {
            let entry = archive.by_index(i)
                .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
            names.insert(entry.name().to_string());
        }
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apk_info_defaults() {
        let info = ApkInfo {
            file_size: 1024,
            entry_count: 10,
            dex_count: 1,
            dex_total_size: 512,
            resource_size: 256,
            native_lib_size: 0,
            asset_size: 128,
            signature_size: 64,
            has_manifest: true,
            native_abis: vec![],
            dex_files: vec![DexFileInfo { name: "classes.dex".into(), size: 512 }],
        };
        assert!(info.has_manifest);
        assert_eq!(info.dex_count, 1);
    }
}
