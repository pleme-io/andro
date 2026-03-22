use andro_core::traits::ArchiveReader;
use andro_core::types::ArchiveEntry;
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

// ── ZipArchiveReader ─────────────────────────────────────────────────

/// Production `ArchiveReader` backed by the `zip` crate.
pub struct ZipArchiveReader;

impl ArchiveReader for ZipArchiveReader {
    fn list_entries(&self, data: &[u8]) -> andro_core::Result<Vec<ArchiveEntry>> {
        let cursor = std::io::Cursor::new(data);
        let mut archive = ZipArchive::new(cursor)
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        let mut entries = Vec::with_capacity(archive.len());
        for i in 0..archive.len() {
            let entry = archive
                .by_index(i)
                .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
            entries.push(ArchiveEntry {
                path: entry.name().to_string(),
                size: entry.size(),
                compressed_size: entry.compressed_size(),
                is_dir: entry.is_dir(),
            });
        }
        Ok(entries)
    }

    fn read_entry(&self, data: &[u8], path: &str) -> andro_core::Result<Vec<u8>> {
        let cursor = std::io::Cursor::new(data);
        let mut archive = ZipArchive::new(cursor)
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        let mut entry = archive
            .by_name(path)
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        let mut buf = Vec::with_capacity(entry.size() as usize);
        std::io::Read::read_to_end(&mut entry, &mut buf)?;
        Ok(buf)
    }

    fn entry_metadata(
        &self,
        data: &[u8],
        path: &str,
    ) -> andro_core::Result<andro_core::types::EntryMetadata> {
        let cursor = std::io::Cursor::new(data);
        let mut archive = ZipArchive::new(cursor)
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        let entry = archive
            .by_name(path)
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        Ok(andro_core::types::EntryMetadata {
            path: entry.name().to_string(),
            size: entry.size(),
            compressed_size: entry.compressed_size(),
            crc32: entry.crc32(),
            #[allow(deprecated)]
            compression_method: entry.compression().to_u16(),
        })
    }
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

    /// Analyze APK data using a trait-based archive reader.
    ///
    /// Accepts any `ArchiveReader` implementation, enabling mock-based testing
    /// without real ZIP files.
    pub fn analyze_with(
        data: &[u8],
        data_len: u64,
        reader: &dyn ArchiveReader,
    ) -> andro_core::Result<ApkInfo> {
        let entries = reader.list_entries(data)?;
        let entry_count = entries.len();
        let mut dex_count = 0;
        let mut dex_total_size = 0u64;
        let mut resource_size = 0u64;
        let mut native_lib_size = 0u64;
        let mut asset_size = 0u64;
        let mut signature_size = 0u64;
        let mut has_manifest = false;
        let mut native_abis = std::collections::HashSet::new();
        let mut dex_files = Vec::new();

        for entry in &entries {
            let name = &entry.path;
            let size = entry.size;

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
            file_size: data_len,
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
    use andro_core::mocks::MockArchiveReader;

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

    #[test]
    fn analyze_with_mock_counts_dex_files() {
        let reader = MockArchiveReader::new()
            .with_entry("classes.dex", &[0u8; 512])
            .with_entry("classes2.dex", &[0u8; 256])
            .with_entry("AndroidManifest.xml", b"<manifest/>");
        let info = ApkAnalyzer::analyze_with(&[], 1024, &reader).unwrap();
        assert_eq!(info.dex_count, 2);
        assert_eq!(info.dex_total_size, 768);
        assert!(info.has_manifest);
        assert_eq!(info.entry_count, 3);
        assert_eq!(info.file_size, 1024);
    }

    #[test]
    fn analyze_with_mock_categorizes_entries() {
        let reader = MockArchiveReader::new()
            .with_entry("classes.dex", &[0u8; 100])
            .with_entry("res/layout/main.xml", &[0u8; 200])
            .with_entry("resources.arsc", &[0u8; 300])
            .with_entry("lib/arm64-v8a/libnative.so", &[0u8; 400])
            .with_entry("lib/armeabi-v7a/libnative.so", &[0u8; 350])
            .with_entry("assets/data.bin", &[0u8; 150])
            .with_entry("META-INF/CERT.SF", &[0u8; 50]);
        let info = ApkAnalyzer::analyze_with(&[], 2000, &reader).unwrap();
        assert_eq!(info.dex_count, 1);
        assert_eq!(info.resource_size, 500); // res + resources.arsc
        assert_eq!(info.native_lib_size, 750);
        assert_eq!(info.asset_size, 150);
        assert_eq!(info.signature_size, 50);
        assert_eq!(info.native_abis.len(), 2);
    }

    #[test]
    fn analyze_with_empty_archive() {
        let reader = MockArchiveReader::new();
        let info = ApkAnalyzer::analyze_with(&[], 0, &reader).unwrap();
        assert_eq!(info.entry_count, 0);
        assert_eq!(info.dex_count, 0);
        assert!(!info.has_manifest);
    }

    #[test]
    fn analyze_with_no_manifest() {
        let reader = MockArchiveReader::new()
            .with_entry("classes.dex", &[0u8; 64]);
        let info = ApkAnalyzer::analyze_with(&[], 64, &reader).unwrap();
        assert!(!info.has_manifest);
    }

    #[test]
    fn zip_archive_reader_implements_trait() {
        // Verify ZipArchiveReader is Send + Sync (required by trait)
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ZipArchiveReader>();
    }
}
