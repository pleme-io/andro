use adb_client::ADBDeviceExt;
use adb_client::server::ADBServer;
use andro_core::{AndroConfig, AndroError, Result};
use std::io::Write;
use std::net::SocketAddrV4;
use std::path::{Path, PathBuf};
use tracing::info;

use fudajiku::Manifest;

#[derive(Debug, Clone)]
pub enum SyncDirection {
    Push,
    Pull,
}

#[derive(Debug, Clone)]
pub struct SyncOptions {
    pub direction: SyncDirection,
    pub source: String,
    pub destination: String,
    pub device: Option<String>,
    pub exclude: Vec<String>,
    pub incremental: bool,
    pub delete: bool,
}

#[derive(Debug, Clone)]
pub struct SyncResult {
    pub files_transferred: usize,
    pub files_skipped: usize,
    pub bytes_transferred: u64,
}

pub struct FileSyncer {
    server_addr: SocketAddrV4,
    manifest_dir: PathBuf,
}

impl FileSyncer {
    pub fn from_config(config: &AndroConfig) -> Self {
        let manifest_dir = config.sync.backup_dir.join(".manifests");
        Self {
            server_addr: config.server_addr(),
            manifest_dir,
        }
    }

    /// Push a local file to the device.
    pub fn push_file(
        &self,
        device_serial: &str,
        local_path: &Path,
        remote_path: &str,
    ) -> Result<u64> {
        let mut server = ADBServer::new(self.server_addr);
        let mut device = server
            .get_device_by_name(device_serial)
            .map_err(|e| AndroError::Adb(e.to_string()))?;

        let data = std::fs::read(local_path)?;
        let size = data.len() as u64;
        let mut cursor = std::io::Cursor::new(data);

        device
            .push(&mut cursor, &remote_path)
            .map_err(|e| AndroError::Adb(e.to_string()))?;

        info!(
            file = %local_path.display(),
            remote = remote_path,
            bytes = size,
            "pushed"
        );

        Ok(size)
    }

    /// Pull a remote file from the device.
    pub fn pull_file(
        &self,
        device_serial: &str,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<u64> {
        let mut server = ADBServer::new(self.server_addr);
        let mut device = server
            .get_device_by_name(device_serial)
            .map_err(|e| AndroError::Adb(e.to_string()))?;

        let mut output = Vec::new();
        device
            .pull(&remote_path, &mut output)
            .map_err(|e| AndroError::Adb(e.to_string()))?;

        let size = output.len() as u64;

        if let Some(parent) = local_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::File::create(local_path)?;
        file.write_all(&output)?;

        // Record in manifest
        let hash = blake3::hash(&output);
        let manifest_path = self.manifest_dir.join("sync.json");
        let mut manifest = Manifest::load(&manifest_path);
        manifest.record(remote_path, &local_path.display().to_string(), hash, size);
        let _ = manifest.save(&manifest_path);

        info!(
            remote = remote_path,
            file = %local_path.display(),
            bytes = size,
            "pulled"
        );

        Ok(size)
    }

    /// Hash a local file with BLAKE3.
    pub fn hash_file(path: &Path) -> Result<blake3::Hash> {
        let data = std::fs::read(path)?;
        Ok(blake3::hash(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_options_default() {
        let opts = SyncOptions {
            direction: SyncDirection::Push,
            source: "/local/file".into(),
            destination: "/sdcard/file".into(),
            device: None,
            exclude: vec![],
            incremental: false,
            delete: false,
        };
        assert!(opts.exclude.is_empty());
    }

    #[test]
    fn hash_consistency() {
        let data = b"hello android";
        let h1 = blake3::hash(data);
        let h2 = blake3::hash(data);
        assert_eq!(h1, h2);
    }
}
