use adb_client::ADBDeviceExt;
use adb_client::server::ADBServer;
use andro_core::traits::AdbTransport;
use andro_core::{AndroConfig, AndroError, Result};
use std::io::Write;
use std::net::SocketAddrV4;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
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

// ── AdbClientTransport ───────────────────────────────────────────────

/// Production ADB transport using the `adb_client` crate over TCP.
pub struct AdbClientTransport {
    server_addr: SocketAddrV4,
}

impl AdbClientTransport {
    pub fn new(server_addr: SocketAddrV4) -> Self {
        Self { server_addr }
    }
}

impl AdbTransport for AdbClientTransport {
    fn devices(&mut self) -> Result<Vec<andro_core::DeviceInfo>> {
        let mut server = ADBServer::new(self.server_addr);
        let devices = server
            .devices()
            .map_err(|e| AndroError::Adb(e.to_string()))?;
        Ok(devices
            .into_iter()
            .map(|d| andro_core::DeviceInfo {
                id: andro_core::DeviceId(d.identifier.clone()),
                state: andro_core::DeviceState::Device,
                model: None,
                manufacturer: None,
                android_version: None,
                api_level: None,
                build_fingerprint: None,
                product: None,
                transport_id: None,
            })
            .collect())
    }

    fn shell(&mut self, serial: &str, command: &str) -> Result<andro_core::ShellOutput> {
        let mut server = ADBServer::new(self.server_addr);
        let mut device = server
            .get_device_by_name(serial)
            .map_err(|e| AndroError::Adb(e.to_string()))?;
        let mut stdout = Vec::new();
        let cmd: &str = command;
        let stderr: Option<&mut dyn std::io::Write> = None;
        let exit_code = device
            .shell_command(&cmd, Some(&mut stdout), stderr)
            .map_err(|e| AndroError::Adb(e.to_string()))?;
        Ok(andro_core::ShellOutput {
            device: andro_core::DeviceId(serial.to_string()),
            stdout: String::from_utf8_lossy(&stdout).to_string(),
            exit_code: exit_code.map(i32::from),
        })
    }

    fn push(&mut self, serial: &str, local: &Path, remote: &str) -> Result<u64> {
        let mut server = ADBServer::new(self.server_addr);
        let mut device = server
            .get_device_by_name(serial)
            .map_err(|e| AndroError::Adb(e.to_string()))?;
        let data = std::fs::read(local)?;
        let size = data.len() as u64;
        let mut cursor = std::io::Cursor::new(data);
        device
            .push(&mut cursor, remote)
            .map_err(|e| AndroError::Adb(e.to_string()))?;
        Ok(size)
    }

    fn pull(&mut self, serial: &str, remote: &str, local: &Path) -> Result<u64> {
        let mut server = ADBServer::new(self.server_addr);
        let mut device = server
            .get_device_by_name(serial)
            .map_err(|e| AndroError::Adb(e.to_string()))?;
        let mut output = Vec::new();
        device
            .pull(&remote, &mut output)
            .map_err(|e| AndroError::Adb(e.to_string()))?;
        let size = output.len() as u64;
        if let Some(parent) = local.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::File::create(local)?;
        file.write_all(&output)?;
        Ok(size)
    }

    fn install(&mut self, serial: &str, apk: &Path) -> Result<()> {
        let mut server = ADBServer::new(self.server_addr);
        let mut device = server
            .get_device_by_name(serial)
            .map_err(|e| AndroError::Adb(e.to_string()))?;
        device
            .install(apk, None)
            .map_err(|e| AndroError::Adb(e.to_string()))?;
        Ok(())
    }

    fn reboot(&mut self, serial: &str, _target: andro_core::types::RebootTarget) -> Result<()> {
        let mut server = ADBServer::new(self.server_addr);
        let mut device = server
            .get_device_by_name(serial)
            .map_err(|e| AndroError::Adb(e.to_string()))?;
        let mut out = Vec::new();
        let stderr: Option<&mut dyn std::io::Write> = None;
        device
            .shell_command(&"reboot", Some(&mut out), stderr)
            .map_err(|e| AndroError::Adb(e.to_string()))?;
        Ok(())
    }
}

// ── FileSyncer ───────────────────────────────────────────────────────

/// File synchronization over ADB.
///
/// Generic over `T: AdbTransport` for testability. Use `from_config` for the
/// production path (`AdbClientTransport`), or `new` with a mock transport
/// for testing.
///
/// Transport is wrapped in a `Mutex` so push/pull methods keep `&self`,
/// preserving backward compatibility with existing callers.
pub struct FileSyncer<T: AdbTransport> {
    transport: Mutex<T>,
    manifest_dir: PathBuf,
}

impl FileSyncer<AdbClientTransport> {
    /// Create a `FileSyncer` using the production ADB transport, configured
    /// from the standard `AndroConfig`.
    pub fn from_config(config: &AndroConfig) -> Self {
        let manifest_dir = config.sync.backup_dir.join(".manifests");
        Self {
            transport: Mutex::new(AdbClientTransport::new(config.server_addr())),
            manifest_dir,
        }
    }
}

impl<T: AdbTransport> FileSyncer<T> {
    /// Create a `FileSyncer` with any `AdbTransport` implementation.
    ///
    /// Primarily for testing with `MockAdbTransport`.
    pub fn new(transport: T, manifest_dir: PathBuf) -> Self {
        Self {
            transport: Mutex::new(transport),
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
        let mut transport = self
            .transport
            .lock()
            .map_err(|e| AndroError::Other(e.to_string()))?;
        let size = transport.push(device_serial, local_path, remote_path)?;

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
        let mut transport = self
            .transport
            .lock()
            .map_err(|e| AndroError::Other(e.to_string()))?;
        let size = transport.pull(device_serial, remote_path, local_path)?;
        drop(transport); // release lock before file I/O for manifest

        // Record in manifest — read back the file for hashing
        if let Ok(data) = std::fs::read(local_path) {
            let hash = blake3::hash(&data);
            let manifest_path = self.manifest_dir.join("sync.json");
            let mut manifest = Manifest::load(&manifest_path);
            manifest.record(remote_path, &local_path.display().to_string(), hash, size);
            let _ = manifest.save(&manifest_path);
        }

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
    use andro_core::mocks::MockAdbTransport;

    fn temp_manifest_dir() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "andro_sync_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

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

    #[test]
    fn push_file_with_mock_transport() {
        let transport = MockAdbTransport::new()
            .with_device("ABC123", "Pixel 7");
        let dir = temp_manifest_dir();
        let syncer = FileSyncer::new(transport, dir.clone());

        // Create a temp file to push
        let tmp = dir.join("test_push.txt");
        std::fs::write(&tmp, b"push data").unwrap();

        let bytes = syncer.push_file("ABC123", &tmp, "/sdcard/test.txt").unwrap();
        assert_eq!(bytes, 1024); // MockAdbTransport returns 1024
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pull_file_with_mock_transport() {
        let transport = MockAdbTransport::new()
            .with_device("ABC123", "Pixel 7");
        let dir = temp_manifest_dir();
        let syncer = FileSyncer::new(transport, dir.clone());

        let local = dir.join("pulled.txt");
        let bytes = syncer.pull_file("ABC123", "/sdcard/photo.jpg", &local).unwrap();
        assert_eq!(bytes, 1024); // MockAdbTransport returns 1024
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new_constructor_accepts_mock() {
        let transport = MockAdbTransport::new();
        let dir = temp_manifest_dir();
        let syncer = FileSyncer::new(transport, dir.clone());
        // Verify the struct can be constructed without panicking
        assert!(syncer.manifest_dir.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn push_uses_transport_trait() {
        let transport = MockAdbTransport::new()
            .with_device("DEV1", "Test Device");
        let dir = temp_manifest_dir();
        let syncer = FileSyncer::new(transport, dir.clone());

        let tmp = dir.join("data.bin");
        std::fs::write(&tmp, &[0xAB; 256]).unwrap();

        // Mock always returns 1024 regardless of actual file size
        let result = syncer.push_file("DEV1", &tmp, "/data/local/tmp/data.bin");
        assert!(result.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn methods_take_shared_ref() {
        // Verify push_file and pull_file take &self (not &mut self)
        // by calling through a shared reference.
        let transport = MockAdbTransport::new();
        let dir = temp_manifest_dir();
        let syncer = FileSyncer::new(transport, dir.clone());
        let shared: &FileSyncer<MockAdbTransport> = &syncer;

        let tmp = dir.join("shared_ref_test.txt");
        std::fs::write(&tmp, b"data").unwrap();
        let _ = shared.push_file("x", &tmp, "/sdcard/x");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
