use adb_client::ADBDeviceExt;
use adb_client::server::ADBServer;
use andro_core::traits::AdbTransport;
use andro_core::types::RebootTarget;
use andro_core::{AndroConfig, AndroError, DeviceId, DeviceInfo, DeviceState, Result, ShellOutput};
use serde::{Deserialize, Serialize};
use std::net::SocketAddrV4;
use std::path::Path;

// ── Real ADB transport (wraps adb_client) ──────────────────────────────

/// Concrete ADB transport using adb_client over TCP.
pub struct AdbClientTransport {
    server_addr: SocketAddrV4,
}

impl AdbClientTransport {
    pub fn from_config(config: &AndroConfig) -> Self {
        Self {
            server_addr: config.server_addr(),
        }
    }

    fn server(&self) -> ADBServer {
        ADBServer::new(self.server_addr)
    }

    fn get_device_serial(&mut self, serial: Option<&str>) -> Result<String> {
        match serial {
            Some(s) => Ok(s.to_string()),
            None => {
                let devices = self.devices()?;
                match devices.len() {
                    0 => Err(AndroError::NoDevices),
                    1 => Ok(devices[0].id.0.clone()),
                    _ => Err(AndroError::MultipleDevices),
                }
            }
        }
    }
}

impl AdbTransport for AdbClientTransport {
    fn devices(&mut self) -> Result<Vec<DeviceInfo>> {
        let mut server = self.server();
        let devices = server
            .devices()
            .map_err(|e| AndroError::Adb(e.to_string()))?;

        Ok(devices
            .into_iter()
            .map(|d| DeviceInfo {
                id: DeviceId(d.identifier.clone()),
                state: DeviceState::Device,
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

    fn shell(&mut self, serial: &str, command: &str) -> Result<ShellOutput> {
        let mut server = self.server();
        let mut device = server
            .get_device_by_name(serial)
            .map_err(|e| AndroError::Adb(e.to_string()))?;

        let mut stdout = Vec::new();
        let cmd: &str = command;
        let stderr: Option<&mut dyn std::io::Write> = None;
        let exit_code = device
            .shell_command(&cmd, Some(&mut stdout), stderr)
            .map_err(|e| AndroError::Adb(e.to_string()))?;

        Ok(ShellOutput {
            device: DeviceId(serial.to_string()),
            stdout: String::from_utf8_lossy(&stdout).to_string(),
            exit_code: exit_code.map(i32::from),
        })
    }

    fn push(&mut self, serial: &str, local: &Path, remote: &str) -> Result<u64> {
        let mut server = self.server();
        let mut device = server
            .get_device_by_name(serial)
            .map_err(|e| AndroError::Adb(e.to_string()))?;

        let data = std::fs::read(local)?;
        let size = data.len() as u64;
        let mut cursor = std::io::Cursor::new(data);
        device
            .push(&mut cursor, &remote)
            .map_err(|e| AndroError::Adb(e.to_string()))?;
        Ok(size)
    }

    fn pull(&mut self, serial: &str, remote: &str, local: &Path) -> Result<u64> {
        let mut server = self.server();
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
        std::fs::write(local, &output)?;
        Ok(size)
    }

    fn install(&mut self, serial: &str, apk: &Path) -> Result<()> {
        let mut server = self.server();
        let mut device = server
            .get_device_by_name(serial)
            .map_err(|e| AndroError::Adb(e.to_string()))?;
        device
            .install(apk, None)
            .map_err(|e| AndroError::Adb(e.to_string()))
    }

    fn reboot(&mut self, serial: &str, _target: RebootTarget) -> Result<()> {
        let mut server = self.server();
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

// ── DeviceManager (trait-based) ────────────────────────────────────────

/// High-level device manager that works with any AdbTransport.
pub struct DeviceManager<T: AdbTransport> {
    transport: T,
}

impl DeviceManager<AdbClientTransport> {
    /// Create a DeviceManager with the real ADB client transport.
    pub fn from_config(config: &AndroConfig) -> Self {
        Self {
            transport: AdbClientTransport::from_config(config),
        }
    }
}

impl<T: AdbTransport> DeviceManager<T> {
    /// Create a DeviceManager with any transport (for testing).
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Resolve device serial: use provided or auto-detect single device.
    pub fn resolve_serial(&mut self, serial: Option<&str>) -> Result<String> {
        match serial {
            Some(s) => Ok(s.to_string()),
            None => {
                let devices = self.transport.devices()?;
                match devices.len() {
                    0 => Err(AndroError::NoDevices),
                    1 => Ok(devices[0].id.0.clone()),
                    _ => Err(AndroError::MultipleDevices),
                }
            }
        }
    }

    /// List all connected devices.
    pub fn list_devices(&mut self) -> Result<Vec<DeviceInfo>> {
        self.transport.devices()
    }

    /// Run a shell command on a device.
    pub fn shell(&mut self, serial: Option<&str>, command: &str) -> Result<ShellOutput> {
        let s = self.resolve_serial(serial)?;
        self.transport.shell(&s, command)
    }

    /// Get detailed device properties via getprop.
    pub fn device_info(&mut self, serial: Option<&str>) -> Result<DeviceInfo> {
        let output = self.shell(serial, "getprop")?;
        let id = output.device.clone();

        let get = |key: &str| -> Option<String> {
            output.stdout.lines().find_map(|line| {
                if line.contains(key) {
                    let parts: Vec<&str> = line.splitn(2, "]: [").collect();
                    if parts.len() == 2 {
                        let v = parts[1].trim_end_matches(']');
                        if v.is_empty() { None } else { Some(v.to_string()) }
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
        };

        Ok(DeviceInfo {
            id,
            state: DeviceState::Device,
            model: get("ro.product.model"),
            manufacturer: get("ro.product.manufacturer"),
            android_version: get("ro.build.version.release"),
            api_level: get("ro.build.version.sdk"),
            build_fingerprint: get("ro.build.fingerprint"),
            product: get("ro.product.name"),
            transport_id: None,
        })
    }

    /// Install an APK on a device.
    pub fn install(&mut self, serial: Option<&str>, apk_path: &Path) -> Result<()> {
        let s = self.resolve_serial(serial)?;
        self.transport.install(&s, apk_path)
    }

    /// Push a file to device.
    pub fn push(&mut self, serial: Option<&str>, local: &Path, remote: &str) -> Result<u64> {
        let s = self.resolve_serial(serial)?;
        self.transport.push(&s, local, remote)
    }

    /// Pull a file from device.
    pub fn pull(&mut self, serial: Option<&str>, remote: &str, local: &Path) -> Result<u64> {
        let s = self.resolve_serial(serial)?;
        self.transport.pull(&s, remote, local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use andro_core::mocks::MockAdbTransport;

    #[test]
    fn device_manager_with_mock_list() {
        let transport = MockAdbTransport::new()
            .with_device("ABC123", "Pixel 7")
            .with_device("DEF456", "Galaxy S24");
        let mut manager = DeviceManager::new(transport);
        let devices = manager.list_devices().unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].id.0, "ABC123");
        assert_eq!(devices[1].id.0, "DEF456");
    }

    #[test]
    fn device_manager_with_mock_shell() {
        let transport = MockAdbTransport::new()
            .with_device("TEST", "TestDevice")
            .with_shell_response("echo hello", "hello\n");
        let mut manager = DeviceManager::new(transport);
        let output = manager.shell(Some("TEST"), "echo hello").unwrap();
        assert_eq!(output.stdout, "hello\n");
    }

    #[test]
    fn device_manager_auto_select_single_device() {
        let transport = MockAdbTransport::new()
            .with_device("ONLY_ONE", "Solo");
        let mut manager = DeviceManager::new(transport);
        let serial = manager.resolve_serial(None).unwrap();
        assert_eq!(serial, "ONLY_ONE");
    }

    #[test]
    fn device_manager_error_no_devices() {
        let transport = MockAdbTransport::new();
        let mut manager = DeviceManager::new(transport);
        let result = manager.resolve_serial(None);
        assert!(result.is_err());
    }

    #[test]
    fn device_manager_error_multiple_devices() {
        let transport = MockAdbTransport::new()
            .with_device("A", "DevA")
            .with_device("B", "DevB");
        let mut manager = DeviceManager::new(transport);
        let result = manager.resolve_serial(None);
        assert!(result.is_err());
    }

    #[test]
    fn device_manager_device_info_from_getprop() {
        let getprop_output = "[ro.product.model]: [Pixel 7]\n\
                              [ro.product.manufacturer]: [Google]\n\
                              [ro.build.version.release]: [14]\n\
                              [ro.build.version.sdk]: [34]\n";
        let transport = MockAdbTransport::new()
            .with_device("PX7", "Pixel 7")
            .with_shell_response("getprop", getprop_output);
        let mut manager = DeviceManager::new(transport);
        let info = manager.device_info(Some("PX7")).unwrap();
        assert_eq!(info.model.as_deref(), Some("Pixel 7"));
        assert_eq!(info.manufacturer.as_deref(), Some("Google"));
        assert_eq!(info.android_version.as_deref(), Some("14"));
        assert_eq!(info.api_level.as_deref(), Some("34"));
    }

    #[test]
    fn device_manager_install_mock() {
        let transport = MockAdbTransport::new()
            .with_device("DEV", "Device");
        let mut manager = DeviceManager::new(transport);
        let result = manager.install(Some("DEV"), Path::new("/tmp/app.apk"));
        assert!(result.is_ok());
    }

    #[test]
    fn real_transport_from_config() {
        let config = AndroConfig::default();
        let _manager = DeviceManager::from_config(&config);
        // Just verify it constructs without panic
    }
}
