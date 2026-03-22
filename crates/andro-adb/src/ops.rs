use adb_client::ADBDeviceExt;
use adb_client::server::ADBServer;
use andro_core::{AndroConfig, AndroError, DeviceId, DeviceInfo, DeviceState, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddrV4;

/// Output from a shell command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellOutput {
    pub device: DeviceId,
    pub stdout: String,
    pub exit_code: Option<i32>,
}

/// Manages connections to Android devices via ADB server.
pub struct DeviceManager {
    server_addr: SocketAddrV4,
}

impl DeviceManager {
    /// Create a new manager from config.
    pub fn from_config(config: &AndroConfig) -> Self {
        let addr: SocketAddrV4 = format!("{}:{}", config.adb_host, config.adb_port)
            .parse()
            .unwrap_or_else(|_| "127.0.0.1:5037".parse().unwrap());
        Self { server_addr: addr }
    }

    fn server(&self) -> ADBServer {
        ADBServer::new(self.server_addr)
    }

    /// List all connected devices.
    pub fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        let mut server = self.server();
        let devices = server
            .devices()
            .map_err(|e| AndroError::Adb(e.to_string()))?;

        Ok(devices
            .into_iter()
            .map(|d| {
                let id = DeviceId(d.identifier.clone());
                DeviceInfo {
                    id,
                    state: DeviceState::Device,
                    model: None,
                    manufacturer: None,
                    android_version: None,
                    api_level: None,
                    build_fingerprint: None,
                    product: None,
                    transport_id: None,
                }
            })
            .collect())
    }

    /// Get a device handle by serial, or the only connected device.
    fn get_device_serial(&self, serial: Option<&str>) -> Result<String> {
        match serial {
            Some(s) => Ok(s.to_string()),
            None => {
                let mut server = self.server();
                let devices = server
                    .devices()
                    .map_err(|e| AndroError::Adb(e.to_string()))?;
                match devices.len() {
                    0 => Err(AndroError::NoDevices),
                    1 => Ok(devices[0].identifier.clone()),
                    _ => Err(AndroError::MultipleDevices),
                }
            }
        }
    }

    /// Run a shell command on a device.
    pub fn shell(&self, serial: Option<&str>, command: &str) -> Result<ShellOutput> {
        let device_serial = self.get_device_serial(serial)?;
        let mut server = self.server();
        let mut device = server
            .get_device_by_name(&device_serial)
            .map_err(|e| AndroError::Adb(e.to_string()))?;

        let mut stdout = Vec::new();
        let cmd: &str = command;
        let stderr: Option<&mut dyn std::io::Write> = None;
        let exit_code = device
            .shell_command(&cmd, Some(&mut stdout), stderr)
            .map_err(|e| AndroError::Adb(e.to_string()))?;

        Ok(ShellOutput {
            device: DeviceId(device_serial),
            stdout: String::from_utf8_lossy(&stdout).to_string(),
            exit_code: exit_code.map(i32::from),
        })
    }

    /// Get detailed device properties via getprop.
    pub fn device_info(&self, serial: Option<&str>) -> Result<DeviceInfo> {
        let output = self.shell(serial, "getprop")?;
        let id = output.device.clone();

        let get = |key: &str| -> Option<String> {
            output.stdout.lines().find_map(|line| {
                if line.contains(key) {
                    // Format: [key]: [value]
                    let parts: Vec<&str> = line.splitn(2, "]: [").collect();
                    if parts.len() == 2 {
                        let v = parts[1].trim_end_matches(']');
                        if v.is_empty() {
                            None
                        } else {
                            Some(v.to_string())
                        }
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
    pub fn install(&self, serial: Option<&str>, apk_path: &std::path::Path) -> Result<()> {
        let device_serial = self.get_device_serial(serial)?;
        let mut server = self.server();
        let mut device = server
            .get_device_by_name(&device_serial)
            .map_err(|e| AndroError::Adb(e.to_string()))?;

        device
            .install(apk_path, None)
            .map_err(|e| AndroError::Adb(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_manager_from_default_config() {
        let config = AndroConfig::default();
        let manager = DeviceManager::from_config(&config);
        assert_eq!(
            manager.server_addr,
            "127.0.0.1:5037".parse::<SocketAddrV4>().unwrap()
        );
    }
}
