//! Fleet orchestration — parallel ADB operations across multiple devices.
//!
//! Uses `tokio::spawn` for concurrent execution of shell commands and
//! APK installations across a fleet of devices. All device communication
//! goes through the `AdbTransport` trait.

use andro_core::error::Result;
use andro_core::traits::AdbTransport;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Summary of a single device in the fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStatus {
    pub serial: String,
    pub model: Option<String>,
    pub state: String,
    pub online: bool,
}

/// Result of a fleet-wide operation for one device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetResult {
    pub serial: String,
    pub success: bool,
    pub output: Option<String>,
    pub error: Option<String>,
}

/// Fleet manager for parallel device operations.
pub struct FleetManager;

impl FleetManager {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Execute a shell command on multiple devices in parallel.
    ///
    /// Returns one `FleetResult` per device, regardless of individual success/failure.
    pub async fn parallel_exec(
        &self,
        serials: &[String],
        command: &str,
        adb: Arc<Mutex<dyn AdbTransport>>,
    ) -> Vec<FleetResult> {
        let mut handles = Vec::new();

        for serial in serials {
            let serial = serial.clone();
            let command = command.to_string();
            let adb = Arc::clone(&adb);

            handles.push(tokio::spawn(async move {
                let result = {
                    let mut transport = adb.lock().unwrap();
                    transport.shell(&serial, &command)
                };
                match result {
                    Ok(output) => FleetResult {
                        serial,
                        success: output.exit_code == Some(0),
                        output: Some(output.stdout),
                        error: None,
                    },
                    Err(e) => FleetResult {
                        serial,
                        success: false,
                        output: None,
                        error: Some(e.to_string()),
                    },
                }
            }));
        }

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(FleetResult {
                    serial: String::new(),
                    success: false,
                    output: None,
                    error: Some(format!("task join error: {e}")),
                }),
            }
        }
        results
    }

    /// Install an APK on multiple devices in parallel.
    pub async fn parallel_install(
        &self,
        serials: &[String],
        apk_path: &Path,
        adb: Arc<Mutex<dyn AdbTransport>>,
    ) -> Vec<FleetResult> {
        let apk_path = apk_path.to_path_buf();
        let mut handles = Vec::new();

        for serial in serials {
            let serial = serial.clone();
            let apk = apk_path.clone();
            let adb = Arc::clone(&adb);

            handles.push(tokio::spawn(async move {
                let result = {
                    let mut transport = adb.lock().unwrap();
                    transport.install(&serial, &apk)
                };
                match result {
                    Ok(()) => FleetResult {
                        serial,
                        success: true,
                        output: Some("installed".to_string()),
                        error: None,
                    },
                    Err(e) => FleetResult {
                        serial,
                        success: false,
                        output: None,
                        error: Some(e.to_string()),
                    },
                }
            }));
        }

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(FleetResult {
                    serial: String::new(),
                    success: false,
                    output: None,
                    error: Some(format!("task join error: {e}")),
                }),
            }
        }
        results
    }

    /// Get the status of all connected devices.
    pub fn fleet_status(
        &self,
        adb: &mut dyn AdbTransport,
    ) -> Result<Vec<DeviceStatus>> {
        let devices = adb.devices()?;
        let statuses = devices
            .into_iter()
            .map(|d| DeviceStatus {
                serial: d.id.0.clone(),
                model: d.model.clone(),
                state: d.state.to_string(),
                online: d.state == andro_core::device::DeviceState::Device,
            })
            .collect();
        Ok(statuses)
    }
}

impl Default for FleetManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use andro_core::mocks::MockAdbTransport;

    #[test]
    fn fleet_status_lists_devices() {
        let mut adb = MockAdbTransport::new()
            .with_device("DEV1", "Pixel 7")
            .with_device("DEV2", "Pixel 8");
        let mgr = FleetManager::new();
        let status = mgr.fleet_status(&mut adb).unwrap();
        assert_eq!(status.len(), 2);
        assert_eq!(status[0].serial, "DEV1");
        assert!(status[0].online);
        assert_eq!(status[1].model, Some("Pixel 8".to_string()));
    }

    #[tokio::test]
    async fn parallel_exec_runs_on_all_devices() {
        let adb = MockAdbTransport::new()
            .with_shell_response("getprop ro.build.id", "ABC123");
        let adb: Arc<Mutex<dyn AdbTransport>> = Arc::new(Mutex::new(adb));
        let mgr = FleetManager::new();
        let serials = vec!["DEV1".to_string(), "DEV2".to_string()];

        let results = mgr
            .parallel_exec(&serials, "getprop ro.build.id", adb)
            .await;
        assert_eq!(results.len(), 2);
        for r in &results {
            assert!(r.success);
            assert_eq!(r.output.as_deref(), Some("ABC123"));
        }
    }

    #[tokio::test]
    async fn parallel_install_succeeds() {
        let adb = MockAdbTransport::new();
        let adb: Arc<Mutex<dyn AdbTransport>> = Arc::new(Mutex::new(adb));
        let mgr = FleetManager::new();
        let serials = vec!["DEV1".to_string()];

        let results = mgr
            .parallel_install(&serials, Path::new("/tmp/test.apk"), adb)
            .await;
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
    }

    #[test]
    fn fleet_status_empty() {
        let mut adb = MockAdbTransport::new();
        let mgr = FleetManager::new();
        let status = mgr.fleet_status(&mut adb).unwrap();
        assert!(status.is_empty());
    }

    #[tokio::test]
    async fn parallel_exec_returns_results_for_all_devices() {
        let adb = MockAdbTransport::new()
            .with_shell_response("echo hello", "hello");
        let adb: Arc<Mutex<dyn AdbTransport>> = Arc::new(Mutex::new(adb));
        let mgr = FleetManager::new();
        let serials: Vec<String> = (1..=5).map(|i| format!("DEV{i}")).collect();

        let results = mgr.parallel_exec(&serials, "echo hello", adb).await;
        assert_eq!(results.len(), 5);
        for r in &results {
            assert!(r.success);
            assert_eq!(r.output.as_deref(), Some("hello"));
            assert!(r.error.is_none());
        }
    }

    #[tokio::test]
    async fn parallel_exec_empty_device_list() {
        let adb = MockAdbTransport::new();
        let adb: Arc<Mutex<dyn AdbTransport>> = Arc::new(Mutex::new(adb));
        let mgr = FleetManager::new();
        let serials: Vec<String> = vec![];

        let results = mgr.parallel_exec(&serials, "ls", adb).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn parallel_exec_single_device() {
        let adb = MockAdbTransport::new()
            .with_shell_response("id", "uid=0(root)");
        let adb: Arc<Mutex<dyn AdbTransport>> = Arc::new(Mutex::new(adb));
        let mgr = FleetManager::new();
        let serials = vec!["SOLO_DEV".to_string()];

        let results = mgr.parallel_exec(&serials, "id", adb).await;
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
        assert_eq!(results[0].output.as_deref(), Some("uid=0(root)"));
    }

    #[test]
    fn fleet_status_returns_all_device_info() {
        let mut adb = MockAdbTransport::new()
            .with_device("PHONE_A", "Pixel 8")
            .with_device("PHONE_B", "Pixel 9")
            .with_device("PHONE_C", "Galaxy S24");
        let mgr = FleetManager::new();
        let status = mgr.fleet_status(&mut adb).unwrap();

        assert_eq!(status.len(), 3);
        assert_eq!(status[0].serial, "PHONE_A");
        assert_eq!(status[0].model, Some("Pixel 8".to_string()));
        assert!(status[0].online);
        assert_eq!(status[1].serial, "PHONE_B");
        assert_eq!(status[2].model, Some("Galaxy S24".to_string()));
    }

    #[tokio::test]
    async fn parallel_install_with_mock_transport() {
        let adb = MockAdbTransport::new();
        let adb: Arc<Mutex<dyn AdbTransport>> = Arc::new(Mutex::new(adb));
        let mgr = FleetManager::new();
        let serials = vec![
            "DEV_A".to_string(),
            "DEV_B".to_string(),
            "DEV_C".to_string(),
        ];

        let results = mgr
            .parallel_install(&serials, Path::new("/tmp/mock.apk"), adb)
            .await;
        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(r.success);
            assert_eq!(r.output.as_deref(), Some("installed"));
            assert!(r.error.is_none());
        }
    }
}
