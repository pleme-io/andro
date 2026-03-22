//! Device health monitoring — battery, storage, memory, and CPU temperature.
//!
//! Extracts health data via ADB shell commands:
//! - `dumpsys battery` for battery level, health, and temperature
//! - `df /data` for storage usage
//! - `cat /proc/meminfo` for memory stats
//! - thermal zone reads for CPU temperature
//!
//! Uses the `AdbTransport` trait for testability.

use andro_core::error::Result;
use andro_core::traits::AdbTransport;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Battery health status.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum BatteryHealth {
    Good,
    Overheat,
    Dead,
    OverVoltage,
    Cold,
    Unknown,
}

impl From<u32> for BatteryHealth {
    fn from(code: u32) -> Self {
        match code {
            2 => Self::Good,
            3 => Self::Overheat,
            4 => Self::Dead,
            5 => Self::OverVoltage,
            6 => Self::Cold,
            _ => Self::Unknown,
        }
    }
}

/// Storage usage in bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageInfo {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
}

/// Memory usage in kilobytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_kb: u64,
    pub free_kb: u64,
    pub available_kb: u64,
}

/// Complete health report for a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub device: String,
    pub timestamp: DateTime<Utc>,
    pub battery_level: Option<u32>,
    pub battery_health: Option<BatteryHealth>,
    pub battery_temp_c: Option<f32>,
    pub storage: Option<StorageInfo>,
    pub memory: Option<MemoryInfo>,
    pub cpu_temp_c: Option<f32>,
}

/// Health monitor that collects device metrics via ADB.
pub struct HealthMonitor;

impl HealthMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Collect a full health report for a device.
    pub fn check(
        &self,
        serial: &str,
        adb: &mut dyn AdbTransport,
    ) -> Result<HealthReport> {
        let battery = self.battery_info(serial, adb);
        let storage = self.storage_info(serial, adb);
        let memory = self.memory_info(serial, adb);
        let cpu_temp = self.cpu_temp(serial, adb);

        let (level, health, temp) = battery.unwrap_or((None, None, None));

        Ok(HealthReport {
            device: serial.to_string(),
            timestamp: Utc::now(),
            battery_level: level,
            battery_health: health,
            battery_temp_c: temp,
            storage: storage.ok(),
            memory: memory.ok(),
            cpu_temp_c: cpu_temp.ok().flatten(),
        })
    }

    /// Parse battery info from `dumpsys battery`.
    ///
    /// Expected output format:
    /// ```text
    /// Current Battery Service state:
    ///   level: 85
    ///   health: 2
    ///   temperature: 280
    /// ```
    fn battery_info(
        &self,
        serial: &str,
        adb: &mut dyn AdbTransport,
    ) -> Result<(Option<u32>, Option<BatteryHealth>, Option<f32>)> {
        let output = adb.shell(serial, "dumpsys battery")?;
        let mut level = None;
        let mut health = None;
        let mut temp = None;

        for line in output.stdout.lines() {
            let trimmed = line.trim();
            if let Some(val) = trimmed.strip_prefix("level: ") {
                level = val.parse::<u32>().ok();
            } else if let Some(val) = trimmed.strip_prefix("health: ") {
                health = val.parse::<u32>().ok().map(BatteryHealth::from);
            } else if let Some(val) = trimmed.strip_prefix("temperature: ") {
                // Temperature is in tenths of a degree Celsius.
                temp = val.parse::<f32>().ok().map(|t| t / 10.0);
            }
        }

        Ok((level, health, temp))
    }

    /// Parse storage info from `df /data`.
    ///
    /// Expected output format:
    /// ```text
    /// Filesystem    1K-blocks    Used Available Use% Mounted on
    /// /dev/block/dm-8  112345678  56789012  55556666  51% /data
    /// ```
    fn storage_info(
        &self,
        serial: &str,
        adb: &mut dyn AdbTransport,
    ) -> Result<StorageInfo> {
        let output = adb.shell(serial, "df /data")?;
        // Parse the second line (skip header).
        let data_line = output
            .stdout
            .lines()
            .nth(1)
            .unwrap_or("");
        let cols: Vec<&str> = data_line.split_whitespace().collect();

        // Columns: filesystem, 1k-blocks, used, available, use%, mount
        if cols.len() >= 4 {
            let total = cols[1].parse::<u64>().unwrap_or(0) * 1024;
            let used = cols[2].parse::<u64>().unwrap_or(0) * 1024;
            let free = cols[3].parse::<u64>().unwrap_or(0) * 1024;
            Ok(StorageInfo {
                total_bytes: total,
                used_bytes: used,
                free_bytes: free,
            })
        } else {
            Ok(StorageInfo {
                total_bytes: 0,
                used_bytes: 0,
                free_bytes: 0,
            })
        }
    }

    /// Parse memory info from `/proc/meminfo`.
    ///
    /// Expected lines:
    /// ```text
    /// MemTotal:        8000000 kB
    /// MemFree:         2000000 kB
    /// MemAvailable:    4000000 kB
    /// ```
    fn memory_info(
        &self,
        serial: &str,
        adb: &mut dyn AdbTransport,
    ) -> Result<MemoryInfo> {
        let output = adb.shell(serial, "cat /proc/meminfo")?;
        let mut total = 0u64;
        let mut free = 0u64;
        let mut available = 0u64;

        for line in output.stdout.lines() {
            let trimmed = line.trim();
            if let Some(val) = trimmed.strip_prefix("MemTotal:") {
                total = Self::parse_meminfo_value(val);
            } else if let Some(val) = trimmed.strip_prefix("MemFree:") {
                free = Self::parse_meminfo_value(val);
            } else if let Some(val) = trimmed.strip_prefix("MemAvailable:") {
                available = Self::parse_meminfo_value(val);
            }
        }

        Ok(MemoryInfo {
            total_kb: total,
            free_kb: free,
            available_kb: available,
        })
    }

    /// Parse a meminfo value like "  8000000 kB" into u64.
    fn parse_meminfo_value(val: &str) -> u64 {
        val.trim()
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    }

    /// Read CPU temperature from thermal zone.
    fn cpu_temp(
        &self,
        serial: &str,
        adb: &mut dyn AdbTransport,
    ) -> Result<Option<f32>> {
        let output = adb.shell(serial, "cat /sys/class/thermal/thermal_zone0/temp")?;
        let millideg = output.stdout.trim().parse::<f32>().ok();
        // Thermal zone reports in millidegrees Celsius.
        Ok(millideg.map(|t| t / 1000.0))
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use andro_core::mocks::MockAdbTransport;

    fn mock_adb() -> MockAdbTransport {
        MockAdbTransport::new()
            .with_shell_response(
                "dumpsys battery",
                "Current Battery Service state:\n  level: 85\n  health: 2\n  temperature: 280\n",
            )
            .with_shell_response(
                "df /data",
                "Filesystem      1K-blocks     Used Available Use% Mounted on\n/dev/block/dm-8  112345678 56789012 55556666  51% /data\n",
            )
            .with_shell_response(
                "cat /proc/meminfo",
                "MemTotal:        8000000 kB\nMemFree:         2000000 kB\nMemAvailable:    4000000 kB\n",
            )
            .with_shell_response(
                "cat /sys/class/thermal/thermal_zone0/temp",
                "42000\n",
            )
    }

    #[test]
    fn health_report_battery() {
        let mut adb = mock_adb();
        let monitor = HealthMonitor::new();
        let report = monitor.check("TEST", &mut adb).unwrap();
        assert_eq!(report.battery_level, Some(85));
        assert_eq!(report.battery_health, Some(BatteryHealth::Good));
        // 280 / 10 = 28.0
        assert!((report.battery_temp_c.unwrap() - 28.0).abs() < 0.1);
    }

    #[test]
    fn health_report_storage() {
        let mut adb = mock_adb();
        let monitor = HealthMonitor::new();
        let report = monitor.check("TEST", &mut adb).unwrap();
        let storage = report.storage.unwrap();
        assert_eq!(storage.total_bytes, 112_345_678 * 1024);
        assert_eq!(storage.used_bytes, 56_789_012 * 1024);
        assert_eq!(storage.free_bytes, 55_556_666 * 1024);
    }

    #[test]
    fn health_report_memory() {
        let mut adb = mock_adb();
        let monitor = HealthMonitor::new();
        let report = monitor.check("TEST", &mut adb).unwrap();
        let memory = report.memory.unwrap();
        assert_eq!(memory.total_kb, 8_000_000);
        assert_eq!(memory.free_kb, 2_000_000);
        assert_eq!(memory.available_kb, 4_000_000);
    }

    #[test]
    fn health_report_cpu_temp() {
        let mut adb = mock_adb();
        let monitor = HealthMonitor::new();
        let report = monitor.check("TEST", &mut adb).unwrap();
        // 42000 / 1000 = 42.0
        assert!((report.cpu_temp_c.unwrap() - 42.0).abs() < 0.1);
    }

    #[test]
    fn battery_health_variants() {
        assert_eq!(BatteryHealth::from(2), BatteryHealth::Good);
        assert_eq!(BatteryHealth::from(3), BatteryHealth::Overheat);
        assert_eq!(BatteryHealth::from(4), BatteryHealth::Dead);
        assert_eq!(BatteryHealth::from(5), BatteryHealth::OverVoltage);
        assert_eq!(BatteryHealth::from(6), BatteryHealth::Cold);
        assert_eq!(BatteryHealth::from(99), BatteryHealth::Unknown);
    }

    #[test]
    fn graceful_on_missing_data() {
        let mut adb = MockAdbTransport::new()
            .with_shell_response("dumpsys battery", "")
            .with_shell_response("df /data", "")
            .with_shell_response("cat /proc/meminfo", "")
            .with_shell_response("cat /sys/class/thermal/thermal_zone0/temp", "");
        let monitor = HealthMonitor::new();
        let report = monitor.check("TEST", &mut adb).unwrap();
        assert!(report.battery_level.is_none());
        assert!(report.cpu_temp_c.is_none());
    }
}
