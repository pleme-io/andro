//! GrapheneOS integration — OTA update checks, user profile enumeration,
//! Play Services status, and Android Verified Boot state.
//!
//! All device operations accept trait references (`AdbTransport`,
//! `FastbootTransport`) for testability. Network calls use an `OtaFetcher`
//! trait so tests can inject mock HTTP responses.

use andro_core::error::{AndroError, Result};
use andro_core::traits::{AdbTransport, FastbootTransport};
use serde::{Deserialize, Serialize};

// ── OTA types ─────────────────────────────────────────────────────────

/// OTA release channel.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Stable,
    Beta,
    Alpha,
}

impl std::fmt::Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stable => write!(f, "stable"),
            Self::Beta => write!(f, "beta"),
            Self::Alpha => write!(f, "alpha"),
        }
    }
}

/// OTA update information from releases.grapheneos.org.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtaInfo {
    pub device: String,
    pub channel: Channel,
    pub version: String,
    pub raw_response: String,
}

/// A user profile on the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub id: u32,
    pub name: String,
    pub running: bool,
}

/// Play Services installation status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayServicesStatus {
    pub installed: bool,
    pub package: Option<String>,
}

/// Android Verified Boot status from fastboot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvbStatus {
    pub state: String,
    pub locked: bool,
}

// ── OTA fetcher trait ─────────────────────────────────────────────────

/// Abstraction over HTTP fetch for OTA version checks.
pub trait OtaFetcher: Send + Sync {
    /// Fetch the OTA version string for the given device and channel.
    /// URL pattern: `https://releases.grapheneos.org/{device}-{channel}`
    fn fetch_ota(&self, device: &str, channel: Channel) -> Result<String>;
}

/// Real HTTP-based OTA fetcher using reqwest (blocking).
pub struct HttpOtaFetcher;

impl OtaFetcher for HttpOtaFetcher {
    fn fetch_ota(&self, device: &str, channel: Channel) -> Result<String> {
        let url = format!("https://releases.grapheneos.org/{device}-{channel}");
        let body = reqwest::blocking::get(&url)
            .map_err(|e| AndroError::Other(format!("HTTP error: {e}")))?
            .text()
            .map_err(|e| AndroError::Other(format!("body read error: {e}")))?;
        Ok(body)
    }
}

// ── GosClient ─────────────────────────────────────────────────────────

/// GrapheneOS client for device and OTA operations.
pub struct GosClient;

impl GosClient {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Check for OTA updates by fetching the latest version from
    /// `releases.grapheneos.org/<device>-<channel>`.
    pub fn check_ota(
        &self,
        device: &str,
        channel: Channel,
        fetcher: &dyn OtaFetcher,
    ) -> Result<OtaInfo> {
        let raw = fetcher.fetch_ota(device, channel)?;
        // The response is a text file; first token on the first line is the version.
        let version = raw
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().next())
            .unwrap_or("")
            .to_string();
        Ok(OtaInfo {
            device: device.to_string(),
            channel,
            version,
            raw_response: raw,
        })
    }

    /// List user profiles via `pm list users`.
    ///
    /// Parses output like:
    /// ```text
    /// Users:
    ///   UserInfo{0:Owner:c13} running
    ///   UserInfo{10:Work:30}
    /// ```
    pub fn list_profiles(
        &self,
        serial: &str,
        adb: &mut dyn AdbTransport,
    ) -> Result<Vec<UserProfile>> {
        let output = adb.shell(serial, "pm list users")?;
        let mut profiles = Vec::new();

        for line in output.stdout.lines() {
            let trimmed = line.trim();
            // Match lines containing "UserInfo{...}"
            if let Some(start) = trimmed.find("UserInfo{") {
                let after = &trimmed[start + 9..];
                if let Some(end) = after.find('}') {
                    let info = &after[..end];
                    // Format: id:name:flags
                    let parts: Vec<&str> = info.splitn(3, ':').collect();
                    if parts.len() >= 2 {
                        let id = parts[0].parse::<u32>().unwrap_or(0);
                        let name = parts[1].to_string();
                        let running = trimmed.contains("running");
                        profiles.push(UserProfile { id, name, running });
                    }
                }
            }
        }

        Ok(profiles)
    }

    /// Check Play Services status via `pm list packages`.
    pub fn play_services_status(
        &self,
        serial: &str,
        adb: &mut dyn AdbTransport,
    ) -> Result<PlayServicesStatus> {
        let output = adb.shell(serial, "pm list packages com.google.android.gms")?;
        let installed = output
            .stdout
            .lines()
            .any(|line| line.contains("com.google.android.gms"));
        Ok(PlayServicesStatus {
            installed,
            package: if installed {
                Some("com.google.android.gms".to_string())
            } else {
                None
            },
        })
    }

    /// Query AVB status via fastboot `getvar`.
    pub fn avb_status(&self, fb: &mut dyn FastbootTransport) -> Result<AvbStatus> {
        let state = fb
            .getvar("avb-state")
            .unwrap_or_else(|_| "unknown".to_string());
        let unlocked = fb.getvar("unlocked").unwrap_or_default();
        Ok(AvbStatus {
            state: state.clone(),
            locked: unlocked != "yes",
        })
    }
}

impl Default for GosClient {
    fn default() -> Self {
        Self::new()
    }
}

// ── Mock OTA fetcher for tests ────────────────────────────────────────

/// Mock OTA fetcher with pre-recorded response.
#[cfg(test)]
struct MockOtaFetcher {
    response: String,
}

#[cfg(test)]
impl OtaFetcher for MockOtaFetcher {
    fn fetch_ota(&self, _device: &str, _channel: Channel) -> Result<String> {
        Ok(self.response.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use andro_core::mocks::{MockAdbTransport, MockFastbootTransport};

    #[test]
    fn check_ota_parses_version() {
        let fetcher = MockOtaFetcher {
            response: "2024032100 factory.zip hash123\n".to_string(),
        };
        let client = GosClient::new();
        let info = client.check_ota("husky", Channel::Stable, &fetcher).unwrap();
        assert_eq!(info.device, "husky");
        assert_eq!(info.version, "2024032100");
        assert_eq!(info.channel, Channel::Stable);
    }

    #[test]
    fn list_profiles_parses_output() {
        let mut adb = MockAdbTransport::new()
            .with_shell_response(
                "pm list users",
                "Users:\n  UserInfo{0:Owner:c13} running\n  UserInfo{10:Work:30}\n",
            );
        let client = GosClient::new();
        let profiles = client.list_profiles("ABC", &mut adb).unwrap();
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].id, 0);
        assert_eq!(profiles[0].name, "Owner");
        assert!(profiles[0].running);
        assert_eq!(profiles[1].id, 10);
        assert_eq!(profiles[1].name, "Work");
        assert!(!profiles[1].running);
    }

    #[test]
    fn play_services_installed() {
        let mut adb = MockAdbTransport::new()
            .with_shell_response(
                "pm list packages com.google.android.gms",
                "package:com.google.android.gms\n",
            );
        let client = GosClient::new();
        let status = client.play_services_status("ABC", &mut adb).unwrap();
        assert!(status.installed);
        assert_eq!(status.package, Some("com.google.android.gms".to_string()));
    }

    #[test]
    fn play_services_not_installed() {
        let mut adb = MockAdbTransport::new()
            .with_shell_response("pm list packages com.google.android.gms", "");
        let client = GosClient::new();
        let status = client.play_services_status("ABC", &mut adb).unwrap();
        assert!(!status.installed);
        assert!(status.package.is_none());
    }

    #[test]
    fn avb_locked() {
        let mut fb = MockFastbootTransport::new()
            .with_var("avb-state", "green")
            .with_var("unlocked", "no");
        let client = GosClient::new();
        let status = client.avb_status(&mut fb).unwrap();
        assert_eq!(status.state, "green");
        assert!(status.locked);
    }

    #[test]
    fn avb_unlocked() {
        let mut fb = MockFastbootTransport::new()
            .with_var("avb-state", "orange")
            .with_var("unlocked", "yes");
        let client = GosClient::new();
        let status = client.avb_status(&mut fb).unwrap();
        assert_eq!(status.state, "orange");
        assert!(!status.locked);
    }
}
