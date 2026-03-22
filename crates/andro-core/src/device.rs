use serde::{Deserialize, Serialize};

/// Unique device identifier (serial number or network address).
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceId(pub String);

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Device connection state.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceState {
    Device,
    Offline,
    Unauthorized,
    Recovery,
    Sideload,
    Unknown,
}

impl std::fmt::Display for DeviceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Device => write!(f, "device"),
            Self::Offline => write!(f, "offline"),
            Self::Unauthorized => write!(f, "unauthorized"),
            Self::Recovery => write!(f, "recovery"),
            Self::Sideload => write!(f, "sideload"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Parsed device information from ADB properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: DeviceId,
    pub state: DeviceState,
    pub model: Option<String>,
    pub manufacturer: Option<String>,
    pub android_version: Option<String>,
    pub api_level: Option<String>,
    pub build_fingerprint: Option<String>,
    pub product: Option<String>,
    pub transport_id: Option<String>,
}
