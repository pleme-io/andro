use andro_core::{ANDROID_VENDOR_IDS, AndroError, Result};
use serde::{Deserialize, Serialize};

/// Fastboot device info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastbootDeviceInfo {
    pub serial: String,
    pub product: Option<String>,
    pub variant: Option<String>,
    pub secure: Option<bool>,
    pub unlocked: Option<bool>,
}

/// Fastboot client using nusb for USB enumeration.
pub struct FastbootClient;

impl FastbootClient {
    /// List fastboot devices via nusb USB enumeration.
    pub fn list_devices() -> Result<Vec<FastbootDeviceInfo>> {
        let mut fastboot_devices = Vec::new();

        let device_list = nusb::list_devices()
            .map_err(|e| AndroError::Other(format!("USB enumeration error: {e}")))?;

        for dev in device_list {
            let vid = dev.vendor_id();

            let is_android = ANDROID_VENDOR_IDS.contains(&vid);

            if is_android {
                let serial = dev
                    .serial_number()
                    .unwrap_or_default()
                    .to_string();
                if !serial.is_empty() {
                    fastboot_devices.push(FastbootDeviceInfo {
                        serial,
                        product: dev.product_string().map(|s| s.to_string()),
                        variant: None,
                        secure: None,
                        unlocked: None,
                    });
                }
            }
        }

        Ok(fastboot_devices)
    }

    /// Check if any fastboot device is connected.
    pub fn has_device() -> bool {
        Self::list_devices().map(|d| !d.is_empty()).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fastboot_info_serialize() {
        let info = FastbootDeviceInfo {
            serial: "TEST123".into(),
            product: Some("walleye".into()),
            variant: None,
            secure: Some(true),
            unlocked: Some(false),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("TEST123"));
    }
}
