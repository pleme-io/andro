use andro_core::traits::UsbEnumerator;
use andro_core::types::UsbDeviceInfo;
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

/// Real USB enumerator for fastboot (shared with andro-farm).
pub struct NusbEnumerator;

impl UsbEnumerator for NusbEnumerator {
    fn list_devices(&self) -> Result<Vec<UsbDeviceInfo>> {
        let device_list = nusb::list_devices()
            .map_err(|e| AndroError::Other(format!("USB enumeration error: {e}")))?;

        Ok(device_list
            .map(|dev| UsbDeviceInfo {
                vendor_id: dev.vendor_id(),
                product_id: dev.product_id(),
                serial: dev.serial_number().map(|s| s.to_string()),
                manufacturer: dev.manufacturer_string().map(|s| s.to_string()),
                product: dev.product_string().map(|s| s.to_string()),
            })
            .collect())
    }
}

/// Fastboot client using USB enumeration.
pub struct FastbootClient;

impl FastbootClient {
    /// List fastboot devices using the real nusb enumerator.
    pub fn list_devices() -> Result<Vec<FastbootDeviceInfo>> {
        Self::list_devices_with(&NusbEnumerator)
    }

    /// List fastboot devices using any UsbEnumerator (for testing).
    pub fn list_devices_with(enumerator: &dyn UsbEnumerator) -> Result<Vec<FastbootDeviceInfo>> {
        let devices = enumerator.list_devices()?;
        Ok(devices
            .into_iter()
            .filter(|d| ANDROID_VENDOR_IDS.contains(&d.vendor_id))
            .filter(|d| d.serial.is_some())
            .map(|d| FastbootDeviceInfo {
                serial: d.serial.unwrap_or_default(),
                product: d.product,
                variant: None,
                secure: None,
                unlocked: None,
            })
            .collect())
    }

    /// Check if any fastboot device is connected.
    pub fn has_device() -> bool {
        Self::list_devices().map(|d| !d.is_empty()).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use andro_core::mocks::MockUsbEnumerator;

    #[test]
    fn fastboot_with_mock_enumerator() {
        let enumerator = MockUsbEnumerator::new()
            .with_device(0x18D1, "FB_DEVICE");
        let devices = FastbootClient::list_devices_with(&enumerator).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].serial, "FB_DEVICE");
    }

    #[test]
    fn fastboot_empty() {
        let enumerator = MockUsbEnumerator::new();
        let devices = FastbootClient::list_devices_with(&enumerator).unwrap();
        assert!(devices.is_empty());
    }

    #[test]
    fn fastboot_filters_non_android() {
        let enumerator = MockUsbEnumerator::new()
            .with_device(0x05AC, "APPLE"); // Not Android
        let devices = FastbootClient::list_devices_with(&enumerator).unwrap();
        assert!(devices.is_empty());
    }

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
