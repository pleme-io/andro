use andro_core::traits::UsbEnumerator;
use andro_core::types::UsbDeviceInfo;
use andro_core::{ANDROID_VENDOR_IDS, Result};
use serde::{Deserialize, Serialize};

/// A discovered Android USB device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDevice {
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial: Option<String>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub is_android: bool,
}

/// Real USB enumerator using nusb.
pub struct NusbEnumerator;

impl UsbEnumerator for NusbEnumerator {
    fn list_devices(&self) -> Result<Vec<UsbDeviceInfo>> {
        let device_list = nusb::list_devices()
            .map_err(|e| andro_core::AndroError::Other(format!("USB scan error: {e}")))?;

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

/// Discovers Android devices connected via USB.
pub struct UsbDiscovery;

impl UsbDiscovery {
    /// Scan USB bus using the real nusb enumerator.
    pub fn scan() -> Result<Vec<UsbDevice>> {
        Self::scan_with(&NusbEnumerator)
    }

    /// Scan USB bus using any UsbEnumerator (for testing).
    pub fn scan_with(enumerator: &dyn UsbEnumerator) -> Result<Vec<UsbDevice>> {
        let devices = enumerator.list_devices()?;
        Ok(devices
            .into_iter()
            .filter(|d| ANDROID_VENDOR_IDS.contains(&d.vendor_id))
            .map(|d| UsbDevice {
                vendor_id: d.vendor_id,
                product_id: d.product_id,
                serial: d.serial,
                manufacturer: d.manufacturer,
                product: d.product,
                is_android: true,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use andro_core::mocks::MockUsbEnumerator;

    #[test]
    fn scan_with_mock_enumerator() {
        let enumerator = MockUsbEnumerator::new()
            .with_device(0x18D1, "GOOGLE123") // Google — Android
            .with_device(0x05AC, "APPLE456"); // Apple — NOT Android
        let devices = UsbDiscovery::scan_with(&enumerator).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].vendor_id, 0x18D1);
        assert!(devices[0].is_android);
    }

    #[test]
    fn scan_empty_bus() {
        let enumerator = MockUsbEnumerator::new();
        let devices = UsbDiscovery::scan_with(&enumerator).unwrap();
        assert!(devices.is_empty());
    }

    #[test]
    fn scan_multiple_android_devices() {
        let enumerator = MockUsbEnumerator::new()
            .with_device(0x18D1, "PIXEL") // Google
            .with_device(0x04E8, "GALAXY") // Samsung
            .with_device(0x2717, "XIAOMI"); // Xiaomi
        let devices = UsbDiscovery::scan_with(&enumerator).unwrap();
        assert_eq!(devices.len(), 3);
    }
}
