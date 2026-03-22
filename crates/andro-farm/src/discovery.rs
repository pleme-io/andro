use andro_core::Result;
use serde::{Deserialize, Serialize};

/// A discovered USB device that might be an Android device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDevice {
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial: Option<String>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub is_android: bool,
}

/// Discovers Android devices connected via USB.
pub struct UsbDiscovery;

impl UsbDiscovery {
    /// Known Android device vendor IDs.
    const ANDROID_VENDORS: &[u16] = &[
        0x18D1, // Google
        0x04E8, // Samsung
        0x22B8, // Motorola
        0x2717, // Xiaomi
        0x2A70, // OnePlus
        0x05C6, // Qualcomm
        0x1949, // Lab126 (Amazon)
        0x0BB4, // HTC
        0x12D1, // Huawei
        0x2B4C, // Nothing
        0x1004, // LG
        0x0FCE, // Sony
        0x2A96, // Google (Tensor)
        0x0E8D, // MediaTek
        0x1532, // Razer
        0x2916, // Google (AOSP)
    ];

    /// Scan USB bus for Android devices.
    pub fn scan() -> Result<Vec<UsbDevice>> {
        let mut android_devices = Vec::new();

        let device_list = nusb::list_devices()
            .map_err(|e| andro_core::AndroError::Other(format!("USB scan error: {e}")))?;

        for dev in device_list {
            let vid = dev.vendor_id();
            let is_android = Self::ANDROID_VENDORS.contains(&vid);

            if is_android {
                android_devices.push(UsbDevice {
                    vendor_id: vid,
                    product_id: dev.product_id(),
                    serial: dev.serial_number().map(|s| s.to_string()),
                    manufacturer: dev.manufacturer_string().map(|s| s.to_string()),
                    product: dev.product_string().map(|s| s.to_string()),
                    is_android,
                });
            }
        }

        Ok(android_devices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vendor_ids() {
        assert!(UsbDiscovery::ANDROID_VENDORS.contains(&0x18D1)); // Google
        assert!(UsbDiscovery::ANDROID_VENDORS.contains(&0x04E8)); // Samsung
    }
}
