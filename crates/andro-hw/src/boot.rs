use serde::{Deserialize, Serialize};
use std::path::Path;

/// Android boot image magic bytes: "ANDROID!"
const BOOT_MAGIC: [u8; 8] = *b"ANDROID!";
const HEADER_SIZE: usize = 1648; // v0 header size

/// Android boot image header (v0 layout).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootImageHeader {
    pub kernel_size: u32,
    pub kernel_addr: u32,
    pub ramdisk_size: u32,
    pub ramdisk_addr: u32,
    pub second_size: u32,
    pub second_addr: u32,
    pub tags_addr: u32,
    pub page_size: u32,
    pub header_version: u32,
    pub os_version: u32,
    pub name: String,
    pub cmdline: String,
}

/// Parsed boot image with header and section offsets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootImage {
    pub header: BootImageHeader,
    pub kernel_offset: u64,
    pub ramdisk_offset: u64,
    pub second_offset: u64,
}

impl BootImage {
    /// Parse a boot image file.
    pub fn parse(path: &Path) -> andro_core::Result<Self> {
        let data = std::fs::read(path)?;

        // Verify magic
        if data.len() < HEADER_SIZE || &data[..8] != &BOOT_MAGIC {
            return Err(andro_core::AndroError::Other(
                "not a valid Android boot image (bad magic)".into(),
            ));
        }

        // Parse header fields (little-endian u32)
        let u32_at = |off: usize| -> u32 {
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        };

        let kernel_size = u32_at(8);
        let kernel_addr = u32_at(12);
        let ramdisk_size = u32_at(16);
        let ramdisk_addr = u32_at(20);
        let second_size = u32_at(24);
        let second_addr = u32_at(28);
        let tags_addr = u32_at(32);
        let page_size = u32_at(36);
        let header_version = u32_at(40);
        let os_version = u32_at(44);

        let name = String::from_utf8_lossy(&data[48..64])
            .trim_end_matches('\0')
            .to_string();
        let cmdline = String::from_utf8_lossy(&data[64..576])
            .trim_end_matches('\0')
            .to_string();

        let header = BootImageHeader {
            kernel_size,
            kernel_addr,
            ramdisk_size,
            ramdisk_addr,
            second_size,
            second_addr,
            tags_addr,
            page_size,
            header_version,
            os_version,
            name,
            cmdline,
        };

        let ps = page_size as u64;
        let kernel_offset = ps;
        let kernel_pages = (u64::from(kernel_size) + ps - 1) / ps;
        let ramdisk_offset = kernel_offset + kernel_pages * ps;
        let ramdisk_pages = (u64::from(ramdisk_size) + ps - 1) / ps;
        let second_offset = ramdisk_offset + ramdisk_pages * ps;

        Ok(Self {
            header,
            kernel_offset,
            ramdisk_offset,
            second_offset,
        })
    }

    /// Extract kernel, ramdisk, and second stage to an output directory.
    pub fn unpack(&self, image_path: &Path, output_dir: &Path) -> andro_core::Result<()> {
        let data = std::fs::read(image_path)?;
        std::fs::create_dir_all(output_dir)?;

        if self.header.kernel_size > 0 {
            let start = self.kernel_offset as usize;
            let end = start + self.header.kernel_size as usize;
            if end <= data.len() {
                std::fs::write(output_dir.join("kernel"), &data[start..end])?;
            }
        }

        if self.header.ramdisk_size > 0 {
            let start = self.ramdisk_offset as usize;
            let end = start + self.header.ramdisk_size as usize;
            if end <= data.len() {
                std::fs::write(output_dir.join("ramdisk.gz"), &data[start..end])?;
            }
        }

        if self.header.second_size > 0 {
            let start = self.second_offset as usize;
            let end = start + self.header.second_size as usize;
            if end <= data.len() {
                std::fs::write(output_dir.join("second"), &data[start..end])?;
            }
        }

        let info = serde_json::to_string_pretty(self)
            .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
        std::fs::write(output_dir.join("boot_info.json"), info)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_magic_bytes() {
        assert_eq!(&BOOT_MAGIC, b"ANDROID!");
    }
}
