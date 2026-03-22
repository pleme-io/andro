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

    /// Build a synthetic v0 boot image header (1648+ bytes) written to a temp file.
    fn build_v0_boot_image(
        kernel_size: u32,
        ramdisk_size: u32,
        second_size: u32,
        page_size: u32,
        name: &str,
        cmdline: &str,
    ) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "andro_hw_boot_test_{}_{}.img",
            std::process::id(),
            id
        ));

        let mut buf = vec![0u8; HEADER_SIZE];
        // magic
        buf[..8].copy_from_slice(b"ANDROID!");
        // kernel_size @ 8
        buf[8..12].copy_from_slice(&kernel_size.to_le_bytes());
        // kernel_addr @ 12
        buf[12..16].copy_from_slice(&0x0080_0000u32.to_le_bytes());
        // ramdisk_size @ 16
        buf[16..20].copy_from_slice(&ramdisk_size.to_le_bytes());
        // ramdisk_addr @ 20
        buf[20..24].copy_from_slice(&0x0100_0000u32.to_le_bytes());
        // second_size @ 24
        buf[24..28].copy_from_slice(&second_size.to_le_bytes());
        // second_addr @ 28
        buf[28..32].copy_from_slice(&0x0_u32.to_le_bytes());
        // tags_addr @ 32
        buf[32..36].copy_from_slice(&0x0_u32.to_le_bytes());
        // page_size @ 36
        buf[36..40].copy_from_slice(&page_size.to_le_bytes());
        // header_version @ 40
        buf[40..44].copy_from_slice(&0u32.to_le_bytes());
        // os_version @ 44
        buf[44..48].copy_from_slice(&0u32.to_le_bytes());
        // name @ 48..64 (16 bytes)
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len().min(16);
        buf[48..48 + name_len].copy_from_slice(&name_bytes[..name_len]);
        // cmdline @ 64..576 (512 bytes)
        let cmd_bytes = cmdline.as_bytes();
        let cmd_len = cmd_bytes.len().min(512);
        buf[64..64 + cmd_len].copy_from_slice(&cmd_bytes[..cmd_len]);

        // Pad with enough data after the header to cover kernel + ramdisk + second
        let pages_fn = |size: u32, ps: u32| -> u32 {
            if ps == 0 { 0 } else { (size + ps - 1) / ps }
        };
        let total_pages = 1 // header page
            + pages_fn(kernel_size, page_size)
            + pages_fn(ramdisk_size, page_size)
            + pages_fn(second_size, page_size);
        let total_size = total_pages as usize * page_size as usize;
        buf.resize(total_size.max(HEADER_SIZE), 0xAA);

        std::fs::write(&path, &buf).unwrap();
        path
    }

    #[test]
    fn parse_valid_v0_header() {
        let path = build_v0_boot_image(4096, 2048, 0, 4096, "testboot", "console=ttyS0");
        let boot = BootImage::parse(&path).unwrap();
        assert_eq!(boot.header.kernel_size, 4096);
        assert_eq!(boot.header.ramdisk_size, 2048);
        assert_eq!(boot.header.page_size, 4096);
        assert_eq!(boot.header.header_version, 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn parse_rejects_data_shorter_than_header() {
        let path = std::env::temp_dir().join(format!(
            "andro_hw_short_{}.img",
            std::process::id()
        ));
        // Write only 100 bytes — well under 1648
        std::fs::write(&path, &[0u8; 100]).unwrap();
        let result = BootImage::parse(&path);
        assert!(result.is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn parse_rejects_wrong_magic() {
        let path = std::env::temp_dir().join(format!(
            "andro_hw_badmagic_{}.img",
            std::process::id()
        ));
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[..8].copy_from_slice(b"INVALID!");
        std::fs::write(&path, &buf).unwrap();
        let result = BootImage::parse(&path);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("bad magic"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn header_fields_correct_after_parse() {
        let path = build_v0_boot_image(8192, 4096, 1024, 2048, "mydevice", "");
        let boot = BootImage::parse(&path).unwrap();
        assert_eq!(boot.header.kernel_size, 8192);
        assert_eq!(boot.header.kernel_addr, 0x0080_0000);
        assert_eq!(boot.header.ramdisk_size, 4096);
        assert_eq!(boot.header.ramdisk_addr, 0x0100_0000);
        assert_eq!(boot.header.second_size, 1024);
        assert_eq!(boot.header.page_size, 2048);
        assert_eq!(boot.header.name, "mydevice");
        // Verify offsets are page-aligned
        assert_eq!(boot.kernel_offset, 2048);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn cmdline_extraction() {
        let cmdline_str = "console=ttyMSM0,115200n8 androidboot.hardware=sargo";
        let path = build_v0_boot_image(4096, 2048, 0, 4096, "", cmdline_str);
        let boot = BootImage::parse(&path).unwrap();
        assert_eq!(boot.header.cmdline, cmdline_str);
        let _ = std::fs::remove_file(&path);
    }
}
