//! Trait boundaries for all Android protocol integration points.
//!
//! Every external dependency (ADB, USB, SQLite, ZIP, fastboot, etc.)
//! is behind a trait for testability. Mock implementations in `mocks` module.

use crate::error::Result;
use crate::device::{DeviceId, DeviceInfo};
use crate::types::*;
use std::path::Path;

// ── Tier 1: Transport Layer ────────────────────────────────────────────

/// ADB protocol transport — device communication over TCP or USB.
pub trait AdbTransport: Send + Sync {
    /// List connected devices.
    fn devices(&mut self) -> Result<Vec<DeviceInfo>>;

    /// Execute a shell command on a device, return stdout.
    fn shell(&mut self, serial: &str, command: &str) -> Result<crate::ShellOutput>;

    /// Push a file from host to device. Returns bytes transferred.
    fn push(&mut self, serial: &str, local: &Path, remote: &str) -> Result<u64>;

    /// Pull a file from device to host. Returns bytes transferred.
    fn pull(&mut self, serial: &str, remote: &str, local: &Path) -> Result<u64>;

    /// Install an APK on a device.
    fn install(&mut self, serial: &str, apk: &Path) -> Result<()>;

    /// Reboot the device to a target.
    fn reboot(&mut self, serial: &str, target: RebootTarget) -> Result<()>;
}

/// USB device enumeration — discover connected USB devices.
pub trait UsbEnumerator: Send + Sync {
    /// List all USB devices on the bus.
    fn list_devices(&self) -> Result<Vec<UsbDeviceInfo>>;
}

/// Fastboot protocol transport — bootloader communication over USB.
pub trait FastbootTransport: Send + Sync {
    /// Send a command and get the response.
    fn command(&mut self, cmd: &str) -> Result<FastbootResponse>;

    /// Get a bootloader variable value.
    fn getvar(&mut self, name: &str) -> Result<String>;

    /// Send data to the device (download payload).
    fn send_data(&mut self, data: &[u8]) -> Result<()>;

    /// Flash a partition with previously downloaded data.
    fn flash(&mut self, partition: &str) -> Result<()>;

    /// Erase a partition.
    fn erase(&mut self, partition: &str) -> Result<()>;

    /// Reboot the device.
    fn reboot(&mut self) -> Result<()>;
}

// ── Tier 2: Format Parsers ─────────────────────────────────────────────

/// Android boot image parser (v0-v4).
pub trait BootImageParser: Send + Sync {
    /// Parse boot image from raw bytes.
    fn parse(&self, data: &[u8]) -> Result<crate::device::DeviceInfo>; // Using BootImage from types

    /// Unpack boot image into components (kernel, ramdisk, dtb).
    fn unpack(&self, data: &[u8]) -> Result<BootComponents>;

    /// Repack components into a boot image.
    fn repack(&self, components: &BootComponents) -> Result<Vec<u8>>;
}

/// DEX file parser.
pub trait DexParser: Send + Sync {
    /// Parse a DEX file from raw bytes.
    fn parse(&self, data: &[u8]) -> Result<DexFile>;
}

/// Android binary XML (AXML) parser.
pub trait AxmlParser: Send + Sync {
    /// Parse binary XML from raw bytes.
    fn parse(&self, data: &[u8]) -> Result<XmlDocument>;

    /// Extract package name from a parsed manifest.
    fn package_name(&self, doc: &XmlDocument) -> Option<String>;

    /// Extract declared permissions from a parsed manifest.
    fn permissions(&self, doc: &XmlDocument) -> Vec<String>;

    /// Extract minSdkVersion.
    fn min_sdk(&self, doc: &XmlDocument) -> Option<u32>;

    /// Extract targetSdkVersion.
    fn target_sdk(&self, doc: &XmlDocument) -> Option<u32>;
}

/// APK signature verification (schemes v1-v4).
pub trait ApkSignatureVerifier: Send + Sync {
    /// Find the APK signing block in a ZIP file.
    fn find_signing_block(&self, data: &[u8]) -> Result<Option<SigningBlock>>;

    /// Verify APK signature and return result.
    fn verify(&self, data: &[u8]) -> Result<SignatureResult>;

    /// Extract certificates from the signing block.
    fn certificates(&self, data: &[u8]) -> Result<Vec<Certificate>>;
}

/// Android Verified Boot (AVB) VBMeta parser.
pub trait VbmetaParser: Send + Sync {
    /// Parse VBMeta image from raw bytes.
    fn parse(&self, data: &[u8]) -> Result<VbmetaImage>;

    /// Verify VBMeta signature against a public key.
    fn verify(&self, image: &VbmetaImage, public_key: &[u8]) -> Result<bool>;
}

/// Android sparse image format parser.
pub trait SparseImageParser: Send + Sync {
    /// Parse sparse image from raw bytes.
    fn parse(&self, data: &[u8]) -> Result<SparseImage>;

    /// Convert sparse image to raw (unsparsed) data.
    fn to_raw(&self, sparse: &SparseImage) -> Result<Vec<u8>>;

    /// Create sparse image from raw data.
    fn from_raw(&self, data: &[u8], block_size: u32) -> Result<SparseImage>;
}

// ── Tier 3: I/O Abstraction ────────────────────────────────────────────

/// Archive (ZIP/APK/AAB) reading.
pub trait ArchiveReader: Send + Sync {
    /// List all entries in the archive.
    fn list_entries(&self, data: &[u8]) -> Result<Vec<ArchiveEntry>>;

    /// Read a specific entry's contents.
    fn read_entry(&self, data: &[u8], path: &str) -> Result<Vec<u8>>;

    /// Get metadata for a specific entry.
    fn entry_metadata(&self, data: &[u8], path: &str) -> Result<EntryMetadata>;
}

/// Logcat format parser — text and binary formats.
pub trait LogcatParser: Send + Sync {
    /// Parse a threadtime-format logcat line.
    fn parse_text_line(&self, line: &str) -> Option<crate::LogEntry>;

    /// Parse a binary logger entry (28-byte header + payload).
    fn parse_binary_entry(&self, data: &[u8]) -> Result<crate::LogEntry>;
}

// ── Tier 3b: Attestation ───────────────────────────────────────────────

/// Device attestation verification — GrapheneOS Auditor/AttestationServer protocol.
/// Integrates with tameshi's BLAKE3 Merkle tree for infrastructure attestation.
pub trait AttestationVerifier: Send + Sync {
    /// Verify device attestation against a challenge.
    fn verify(&self, challenge: &[u8], response: &[u8]) -> Result<AttestationResult>;

    /// Generate a challenge for device attestation.
    fn generate_challenge(&self) -> Result<Vec<u8>>;

    /// Get the attestation trust chain for a device.
    fn trust_chain(&self, device_id: &str) -> Result<Vec<AttestationCert>>;
}

/// OTA update provider — check and fetch updates from release servers.
pub trait OtaProvider: Send + Sync {
    /// Check for available updates for a device on a channel.
    fn check_update(&self, device: &str, channel: &str) -> Result<Option<OtaManifest>>;

    /// Verify an OTA payload's integrity.
    fn verify_payload(&self, payload: &[u8], expected_hash: &str) -> Result<bool>;
}

// ── Tier 4: Storage ────────────────────────────────────────────────────

/// Database storage backend — abstracts SQLite for testability.
pub trait StorageBackend: Send + Sync {
    /// Execute a SQL statement, return rows affected.
    fn execute(&self, sql: &str, params: &[&str]) -> Result<usize>;

    /// Execute a batch of SQL statements (schema creation, etc.).
    fn execute_batch(&self, sql: &str) -> Result<()>;

    /// Query rows from a table.
    fn query_rows(&self, sql: &str, params: &[&str]) -> Result<Vec<Row>>;

    /// Count rows in a table.
    fn count(&self, table: &str) -> Result<u64>;

    /// Delete rows older than N days based on a timestamp column.
    fn prune(&self, table: &str, ts_col: &str, days: u32) -> Result<u64>;
}
