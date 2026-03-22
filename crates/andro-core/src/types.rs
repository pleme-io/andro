//! Shared protocol types used across trait boundaries.

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ── ADB types ──────────────────────────────────────────────────────────

/// Options for logcat streaming.
#[derive(Debug, Clone, Default)]
pub struct LogcatOptions {
    pub buffers: Vec<LogBuffer>,
    pub filter_tag: Option<String>,
    pub filter_priority: Option<u8>,
    pub max_entries: Option<usize>,
}

/// Log buffer identifiers.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LogBuffer {
    Main,
    System,
    Radio,
    Events,
    Crash,
    Stats,
    Security,
    Kernel,
}

/// Reboot target for ADB/fastboot.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RebootTarget {
    System,
    Bootloader,
    Recovery,
    Sideload,
    Fastboot,
}

/// Raw framebuffer capture.
#[derive(Debug, Clone)]
pub struct FramebufferImage {
    pub width: u32,
    pub height: u32,
    pub bpp: u32,
    pub data: Vec<u8>,
}

// ── Fastboot types ─────────────────────────────────────────────────────

/// Fastboot protocol response.
#[derive(Debug, Clone)]
pub enum FastbootResponse {
    Okay(String),
    Fail(String),
    Data(u32),
    Info(String),
}

/// A/B slot identifier.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Slot {
    A,
    B,
}

// ── USB types ──────────────────────────────────────────────────────────

/// Information about a USB device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDeviceInfo {
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial: Option<String>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
}

// ── Boot image types ───────────────────────────────────────────────────

/// Unpacked boot image components.
#[derive(Debug, Clone)]
pub struct BootComponents {
    pub kernel: Vec<u8>,
    pub ramdisk: Vec<u8>,
    pub second: Option<Vec<u8>>,
    pub dtb: Option<Vec<u8>>,
    pub cmdline: String,
    pub header_version: u32,
}

// ── DEX types ──────────────────────────────────────────────────────────

/// Parsed DEX file representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexFile {
    pub version: String,
    pub checksum: u32,
    pub file_size: u32,
    pub string_count: u32,
    pub type_count: u32,
    pub method_count: u32,
    pub class_count: u32,
    pub strings: Vec<String>,
}

// ── AXML types ─────────────────────────────────────────────────────────

/// Parsed Android binary XML document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmlDocument {
    pub string_pool: Vec<String>,
    pub resource_map: Vec<u32>,
    pub elements: Vec<XmlElement>,
}

/// An XML element with attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmlElement {
    pub namespace: Option<String>,
    pub name: String,
    pub attributes: Vec<XmlAttribute>,
    pub children: Vec<XmlElement>,
}

/// An XML attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmlAttribute {
    pub namespace: Option<String>,
    pub name: String,
    pub value: String,
    pub resource_id: Option<u32>,
}

// ── APK signing types ──────────────────────────────────────────────────

/// APK signing block parsed from the ZIP structure.
#[derive(Debug, Clone)]
pub struct SigningBlock {
    pub offset: u64,
    pub size: u64,
    pub pairs: Vec<SigningBlockPair>,
}

#[derive(Debug, Clone)]
pub struct SigningBlockPair {
    pub id: u32,
    pub data: Vec<u8>,
}

/// Result of APK signature verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureResult {
    pub valid: bool,
    pub scheme_version: u8,
    pub signer_count: usize,
    pub error: Option<String>,
}

/// X.509 certificate info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint_sha256: String,
}

// ── AVB types ──────────────────────────────────────────────────────────

/// Parsed VBMeta image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbmetaImage {
    pub algorithm: u32,
    pub rollback_index: u64,
    pub flags: u32,
    pub release_string: String,
    pub descriptors: Vec<AvbDescriptor>,
}

/// AVB descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AvbDescriptor {
    Property { key: String, value: String },
    Hashtree { partition: String, root_digest: Vec<u8>, algorithm: String },
    Hash { partition: String, digest: Vec<u8>, algorithm: String },
    KernelCmdline { cmdline: String },
    ChainPartition { partition: String, public_key: Vec<u8> },
}

// ── Sparse image types ─────────────────────────────────────────────────

/// Parsed sparse image.
#[derive(Debug, Clone)]
pub struct SparseImage {
    pub block_size: u32,
    pub total_blocks: u32,
    pub chunks: Vec<SparseChunk>,
}

/// A chunk in a sparse image.
#[derive(Debug, Clone)]
pub enum SparseChunk {
    Raw(Vec<u8>),
    Fill(u32, u32), // fill_value, block_count
    DontCare(u32),  // block_count
    Crc32(u32),
}

// ── Archive types ──────────────────────────────────────────────────────

/// Entry in a ZIP/APK archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub path: String,
    pub size: u64,
    pub compressed_size: u64,
    pub is_dir: bool,
}

/// Metadata about an archive entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryMetadata {
    pub path: String,
    pub size: u64,
    pub compressed_size: u64,
    pub crc32: u32,
    pub compression_method: u16,
}

// ── Logcat binary types ────────────────────────────────────────────────

/// Binary event log value (from events buffer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventLogValue {
    Int(u32),
    Long(u64),
    Float(f32),
    String(String),
    List(Vec<EventLogValue>),
}

// ── Shell output ───────────────────────────────────────────────────────

/// Output from a shell command execution (shared across ADB trait + crates).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellOutput {
    pub device: crate::DeviceId,
    pub stdout: String,
    pub exit_code: Option<i32>,
}

// ── Log types ──────────────────────────────────────────────────────────

/// Android log level.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum LogLevel {
    Verbose,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
    Silent,
}

/// A parsed logcat line (shared across log parser + traits).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: Option<NaiveDateTime>,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub level: LogLevel,
    pub tag: String,
    pub message: String,
    pub raw: String,
}

// ── Storage types ──────────────────────────────────────────────────────

/// A generic database row as key-value pairs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub values: std::collections::HashMap<String, serde_json::Value>,
}
