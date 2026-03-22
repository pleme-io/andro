//! DEX file format parser.
//!
//! Parses the 112-byte DEX header, reads the string ID table, and follows
//! each offset to decode MUTF-8 length-prefixed strings. Implements the
//! [`DexParser`](andro_core::traits::DexParser) trait from `andro-core`.

use andro_core::error::{AndroError, Result};
use andro_core::traits::DexParser;
use andro_core::types::DexFile;

/// DEX magic: `dex\n035\0` (8 bytes).
const DEX_MAGIC: [u8; 8] = [0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00];

/// Minimum DEX file size: the 112-byte header.
const DEX_HEADER_SIZE: usize = 112;

// ── Header field offsets (little-endian u32) ─────────────────────────────

const OFF_CHECKSUM: usize = 8;
const OFF_FILE_SIZE: usize = 32;
const OFF_STRING_IDS_SIZE: usize = 56;
const OFF_STRING_IDS_OFF: usize = 60;
const OFF_TYPE_IDS_SIZE: usize = 64;
const OFF_METHOD_IDS_SIZE: usize = 88;
const OFF_CLASS_DEFS_SIZE: usize = 96;

/// Concrete DEX parser that operates on raw bytes.
#[derive(Debug, Default, Clone)]
pub struct DexFileParser;

impl DexFileParser {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl DexParser for DexFileParser {
    fn parse(&self, data: &[u8]) -> Result<DexFile> {
        parse_dex(data)
    }
}

/// Parse a DEX file from raw bytes.
///
/// # Errors
///
/// Returns [`AndroError::Other`] when:
/// - The data is shorter than 112 bytes (header).
/// - The magic bytes do not match `dex\n035\0`.
/// - A string ID offset points outside the data.
/// - A MUTF-8 string length prefix cannot be decoded.
fn parse_dex(data: &[u8]) -> Result<DexFile> {
    if data.len() < DEX_HEADER_SIZE {
        return Err(AndroError::Other(format!(
            "DEX file too short: {} bytes, need at least {DEX_HEADER_SIZE}",
            data.len()
        )));
    }

    // ── Validate magic ───────────────────────────────────────────────
    if data[..8] != DEX_MAGIC {
        return Err(AndroError::Other(
            "invalid DEX magic (expected dex\\n035\\0)".into(),
        ));
    }

    let version = "035".to_owned();

    // ── Read header fields ───────────────────────────────────────────
    let checksum = read_u32_le(data, OFF_CHECKSUM);
    let file_size = read_u32_le(data, OFF_FILE_SIZE);
    let string_ids_size = read_u32_le(data, OFF_STRING_IDS_SIZE);
    let string_ids_off = read_u32_le(data, OFF_STRING_IDS_OFF);
    let type_ids_size = read_u32_le(data, OFF_TYPE_IDS_SIZE);
    let method_ids_size = read_u32_le(data, OFF_METHOD_IDS_SIZE);
    let class_defs_size = read_u32_le(data, OFF_CLASS_DEFS_SIZE);

    // ── Read string table ────────────────────────────────────────────
    let strings = read_string_table(data, string_ids_size, string_ids_off)?;

    Ok(DexFile {
        version,
        checksum,
        file_size,
        string_count: string_ids_size,
        type_count: type_ids_size,
        method_count: method_ids_size,
        class_count: class_defs_size,
        strings,
    })
}

/// Read a little-endian `u32` at the given byte offset.
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Read the string ID table (array of `u32` data offsets) and decode each
/// referenced MUTF-8 string.
fn read_string_table(data: &[u8], count: u32, ids_offset: u32) -> Result<Vec<String>> {
    let count = count as usize;
    let ids_offset = ids_offset as usize;

    let ids_end = ids_offset
        .checked_add(count.checked_mul(4).ok_or_else(|| {
            AndroError::Other("string_ids_size overflow".into())
        })?)
        .ok_or_else(|| AndroError::Other("string_ids table overflows address space".into()))?;

    if ids_end > data.len() {
        return Err(AndroError::Other(format!(
            "string_ids table extends past end of data ({ids_end} > {})",
            data.len()
        )));
    }

    let mut strings = Vec::with_capacity(count);

    for i in 0..count {
        let id_off = ids_offset + i * 4;
        let string_data_off = read_u32_le(data, id_off) as usize;

        if string_data_off >= data.len() {
            return Err(AndroError::Other(format!(
                "string data offset {string_data_off} out of bounds (file len {})",
                data.len()
            )));
        }

        let s = read_mutf8_string(data, string_data_off)?;
        strings.push(s);
    }

    Ok(strings)
}

/// Decode a MUTF-8 length-prefixed string at the given offset.
///
/// The encoding uses ULEB128 for the character count (number of UTF-16 code
/// units), followed by a modified UTF-8 payload terminated by a null byte.
/// We read until the null terminator rather than trusting the length prefix,
/// which is the standard approach for DEX string parsing.
fn read_mutf8_string(data: &[u8], offset: usize) -> Result<String> {
    let mut pos = offset;

    // ── Skip ULEB128 length prefix ───────────────────────────────────
    // Each byte contributes 7 bits; high bit set means "more bytes follow".
    loop {
        if pos >= data.len() {
            return Err(AndroError::Other(
                "ULEB128 length extends past end of data".into(),
            ));
        }
        let b = data[pos];
        pos += 1;
        if b & 0x80 == 0 {
            break;
        }
    }

    // ── Read MUTF-8 bytes until null terminator ──────────────────────
    let start = pos;
    while pos < data.len() && data[pos] != 0 {
        pos += 1;
    }

    let bytes = &data[start..pos];

    // MUTF-8 is mostly UTF-8 compatible for ASCII and BMP characters.
    // For a robust parser we attempt direct UTF-8 first and fall back to
    // lossy conversion for supplementary-plane surrogates.
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal synthetic DEX binary with the given parameters.
    fn build_synthetic_dex(strings: &[&str]) -> Vec<u8> {
        // Header is 112 bytes.  String IDs table starts right after.
        let string_ids_off: u32 = DEX_HEADER_SIZE as u32;
        let string_count = strings.len() as u32;
        let string_ids_table_size = string_count as usize * 4;

        // String data starts right after the IDs table.
        let string_data_start = DEX_HEADER_SIZE + string_ids_table_size;

        // Pre-compute encoded strings: ULEB128 length + MUTF-8 bytes + null.
        let mut encoded_strings: Vec<Vec<u8>> = Vec::new();
        for s in strings {
            let mut enc = Vec::new();
            // ULEB128-encode the length (number of UTF-16 code units ≈ byte
            // count for ASCII).
            let mut len = s.len();
            loop {
                let mut byte = (len & 0x7F) as u8;
                len >>= 7;
                if len != 0 {
                    byte |= 0x80;
                }
                enc.push(byte);
                if len == 0 {
                    break;
                }
            }
            enc.extend_from_slice(s.as_bytes());
            enc.push(0); // null terminator
            encoded_strings.push(enc);
        }

        // Total file size.
        let total_string_data: usize = encoded_strings.iter().map(Vec::len).sum();
        let file_size = string_data_start + total_string_data;

        let mut buf = vec![0u8; file_size];

        // ── Magic ────────────────────────────────────────────────────
        buf[..8].copy_from_slice(&DEX_MAGIC);

        // ── Checksum (offset 8) — use a known value ──────────────────
        let checksum: u32 = 0xDEAD_BEEF;
        buf[OFF_CHECKSUM..OFF_CHECKSUM + 4].copy_from_slice(&checksum.to_le_bytes());

        // ── File size (offset 32) ────────────────────────────────────
        buf[OFF_FILE_SIZE..OFF_FILE_SIZE + 4]
            .copy_from_slice(&(file_size as u32).to_le_bytes());

        // ── String IDs size (offset 56) & offset (60) ────────────────
        buf[OFF_STRING_IDS_SIZE..OFF_STRING_IDS_SIZE + 4]
            .copy_from_slice(&string_count.to_le_bytes());
        buf[OFF_STRING_IDS_OFF..OFF_STRING_IDS_OFF + 4]
            .copy_from_slice(&string_ids_off.to_le_bytes());

        // ── Type/method/class counts ─────────────────────────────────
        let type_count: u32 = 3;
        let method_count: u32 = 7;
        let class_count: u32 = 2;
        buf[OFF_TYPE_IDS_SIZE..OFF_TYPE_IDS_SIZE + 4]
            .copy_from_slice(&type_count.to_le_bytes());
        buf[OFF_METHOD_IDS_SIZE..OFF_METHOD_IDS_SIZE + 4]
            .copy_from_slice(&method_count.to_le_bytes());
        buf[OFF_CLASS_DEFS_SIZE..OFF_CLASS_DEFS_SIZE + 4]
            .copy_from_slice(&class_count.to_le_bytes());

        // ── String IDs table (u32 offsets) ───────────────────────────
        let mut data_cursor = string_data_start;
        for i in 0..strings.len() {
            let table_off = DEX_HEADER_SIZE + i * 4;
            buf[table_off..table_off + 4]
                .copy_from_slice(&(data_cursor as u32).to_le_bytes());
            data_cursor += encoded_strings[i].len();
        }

        // ── String data ──────────────────────────────────────────────
        let mut pos = string_data_start;
        for enc in &encoded_strings {
            buf[pos..pos + enc.len()].copy_from_slice(enc);
            pos += enc.len();
        }

        buf
    }

    #[test]
    fn parse_minimal_header() {
        let dex = build_synthetic_dex(&[]);
        let parser = DexFileParser::new();
        let result = parser.parse(&dex).expect("should parse empty DEX");

        assert_eq!(result.version, "035");
        assert_eq!(result.checksum, 0xDEAD_BEEF);
        assert_eq!(result.file_size, DEX_HEADER_SIZE as u32);
        assert_eq!(result.string_count, 0);
        assert_eq!(result.type_count, 3);
        assert_eq!(result.method_count, 7);
        assert_eq!(result.class_count, 2);
        assert!(result.strings.is_empty());
    }

    #[test]
    fn parse_with_strings() {
        let dex = build_synthetic_dex(&["Hello", "com.example.App", "<init>"]);
        let parser = DexFileParser::new();
        let result = parser.parse(&dex).expect("should parse DEX with strings");

        assert_eq!(result.string_count, 3);
        assert_eq!(result.strings.len(), 3);
        assert_eq!(result.strings[0], "Hello");
        assert_eq!(result.strings[1], "com.example.App");
        assert_eq!(result.strings[2], "<init>");
    }

    #[test]
    fn reject_too_short() {
        let parser = DexFileParser::new();
        let result = parser.parse(&[0u8; 50]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("too short"), "error was: {msg}");
    }

    #[test]
    fn reject_bad_magic() {
        let mut dex = build_synthetic_dex(&[]);
        dex[0] = b'X'; // corrupt magic
        let parser = DexFileParser::new();
        let result = parser.parse(&dex);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("magic"), "error was: {msg}");
    }

    #[test]
    fn reject_out_of_bounds_string_id() {
        let mut dex = build_synthetic_dex(&["test"]);
        // Overwrite the string data offset to point way past the end.
        let table_off = DEX_HEADER_SIZE;
        let bad_offset: u32 = 0xFFFF_FFFF;
        dex[table_off..table_off + 4].copy_from_slice(&bad_offset.to_le_bytes());

        let parser = DexFileParser::new();
        let result = parser.parse(&dex);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("out of bounds"), "error was: {msg}");
    }

    #[test]
    fn parse_empty_string() {
        let dex = build_synthetic_dex(&[""]);
        let parser = DexFileParser::new();
        let result = parser.parse(&dex).expect("should parse DEX with empty string");
        assert_eq!(result.strings.len(), 1);
        assert_eq!(result.strings[0], "");
    }
}
