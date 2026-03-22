//! Android binary XML (AXML) parser.
//!
//! Decodes the chunk-based binary XML format used inside APK files
//! (e.g. `AndroidManifest.xml`). Implements `andro_core::traits::AxmlParser`.
//!
//! ## Binary format overview
//!
//! Every structure starts with a `ResChunk_header`:
//! - `type`       (u16) — chunk type identifier
//! - `headerSize` (u16) — header length in bytes
//! - `size`       (u32) — total chunk length including header
//!
//! Chunk types:
//! - `0x0003` — XML document (outermost container)
//! - `0x0001` — String pool
//! - `0x0180` — Resource ID map
//! - `0x0100` — Namespace start
//! - `0x0101` — Namespace end
//! - `0x0102` — Element start
//! - `0x0103` — Element end

use andro_core::error::{AndroError, Result};
use andro_core::traits::AxmlParser;
use andro_core::types::{XmlAttribute, XmlDocument, XmlElement};
use std::collections::HashMap;

// ── Chunk type constants ────────────────────────────────────────────────

const CHUNK_STRING_POOL: u16 = 0x0001;
const CHUNK_XML: u16 = 0x0003;
const CHUNK_XML_NS_START: u16 = 0x0100;
const CHUNK_XML_NS_END: u16 = 0x0101;
const CHUNK_XML_ELEM_START: u16 = 0x0102;
const CHUNK_XML_ELEM_END: u16 = 0x0103;
const CHUNK_RESOURCE_MAP: u16 = 0x0180;

// String pool flag indicating UTF-8 encoding.
const FLAG_UTF8: u32 = 1 << 8;

// ── Well-known Android resource IDs ─────────────────────────────────────

/// `android:name` — used in test builder; kept for completeness alongside other IDs.
#[cfg(test)]
const ATTR_NAME: u32 = 0x0101_0003;
const ATTR_MIN_SDK_VERSION: u32 = 0x0101_0020;
const ATTR_TARGET_SDK_VERSION: u32 = 0x0101_0270;

// ── AXML value types ────────────────────────────────────────────────────

const TYPE_NULL: u8 = 0x00;
const TYPE_REFERENCE: u8 = 0x01;
const TYPE_STRING: u8 = 0x03;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const TYPE_INT_BOOLEAN: u8 = 0x12;

// ── Binary reader helpers ───────────────────────────────────────────────

/// Read a little-endian u16 at `offset`.
fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    if offset + 2 > data.len() {
        return Err(AndroError::Other("axml: unexpected end of data reading u16".into()));
    }
    Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

/// Read a little-endian u32 at `offset`.
fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    if offset + 4 > data.len() {
        return Err(AndroError::Other("axml: unexpected end of data reading u32".into()));
    }
    Ok(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Read a little-endian i32 at `offset`.
fn read_i32(data: &[u8], offset: usize) -> Result<i32> {
    if offset + 4 > data.len() {
        return Err(AndroError::Other("axml: unexpected end of data reading i32".into()));
    }
    Ok(i32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

// ── String pool decoder ─────────────────────────────────────────────────

/// Decode the string pool starting at `base` in `data`.
///
/// Layout (offsets relative to `base`):
///   0..2   chunk type (0x0001)
///   2..4   header size
///   4..8   total chunk size
///   8..12  string count
///  12..16  style count
///  16..20  flags (bit 8 = UTF-8)
///  20..24  strings start (relative to `base`)
///  24..28  styles start
///  28..    string offset array (stringCount * u32)
fn decode_string_pool(data: &[u8], base: usize) -> Result<Vec<String>> {
    let string_count = read_u32(data, base + 8)? as usize;
    let flags = read_u32(data, base + 16)?;
    let strings_start = read_u32(data, base + 20)? as usize;
    let is_utf8 = (flags & FLAG_UTF8) != 0;

    let mut strings = Vec::with_capacity(string_count);

    for i in 0..string_count {
        let offset_pos = base + 28 + i * 4;
        let str_offset = read_u32(data, offset_pos)? as usize;
        let abs = base + strings_start + str_offset;

        if abs >= data.len() {
            strings.push(String::new());
            continue;
        }

        let s = if is_utf8 {
            decode_utf8_string(data, abs)?
        } else {
            decode_utf16_string(data, abs)?
        };
        strings.push(s);
    }

    Ok(strings)
}

/// Decode a UTF-8 length-prefixed string.
///
/// Format: charLen (1-2 bytes) + byteLen (1-2 bytes) + data + NUL.
fn decode_utf8_string(data: &[u8], offset: usize) -> Result<String> {
    let mut pos = offset;

    // Skip char length (1 or 2 bytes).
    if pos >= data.len() {
        return Ok(String::new());
    }
    if data[pos] & 0x80 != 0 {
        pos += 2;
    } else {
        pos += 1;
    }

    // Read byte length (1 or 2 bytes).
    if pos >= data.len() {
        return Ok(String::new());
    }
    let byte_len = if data[pos] & 0x80 != 0 {
        if pos + 1 >= data.len() {
            return Ok(String::new());
        }
        let hi = u16::from(data[pos] & 0x7F);
        let lo = u16::from(data[pos + 1]);
        pos += 2;
        (hi << 8 | lo) as usize
    } else {
        let l = data[pos] as usize;
        pos += 1;
        l
    };

    let end = (pos + byte_len).min(data.len());
    String::from_utf8(data[pos..end].to_vec())
        .map_err(|e| AndroError::Other(format!("axml: invalid utf-8 string: {e}")))
}

/// Decode a UTF-16LE length-prefixed string.
///
/// Format: charLen(u16) + data(charLen * 2 bytes) + NUL(u16).
fn decode_utf16_string(data: &[u8], offset: usize) -> Result<String> {
    if offset + 2 > data.len() {
        return Ok(String::new());
    }

    let char_len = if read_u16(data, offset)? & 0x8000 != 0 {
        // High bit set means two u16s encode the length.
        if offset + 4 > data.len() {
            return Ok(String::new());
        }
        let hi = u32::from(read_u16(data, offset)? & 0x7FFF);
        let lo = u32::from(read_u16(data, offset + 2)?);
        (hi << 16 | lo) as usize
    } else {
        read_u16(data, offset)? as usize
    };

    // Determine where the u16 data starts.
    let str_start = if read_u16(data, offset)? & 0x8000 != 0 {
        offset + 4
    } else {
        offset + 2
    };

    let byte_count = char_len * 2;
    let end = (str_start + byte_count).min(data.len());
    if end < str_start {
        return Ok(String::new());
    }

    let units: Vec<u16> = (str_start..end)
        .step_by(2)
        .filter_map(|i| {
            if i + 1 < data.len() {
                Some(u16::from_le_bytes([data[i], data[i + 1]]))
            } else {
                None
            }
        })
        .collect();

    String::from_utf16(&units)
        .map_err(|e| AndroError::Other(format!("axml: invalid utf-16 string: {e}")))
}

// ── Format a typed attribute value as a string ──────────────────────────

fn format_value(value_type: u8, value_data: u32, strings: &[String]) -> String {
    match value_type {
        TYPE_STRING => strings
            .get(value_data as usize)
            .cloned()
            .unwrap_or_default(),
        TYPE_INT_DEC => value_data.to_string(),
        TYPE_INT_HEX => format!("0x{value_data:08x}"),
        TYPE_INT_BOOLEAN => {
            if value_data != 0 {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        TYPE_REFERENCE => format!("@0x{value_data:08x}"),
        TYPE_NULL => String::new(),
        _ => format!("0x{value_data:08x}"),
    }
}

// ── Core parser ─────────────────────────────────────────────────────────

/// Internal parsing state used while walking through the AXML chunks.
struct ParseState {
    strings: Vec<String>,
    resource_map: Vec<u32>,
    /// Map from namespace URI string index to prefix string index.
    ns_prefixes: HashMap<u32, u32>,
}

/// Resolve a string pool index to its string, returning `None` for 0xFFFFFFFF.
fn resolve_string(strings: &[String], idx: u32) -> Option<String> {
    if idx == 0xFFFF_FFFF {
        None
    } else {
        strings.get(idx as usize).cloned()
    }
}

/// Parse the full binary XML stream and return an `XmlDocument`.
fn parse_axml(data: &[u8]) -> Result<XmlDocument> {
    if data.len() < 8 {
        return Err(AndroError::Other("axml: data too short".into()));
    }

    let doc_type = read_u16(data, 0)?;
    if doc_type != CHUNK_XML {
        return Err(AndroError::Other(format!(
            "axml: expected XML document chunk (0x0003), got 0x{doc_type:04x}"
        )));
    }

    let mut state = ParseState {
        strings: Vec::new(),
        resource_map: Vec::new(),
        ns_prefixes: HashMap::new(),
    };

    // Element stack for building the tree.
    let mut root_elements: Vec<XmlElement> = Vec::new();
    let mut stack: Vec<XmlElement> = Vec::new();

    // Walk chunks inside the document.
    let doc_header_size = read_u16(data, 2)? as usize;
    let mut pos = doc_header_size;

    while pos + 8 <= data.len() {
        let chunk_type = read_u16(data, pos)?;
        let chunk_header_size = read_u16(data, pos + 2)? as usize;
        let chunk_size = read_u32(data, pos + 4)? as usize;

        if chunk_size < 8 || pos + chunk_size > data.len() {
            break;
        }

        match chunk_type {
            CHUNK_STRING_POOL => {
                state.strings = decode_string_pool(data, pos)?;
            }
            CHUNK_RESOURCE_MAP => {
                let count = (chunk_size - chunk_header_size) / 4;
                let mut ids = Vec::with_capacity(count);
                for i in 0..count {
                    ids.push(read_u32(data, pos + chunk_header_size + i * 4)?);
                }
                state.resource_map = ids;
            }
            CHUNK_XML_NS_START => {
                // After the 16-byte header (ResChunk_header + lineNumber + comment),
                // the extension has: prefix(u32), uri(u32).
                let prefix_idx = read_u32(data, pos + chunk_header_size)?;
                let uri_idx = read_u32(data, pos + chunk_header_size + 4)?;
                state.ns_prefixes.insert(uri_idx, prefix_idx);
            }
            CHUNK_XML_NS_END => {
                // Nothing to do on namespace end for our purposes.
            }
            CHUNK_XML_ELEM_START => {
                let elem = parse_element_start(data, pos, chunk_header_size, &state)?;
                stack.push(elem);
            }
            CHUNK_XML_ELEM_END => {
                if let Some(elem) = stack.pop() {
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(elem);
                    } else {
                        root_elements.push(elem);
                    }
                }
            }
            _ => {
                // Unknown chunk — skip.
            }
        }

        pos += chunk_size;
    }

    // If anything remains on the stack (malformed), drain it.
    while let Some(elem) = stack.pop() {
        if let Some(parent) = stack.last_mut() {
            parent.children.push(elem);
        } else {
            root_elements.push(elem);
        }
    }

    Ok(XmlDocument {
        string_pool: state.strings,
        resource_map: state.resource_map,
        elements: root_elements,
    })
}

/// Parse an element-start chunk into an `XmlElement` (without children yet).
fn parse_element_start(
    data: &[u8],
    chunk_pos: usize,
    header_size: usize,
    state: &ParseState,
) -> Result<XmlElement> {
    // The 16-byte header includes ResChunk_header(8) + lineNumber(4) + comment(4).
    // After the header, the element-start extension (ResXMLTree_attrExt) is:
    //   0..4   namespace URI index (i32)
    //   4..8   name index (i32)
    //   8..10  attributeStart (u16) — offset from ext_base to first attribute
    //  10..12  attributeSize (u16)  — bytes per attribute (typically 20)
    //  12..14  attributeCount (u16)
    //  14..16  idIndex (u16)
    //  16..18  classIndex (u16)
    //  18..20  styleIndex (u16)
    let ext_base = chunk_pos + header_size;

    let ns_idx = read_i32(data, ext_base)?;
    let name_idx = read_i32(data, ext_base + 4)?;
    let attr_start = read_u16(data, ext_base + 8)? as usize;
    let attr_size = read_u16(data, ext_base + 10)? as usize;
    let attr_count = read_u16(data, ext_base + 12)? as usize;

    let namespace = if ns_idx >= 0 {
        resolve_string(&state.strings, ns_idx as u32)
    } else {
        None
    };

    let name = if name_idx >= 0 {
        resolve_string(&state.strings, name_idx as u32).unwrap_or_default()
    } else {
        String::new()
    };

    // Each attribute is `attr_size` bytes (typically 20).
    let attr_actual_size = if attr_size == 0 { 20 } else { attr_size };
    let attrs_base = ext_base + attr_start;

    let mut attributes = Vec::with_capacity(attr_count);
    for i in 0..attr_count {
        let a = attrs_base + i * attr_actual_size;
        if a + 20 > data.len() {
            break;
        }

        let attr_ns_idx = read_i32(data, a)?;
        let attr_name_idx = read_i32(data, a + 4)?;
        let raw_value_idx = read_i32(data, a + 8)?; // raw (string) value index
        let _typed_size = read_u16(data, a + 12)?;
        let _typed_res0 = data.get(a + 14).copied().unwrap_or(0);
        let typed_type = data.get(a + 15).copied().unwrap_or(0);
        let typed_data = read_u32(data, a + 16)?;

        let attr_namespace = if attr_ns_idx >= 0 {
            resolve_string(&state.strings, attr_ns_idx as u32)
        } else {
            None
        };

        let attr_name = if attr_name_idx >= 0 {
            resolve_string(&state.strings, attr_name_idx as u32).unwrap_or_default()
        } else {
            String::new()
        };

        // Prefer typed value. Fall back to raw string value.
        let value = if typed_type == TYPE_STRING {
            resolve_string(&state.strings, typed_data).unwrap_or_default()
        } else if typed_type != TYPE_NULL {
            format_value(typed_type, typed_data, &state.strings)
        } else if raw_value_idx >= 0 {
            resolve_string(&state.strings, raw_value_idx as u32).unwrap_or_default()
        } else {
            String::new()
        };

        // Map attribute name index to resource id if available.
        let resource_id = if attr_name_idx >= 0 {
            state.resource_map.get(attr_name_idx as usize).copied()
        } else {
            None
        };

        attributes.push(XmlAttribute {
            namespace: attr_namespace,
            name: attr_name,
            value,
            resource_id,
        });
    }

    Ok(XmlElement {
        namespace,
        name,
        attributes,
        children: Vec::new(),
    })
}

// ── Trait implementation ────────────────────────────────────────────────

/// Concrete AXML parser.
pub struct BinaryXmlParser;

impl BinaryXmlParser {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for BinaryXmlParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AxmlParser for BinaryXmlParser {
    fn parse(&self, data: &[u8]) -> Result<XmlDocument> {
        parse_axml(data)
    }

    fn package_name(&self, doc: &XmlDocument) -> Option<String> {
        find_root_manifest(doc).and_then(|elem| {
            elem.attributes
                .iter()
                .find(|a| a.name == "package" && a.namespace.is_none())
                .map(|a| a.value.clone())
        })
    }

    fn permissions(&self, doc: &XmlDocument) -> Vec<String> {
        let mut perms = Vec::new();
        collect_permissions(&doc.elements, &mut perms);
        perms
    }

    fn min_sdk(&self, doc: &XmlDocument) -> Option<u32> {
        find_uses_sdk(doc).and_then(|elem| {
            elem.attributes
                .iter()
                .find(|a| {
                    a.name == "minSdkVersion"
                        || a.resource_id == Some(ATTR_MIN_SDK_VERSION)
                })
                .and_then(|a| a.value.parse::<u32>().ok())
        })
    }

    fn target_sdk(&self, doc: &XmlDocument) -> Option<u32> {
        find_uses_sdk(doc).and_then(|elem| {
            elem.attributes
                .iter()
                .find(|a| {
                    a.name == "targetSdkVersion"
                        || a.resource_id == Some(ATTR_TARGET_SDK_VERSION)
                })
                .and_then(|a| a.value.parse::<u32>().ok())
        })
    }
}

// ── Helpers for trait methods ───────────────────────────────────────────

/// Find the root `<manifest>` element.
fn find_root_manifest(doc: &XmlDocument) -> Option<&XmlElement> {
    doc.elements.iter().find(|e| e.name == "manifest")
}

/// Find the `<uses-sdk>` element (child of manifest).
fn find_uses_sdk(doc: &XmlDocument) -> Option<&XmlElement> {
    find_root_manifest(doc).and_then(|m| m.children.iter().find(|e| e.name == "uses-sdk"))
}

/// Recursively collect `android:name` from `<uses-permission>` elements.
fn collect_permissions(elements: &[XmlElement], out: &mut Vec<String>) {
    for elem in elements {
        if elem.name == "uses-permission" {
            if let Some(attr) = elem.attributes.iter().find(|a| a.name == "name") {
                out.push(attr.value.clone());
            }
        }
        collect_permissions(&elem.children, out);
    }
}

// ── Test helpers ────────────────────────────────────────────────────────

/// Build a minimal binary XML blob for testing.
///
/// This constructs a valid AXML byte stream from scratch, including the
/// XML document header, string pool, resource map, namespace, and elements.
#[cfg(test)]
mod test_builder {
    //! Minimal AXML byte-stream builder for unit tests.

    /// Write a little-endian u16.
    fn put_u16(buf: &mut Vec<u8>, v: u16) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a little-endian u32.
    fn put_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a little-endian i32.
    fn put_i32(buf: &mut Vec<u8>, v: i32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Encode a UTF-8 string in the AXML string pool format.
    fn encode_utf8_pool_string(s: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        let char_len = s.chars().count();
        let byte_len = s.len();

        // Char length (1 or 2 bytes).
        if char_len > 0x7F {
            buf.push(((char_len >> 8) as u8) | 0x80);
            buf.push((char_len & 0xFF) as u8);
        } else {
            buf.push(char_len as u8);
        }

        // Byte length (1 or 2 bytes).
        if byte_len > 0x7F {
            buf.push(((byte_len >> 8) as u8) | 0x80);
            buf.push((byte_len & 0xFF) as u8);
        } else {
            buf.push(byte_len as u8);
        }

        buf.extend_from_slice(s.as_bytes());
        buf.push(0); // NUL terminator
        buf
    }

    /// Build a string pool chunk (type 0x0001).
    fn build_string_pool(strings: &[&str]) -> Vec<u8> {
        let header_size: u16 = 28;
        let offsets_size = strings.len() * 4;

        // Encode all strings.
        let encoded: Vec<Vec<u8>> = strings.iter().map(|s| encode_utf8_pool_string(s)).collect();
        let mut offsets = Vec::new();
        let mut current_offset: u32 = 0;
        for e in &encoded {
            offsets.push(current_offset);
            current_offset += e.len() as u32;
        }
        let strings_data_len = current_offset as usize;

        let strings_start = header_size as u32 + offsets_size as u32;
        let total_size = strings_start as usize + strings_data_len;

        let mut buf = Vec::with_capacity(total_size);
        put_u16(&mut buf, 0x0001); // chunk type
        put_u16(&mut buf, header_size);
        put_u32(&mut buf, total_size as u32);
        put_u32(&mut buf, strings.len() as u32); // string count
        put_u32(&mut buf, 0); // style count
        put_u32(&mut buf, super::FLAG_UTF8); // flags (UTF-8)
        put_u32(&mut buf, strings_start); // strings start
        put_u32(&mut buf, 0); // styles start

        // String offset array.
        for off in &offsets {
            put_u32(&mut buf, *off);
        }

        // String data.
        for e in &encoded {
            buf.extend_from_slice(e);
        }

        buf
    }

    /// Build a resource map chunk (type 0x0180).
    fn build_resource_map(ids: &[u32]) -> Vec<u8> {
        let header_size: u16 = 8;
        let total = header_size as usize + ids.len() * 4;

        let mut buf = Vec::with_capacity(total);
        put_u16(&mut buf, 0x0180);
        put_u16(&mut buf, header_size);
        put_u32(&mut buf, total as u32);
        for id in ids {
            put_u32(&mut buf, *id);
        }
        buf
    }

    /// Build a namespace-start chunk.
    ///
    /// Total layout (24 bytes):
    ///   ResChunk_header: type(2) + headerSize(2) + size(4) = 8
    ///   ResXMLTree_node: lineNumber(4) + comment(4) = 8
    ///   ResXMLTree_namespaceExt: prefix(4) + uri(4) = 8
    fn build_ns_start(prefix_idx: u32, uri_idx: u32) -> Vec<u8> {
        let header_size: u16 = 16;
        let total: u32 = 24; // 16 header + 8 body
        let mut buf = Vec::with_capacity(total as usize);
        put_u16(&mut buf, 0x0100);
        put_u16(&mut buf, header_size);
        put_u32(&mut buf, total);
        put_u32(&mut buf, 1); // line number
        put_i32(&mut buf, -1); // comment
        put_u32(&mut buf, prefix_idx);
        put_u32(&mut buf, uri_idx);
        buf
    }

    /// Build a namespace-end chunk.
    ///
    /// Total layout (24 bytes): same as namespace-start.
    fn build_ns_end(prefix_idx: u32, uri_idx: u32) -> Vec<u8> {
        let header_size: u16 = 16;
        let total: u32 = 24; // 16 header + 8 body
        let mut buf = Vec::with_capacity(total as usize);
        put_u16(&mut buf, 0x0101);
        put_u16(&mut buf, header_size);
        put_u32(&mut buf, total);
        put_u32(&mut buf, 1);
        put_i32(&mut buf, -1);
        put_u32(&mut buf, prefix_idx);
        put_u32(&mut buf, uri_idx);
        buf
    }

    /// Attribute descriptor for element-start builder.
    pub struct TestAttr {
        pub ns_idx: i32,
        pub name_idx: i32,
        pub raw_value_idx: i32,
        pub typed_type: u8,
        pub typed_data: u32,
    }

    /// Build an element-start chunk.
    fn build_elem_start(ns_idx: i32, name_idx: i32, attrs: &[TestAttr]) -> Vec<u8> {
        let header_size: u16 = 16;
        let attr_start: u16 = 20; // relative to extension start
        let attr_size: u16 = 20;
        let ext_size = attr_start as usize + attrs.len() * attr_size as usize;
        let total = header_size as usize + ext_size;

        let mut buf = Vec::with_capacity(total);
        put_u16(&mut buf, 0x0102);
        put_u16(&mut buf, header_size);
        put_u32(&mut buf, total as u32);

        // Extension header.
        put_u32(&mut buf, 1); // line number
        put_i32(&mut buf, -1); // comment
        put_i32(&mut buf, ns_idx); // namespace
        put_i32(&mut buf, name_idx); // name
        put_u16(&mut buf, attr_start); // attributeStart
        put_u16(&mut buf, attr_size); // attributeSize
        put_u16(&mut buf, attrs.len() as u16); // attributeCount
        put_u16(&mut buf, 0); // idIndex
        put_u16(&mut buf, 0); // classIndex
        put_u16(&mut buf, 0); // styleIndex

        // Attributes.
        for a in attrs {
            put_i32(&mut buf, a.ns_idx);
            put_i32(&mut buf, a.name_idx);
            put_i32(&mut buf, a.raw_value_idx);
            // Typed value: size(u16) + res0(u8) + type(u8) + data(u32)
            put_u16(&mut buf, 8); // typed value size
            buf.push(0); // res0
            buf.push(a.typed_type);
            put_u32(&mut buf, a.typed_data);
        }

        buf
    }

    /// Build an element-end chunk.
    ///
    /// Total layout (24 bytes):
    ///   ResChunk_header: type(2) + headerSize(2) + size(4) = 8
    ///   ResXMLTree_node: lineNumber(4) + comment(4) = 8  (headerSize=16 covers these)
    ///   ResXMLTree_endElementExt: ns(4) + name(4) = 8
    fn build_elem_end(ns_idx: i32, name_idx: i32) -> Vec<u8> {
        let header_size: u16 = 16;
        let total: u32 = 24; // 16 header + 8 body
        let mut buf = Vec::with_capacity(total as usize);
        put_u16(&mut buf, 0x0103);
        put_u16(&mut buf, header_size);
        put_u32(&mut buf, total);
        put_u32(&mut buf, 1); // line number
        put_i32(&mut buf, -1); // comment
        put_i32(&mut buf, ns_idx);
        put_i32(&mut buf, name_idx);
        buf
    }

    /// Build a complete binary XML document for a simple Android manifest.
    ///
    /// Produces a document equivalent to:
    /// ```xml
    /// <manifest package="com.example.app">
    ///   <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34" />
    ///   <uses-permission android:name="android.permission.INTERNET" />
    ///   <uses-permission android:name="android.permission.CAMERA" />
    /// </manifest>
    /// ```
    pub fn build_test_manifest() -> Vec<u8> {
        // String pool indices:
        //  0: "" (empty)
        //  1: "http://schemas.android.com/apk/res/android" (namespace URI)
        //  2: "manifest"
        //  3: "package"
        //  4: "com.example.app"
        //  5: "uses-sdk"
        //  6: "minSdkVersion"
        //  7: "targetSdkVersion"
        //  8: "uses-permission"
        //  9: "name"
        // 10: "android.permission.INTERNET"
        // 11: "android.permission.CAMERA"
        // 12: "android"
        let strings = &[
            "",
            "http://schemas.android.com/apk/res/android",
            "manifest",
            "package",
            "com.example.app",
            "uses-sdk",
            "minSdkVersion",
            "targetSdkVersion",
            "uses-permission",
            "name",
            "android.permission.INTERNET",
            "android.permission.CAMERA",
            "android",
        ];

        // Resource map — one entry per attribute name string.
        let resource_ids: &[u32] = &[
            0,                              // 0: ""
            0,                              // 1: ns uri
            0,                              // 2: "manifest"
            0,                              // 3: "package"
            0,                              // 4: "com.example.app"
            0,                              // 5: "uses-sdk"
            super::ATTR_MIN_SDK_VERSION,    // 6: "minSdkVersion"
            super::ATTR_TARGET_SDK_VERSION, // 7: "targetSdkVersion"
            0,                              // 8: "uses-permission"
            super::ATTR_NAME,               // 9: "name"
            0,                              // 10
            0,                              // 11
            0,                              // 12
        ];

        let pool = build_string_pool(strings);
        let resmap = build_resource_map(resource_ids);
        let ns_start = build_ns_start(12, 1); // prefix="android", uri=ns URI

        // <manifest package="com.example.app">
        let manifest_start = build_elem_start(-1, 2, &[TestAttr {
            ns_idx: -1,
            name_idx: 3,
            raw_value_idx: 4,
            typed_type: super::TYPE_STRING,
            typed_data: 4,
        }]);

        // <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34" />
        let uses_sdk_start = build_elem_start(-1, 5, &[
            TestAttr {
                ns_idx: 1,
                name_idx: 6,
                raw_value_idx: -1,
                typed_type: super::TYPE_INT_DEC,
                typed_data: 21,
            },
            TestAttr {
                ns_idx: 1,
                name_idx: 7,
                raw_value_idx: -1,
                typed_type: super::TYPE_INT_DEC,
                typed_data: 34,
            },
        ]);
        let uses_sdk_end = build_elem_end(-1, 5);

        // <uses-permission android:name="android.permission.INTERNET" />
        let perm1_start = build_elem_start(-1, 8, &[TestAttr {
            ns_idx: 1,
            name_idx: 9,
            raw_value_idx: 10,
            typed_type: super::TYPE_STRING,
            typed_data: 10,
        }]);
        let perm1_end = build_elem_end(-1, 8);

        // <uses-permission android:name="android.permission.CAMERA" />
        let perm2_start = build_elem_start(-1, 8, &[TestAttr {
            ns_idx: 1,
            name_idx: 9,
            raw_value_idx: 11,
            typed_type: super::TYPE_STRING,
            typed_data: 11,
        }]);
        let perm2_end = build_elem_end(-1, 8);

        let manifest_end = build_elem_end(-1, 2);
        let ns_end = build_ns_end(12, 1);

        // Assemble the inner chunks.
        let mut inner = Vec::new();
        inner.extend_from_slice(&pool);
        inner.extend_from_slice(&resmap);
        inner.extend_from_slice(&ns_start);
        inner.extend_from_slice(&manifest_start);
        inner.extend_from_slice(&uses_sdk_start);
        inner.extend_from_slice(&uses_sdk_end);
        inner.extend_from_slice(&perm1_start);
        inner.extend_from_slice(&perm1_end);
        inner.extend_from_slice(&perm2_start);
        inner.extend_from_slice(&perm2_end);
        inner.extend_from_slice(&manifest_end);
        inner.extend_from_slice(&ns_end);

        // Wrap in XML document chunk.
        let header_size: u16 = 8;
        let total = header_size as u32 + inner.len() as u32;

        let mut doc = Vec::with_capacity(total as usize);
        put_u16(&mut doc, 0x0003);
        put_u16(&mut doc, header_size);
        put_u32(&mut doc, total);
        doc.extend_from_slice(&inner);
        doc
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use super::test_builder::build_test_manifest;

    #[test]
    fn parse_test_manifest() {
        let data = build_test_manifest();
        let parser = BinaryXmlParser::new();
        let doc = parser.parse(&data).expect("parse should succeed");

        assert!(!doc.string_pool.is_empty(), "string pool should not be empty");
        assert!(!doc.elements.is_empty(), "should have root elements");
        assert_eq!(doc.elements[0].name, "manifest");
    }

    #[test]
    fn extract_package_name() {
        let data = build_test_manifest();
        let parser = BinaryXmlParser::new();
        let doc = parser.parse(&data).unwrap();

        let pkg = parser.package_name(&doc);
        assert_eq!(pkg, Some("com.example.app".to_string()));
    }

    #[test]
    fn extract_permissions() {
        let data = build_test_manifest();
        let parser = BinaryXmlParser::new();
        let doc = parser.parse(&data).unwrap();

        let perms = parser.permissions(&doc);
        assert_eq!(perms.len(), 2);
        assert!(perms.contains(&"android.permission.INTERNET".to_string()));
        assert!(perms.contains(&"android.permission.CAMERA".to_string()));
    }

    #[test]
    fn extract_min_sdk() {
        let data = build_test_manifest();
        let parser = BinaryXmlParser::new();
        let doc = parser.parse(&data).unwrap();

        assert_eq!(parser.min_sdk(&doc), Some(21));
    }

    #[test]
    fn extract_target_sdk() {
        let data = build_test_manifest();
        let parser = BinaryXmlParser::new();
        let doc = parser.parse(&data).unwrap();

        assert_eq!(parser.target_sdk(&doc), Some(34));
    }

    #[test]
    fn reject_too_short() {
        let parser = BinaryXmlParser::new();
        let result = parser.parse(&[0x03, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn reject_wrong_chunk_type() {
        let parser = BinaryXmlParser::new();
        // Valid-looking header but wrong type.
        let mut data = vec![0; 8];
        data[0] = 0x01; // type = 0x0001 (not XML doc)
        data[1] = 0x00;
        data[2] = 0x08; // header size = 8
        data[3] = 0x00;
        data[4] = 0x08; // total size = 8
        let result = parser.parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn empty_manifest_no_package() {
        let doc = XmlDocument {
            string_pool: vec![],
            resource_map: vec![],
            elements: vec![XmlElement {
                namespace: None,
                name: "manifest".into(),
                attributes: vec![],
                children: vec![],
            }],
        };
        let parser = BinaryXmlParser::new();
        assert_eq!(parser.package_name(&doc), None);
        assert!(parser.permissions(&doc).is_empty());
        assert_eq!(parser.min_sdk(&doc), None);
        assert_eq!(parser.target_sdk(&doc), None);
    }

    #[test]
    fn no_manifest_element() {
        let doc = XmlDocument {
            string_pool: vec![],
            resource_map: vec![],
            elements: vec![XmlElement {
                namespace: None,
                name: "other".into(),
                attributes: vec![],
                children: vec![],
            }],
        };
        let parser = BinaryXmlParser::new();
        assert_eq!(parser.package_name(&doc), None);
        assert_eq!(parser.min_sdk(&doc), None);
        assert_eq!(parser.target_sdk(&doc), None);
    }

    #[test]
    fn default_parser() {
        let parser = BinaryXmlParser::default();
        let data = build_test_manifest();
        let doc = parser.parse(&data).unwrap();
        assert_eq!(parser.package_name(&doc), Some("com.example.app".to_string()));
    }
}
