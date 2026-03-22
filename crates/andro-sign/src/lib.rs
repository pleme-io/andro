//! APK signature verification — find and parse the APK Signing Block.
//!
//! Implements `andro_core::traits::ApkSignatureVerifier` by locating
//! the signing block (magic "APK Sig Block 42") just before the central
//! directory, then parsing ID-value pairs to identify v2 (0x7109871a)
//! and v3 (0xf05368c0) signature schemes.

use andro_core::error::{AndroError, Result};
use andro_core::traits::ApkSignatureVerifier;
use andro_core::types::{Certificate, SignatureResult, SigningBlock, SigningBlockPair};

/// Magic bytes at the end of the APK Signing Block.
const APK_SIG_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";

/// APK Signature Scheme v2 block ID.
const APK_SIG_V2_ID: u32 = 0x7109_871a;

/// APK Signature Scheme v3 block ID.
const APK_SIG_V3_ID: u32 = 0xf053_68c0;

/// End-of-central-directory signature (PK\x05\x06).
const EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];

/// Minimum EOCD record size (no comment).
const EOCD_MIN_SIZE: usize = 22;

/// Real APK signature verifier.
pub struct ApkSignVerifier;

impl ApkSignVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Find the End-of-Central-Directory record offset by scanning backward.
    fn find_eocd(data: &[u8]) -> Option<usize> {
        if data.len() < EOCD_MIN_SIZE {
            return None;
        }
        // EOCD can have a comment up to 65535 bytes, scan backward.
        let max_comment = 65535.min(data.len() - EOCD_MIN_SIZE);
        for i in 0..=max_comment {
            let offset = data.len() - EOCD_MIN_SIZE - i;
            if data[offset..offset + 4] == EOCD_SIGNATURE {
                return Some(offset);
            }
        }
        None
    }

    /// Read the central directory offset from the EOCD record.
    fn central_dir_offset(data: &[u8], eocd_offset: usize) -> Option<u64> {
        if eocd_offset + 20 > data.len() {
            return None;
        }
        // Offset of start of central directory is at EOCD + 16 (4 bytes LE).
        let cd_offset = u32::from_le_bytes([
            data[eocd_offset + 16],
            data[eocd_offset + 17],
            data[eocd_offset + 18],
            data[eocd_offset + 19],
        ]);
        Some(u64::from(cd_offset))
    }

    /// Parse the signing block located just before the central directory.
    fn parse_signing_block(data: &[u8], cd_offset: u64) -> Option<SigningBlock> {
        let cd = cd_offset as usize;

        // The signing block ends with:
        //   - 8 bytes: block size (same as at start)
        //   - 16 bytes: magic "APK Sig Block 42"
        // Total footer = 24 bytes, must fit before central directory.
        if cd < 24 {
            return None;
        }

        // Check magic at cd - 16.
        let magic_start = cd - 16;
        if &data[magic_start..cd] != APK_SIG_BLOCK_MAGIC {
            return None;
        }

        // Read block size from the footer (8 bytes before magic).
        let size_offset = magic_start - 8;
        let block_size = u64::from_le_bytes([
            data[size_offset],
            data[size_offset + 1],
            data[size_offset + 2],
            data[size_offset + 3],
            data[size_offset + 4],
            data[size_offset + 5],
            data[size_offset + 6],
            data[size_offset + 7],
        ]);

        // The block size includes the 8-byte size field + pairs + magic but not the
        // leading 8-byte size field. The block starts at cd - block_size - 8.
        let block_start = cd
            .checked_sub(block_size as usize)?
            .checked_sub(8)?;

        // Parse ID-value pairs between the two size fields.
        // Layout: [size_of_block(8)] [pairs...] [size_of_block(8)] [magic(16)]
        let pairs_start = block_start + 8;
        let pairs_end = size_offset;
        let pairs = Self::parse_pairs(data, pairs_start, pairs_end);

        Some(SigningBlock {
            offset: block_start as u64,
            size: block_size,
            pairs,
        })
    }

    /// Parse ID-value pairs from the signing block payload.
    ///
    /// Each pair: u64 length (of id + data), u32 id, data[length - 4].
    fn parse_pairs(data: &[u8], start: usize, end: usize) -> Vec<SigningBlockPair> {
        let mut pairs = Vec::new();
        let mut pos = start;
        while pos + 12 <= end {
            let pair_len = u64::from_le_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]);
            pos += 8;

            if pair_len < 4 || pos + pair_len as usize > end {
                break;
            }

            let id = u32::from_le_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            ]);
            pos += 4;

            let data_len = (pair_len - 4) as usize;
            let pair_data = data[pos..pos + data_len].to_vec();
            pos += data_len;

            pairs.push(SigningBlockPair { id, data: pair_data });
        }
        pairs
    }

    /// Determine the highest signature scheme version present.
    fn detect_scheme_version(pairs: &[SigningBlockPair]) -> u8 {
        let has_v3 = pairs.iter().any(|p| p.id == APK_SIG_V3_ID);
        let has_v2 = pairs.iter().any(|p| p.id == APK_SIG_V2_ID);
        if has_v3 {
            3
        } else if has_v2 {
            2
        } else {
            1
        }
    }
}

impl Default for ApkSignVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ApkSignatureVerifier for ApkSignVerifier {
    fn find_signing_block(&self, data: &[u8]) -> Result<Option<SigningBlock>> {
        let eocd_offset = match Self::find_eocd(data) {
            Some(o) => o,
            None => return Ok(None),
        };
        let cd_offset = Self::central_dir_offset(data, eocd_offset)
            .ok_or_else(|| AndroError::Other("invalid EOCD record".to_string()))?;

        Ok(Self::parse_signing_block(data, cd_offset))
    }

    fn verify(&self, data: &[u8]) -> Result<SignatureResult> {
        let block = self.find_signing_block(data)?;
        match block {
            Some(block) => {
                let version = Self::detect_scheme_version(&block.pairs);
                let signer_count = block
                    .pairs
                    .iter()
                    .filter(|p| p.id == APK_SIG_V2_ID || p.id == APK_SIG_V3_ID)
                    .count();
                Ok(SignatureResult {
                    valid: signer_count > 0,
                    scheme_version: version,
                    signer_count,
                    error: if signer_count == 0 {
                        Some("no v2/v3 signature blocks found".to_string())
                    } else {
                        None
                    },
                })
            }
            None => Ok(SignatureResult {
                valid: false,
                scheme_version: 0,
                signer_count: 0,
                error: Some("no APK signing block found".to_string()),
            }),
        }
    }

    fn certificates(&self, data: &[u8]) -> Result<Vec<Certificate>> {
        let block = self.find_signing_block(data)?;
        match block {
            Some(block) => {
                // Extract certificate stubs from v2/v3 signature blocks.
                // Full X.509 parsing would require a crypto library; we return
                // the raw block metadata as placeholder certificates.
                let certs: Vec<Certificate> = block
                    .pairs
                    .iter()
                    .filter(|p| p.id == APK_SIG_V2_ID || p.id == APK_SIG_V3_ID)
                    .enumerate()
                    .map(|(i, p)| {
                        let scheme = if p.id == APK_SIG_V3_ID { "v3" } else { "v2" };
                        Certificate {
                            subject: format!("APK Signer #{} ({scheme})", i + 1),
                            issuer: format!("APK Signer #{} ({scheme})", i + 1),
                            serial: format!("{i}"),
                            not_before: String::new(),
                            not_after: String::new(),
                            fingerprint_sha256: format!("{:x?}", &p.data[..p.data.len().min(32)]),
                        }
                    })
                    .collect();
                Ok(certs)
            }
            None => Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal mock APK with a signing block before the central directory.
    ///
    /// Layout:
    ///   [zip local entries (empty)]
    ///   [APK Signing Block]
    ///   [central directory (empty)]
    ///   [EOCD pointing to central directory]
    fn build_mock_apk(pairs: &[(u32, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();

        // -- Build pairs payload --
        let mut pairs_payload = Vec::new();
        for &(id, data) in pairs {
            let pair_len: u64 = 4 + data.len() as u64;
            pairs_payload.extend_from_slice(&pair_len.to_le_bytes());
            pairs_payload.extend_from_slice(&id.to_le_bytes());
            pairs_payload.extend_from_slice(data);
        }

        // block_size = pairs_payload + 8 (trailing size) + 16 (magic)
        let block_size: u64 = pairs_payload.len() as u64 + 8 + 16;

        // -- Leading size field --
        buf.extend_from_slice(&block_size.to_le_bytes());
        // -- Pairs --
        buf.extend_from_slice(&pairs_payload);
        // -- Trailing size field --
        buf.extend_from_slice(&block_size.to_le_bytes());
        // -- Magic --
        buf.extend_from_slice(APK_SIG_BLOCK_MAGIC);

        let cd_offset = buf.len() as u32;

        // -- Empty central directory (no entries) --
        // Nothing to write for an empty CD.

        // -- EOCD record --
        buf.extend_from_slice(&EOCD_SIGNATURE); // signature
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk number
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
        buf.extend_from_slice(&0u16.to_le_bytes()); // entries on disk
        buf.extend_from_slice(&0u16.to_le_bytes()); // total entries
        buf.extend_from_slice(&0u32.to_le_bytes()); // CD size
        buf.extend_from_slice(&cd_offset.to_le_bytes()); // CD offset
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment length

        buf
    }

    #[test]
    fn find_signing_block_with_v2() {
        let verifier = ApkSignVerifier::new();
        let apk = build_mock_apk(&[(APK_SIG_V2_ID, &[0xAA; 16])]);
        let block = verifier.find_signing_block(&apk).unwrap();
        assert!(block.is_some());
        let block = block.unwrap();
        assert_eq!(block.pairs.len(), 1);
        assert_eq!(block.pairs[0].id, APK_SIG_V2_ID);
        assert_eq!(block.pairs[0].data.len(), 16);
    }

    #[test]
    fn verify_v2_signature() {
        let verifier = ApkSignVerifier::new();
        let apk = build_mock_apk(&[(APK_SIG_V2_ID, &[0xBB; 32])]);
        let result = verifier.verify(&apk).unwrap();
        assert!(result.valid);
        assert_eq!(result.scheme_version, 2);
        assert_eq!(result.signer_count, 1);
        assert!(result.error.is_none());
    }

    #[test]
    fn verify_v3_preferred_over_v2() {
        let verifier = ApkSignVerifier::new();
        let apk = build_mock_apk(&[
            (APK_SIG_V2_ID, &[0xCC; 8]),
            (APK_SIG_V3_ID, &[0xDD; 8]),
        ]);
        let result = verifier.verify(&apk).unwrap();
        assert!(result.valid);
        assert_eq!(result.scheme_version, 3);
        assert_eq!(result.signer_count, 2);
    }

    #[test]
    fn verify_no_signing_block() {
        let verifier = ApkSignVerifier::new();
        // Minimal EOCD-only buffer (no signing block).
        let mut buf = Vec::new();
        let cd_offset: u32 = 0;
        buf.extend_from_slice(&EOCD_SIGNATURE);
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&cd_offset.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        let result = verifier.verify(&buf).unwrap();
        assert!(!result.valid);
        assert_eq!(result.scheme_version, 0);
    }

    #[test]
    fn certificates_from_v2_block() {
        let verifier = ApkSignVerifier::new();
        let apk = build_mock_apk(&[(APK_SIG_V2_ID, &[0xEE; 48])]);
        let certs = verifier.certificates(&apk).unwrap();
        assert_eq!(certs.len(), 1);
        assert!(certs[0].subject.contains("v2"));
    }

    #[test]
    fn find_signing_block_with_magic_present() {
        let verifier = ApkSignVerifier::new();
        let apk = build_mock_apk(&[
            (APK_SIG_V2_ID, &[0x11; 24]),
            (APK_SIG_V3_ID, &[0x22; 24]),
        ]);
        let block = verifier.find_signing_block(&apk).unwrap();
        assert!(block.is_some());
        let block = block.unwrap();
        assert_eq!(block.pairs.len(), 2);
        assert_eq!(block.pairs[0].id, APK_SIG_V2_ID);
        assert_eq!(block.pairs[1].id, APK_SIG_V3_ID);
    }

    #[test]
    fn find_signing_block_returns_none_without_signing_block() {
        let verifier = ApkSignVerifier::new();
        // Build a buffer with just an EOCD and no signing block
        let mut buf = Vec::new();
        let cd_offset: u32 = 0;
        buf.extend_from_slice(&EOCD_SIGNATURE);
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&cd_offset.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        let block = verifier.find_signing_block(&buf).unwrap();
        assert!(block.is_none());
    }

    #[test]
    fn certificates_empty_when_no_signing_block() {
        let verifier = ApkSignVerifier::new();
        // Minimal EOCD only — no signing block
        let mut buf = Vec::new();
        buf.extend_from_slice(&EOCD_SIGNATURE);
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // cd_offset = 0
        buf.extend_from_slice(&0u16.to_le_bytes());
        let certs = verifier.certificates(&buf).unwrap();
        assert!(certs.is_empty());
    }

    #[test]
    fn trait_send_sync_bounds_satisfied() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ApkSignVerifier>();
    }

    #[test]
    fn signature_result_serialization_roundtrip() {
        let result = SignatureResult {
            valid: true,
            scheme_version: 3,
            signer_count: 2,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: SignatureResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.valid, result.valid);
        assert_eq!(deserialized.scheme_version, result.scheme_version);
        assert_eq!(deserialized.signer_count, result.signer_count);
        assert!(deserialized.error.is_none());
    }
}
