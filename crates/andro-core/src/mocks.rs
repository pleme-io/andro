//! Mock implementations for all Android protocol traits.
//!
//! These mocks enable unit testing without ADB daemon, USB hardware,
//! or SQLite files. Import via `andro_core::mocks::*`.

use crate::device::{DeviceId, DeviceInfo, DeviceState};
use crate::error::{AndroError, Result};
use crate::traits::*;
use crate::types::*;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

// ── MockAdbTransport ───────────────────────────────────────────────────

/// Mock ADB transport with pre-recorded responses.
pub struct MockAdbTransport {
    pub devices: Vec<DeviceInfo>,
    pub shell_responses: HashMap<String, String>,
    pub install_results: HashMap<String, Result<()>>,
}

impl MockAdbTransport {
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
            shell_responses: HashMap::new(),
            install_results: HashMap::new(),
        }
    }

    pub fn with_device(mut self, id: &str, model: &str) -> Self {
        self.devices.push(DeviceInfo {
            id: DeviceId(id.to_string()),
            state: DeviceState::Device,
            model: Some(model.to_string()),
            manufacturer: None,
            android_version: None,
            api_level: None,
            build_fingerprint: None,
            product: None,
            transport_id: None,
        });
        self
    }

    pub fn with_shell_response(mut self, command: &str, response: &str) -> Self {
        self.shell_responses.insert(command.to_string(), response.to_string());
        self
    }
}

impl Default for MockAdbTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl AdbTransport for MockAdbTransport {
    fn devices(&mut self) -> Result<Vec<DeviceInfo>> {
        Ok(self.devices.clone())
    }

    fn shell(&mut self, _serial: &str, command: &str) -> Result<crate::ShellOutput> {
        let stdout = self.shell_responses
            .get(command)
            .cloned()
            .unwrap_or_default();
        Ok(crate::ShellOutput {
            device: DeviceId("mock".to_string()),
            stdout,
            exit_code: Some(0),
        })
    }

    fn push(&mut self, _serial: &str, local: &Path, _remote: &str) -> Result<u64> {
        Ok(1024) // pretend 1KB transferred
    }

    fn pull(&mut self, _serial: &str, _remote: &str, _local: &Path) -> Result<u64> {
        Ok(1024)
    }

    fn install(&mut self, _serial: &str, _apk: &Path) -> Result<()> {
        Ok(())
    }

    fn reboot(&mut self, _serial: &str, _target: RebootTarget) -> Result<()> {
        Ok(())
    }
}

// ── MockUsbEnumerator ──────────────────────────────────────────────────

/// Mock USB enumerator with pre-populated device list.
pub struct MockUsbEnumerator {
    pub devices: Vec<UsbDeviceInfo>,
}

impl MockUsbEnumerator {
    pub fn new() -> Self {
        Self { devices: Vec::new() }
    }

    pub fn with_device(mut self, vendor_id: u16, serial: &str) -> Self {
        self.devices.push(UsbDeviceInfo {
            vendor_id,
            product_id: 0,
            serial: Some(serial.to_string()),
            manufacturer: None,
            product: None,
        });
        self
    }
}

impl Default for MockUsbEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbEnumerator for MockUsbEnumerator {
    fn list_devices(&self) -> Result<Vec<UsbDeviceInfo>> {
        Ok(self.devices.clone())
    }
}

// ── MockFastbootTransport ──────────────────────────────────────────────

/// Mock fastboot transport with pre-recorded variable responses.
pub struct MockFastbootTransport {
    pub vars: HashMap<String, String>,
    pub flash_log: Mutex<Vec<String>>,
}

impl MockFastbootTransport {
    pub fn new() -> Self {
        Self {
            vars: HashMap::new(),
            flash_log: Mutex::new(Vec::new()),
        }
    }

    pub fn with_var(mut self, name: &str, value: &str) -> Self {
        self.vars.insert(name.to_string(), value.to_string());
        self
    }
}

impl Default for MockFastbootTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl FastbootTransport for MockFastbootTransport {
    fn command(&mut self, cmd: &str) -> Result<FastbootResponse> {
        Ok(FastbootResponse::Okay(cmd.to_string()))
    }

    fn getvar(&mut self, name: &str) -> Result<String> {
        self.vars.get(name).cloned().ok_or_else(|| AndroError::Other(format!("unknown variable: {name}")))
    }

    fn send_data(&mut self, _data: &[u8]) -> Result<()> {
        Ok(())
    }

    fn flash(&mut self, partition: &str) -> Result<()> {
        self.flash_log.lock().unwrap().push(partition.to_string());
        Ok(())
    }

    fn erase(&mut self, _partition: &str) -> Result<()> {
        Ok(())
    }

    fn reboot(&mut self) -> Result<()> {
        Ok(())
    }
}

// ── MockArchiveReader ──────────────────────────────────────────────────

/// Mock archive reader with pre-populated entries.
pub struct MockArchiveReader {
    pub entries: HashMap<String, Vec<u8>>,
}

impl MockArchiveReader {
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    pub fn with_entry(mut self, path: &str, content: &[u8]) -> Self {
        self.entries.insert(path.to_string(), content.to_vec());
        self
    }
}

impl Default for MockArchiveReader {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveReader for MockArchiveReader {
    fn list_entries(&self, _data: &[u8]) -> Result<Vec<ArchiveEntry>> {
        Ok(self.entries.iter().map(|(path, data)| ArchiveEntry {
            path: path.clone(),
            size: data.len() as u64,
            compressed_size: data.len() as u64,
            is_dir: false,
        }).collect())
    }

    fn read_entry(&self, _data: &[u8], path: &str) -> Result<Vec<u8>> {
        self.entries.get(path).cloned().ok_or_else(|| AndroError::Other(format!("entry not found: {path}")))
    }

    fn entry_metadata(&self, _data: &[u8], path: &str) -> Result<EntryMetadata> {
        let data = self.entries.get(path).ok_or_else(|| AndroError::Other(format!("entry not found: {path}")))?;
        Ok(EntryMetadata {
            path: path.to_string(),
            size: data.len() as u64,
            compressed_size: data.len() as u64,
            crc32: 0,
            compression_method: 0,
        })
    }
}

// ── MockStorageBackend ─────────────────────────────────────────────────

/// In-memory storage backend for testing without SQLite.
pub struct MockStorageBackend {
    pub tables: Mutex<HashMap<String, Vec<HashMap<String, String>>>>,
}

impl MockStorageBackend {
    pub fn new() -> Self {
        Self {
            tables: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MockStorageBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for MockStorageBackend {
    fn execute(&self, _sql: &str, _params: &[&str]) -> Result<usize> {
        Ok(1)
    }

    fn execute_batch(&self, _sql: &str) -> Result<()> {
        Ok(())
    }

    fn query_rows(&self, _sql: &str, _params: &[&str]) -> Result<Vec<Row>> {
        Ok(Vec::new())
    }

    fn count(&self, _table: &str) -> Result<u64> {
        Ok(0)
    }

    fn prune(&self, _table: &str, _ts_col: &str, _days: u32) -> Result<u64> {
        Ok(0)
    }
}

// ── MockDexParser ──────────────────────────────────────────────────────

/// Mock DEX parser returning pre-built data.
pub struct MockDexParser {
    pub dex: DexFile,
}

impl MockDexParser {
    pub fn new() -> Self {
        Self {
            dex: DexFile {
                version: "035".to_string(),
                checksum: 0,
                file_size: 0,
                string_count: 0,
                type_count: 0,
                method_count: 0,
                class_count: 0,
                strings: Vec::new(),
            },
        }
    }
}

impl Default for MockDexParser {
    fn default() -> Self {
        Self::new()
    }
}

impl DexParser for MockDexParser {
    fn parse(&self, _data: &[u8]) -> Result<DexFile> {
        Ok(self.dex.clone())
    }
}

// ── MockAxmlParser ─────────────────────────────────────────────────────

/// Mock AXML parser returning pre-built manifest data.
pub struct MockAxmlParser {
    pub package_name: Option<String>,
    pub permissions: Vec<String>,
    pub min_sdk: Option<u32>,
    pub target_sdk: Option<u32>,
}

impl MockAxmlParser {
    pub fn new() -> Self {
        Self {
            package_name: Some("com.example.app".to_string()),
            permissions: vec!["android.permission.INTERNET".to_string()],
            min_sdk: Some(24),
            target_sdk: Some(34),
        }
    }
}

impl Default for MockAxmlParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AxmlParser for MockAxmlParser {
    fn parse(&self, _data: &[u8]) -> Result<XmlDocument> {
        Ok(XmlDocument {
            string_pool: Vec::new(),
            resource_map: Vec::new(),
            elements: Vec::new(),
        })
    }

    fn package_name(&self, _doc: &XmlDocument) -> Option<String> {
        self.package_name.clone()
    }

    fn permissions(&self, _doc: &XmlDocument) -> Vec<String> {
        self.permissions.clone()
    }

    fn min_sdk(&self, _doc: &XmlDocument) -> Option<u32> {
        self.min_sdk
    }

    fn target_sdk(&self, _doc: &XmlDocument) -> Option<u32> {
        self.target_sdk
    }
}

// ── MockApkSignatureVerifier ───────────────────────────────────────────

/// Mock APK signature verifier.
pub struct MockApkVerifier {
    pub valid: bool,
}

impl MockApkVerifier {
    pub fn valid() -> Self {
        Self { valid: true }
    }

    pub fn invalid() -> Self {
        Self { valid: false }
    }
}

impl ApkSignatureVerifier for MockApkVerifier {
    fn find_signing_block(&self, _data: &[u8]) -> Result<Option<SigningBlock>> {
        Ok(Some(SigningBlock {
            offset: 0,
            size: 0,
            pairs: Vec::new(),
        }))
    }

    fn verify(&self, _data: &[u8]) -> Result<SignatureResult> {
        Ok(SignatureResult {
            valid: self.valid,
            scheme_version: 2,
            signer_count: 1,
            error: if self.valid { None } else { Some("invalid signature".to_string()) },
        })
    }

    fn certificates(&self, _data: &[u8]) -> Result<Vec<Certificate>> {
        Ok(vec![Certificate {
            subject: "CN=Mock".to_string(),
            issuer: "CN=Mock CA".to_string(),
            serial: "1".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2025-01-01".to_string(),
            fingerprint_sha256: "mock_fingerprint".to_string(),
        }])
    }
}

// ── MockVbmetaParser ───────────────────────────────────────────────────

/// Mock VBMeta parser.
pub struct MockVbmetaParser;

impl VbmetaParser for MockVbmetaParser {
    fn parse(&self, _data: &[u8]) -> Result<VbmetaImage> {
        Ok(VbmetaImage {
            algorithm: 1,
            rollback_index: 0,
            flags: 0,
            release_string: "mock-1.0".to_string(),
            descriptors: Vec::new(),
        })
    }

    fn verify(&self, _image: &VbmetaImage, _public_key: &[u8]) -> Result<bool> {
        Ok(true)
    }
}

// ── MockSparseImageParser ──────────────────────────────────────────────

/// Mock sparse image parser.
pub struct MockSparseParser;

impl SparseImageParser for MockSparseParser {
    fn parse(&self, _data: &[u8]) -> Result<SparseImage> {
        Ok(SparseImage {
            block_size: 4096,
            total_blocks: 1,
            chunks: vec![SparseChunk::DontCare(1)],
        })
    }

    fn to_raw(&self, sparse: &SparseImage) -> Result<Vec<u8>> {
        Ok(vec![0u8; (sparse.block_size * sparse.total_blocks) as usize])
    }

    fn from_raw(&self, _data: &[u8], block_size: u32) -> Result<SparseImage> {
        Ok(SparseImage {
            block_size,
            total_blocks: 1,
            chunks: vec![SparseChunk::DontCare(1)],
        })
    }
}

// ── MockLogcatParser ───────────────────────────────────────────────────

/// Mock logcat parser.
pub struct MockLogcatParser;

impl LogcatParser for MockLogcatParser {
    fn parse_text_line(&self, line: &str) -> Option<crate::LogEntry> {
        Some(crate::LogEntry {
            timestamp: None,
            pid: Some(1234),
            tid: Some(5678),
            level: crate::LogLevel::Info,
            tag: "MockTag".to_string(),
            message: line.to_string(),
            raw: line.to_string(),
        })
    }

    fn parse_binary_entry(&self, _data: &[u8]) -> Result<crate::LogEntry> {
        Ok(crate::LogEntry {
            timestamp: None,
            pid: Some(1),
            tid: Some(1),
            level: crate::LogLevel::Debug,
            tag: "binary".to_string(),
            message: "mock binary entry".to_string(),
            raw: String::new(),
        })
    }
}

// ── MockBootImageParser ────────────────────────────────────────────────

/// Mock boot image parser.
pub struct MockBootImageParser;

impl BootImageParser for MockBootImageParser {
    fn parse(&self, _data: &[u8]) -> Result<DeviceInfo> {
        Ok(DeviceInfo {
            id: DeviceId("boot".to_string()),
            state: DeviceState::Device,
            model: None,
            manufacturer: None,
            android_version: None,
            api_level: None,
            build_fingerprint: None,
            product: None,
            transport_id: None,
        })
    }

    fn unpack(&self, _data: &[u8]) -> Result<BootComponents> {
        Ok(BootComponents {
            kernel: vec![0u8; 64],
            ramdisk: vec![0u8; 32],
            second: None,
            dtb: None,
            cmdline: "mock cmdline".to_string(),
            header_version: 0,
        })
    }

    fn repack(&self, _components: &BootComponents) -> Result<Vec<u8>> {
        Ok(vec![0u8; 4096])
    }
}

// ── MockAttestationVerifier ─────────────────────────────────────────────

/// Mock attestation verifier for testing.
pub struct MockAttestationVerifier {
    pub verified: bool,
}

impl MockAttestationVerifier {
    pub fn verified() -> Self { Self { verified: true } }
    pub fn failed() -> Self { Self { verified: false } }
}

impl AttestationVerifier for MockAttestationVerifier {
    fn verify(&self, _challenge: &[u8], _response: &[u8]) -> Result<AttestationResult> {
        Ok(AttestationResult {
            verified: self.verified,
            device_model: Some("Pixel 8 Pro".to_string()),
            os_version: Some("14".to_string()),
            patch_level: Some("2026-03-05".to_string()),
            boot_state: Some("verified".to_string()),
            blake3_hash: Some(blake3::hash(b"mock_attestation").to_hex().to_string()),
            error: if self.verified { None } else { Some("attestation failed".to_string()) },
        })
    }

    fn generate_challenge(&self) -> Result<Vec<u8>> {
        Ok(vec![0x42; 32])
    }

    fn trust_chain(&self, _device_id: &str) -> Result<Vec<AttestationCert>> {
        Ok(vec![AttestationCert {
            subject: "CN=GrapheneOS".to_string(),
            issuer: "CN=Google Hardware Attestation Root".to_string(),
            serial: "1".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2034-01-01".to_string(),
            key_usage: vec!["digitalSignature".to_string()],
        }])
    }
}

// ── MockOtaProvider ────────────────────────────────────────────────────

/// Mock OTA provider for testing.
pub struct MockOtaProvider {
    pub build_number: String,
}

impl MockOtaProvider {
    pub fn new(build: &str) -> Self { Self { build_number: build.to_string() } }
}

impl OtaProvider for MockOtaProvider {
    fn check_update(&self, device: &str, channel: &str) -> Result<Option<OtaManifest>> {
        Ok(Some(OtaManifest {
            device: device.to_string(),
            channel: channel.to_string(),
            build_number: self.build_number.clone(),
            factory_url: format!("https://releases.grapheneos.org/{device}-factory-{}.zip", self.build_number),
            ota_url: format!("https://releases.grapheneos.org/{device}-ota_update-{}.zip", self.build_number),
            incremental_url: None,
        }))
    }

    fn verify_payload(&self, payload: &[u8], expected_hash: &str) -> Result<bool> {
        let hash = blake3::hash(payload).to_hex().to_string();
        Ok(hash == expected_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_adb_transport_devices() {
        let mut transport = MockAdbTransport::new()
            .with_device("ABC123", "Pixel 7");
        let devices = transport.devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id.0, "ABC123");
    }

    #[test]
    fn mock_adb_transport_shell() {
        let mut transport = MockAdbTransport::new()
            .with_shell_response("getprop ro.product.model", "Pixel 7");
        let output = transport.shell("ABC", "getprop ro.product.model").unwrap();
        assert_eq!(output.stdout, "Pixel 7");
    }

    #[test]
    fn mock_usb_enumerator() {
        let enumerator = MockUsbEnumerator::new()
            .with_device(0x18D1, "GOOGLE123");
        let devices = enumerator.list_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].vendor_id, 0x18D1);
    }

    #[test]
    fn mock_fastboot_getvar() {
        let mut fb = MockFastbootTransport::new()
            .with_var("product", "walleye")
            .with_var("serialno", "TEST123");
        assert_eq!(fb.getvar("product").unwrap(), "walleye");
        assert_eq!(fb.getvar("serialno").unwrap(), "TEST123");
        assert!(fb.getvar("nonexistent").is_err());
    }

    #[test]
    fn mock_archive_reader() {
        let reader = MockArchiveReader::new()
            .with_entry("classes.dex", &[0u8; 112])
            .with_entry("AndroidManifest.xml", b"<manifest/>");
        let entries = reader.list_entries(&[]).unwrap();
        assert_eq!(entries.len(), 2);
        let dex = reader.read_entry(&[], "classes.dex").unwrap();
        assert_eq!(dex.len(), 112);
    }

    #[test]
    fn mock_storage_backend() {
        let storage = MockStorageBackend::new();
        assert_eq!(storage.count("any_table").unwrap(), 0);
        assert_eq!(storage.execute("INSERT", &[]).unwrap(), 1);
    }

    #[test]
    fn mock_apk_verifier_valid() {
        let verifier = MockApkVerifier::valid();
        let result = verifier.verify(&[]).unwrap();
        assert!(result.valid);
    }

    #[test]
    fn mock_apk_verifier_invalid() {
        let verifier = MockApkVerifier::invalid();
        let result = verifier.verify(&[]).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn mock_axml_parser() {
        let parser = MockAxmlParser::new();
        let doc = parser.parse(&[]).unwrap();
        assert_eq!(parser.package_name(&doc), Some("com.example.app".to_string()));
        assert_eq!(parser.min_sdk(&doc), Some(24));
    }

    #[test]
    fn mock_dex_parser() {
        let parser = MockDexParser::new();
        let dex = parser.parse(&[]).unwrap();
        assert_eq!(dex.version, "035");
    }

    #[test]
    fn mock_sparse_roundtrip() {
        let parser = MockSparseParser;
        let sparse = parser.parse(&[]).unwrap();
        let raw = parser.to_raw(&sparse).unwrap();
        assert_eq!(raw.len(), 4096);
    }

    #[test]
    fn mock_attestation_verified() {
        let verifier = MockAttestationVerifier::verified();
        let result = verifier.verify(&[0x01], &[0x02]).unwrap();
        assert!(result.verified);
        assert_eq!(result.device_model.as_deref(), Some("Pixel 8 Pro"));
        assert!(result.blake3_hash.is_some());
    }

    #[test]
    fn mock_attestation_failed() {
        let verifier = MockAttestationVerifier::failed();
        let result = verifier.verify(&[0x01], &[0x02]).unwrap();
        assert!(!result.verified);
        assert!(result.error.is_some());
    }

    #[test]
    fn mock_attestation_challenge() {
        let verifier = MockAttestationVerifier::verified();
        let challenge = verifier.generate_challenge().unwrap();
        assert_eq!(challenge.len(), 32);
    }

    #[test]
    fn mock_attestation_trust_chain() {
        let verifier = MockAttestationVerifier::verified();
        let chain = verifier.trust_chain("test").unwrap();
        assert_eq!(chain.len(), 1);
        assert!(chain[0].subject.contains("GrapheneOS"));
    }

    #[test]
    fn mock_ota_provider() {
        let provider = MockOtaProvider::new("2026031500");
        let manifest = provider.check_update("husky", "stable").unwrap().unwrap();
        assert_eq!(manifest.device, "husky");
        assert_eq!(manifest.build_number, "2026031500");
        assert!(manifest.factory_url.contains("husky"));
    }

    #[test]
    fn mock_ota_verify_payload() {
        let provider = MockOtaProvider::new("test");
        let data = b"test payload";
        let hash = blake3::hash(data).to_hex().to_string();
        assert!(provider.verify_payload(data, &hash).unwrap());
        assert!(!provider.verify_payload(data, "wrong_hash").unwrap());
    }
}
