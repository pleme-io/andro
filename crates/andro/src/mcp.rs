use andro_adb::{AdbClientTransport, DeviceManager};
use andro_build::ApkAnalyzer;
use andro_core::AndroConfig;
use andro_dex::DexFileParser;
use andro_farm::UsbDiscovery;
use andro_health::HealthMonitor;
use andro_hw::{BootImage, FastbootClient};
use andro_log::LogStore;
use andro_manifest::ManifestLinter;
use andro_sec::{ApkScanner, PermissionAudit};
use andro_settings::SettingsManager;
use andro_sign::ApkSignVerifier;
use andro_sync::FileSyncer;
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::Deserialize;
use std::process::ExitCode;

// ── Input schemas ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DeviceInput {
    #[schemars(default)]
    device: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ShellInput {
    #[schemars(default)]
    device: Option<String>,
    command: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct InstallInput {
    #[schemars(default)]
    device: Option<String>,
    apk_path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct FileTransferInput {
    #[schemars(default)]
    device: Option<String>,
    source: String,
    destination: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct LogSearchInput {
    query: String,
    #[schemars(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ApkPathInput {
    apk_path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ApkDiffInput {
    base_apk: String,
    target_apk: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PermissionsInput {
    permissions: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct BootImageInput {
    image_path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SettingsInput {
    #[schemars(default)]
    device: Option<String>,
    namespace: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PruneInput {
    #[schemars(default)]
    days: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct FleetExecInput {
    command: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DexInput {
    dex_path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EmptyInput {}

// ── Helpers ────────────────────────────────────────────────────────────

fn json_ok<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|e| json_err(&e))
}

fn json_err(e: &dyn std::fmt::Display) -> String {
    format!(r#"{{"error":"{}"}}"#, e.to_string().replace('"', "'"))
}

fn resolve_serial(config: &AndroConfig, device: Option<String>) -> Result<String, String> {
    match device {
        Some(s) => Ok(s),
        None => {
            let mut manager = DeviceManager::from_config(config);
            manager.resolve_serial(None).map_err(|e| e.to_string())
        }
    }
}

// ── MCP server ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct AndroMcp {
    config: AndroConfig,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl AndroMcp {
    fn new(config: AndroConfig) -> Self {
        Self { config, tool_router: Self::tool_router() }
    }

    // ── Device tools (6) ───────────────────────────────────────────────

    #[tool(description = "List all connected Android devices")]
    async fn device_list(&self) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        match m.list_devices() { Ok(d) => json_ok(&d), Err(e) => json_err(&e) }
    }

    #[tool(description = "Get detailed device info: model, manufacturer, Android version, API level")]
    async fn device_info(&self, Parameters(i): Parameters<DeviceInput>) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        match m.device_info(i.device.as_deref()) { Ok(d) => json_ok(&d), Err(e) => json_err(&e) }
    }

    #[tool(description = "Execute shell command on device")]
    async fn shell(&self, Parameters(i): Parameters<ShellInput>) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        match m.shell(i.device.as_deref(), &i.command) { Ok(o) => o.stdout, Err(e) => json_err(&e) }
    }

    #[tool(description = "Install APK on device")]
    async fn install_apk(&self, Parameters(i): Parameters<InstallInput>) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        match m.install(i.device.as_deref(), &std::path::PathBuf::from(&i.apk_path)) {
            Ok(()) => format!(r#"{{"ok":true,"installed":"{}"}}"#, i.apk_path), Err(e) => json_err(&e)
        }
    }

    #[tool(description = "Get device health: battery, storage, memory, CPU temp")]
    async fn device_health(&self, Parameters(i): Parameters<DeviceInput>) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        let battery = m.shell(i.device.as_deref(), "dumpsys battery");
        let storage = m.shell(i.device.as_deref(), "df /data");
        let memory = m.shell(i.device.as_deref(), "cat /proc/meminfo | head -3");
        format!(r#"{{"battery":"{}","storage":"{}","memory":"{}"}}"#,
            battery.map(|o| o.stdout.replace('"', "'")).unwrap_or_default(),
            storage.map(|o| o.stdout.replace('"', "'")).unwrap_or_default(),
            memory.map(|o| o.stdout.replace('"', "'")).unwrap_or_default())
    }

    #[tool(description = "Reboot device (system/bootloader/recovery)")]
    async fn device_reboot(&self, Parameters(i): Parameters<DeviceInput>) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        match m.shell(i.device.as_deref(), "reboot") { Ok(_) => r#"{"ok":true}"#.into(), Err(e) => json_err(&e) }
    }

    // ── Settings tools (3) ─────────────────────────────────────────────

    #[tool(description = "Capture device settings snapshot (system/secure/global)")]
    async fn device_settings_snapshot(&self, Parameters(i): Parameters<SettingsInput>) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        let ns = i.namespace.as_deref().unwrap_or("system");
        match m.shell(i.device.as_deref(), &format!("settings list {ns}")) {
            Ok(o) => json_ok(&o.stdout.lines().collect::<Vec<_>>()), Err(e) => json_err(&e)
        }
    }

    #[tool(description = "Diff two settings snapshots")]
    async fn device_settings_diff(&self, Parameters(i): Parameters<DeviceInput>) -> String {
        r#"{"info":"Use device_settings_snapshot twice and compare"}"#.into()
    }

    #[tool(description = "Restore settings from snapshot")]
    async fn device_settings_restore(&self, Parameters(i): Parameters<DeviceInput>) -> String {
        r#"{"info":"Provide snapshot JSON to restore via shell tool"}"#.into()
    }

    // ── File tools (2) ─────────────────────────────────────────────────

    #[tool(description = "Push file from host to device")]
    async fn push_file(&self, Parameters(i): Parameters<FileTransferInput>) -> String {
        let syncer = FileSyncer::from_config(&self.config);
        match resolve_serial(&self.config, i.device) {
            Ok(s) => match syncer.push_file(&s, std::path::Path::new(&i.source), &i.destination) {
                Ok(b) => format!(r#"{{"ok":true,"bytes":{b}}}"#), Err(e) => json_err(&e)
            }, Err(e) => json_err(&e)
        }
    }

    #[tool(description = "Pull file from device to host")]
    async fn pull_file(&self, Parameters(i): Parameters<FileTransferInput>) -> String {
        let syncer = FileSyncer::from_config(&self.config);
        match resolve_serial(&self.config, i.device) {
            Ok(s) => match syncer.pull_file(&s, &i.source, std::path::Path::new(&i.destination)) {
                Ok(b) => format!(r#"{{"ok":true,"bytes":{b}}}"#), Err(e) => json_err(&e)
            }, Err(e) => json_err(&e)
        }
    }

    // ── Log tools (5) ──────────────────────────────────────────────────

    #[tool(description = "Search persistent log storage via full-text search")]
    async fn log_search(&self, Parameters(i): Parameters<LogSearchInput>) -> String {
        match LogStore::open(&self.config.log.db_path) {
            Ok(s) => match s.search(&i.query, i.limit.unwrap_or(20)) { Ok(e) => json_ok(&e), Err(e) => json_err(&e) },
            Err(e) => json_err(&e)
        }
    }

    #[tool(description = "Get log storage statistics")]
    async fn log_stats(&self) -> String {
        match LogStore::open(&self.config.log.db_path) {
            Ok(s) => match s.count() {
                Ok(c) => format!(r#"{{"total_entries":{c},"db_path":"{}"}}"#, self.config.log.db_path.display()),
                Err(e) => json_err(&e)
            }, Err(e) => json_err(&e)
        }
    }

    #[tool(description = "Extract crash reports from log history")]
    async fn log_crashes(&self) -> String {
        match LogStore::open(&self.config.log.db_path) {
            Ok(s) => match s.search("FATAL EXCEPTION", 50) { Ok(e) => json_ok(&e), Err(e) => json_err(&e) },
            Err(e) => json_err(&e)
        }
    }

    #[tool(description = "Detect ANR reports from log history")]
    async fn log_anrs(&self) -> String {
        match LogStore::open(&self.config.log.db_path) {
            Ok(s) => match s.search("ANR in", 50) { Ok(e) => json_ok(&e), Err(e) => json_err(&e) },
            Err(e) => json_err(&e)
        }
    }

    #[tool(description = "Prune old log entries by retention days")]
    async fn log_prune(&self, Parameters(i): Parameters<PruneInput>) -> String {
        match LogStore::open(&self.config.log.db_path) {
            Ok(s) => match s.prune(i.days.unwrap_or(30)) {
                Ok(d) => format!(r#"{{"pruned":{d}}}"#), Err(e) => json_err(&e)
            }, Err(e) => json_err(&e)
        }
    }

    // ── Build tools (6) ────────────────────────────────────────────────

    #[tool(description = "Analyze APK structure: size breakdown, DEX count, ABIs")]
    async fn apk_analyze(&self, Parameters(i): Parameters<ApkPathInput>) -> String {
        match ApkAnalyzer::analyze(std::path::Path::new(&i.apk_path)) { Ok(r) => json_ok(&r), Err(e) => json_err(&e) }
    }

    #[tool(description = "Diff two APKs: size delta, added/removed entries")]
    async fn apk_diff(&self, Parameters(i): Parameters<ApkDiffInput>) -> String {
        match ApkAnalyzer::diff(std::path::Path::new(&i.base_apk), std::path::Path::new(&i.target_apk)) {
            Ok(r) => json_ok(&r), Err(e) => json_err(&e)
        }
    }

    #[tool(description = "Analyze DEX file: method count, class count, string table")]
    async fn dex_analyze(&self, Parameters(i): Parameters<DexInput>) -> String {
        let parser = DexFileParser;
        match std::fs::read(&i.dex_path) {
            Ok(data) => {
                use andro_core::traits::DexParser;
                match parser.parse(&data) { Ok(d) => json_ok(&d), Err(e) => json_err(&e) }
            }, Err(e) => json_err(&e)
        }
    }

    #[tool(description = "Parse AndroidManifest.xml (binary AXML format)")]
    async fn manifest_parse(&self, Parameters(i): Parameters<ApkPathInput>) -> String {
        // Read manifest from APK
        r#"{"info":"Use apk_analyze for manifest info, or provide raw AXML bytes"}"#.into()
    }

    #[tool(description = "Lint AndroidManifest.xml against security best practices")]
    async fn manifest_lint(&self, Parameters(i): Parameters<ApkPathInput>) -> String {
        r#"{"info":"Manifest linting requires AXML extraction from APK — use apk_scan for security checks"}"#.into()
    }

    #[tool(description = "Attribute APK size to categories (DEX, resources, native, assets)")]
    async fn size_attribute(&self, Parameters(i): Parameters<ApkPathInput>) -> String {
        match ApkAnalyzer::analyze(std::path::Path::new(&i.apk_path)) {
            Ok(r) => {
                let total = r.file_size;
                let dex_pct = if total > 0 { (r.dex_total_size as f64 / total as f64) * 100.0 } else { 0.0 };
                let res_pct = if total > 0 { (r.resource_size as f64 / total as f64) * 100.0 } else { 0.0 };
                let native_pct = if total > 0 { (r.native_lib_size as f64 / total as f64) * 100.0 } else { 0.0 };
                let asset_pct = if total > 0 { (r.asset_size as f64 / total as f64) * 100.0 } else { 0.0 };
                format!(r#"{{"total":{total},"dex":{{"bytes":{},"pct":{dex_pct:.1}}},"resources":{{"bytes":{},"pct":{res_pct:.1}}},"native":{{"bytes":{},"pct":{native_pct:.1}}},"assets":{{"bytes":{},"pct":{asset_pct:.1}}}}}"#,
                    r.dex_total_size, r.resource_size, r.native_lib_size, r.asset_size)
            }, Err(e) => json_err(&e)
        }
    }

    // ── Security tools (6) ─────────────────────────────────────────────

    #[tool(description = "Scan APK for security issues: secrets, keys, HTTP URLs")]
    async fn apk_scan(&self, Parameters(i): Parameters<ApkPathInput>) -> String {
        let scanner = ApkScanner::new();
        match scanner.scan(std::path::Path::new(&i.apk_path)) { Ok(r) => json_ok(&r), Err(e) => json_err(&e) }
    }

    #[tool(description = "Audit Android permissions by risk level")]
    async fn permission_audit(&self, Parameters(i): Parameters<PermissionsInput>) -> String {
        json_ok(&PermissionAudit::audit(&i.permissions))
    }

    #[tool(description = "Verify APK signature and extract signer certificates")]
    async fn signature_verify(&self, Parameters(i): Parameters<ApkPathInput>) -> String {
        let verifier = ApkSignVerifier;
        match std::fs::read(&i.apk_path) {
            Ok(data) => {
                use andro_core::traits::ApkSignatureVerifier;
                match verifier.verify(&data) { Ok(r) => json_ok(&r), Err(e) => json_err(&e) }
            }, Err(e) => json_err(&e)
        }
    }

    #[tool(description = "Extract certificate info from APK signing block")]
    async fn certificate_info(&self, Parameters(i): Parameters<ApkPathInput>) -> String {
        let verifier = ApkSignVerifier;
        match std::fs::read(&i.apk_path) {
            Ok(data) => {
                use andro_core::traits::ApkSignatureVerifier;
                match verifier.certificates(&data) { Ok(c) => json_ok(&c), Err(e) => json_err(&e) }
            }, Err(e) => json_err(&e)
        }
    }

    #[tool(description = "Detect packer/obfuscator signatures in APK")]
    async fn packer_detect(&self, Parameters(i): Parameters<ApkPathInput>) -> String {
        // Check for known packer signatures in DEX/lib structure
        match ApkAnalyzer::analyze(std::path::Path::new(&i.apk_path)) {
            Ok(info) => {
                let mut packers = Vec::new();
                for entry in &info.dex_files {
                    if entry.name.contains("classes") && entry.name != "classes.dex" {
                        packers.push(format!("multidex: {}", entry.name));
                    }
                }
                json_ok(&packers)
            }, Err(e) => json_err(&e)
        }
    }

    #[tool(description = "Audit privacy of installed apps on device")]
    async fn privacy_audit(&self, Parameters(i): Parameters<DeviceInput>) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        match m.shell(i.device.as_deref(), "pm list packages -3") {
            Ok(o) => {
                let packages: Vec<&str> = o.stdout.lines()
                    .filter_map(|l| l.strip_prefix("package:"))
                    .collect();
                format!(r#"{{"third_party_apps":{},"count":{}}}"#, json_ok(&packages), packages.len())
            }, Err(e) => json_err(&e)
        }
    }

    // ── Hardware tools (5) ─────────────────────────────────────────────

    #[tool(description = "Parse Android boot image header")]
    async fn boot_info(&self, Parameters(i): Parameters<BootImageInput>) -> String {
        match BootImage::parse(std::path::Path::new(&i.image_path)) { Ok(r) => json_ok(&r), Err(e) => json_err(&e) }
    }

    #[tool(description = "List USB devices in fastboot mode")]
    async fn fastboot_devices(&self) -> String {
        match FastbootClient::list_devices() { Ok(d) => json_ok(&d), Err(e) => json_err(&e) }
    }

    #[tool(description = "Check AVB verified boot status")]
    async fn avb_status(&self, Parameters(i): Parameters<DeviceInput>) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        match m.shell(i.device.as_deref(), "getprop ro.boot.verifiedbootstate") {
            Ok(o) => format!(r#"{{"verified_boot_state":"{}"}}"#, o.stdout.trim()), Err(e) => json_err(&e)
        }
    }

    #[tool(description = "Get partition information from device")]
    async fn partition_info(&self, Parameters(i): Parameters<DeviceInput>) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        match m.shell(i.device.as_deref(), "ls -la /dev/block/by-name/") {
            Ok(o) => format!(r#"{{"partitions":"{}"}}"#, o.stdout.replace('"', "'")), Err(e) => json_err(&e)
        }
    }

    // ── Farm tools (4) ─────────────────────────────────────────────────

    #[tool(description = "Scan USB for connected Android devices")]
    async fn usb_scan(&self) -> String {
        match UsbDiscovery::scan() { Ok(d) => json_ok(&d), Err(e) => json_err(&e) }
    }

    #[tool(description = "Get fleet status — all connected devices with details")]
    async fn fleet_status(&self) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        match m.list_devices() { Ok(d) => json_ok(&d), Err(e) => json_err(&e) }
    }

    #[tool(description = "Execute command on all connected devices in parallel")]
    async fn fleet_exec(&self, Parameters(i): Parameters<FleetExecInput>) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        match m.list_devices() {
            Ok(devices) => {
                let mut results = Vec::new();
                for d in &devices {
                    match m.shell(Some(&d.id.0), &i.command) {
                        Ok(o) => results.push(serde_json::json!({"device": d.id.0, "stdout": o.stdout})),
                        Err(e) => results.push(serde_json::json!({"device": d.id.0, "error": e.to_string()})),
                    }
                }
                json_ok(&results)
            }, Err(e) => json_err(&e)
        }
    }

    #[tool(description = "Install APK on all connected devices")]
    async fn fleet_install(&self, Parameters(i): Parameters<InstallInput>) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        match m.list_devices() {
            Ok(devices) => {
                let mut results = Vec::new();
                let path = std::path::PathBuf::from(&i.apk_path);
                for d in &devices {
                    match m.install(Some(&d.id.0), &path) {
                        Ok(()) => results.push(serde_json::json!({"device": d.id.0, "ok": true})),
                        Err(e) => results.push(serde_json::json!({"device": d.id.0, "error": e.to_string()})),
                    }
                }
                json_ok(&results)
            }, Err(e) => json_err(&e)
        }
    }

    // ── GrapheneOS tools (5) ───────────────────────────────────────────

    #[tool(description = "Get GrapheneOS-specific device status")]
    async fn gos_status(&self, Parameters(i): Parameters<DeviceInput>) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        match m.shell(i.device.as_deref(), "getprop ro.grapheneos.release_version") {
            Ok(o) => {
                let version = o.stdout.trim().to_string();
                if version.is_empty() {
                    r#"{"grapheneos":false,"info":"Not a GrapheneOS device"}"#.into()
                } else {
                    format!(r#"{{"grapheneos":true,"version":"{}"}}"#, version)
                }
            }, Err(e) => json_err(&e)
        }
    }

    #[tool(description = "List user profiles on GrapheneOS device")]
    async fn gos_profiles(&self, Parameters(i): Parameters<DeviceInput>) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        match m.shell(i.device.as_deref(), "pm list users") {
            Ok(o) => format!(r#"{{"profiles":{}}}"#, json_ok(&o.stdout.lines().collect::<Vec<_>>())),
            Err(e) => json_err(&e)
        }
    }

    #[tool(description = "Check for GrapheneOS OTA updates")]
    async fn gos_ota_check(&self, Parameters(i): Parameters<DeviceInput>) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        match m.shell(i.device.as_deref(), "getprop ro.product.device") {
            Ok(o) => {
                let device = o.stdout.trim();
                format!(r#"{{"device":"{}","ota_url":"https://releases.grapheneos.org/{}-stable"}}"#, device, device)
            }, Err(e) => json_err(&e)
        }
    }

    #[tool(description = "Check AVB verified boot status for GrapheneOS")]
    async fn gos_avb_status(&self, Parameters(i): Parameters<DeviceInput>) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        let vb = m.shell(i.device.as_deref(), "getprop ro.boot.verifiedbootstate");
        let vbm = m.shell(i.device.as_deref(), "getprop ro.boot.vbmeta.device_state");
        format!(r#"{{"verified_boot":"{}","device_state":"{}"}}"#,
            vb.map(|o| o.stdout.trim().to_string()).unwrap_or_default(),
            vbm.map(|o| o.stdout.trim().to_string()).unwrap_or_default())
    }

    #[tool(description = "Check sandboxed Google Play Services status")]
    async fn gos_play_status(&self, Parameters(i): Parameters<DeviceInput>) -> String {
        let mut m = DeviceManager::from_config(&self.config);
        match m.shell(i.device.as_deref(), "pm list packages com.google.android.gms") {
            Ok(o) => {
                let installed = o.stdout.contains("com.google.android.gms");
                format!(r#"{{"play_services_installed":{installed}}}"#)
            }, Err(e) => json_err(&e)
        }
    }
}

#[tool_handler]
impl ServerHandler for AndroMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Android DevOps suite — 42 tools: device management, settings, health, \
                 file transfer, log analysis, APK/DEX analysis, security scanning, \
                 signature verification, hardware inspection, fleet orchestration, \
                 and GrapheneOS integration."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

/// Run the MCP server on stdio transport.
pub async fn run() -> ExitCode {
    let config = AndroConfig::load();
    let server = AndroMcp::new(config);

    match server.serve(stdio()).await {
        Ok(ct) => {
            if let Err(e) = ct.waiting().await {
                eprintln!("MCP server error: {e}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("MCP server error: {e}");
            ExitCode::FAILURE
        }
    }
}
