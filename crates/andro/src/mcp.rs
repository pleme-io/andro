use andro_adb::DeviceManager;
use andro_build::ApkAnalyzer;
use andro_core::AndroConfig;
use andro_farm::UsbDiscovery;
use andro_hw::{BootImage, FastbootClient};
use andro_log::LogStore;
use andro_sec::{ApkScanner, PermissionAudit};
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
    /// Device serial number (omit for single-device auto-selection)
    #[schemars(default)]
    device: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ShellInput {
    /// Device serial number
    #[schemars(default)]
    device: Option<String>,
    /// Shell command to execute on the device
    command: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct InstallInput {
    /// Device serial number
    #[schemars(default)]
    device: Option<String>,
    /// Path to APK file on the host machine
    apk_path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct FileTransferInput {
    /// Device serial number
    #[schemars(default)]
    device: Option<String>,
    /// Source path
    source: String,
    /// Destination path
    destination: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct LogSearchInput {
    /// FTS search query
    query: String,
    /// Maximum results to return (default: 20)
    #[schemars(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ApkPathInput {
    /// Path to APK file
    apk_path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ApkDiffInput {
    /// Path to base APK
    base_apk: String,
    /// Path to target APK
    target_apk: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PermissionsInput {
    /// List of Android permission strings
    permissions: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct BootImageInput {
    /// Path to boot.img file
    image_path: String,
}

// ── Helpers ────────────────────────────────────────────────────────────

fn json_ok<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|e| json_err(&e))
}

fn json_err(e: &dyn std::fmt::Display) -> String {
    format!(r#"{{"error":"{}"}}"#, e.to_string().replace('"', "'"))
}

/// Resolve device serial: use provided serial or auto-detect single device.
fn resolve_serial(config: &AndroConfig, device: Option<String>) -> Result<String, String> {
    match device {
        Some(s) => Ok(s),
        None => {
            let manager = DeviceManager::from_config(config);
            match manager.list_devices() {
                Ok(devices) => match devices.len() {
                    0 => Err("no devices connected".into()),
                    1 => Ok(devices[0].id.0.clone()),
                    _ => Err("multiple devices connected, specify device serial".into()),
                },
                Err(e) => Err(e.to_string()),
            }
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
        Self {
            config,
            tool_router: Self::tool_router(),
        }
    }

    // ── Device tools ───────────────────────────────────────────────────

    #[tool(description = "List all connected Android devices with serial numbers and connection state. Returns JSON array.")]
    async fn device_list(&self) -> String {
        let manager = DeviceManager::from_config(&self.config);
        match manager.list_devices() {
            Ok(devices) => json_ok(&devices),
            Err(e) => json_err(&e),
        }
    }

    #[tool(description = "Get detailed device information: model, manufacturer, Android version, API level, build fingerprint. Returns JSON.")]
    async fn device_info(&self, Parameters(input): Parameters<DeviceInput>) -> String {
        let manager = DeviceManager::from_config(&self.config);
        match manager.device_info(input.device.as_deref()) {
            Ok(info) => json_ok(&info),
            Err(e) => json_err(&e),
        }
    }

    #[tool(description = "Execute a shell command on an Android device and return stdout.")]
    async fn shell(&self, Parameters(input): Parameters<ShellInput>) -> String {
        let manager = DeviceManager::from_config(&self.config);
        match manager.shell(input.device.as_deref(), &input.command) {
            Ok(output) => output.stdout,
            Err(e) => json_err(&e),
        }
    }

    #[tool(description = "Install an APK file on an Android device.")]
    async fn install_apk(&self, Parameters(input): Parameters<InstallInput>) -> String {
        let manager = DeviceManager::from_config(&self.config);
        let path = std::path::PathBuf::from(&input.apk_path);
        match manager.install(input.device.as_deref(), &path) {
            Ok(()) => format!(r#"{{"ok":true,"installed":"{}"}}"#, input.apk_path),
            Err(e) => json_err(&e),
        }
    }

    // ── File transfer tools ────────────────────────────────────────────

    #[tool(description = "Push a file from host to Android device. Returns bytes transferred.")]
    async fn push_file(&self, Parameters(input): Parameters<FileTransferInput>) -> String {
        let syncer = FileSyncer::from_config(&self.config);
        match resolve_serial(&self.config, input.device) {
            Ok(serial) => {
                match syncer.push_file(&serial, std::path::Path::new(&input.source), &input.destination) {
                    Ok(bytes) => format!(r#"{{"ok":true,"bytes":{bytes}}}"#),
                    Err(e) => json_err(&e),
                }
            }
            Err(e) => json_err(&e),
        }
    }

    #[tool(description = "Pull a file from Android device to host. Returns bytes transferred.")]
    async fn pull_file(&self, Parameters(input): Parameters<FileTransferInput>) -> String {
        let syncer = FileSyncer::from_config(&self.config);
        match resolve_serial(&self.config, input.device) {
            Ok(serial) => {
                match syncer.pull_file(&serial, &input.source, std::path::Path::new(&input.destination)) {
                    Ok(bytes) => format!(r#"{{"ok":true,"bytes":{bytes}}}"#),
                    Err(e) => json_err(&e),
                }
            }
            Err(e) => json_err(&e),
        }
    }

    // ── Log tools ──────────────────────────────────────────────────────

    #[tool(description = "Search persistent log storage using full-text search. Returns matching log entries as JSON.")]
    async fn log_search(&self, Parameters(input): Parameters<LogSearchInput>) -> String {
        let db_path = &self.config.log.db_path;
        match LogStore::open(db_path) {
            Ok(store) => {
                let limit = input.limit.unwrap_or(20);
                match store.search(&input.query, limit) {
                    Ok(entries) => json_ok(&entries),
                    Err(e) => json_err(&e),
                }
            }
            Err(e) => json_err(&e),
        }
    }

    #[tool(description = "Get log storage statistics: total entries, database path.")]
    async fn log_stats(&self) -> String {
        let db_path = &self.config.log.db_path;
        match LogStore::open(db_path) {
            Ok(store) => match store.count() {
                Ok(count) => format!(
                    r#"{{"total_entries":{count},"db_path":"{}"}}"#,
                    db_path.display()
                ),
                Err(e) => json_err(&e),
            },
            Err(e) => json_err(&e),
        }
    }

    // ── Build analysis tools ───────────────────────────────────────────

    #[tool(description = "Analyze an APK file: size breakdown by category (DEX, resources, native libs, assets), entry count, ABIs. Returns JSON.")]
    async fn apk_analyze(&self, Parameters(input): Parameters<ApkPathInput>) -> String {
        match ApkAnalyzer::analyze(std::path::Path::new(&input.apk_path)) {
            Ok(info) => json_ok(&info),
            Err(e) => json_err(&e),
        }
    }

    #[tool(description = "Diff two APK files: size delta, DEX/resource/native size changes, added/removed entries. Returns JSON.")]
    async fn apk_diff(&self, Parameters(input): Parameters<ApkDiffInput>) -> String {
        match ApkAnalyzer::diff(
            std::path::Path::new(&input.base_apk),
            std::path::Path::new(&input.target_apk),
        ) {
            Ok(diff) => json_ok(&diff),
            Err(e) => json_err(&e),
        }
    }

    // ── Security tools ─────────────────────────────────────────────────

    #[tool(description = "Scan an APK for security issues: hardcoded secrets, API keys, private keys, insecure HTTP URLs, debug flags. Returns findings with severity.")]
    async fn apk_scan(&self, Parameters(input): Parameters<ApkPathInput>) -> String {
        let scanner = ApkScanner::new();
        match scanner.scan(std::path::Path::new(&input.apk_path)) {
            Ok(result) => json_ok(&result),
            Err(e) => json_err(&e),
        }
    }

    #[tool(description = "Audit Android permissions by risk level: Normal, Dangerous, Critical. Returns classified permission list.")]
    async fn permission_audit(&self, Parameters(input): Parameters<PermissionsInput>) -> String {
        let audit = PermissionAudit::audit(&input.permissions);
        json_ok(&audit)
    }

    // ── Hardware tools ─────────────────────────────────────────────────

    #[tool(description = "Parse an Android boot image header: kernel/ramdisk sizes, page size, command line. Returns JSON.")]
    async fn boot_info(&self, Parameters(input): Parameters<BootImageInput>) -> String {
        match BootImage::parse(std::path::Path::new(&input.image_path)) {
            Ok(image) => json_ok(&image),
            Err(e) => json_err(&e),
        }
    }

    #[tool(description = "List USB devices in fastboot mode. Returns JSON array.")]
    async fn fastboot_devices(&self) -> String {
        match FastbootClient::list_devices() {
            Ok(devices) => json_ok(&devices),
            Err(e) => json_err(&e),
        }
    }

    // ── Farm tools ─────────────────────────────────────────────────────

    #[tool(description = "Scan USB bus for connected Android devices. Returns JSON array with vendor/product IDs and serial.")]
    async fn usb_scan(&self) -> String {
        match UsbDiscovery::scan() {
            Ok(devices) => json_ok(&devices),
            Err(e) => json_err(&e),
        }
    }
}

#[tool_handler]
impl ServerHandler for AndroMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Android DevOps suite — 15 tools across device management, file transfer, \
                 log analysis, APK analysis, security scanning, hardware inspection, \
                 and USB device discovery."
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
