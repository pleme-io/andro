use andro_adb::DeviceManager;
use andro_core::AndroConfig;
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::Deserialize;
use std::process::ExitCode;

// ── MCP input schemas ──────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DeviceInput {
    /// Device serial number (omit for single-device auto-selection)
    #[schemars(default)]
    device: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ShellInput {
    /// Device serial number (omit for single-device auto-selection)
    #[schemars(default)]
    device: Option<String>,

    /// Shell command to execute on the device
    command: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct InstallInput {
    /// Device serial number (omit for single-device auto-selection)
    #[schemars(default)]
    device: Option<String>,

    /// Path to APK file on the host machine
    apk_path: String,
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

    #[tool(description = "List all connected Android devices with serial numbers and connection state. Returns JSON array.")]
    async fn device_list(&self) -> String {
        let manager = DeviceManager::from_config(&self.config);
        match manager.list_devices() {
            Ok(devices) => serde_json::to_string_pretty(&devices).unwrap_or_else(|e| format!(r#"{{"error":"{e}"}}"#)),
            Err(e) => format!(r#"{{"error":"{e}"}}"#),
        }
    }

    #[tool(description = "Get detailed device information: model, manufacturer, Android version, API level, build fingerprint. Returns JSON.")]
    async fn device_info(&self, Parameters(input): Parameters<DeviceInput>) -> String {
        let manager = DeviceManager::from_config(&self.config);
        match manager.device_info(input.device.as_deref()) {
            Ok(info) => serde_json::to_string_pretty(&info).unwrap_or_else(|e| format!(r#"{{"error":"{e}"}}"#)),
            Err(e) => format!(r#"{{"error":"{e}"}}"#),
        }
    }

    #[tool(description = "Execute a shell command on an Android device and return stdout.")]
    async fn shell(&self, Parameters(input): Parameters<ShellInput>) -> String {
        let manager = DeviceManager::from_config(&self.config);
        match manager.shell(input.device.as_deref(), &input.command) {
            Ok(output) => output.stdout,
            Err(e) => format!(r#"{{"error":"{e}"}}"#),
        }
    }

    #[tool(description = "Install an APK file on an Android device.")]
    async fn install(&self, Parameters(input): Parameters<InstallInput>) -> String {
        let manager = DeviceManager::from_config(&self.config);
        let path = std::path::PathBuf::from(&input.apk_path);
        match manager.install(input.device.as_deref(), &path) {
            Ok(()) => format!(r#"{{"ok":true,"installed":"{}"}}"#, input.apk_path),
            Err(e) => format!(r#"{{"error":"{e}"}}"#),
        }
    }
}

#[tool_handler]
impl ServerHandler for AndroMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Android DevOps suite — device management, file transfer, debugging, \
                 security analysis, and hardware operations."
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
