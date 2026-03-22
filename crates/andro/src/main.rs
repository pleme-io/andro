mod mcp;

use andro_adb::DeviceManager;
use andro_core::AndroConfig;
use clap::{Parser, Subcommand};
use std::process::ExitCode;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser)]
#[command(name = "andro", version, about = "Android DevOps suite")]
struct Cli {
    /// Output logs as JSON (for systemd journal integration)
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    // ── Phase 1: Device operations ─────────────────────────────────────
    /// List connected devices
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },

    /// Run a shell command on a device
    Shell {
        /// Device serial (omit for single-device)
        #[arg(short, long)]
        device: Option<String>,

        /// Command to execute
        command: Vec<String>,
    },

    /// Install an APK on a device
    Install {
        /// Device serial
        #[arg(short, long)]
        device: Option<String>,

        /// Path to APK file
        apk: String,
    },

    // ── Phase 2: File transfer (stub) ──────────────────────────────────
    /// File sync and backup operations
    Sync {
        #[command(subcommand)]
        action: SyncAction,
    },

    // ── Phase 3: Debugging (stub) ──────────────────────────────────────
    /// Log capture and analysis
    Log {
        #[command(subcommand)]
        action: LogAction,
    },

    // ── Phase 4: Build analysis (stub) ─────────────────────────────────
    /// APK/AAB analysis and size tracking
    Build {
        #[command(subcommand)]
        action: BuildAction,
    },

    /// Security scanning
    Sec {
        #[command(subcommand)]
        action: SecAction,
    },

    // ── Phase 5: Hardware (stub) ───────────────────────────────────────
    /// Hardware operations (fastboot, boot images)
    Hw {
        #[command(subcommand)]
        action: HwAction,
    },

    /// Device farm management
    Farm {
        #[command(subcommand)]
        action: FarmAction,
    },

    // ── MCP server ─────────────────────────────────────────────────────
    /// Start MCP server (stdio transport)
    Mcp,
}

// ── Phase 1 subcommands ────────────────────────────────────────────────

#[derive(Subcommand)]
enum DeviceAction {
    /// List all connected devices
    List,
    /// Show detailed device info
    Info {
        /// Device serial
        #[arg(short, long)]
        device: Option<String>,
    },
}

// ── Phase 2-5 stub subcommands ─────────────────────────────────────────

#[derive(Subcommand)]
enum SyncAction {
    /// Push files to device
    Push {
        /// Local source path
        src: String,
        /// Remote destination path
        dst: String,
    },
    /// Pull files from device
    Pull {
        /// Remote source path
        src: String,
        /// Local destination path
        dst: String,
    },
}

#[derive(Subcommand)]
enum LogAction {
    /// Watch live logcat
    Watch,
    /// Search log history
    Search {
        /// Search query
        query: String,
    },
}

#[derive(Subcommand)]
enum BuildAction {
    /// Analyze an APK
    Analyze {
        /// Path to APK file
        apk: String,
    },
    /// Diff two APKs
    Diff {
        /// Base APK
        base: String,
        /// Target APK
        target: String,
    },
}

#[derive(Subcommand)]
enum SecAction {
    /// Scan an APK for security issues
    Scan {
        /// Path to APK file
        apk: String,
    },
}

#[derive(Subcommand)]
enum HwAction {
    /// Show fastboot device status
    Status,
    /// Boot image operations
    Boot {
        #[command(subcommand)]
        action: BootAction,
    },
}

#[derive(Subcommand)]
enum BootAction {
    /// Unpack a boot image
    Unpack {
        /// Path to boot.img
        image: String,
    },
}

#[derive(Subcommand)]
enum FarmAction {
    /// Show device farm status
    Status,
}

// ── Entry point ────────────────────────────────────────────────────────

fn init_tracing(json: bool) {
    if json {
        tracing_subscriber::registry()
            .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .init();
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.json);

    // No subcommand → MCP server (default mode, like kurage)
    let Some(command) = cli.command else {
        return mcp::run().await;
    };

    match run(command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "fatal");
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(command: Command) -> andro_core::Result<()> {
    let config = AndroConfig::load();
    let manager = DeviceManager::from_config(&config);

    match command {
        // ── Phase 1: implemented ───────────────────────────────────────
        Command::Device { action } => match action {
            DeviceAction::List => {
                let devices = manager.list_devices()?;
                if devices.is_empty() {
                    println!("no devices connected");
                } else {
                    for d in &devices {
                        println!("{}\t{}", d.id, d.state);
                    }
                }
                Ok(())
            }
            DeviceAction::Info { device } => {
                let info = manager.device_info(device.as_deref())?;
                println!("{}", serde_json::to_string_pretty(&info)?);
                Ok(())
            }
        },

        Command::Shell { device, command: cmd } => {
            let full_cmd = cmd.join(" ");
            let output = manager.shell(device.as_deref(), &full_cmd)?;
            print!("{}", output.stdout);
            Ok(())
        }

        Command::Install { device, apk } => {
            let path = std::path::PathBuf::from(&apk);
            manager.install(device.as_deref(), &path)?;
            println!("installed {apk}");
            Ok(())
        }

        Command::Mcp => {
            mcp::run().await;
            Ok(())
        }

        // ── Phases 2-5: stubs ──────────────────────────────────────────
        Command::Sync { .. } => {
            eprintln!("andro sync: not yet implemented (phase 2)");
            Ok(())
        }
        Command::Log { .. } => {
            eprintln!("andro log: not yet implemented (phase 3)");
            Ok(())
        }
        Command::Build { .. } => {
            eprintln!("andro build: not yet implemented (phase 4)");
            Ok(())
        }
        Command::Sec { .. } => {
            eprintln!("andro sec: not yet implemented (phase 4)");
            Ok(())
        }
        Command::Hw { .. } => {
            eprintln!("andro hw: not yet implemented (phase 5)");
            Ok(())
        }
        Command::Farm { .. } => {
            eprintln!("andro farm: not yet implemented (phase 5)");
            Ok(())
        }
    }
}
