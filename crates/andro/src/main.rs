mod mcp;

use andro_adb::DeviceManager;
use andro_build::ApkAnalyzer;
use andro_core::AndroConfig;
use andro_farm::UsbDiscovery;
use andro_hw::{BootImage, FastbootClient};
use andro_log::LogStore;
use andro_sec::ApkScanner;
use andro_sync::FileSyncer;
use clap::{Parser, Subcommand};
use std::process::ExitCode;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser)]
#[command(name = "andro", version, about = "Android DevOps suite")]
struct Cli {
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Device operations
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },
    /// Run shell command on device
    Shell {
        #[arg(short, long)]
        device: Option<String>,
        command: Vec<String>,
    },
    /// Install APK
    Install {
        #[arg(short, long)]
        device: Option<String>,
        apk: String,
    },
    /// File sync and transfer
    Sync {
        #[command(subcommand)]
        action: SyncAction,
    },
    /// Log capture and analysis
    Log {
        #[command(subcommand)]
        action: LogAction,
    },
    /// APK/AAB analysis
    Build {
        #[command(subcommand)]
        action: BuildAction,
    },
    /// Security scanning
    Sec {
        #[command(subcommand)]
        action: SecAction,
    },
    /// Hardware operations
    Hw {
        #[command(subcommand)]
        action: HwAction,
    },
    /// Device farm management
    Farm {
        #[command(subcommand)]
        action: FarmAction,
    },
    /// Start MCP server (stdio)
    Mcp,
}

#[derive(Subcommand)]
enum DeviceAction {
    List,
    Info {
        #[arg(short, long)]
        device: Option<String>,
    },
}

#[derive(Subcommand)]
enum SyncAction {
    /// Push file to device
    Push {
        #[arg(short, long)]
        device: Option<String>,
        src: String,
        dst: String,
    },
    /// Pull file from device
    Pull {
        #[arg(short, long)]
        device: Option<String>,
        src: String,
        dst: String,
    },
}

#[derive(Subcommand)]
enum LogAction {
    /// Search log history
    Search {
        query: String,
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },
    /// Show log statistics
    Stats,
    /// Prune old entries
    Prune {
        #[arg(short, long, default_value = "30")]
        days: u32,
    },
}

#[derive(Subcommand)]
enum BuildAction {
    /// Analyze APK structure
    Analyze { apk: String },
    /// Diff two APKs
    Diff { base: String, target: String },
}

#[derive(Subcommand)]
enum SecAction {
    /// Scan APK for security issues
    Scan { apk: String },
}

#[derive(Subcommand)]
enum HwAction {
    /// List fastboot devices
    Fastboot,
    /// Parse boot image
    BootInfo { image: String },
    /// Unpack boot image
    BootUnpack {
        image: String,
        #[arg(short, long, default_value = "./boot_unpacked")]
        output: String,
    },
}

#[derive(Subcommand)]
enum FarmAction {
    /// Scan USB for Android devices
    Scan,
}

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

    match command {
        Command::Device { action } => {
            let manager = DeviceManager::from_config(&config);
            match action {
                DeviceAction::List => {
                    let devices = manager.list_devices()?;
                    if devices.is_empty() {
                        println!("no devices connected");
                    } else {
                        for d in &devices {
                            println!("{}\t{}", d.id, d.state);
                        }
                    }
                }
                DeviceAction::Info { device } => {
                    let info = manager.device_info(device.as_deref())?;
                    println!("{}", serde_json::to_string_pretty(&info)?);
                }
            }
        }

        Command::Shell { device, command: cmd } => {
            let manager = DeviceManager::from_config(&config);
            let output = manager.shell(device.as_deref(), &cmd.join(" "))?;
            print!("{}", output.stdout);
        }

        Command::Install { device, apk } => {
            let manager = DeviceManager::from_config(&config);
            manager.install(device.as_deref(), &std::path::PathBuf::from(&apk))?;
            println!("installed {apk}");
        }

        Command::Sync { action } => {
            let syncer = FileSyncer::from_config(&config);
            let manager = DeviceManager::from_config(&config);
            match action {
                SyncAction::Push { device, src, dst } => {
                    let serial = resolve_device(&manager, device.as_deref())?;
                    let bytes = syncer.push_file(&serial, std::path::Path::new(&src), &dst)?;
                    println!("pushed {bytes} bytes → {dst}");
                }
                SyncAction::Pull { device, src, dst } => {
                    let serial = resolve_device(&manager, device.as_deref())?;
                    let bytes = syncer.pull_file(&serial, &src, std::path::Path::new(&dst))?;
                    println!("pulled {bytes} bytes → {dst}");
                }
            }
        }

        Command::Log { action } => match action {
            LogAction::Search { query, limit } => {
                let store = LogStore::open(&config.log.db_path)
                    .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
                let entries = store.search(&query, limit)?;
                if entries.is_empty() {
                    println!("no matches");
                } else {
                    for entry in &entries {
                        println!(
                            "{} {} {}/{}: {}",
                            entry.timestamp.map(|t| t.to_string()).unwrap_or_default(),
                            entry.level.as_char(),
                            entry.tag,
                            entry.pid.unwrap_or(0),
                            entry.message
                        );
                    }
                    println!("\n{} entries found", entries.len());
                }
            }
            LogAction::Stats => {
                let store = LogStore::open(&config.log.db_path)
                    .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
                let count = store.count()?;
                println!("log entries: {count}");
                println!("database: {}", config.log.db_path.display());
            }
            LogAction::Prune { days } => {
                let store = LogStore::open(&config.log.db_path)
                    .map_err(|e| andro_core::AndroError::Other(e.to_string()))?;
                let deleted = store.prune(days)?;
                println!("pruned {deleted} entries older than {days} days");
            }
        },

        Command::Build { action } => match action {
            BuildAction::Analyze { apk } => {
                let info = ApkAnalyzer::analyze(std::path::Path::new(&apk))?;
                println!("{}", serde_json::to_string_pretty(&info)?);
            }
            BuildAction::Diff { base, target } => {
                let diff = ApkAnalyzer::diff(
                    std::path::Path::new(&base),
                    std::path::Path::new(&target),
                )?;
                println!("{}", serde_json::to_string_pretty(&diff)?);
            }
        },

        Command::Sec { action } => match action {
            SecAction::Scan { apk } => {
                let scanner = ApkScanner::new();
                let result = scanner.scan(std::path::Path::new(&apk))?;
                println!("{}", serde_json::to_string_pretty(&result)?);
                if result.critical_count > 0 || result.high_count > 0 {
                    eprintln!(
                        "\n⚠ {} critical, {} high severity findings",
                        result.critical_count, result.high_count
                    );
                }
            }
        },

        Command::Hw { action } => match action {
            HwAction::Fastboot => {
                let devices = FastbootClient::list_devices()?;
                if devices.is_empty() {
                    println!("no fastboot devices");
                } else {
                    println!("{}", serde_json::to_string_pretty(&devices)?);
                }
            }
            HwAction::BootInfo { image } => {
                let boot = BootImage::parse(std::path::Path::new(&image))?;
                println!("{}", serde_json::to_string_pretty(&boot)?);
            }
            HwAction::BootUnpack { image, output } => {
                let boot = BootImage::parse(std::path::Path::new(&image))?;
                boot.unpack(std::path::Path::new(&image), std::path::Path::new(&output))?;
                println!("unpacked to {output}/");
            }
        },

        Command::Farm { action } => match action {
            FarmAction::Scan => {
                let devices = UsbDiscovery::scan()?;
                if devices.is_empty() {
                    println!("no Android USB devices found");
                } else {
                    println!("{}", serde_json::to_string_pretty(&devices)?);
                }
            }
        },

        Command::Mcp => {
            let code = mcp::run().await;
            return if code == ExitCode::SUCCESS { Ok(()) } else {
                Err(andro_core::AndroError::Other("MCP server failed".into()))
            };
        }
    }

    Ok(())
}

fn resolve_device(manager: &DeviceManager, serial: Option<&str>) -> andro_core::Result<String> {
    match serial {
        Some(s) => Ok(s.to_string()),
        None => {
            let devices = manager.list_devices()?;
            match devices.len() {
                0 => Err(andro_core::AndroError::NoDevices),
                1 => Ok(devices[0].id.0.clone()),
                _ => Err(andro_core::AndroError::MultipleDevices),
            }
        }
    }
}
