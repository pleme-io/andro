# andro — Android DevOps Suite

Single multicall binary: CLI + MCP server for Android device management,
file transfer, debugging, security analysis, build pipeline, and hardware operations.

## Build & Test

```bash
cargo build          # all 9 crates
cargo test           # 23 tests
cargo run -- --help  # CLI usage
cargo run            # MCP server (default, no args)
```

## Architecture

```
andro (binary: CLI + MCP, 17 MCP tools)
├── andro-core    (device model, config, errors)
├── andro-adb     (device list/info/shell/install via adb_client TCP)
├── andro-sync    (BLAKE3 delta sync, manifest tracking, media org)
├── andro-log     (logcat parser, SQLite FTS5 storage, crash/ANR detection)
├── andro-build   (APK ZIP analysis, DEX stats, size tracking)
├── andro-sec     (8 security rules, permission risk classification)
├── andro-farm    (USB discovery via nusb, SQLite device inventory)
└── andro-hw      (boot image parsing, fastboot device enumeration)
```

## CLI Reference

```
andro device list                    # list connected devices
andro device info [-d serial]        # detailed device info (JSON)
andro shell [-d serial] <cmd>        # run shell command
andro install [-d serial] <apk>      # install APK

andro sync push [-d serial] <src> <dst>    # push file to device
andro sync pull [-d serial] <src> <dst>    # pull file from device

andro log search <query> [-l limit]  # FTS search log history
andro log stats                      # log storage statistics
andro log prune [-d days]            # prune old entries

andro build analyze <apk>            # APK structure analysis (JSON)
andro build diff <base> <target>     # APK structural diff (JSON)

andro sec scan <apk>                 # security scan (8 rules)

andro hw fastboot                    # list fastboot devices
andro hw boot-info <image>           # parse boot image header
andro hw boot-unpack <image> [-o dir]  # extract kernel/ramdisk

andro farm scan                      # scan USB for Android devices

andro mcp                            # start MCP server (also default)
```

## MCP Tools (17 tools)

| Tool | Description |
|------|-------------|
| `device_list` | List connected devices |
| `device_info` | Detailed device properties |
| `shell` | Execute shell command on device |
| `install_apk` | Install APK on device |
| `push_file` | Push file host → device |
| `pull_file` | Pull file device → host |
| `log_search` | FTS search log history |
| `log_stats` | Log storage statistics |
| `apk_analyze` | APK structure analysis |
| `apk_diff` | Structural diff of two APKs |
| `apk_scan` | Security scan (8 rules) |
| `permission_audit` | Permission risk classification |
| `boot_info` | Boot image header parsing |
| `fastboot_devices` | List fastboot devices |
| `usb_scan` | Scan USB for Android devices |

## Security Rules (andro-sec)

| Rule | Severity | Pattern |
|------|----------|---------|
| `AWS_KEY` | Critical | `AKIA[0-9A-Z]{16}` |
| `PRIVATE_KEY` | Critical | `-----BEGIN (RSA)?PRIVATE KEY-----` |
| `HARDCODED_SECRET` | High | API key/secret/token assignments |
| `GOOGLE_API_KEY` | Medium | `AIza[0-9A-Za-z_-]{35}` |
| `HTTP_URL` | Medium | `http://` (not HTTPS) |
| `DEBUG_FLAG` | Medium | `debug=true` |
| `LOG_SENSITIVE` | Low | `Log.*password/token/secret` |
| `FIREBASE_URL` | Low | Firebase database URLs |

## Config

`~/.config/andro/andro.yaml`:

```yaml
adb_host: "127.0.0.1"
adb_port: 5037
default_device: null
groups:
  test-phones: ["SERIAL1", "SERIAL2"]
sync:
  backup_dir: "~/.local/share/andro/backups"
  exclude: [".thumbnails", ".trashed-*"]
log:
  db_path: "~/.local/share/andro/logs.db"
  retention_days: 30
```

## Key Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `adb_client` | 3.1 | ADB protocol (TCP transport) |
| `nusb` | 0.1 | Pure Rust USB (fastboot, discovery) |
| `rmcp` | 0.15 | MCP server (stdio transport) |
| `rusqlite` | 0.33 | Log storage, size tracking, inventory |
| `blake3` | 1 | Content-addressed file sync |
| `zip` | 2 | APK/AAB analysis |
| `kamadak-exif` | 0.6 | Media EXIF date extraction |
| `schemars` | 0.8 | MCP tool JSON schemas |

## Conventions

- Edition 2024, Rust 1.91.0+, MIT, clippy pedantic
- Release: codegen-units=1, lto=true, opt-level="z", strip=true
- ADB via TCP only (no libusb), requires `adb start-server`
- No subcommand → MCP server mode (stdin/stdout)
- Config: `~/.config/andro/andro.yaml` with `$ANDRO_CONFIG` override
