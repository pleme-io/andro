# andro — Android DevOps Suite

Single multicall binary: CLI + daemon + MCP server for Android device management,
file transfer, debugging, security analysis, build pipeline, and hardware operations.

## Architecture

```
andro (binary: CLI + daemon + MCP)
├── andro-core    (shared: device model, config, errors, ADB wrapper)
├── andro-adb     (device ops: list, info, shell, install, parallel, groups)
├── andro-sync    (file transfer: BLAKE3 delta sync, backup, media org)
├── andro-log     (debug: persistent logcat, FTS, crash/ANR extraction)
├── andro-build   (APK/AAB: analysis, size tracking, DEX parsing)
├── andro-sec     (security: scan pipeline, permission audit, secrets)
├── andro-farm    (device farm: USB discovery, inventory, health polling)
└── andro-hw      (hardware: boot images, fastboot protocol, partitions)
```

## Implementation Status

| Crate | Phase | Status |
|-------|-------|--------|
| andro-core | 1 | Implemented |
| andro-adb | 1 | Implemented |
| andro (binary) | 1 | Implemented (CLI + MCP) |
| andro-sync | 2 | Stub |
| andro-log | 3 | Stub |
| andro-build | 4 | Stub |
| andro-sec | 4 | Stub |
| andro-farm | 5 | Stub |
| andro-hw | 5 | Stub |

## CLI Quick Reference

```
andro device list              # list connected devices
andro device info [-d serial]  # detailed device info (JSON)
andro shell [-d serial] cmd    # run shell command
andro install [-d serial] app.apk  # install APK
andro mcp                      # start MCP server (also default with no args)
andro sync push src dst        # (phase 2)
andro sync pull src dst        # (phase 2)
andro log watch                # (phase 3)
andro log search "query"       # (phase 3)
andro build analyze app.apk    # (phase 4)
andro build diff base.apk new.apk  # (phase 4)
andro sec scan app.apk         # (phase 4)
andro hw status                # (phase 5)
andro hw boot unpack boot.img  # (phase 5)
andro farm status              # (phase 5)
```

## MCP Tools (Phase 1)

| Tool | Description |
|------|-------------|
| `device_list` | List connected devices |
| `device_info` | Detailed device properties |
| `shell` | Execute shell command on device |
| `install` | Install APK on device |

## Config

`~/.config/andro/andro.yaml` (or `$ANDRO_CONFIG`):

```yaml
adb_host: "127.0.0.1"
adb_port: 5037
default_device: null
groups:
  test-phones:
    - "SERIAL1"
    - "SERIAL2"
sync:
  backup_dir: "~/.local/share/andro/backups"
  exclude: [".thumbnails", ".trashed-*"]
log:
  db_path: "~/.local/share/andro/logs.db"
  retention_days: 30
```

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| `adb_client` 3.1 | Native ADB protocol (TCP transport) |
| `nusb` 0.2 | Pure Rust USB (fastboot, device discovery) |
| `rmcp` 0.15 | MCP server (stdio transport) |
| `binrw` 0.15 | Binary format parsing (boot images) |
| `blake3` | Content-addressed file sync |
| `rusqlite` | Log storage, size tracking, device inventory |

## Conventions

- Edition 2024, Rust 1.91.0+, MIT, clippy pedantic
- Release: codegen-units=1, lto=true, opt-level="z", strip=true
- ADB via TCP transport only (no libusb, requires `adb start-server`)
- Config: `~/.config/andro/andro.yaml` with `$ANDRO_CONFIG` override
- MCP: rmcp 0.15, schemars for tool schemas
- No subcommand → MCP server mode (stdin/stdout)
