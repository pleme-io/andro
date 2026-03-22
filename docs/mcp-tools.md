# MCP Tools Reference

17 tools across 7 domains. All tools return JSON.

## Device (4 tools)

| Tool | Input | Description |
|------|-------|-------------|
| `device_list` | `{device?}` | List connected devices |
| `device_info` | `{device?}` | Model, manufacturer, Android version, API level |
| `shell` | `{device?, command}` | Execute shell command, return stdout |
| `install_apk` | `{device?, apk_path}` | Install APK file |

## File Transfer (2 tools)

| Tool | Input | Description |
|------|-------|-------------|
| `push_file` | `{device?, source, destination}` | Push host → device |
| `pull_file` | `{device?, source, destination}` | Pull device → host |

## Log Analysis (2 tools)

| Tool | Input | Description |
|------|-------|-------------|
| `log_search` | `{query, limit?}` | FTS search persistent log store |
| `log_stats` | `{}` | Total entries, database path |

## Build Analysis (2 tools)

| Tool | Input | Description |
|------|-------|-------------|
| `apk_analyze` | `{apk_path}` | Size breakdown, DEX count, ABIs, entries |
| `apk_diff` | `{base_apk, target_apk}` | Size delta, added/removed entries |

## Security (2 tools)

| Tool | Input | Description |
|------|-------|-------------|
| `apk_scan` | `{apk_path}` | 8-rule security scan with severity |
| `permission_audit` | `{permissions[]}` | Risk classification per permission |

## Hardware (2 tools)

| Tool | Input | Description |
|------|-------|-------------|
| `boot_info` | `{image_path}` | Boot image header: kernel/ramdisk sizes, cmdline |
| `fastboot_devices` | `{}` | USB fastboot device enumeration |

## Farm (1 tool)

| Tool | Input | Description |
|------|-------|-------------|
| `usb_scan` | `{}` | Scan USB for Android devices (16 vendor IDs) |
