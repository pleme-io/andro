# CLI Reference

## Device Operations

```bash
andro device list              # List all connected devices
andro device info -d SERIAL    # Detailed device info as JSON
andro shell -d SERIAL "cmd"    # Execute shell command
andro install -d SERIAL app.apk  # Install APK
```

## File Transfer

```bash
andro sync push -d SERIAL ./local /sdcard/remote  # Push file
andro sync pull -d SERIAL /sdcard/remote ./local   # Pull file
```

## Log Analysis

```bash
andro log search "crash"       # Full-text search log history
andro log search "OOM" -l 50   # Search with limit
andro log stats                # Show storage statistics
andro log prune -d 7           # Delete entries older than 7 days
```

## Build Analysis

```bash
andro build analyze app.apk              # APK structure breakdown
andro build diff v1.apk v2.apk           # Structural diff
```

## Security

```bash
andro sec scan app.apk         # Scan for security issues
```

## Hardware

```bash
andro hw fastboot              # List fastboot devices
andro hw boot-info boot.img    # Parse boot image header
andro hw boot-unpack boot.img -o ./parts  # Extract components
```

## Device Farm

```bash
andro farm scan                # Scan USB for Android devices
```

## MCP Server

```bash
andro mcp                     # Start MCP server (stdio)
andro                         # Same as `andro mcp` (default)
```
