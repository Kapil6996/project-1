# ORACLE — Setup Guide

## System Requirements

### Forensic Workstation

| Component         | Minimum                      | Recommended                   |
|-------------------|------------------------------|-------------------------------|
| OS                | macOS 12+, Ubuntu 22.04+, Windows 10+ | macOS 14+, Ubuntu 24.04+, Windows 11 |
| RAM               | 8 GB                         | 16 GB                         |
| Storage           | 50 GB free                   | 200 GB SSD                    |
| USB               | USB 2.0                      | USB 3.0+                      |
| Network           | Not required during analysis | Required for installation only |

### Software Prerequisites

| Software          | Version   | Purpose                                     |
|-------------------|-----------|---------------------------------------------|
| Rust              | 1.75+     | Compilation of ORACLE platform              |
| ADB               | 34.0+     | Android device communication                |
| SQLite3            | 3.39+     | Evidence store and audit log backend        |
| Git               | 2.30+     | Source control and updates                  |

---

## Installation

### macOS / Linux

```bash
# Clone the repository
git clone https://github.com/Kapil6996/project-1.git oracle
cd oracle

# Make the install script executable
chmod +x scripts/install.sh

# Run the installer
./scripts/install.sh
```

### Windows

```powershell
# Clone the repository
git clone https://github.com/Kapil6996/project-1.git oracle
cd oracle

# Run the installer (as Administrator)
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

---

## ADB Setup and Verification

### 1. Install ADB

The installation script will install ADB automatically. To verify manually:

```bash
adb version
# Expected: Android Debug Bridge version 1.0.41 (or later)
```

### 2. Enable USB Debugging on the Target Device

1. Open **Settings** → **About Phone**
2. Tap **Build Number** 7 times to enable Developer Options
3. Go back to **Settings** → **Developer Options**
4. Enable **USB Debugging**
5. (Optional) Enable **USB Debugging (Security Settings)** on Xiaomi devices

### 3. Connect and Authorize

```bash
# List connected devices
adb devices

# Expected output:
# List of devices attached
# SERIAL_NUMBER    device
```

If the device shows `unauthorized`:
1. Check the device screen for an RSA key authorization prompt
2. Tap **Allow** (check "Always allow from this computer")
3. Run `adb devices` again — should now show `device`

### 4. Verify ADB Shell Access

```bash
# Test basic shell access
adb shell whoami
# Expected: shell

# Test property access
adb shell getprop ro.product.model
# Expected: Device model name (e.g., "Pixel 8 Pro")
```

---

## Test Device Requirements

### Minimum Test Device Setup

For development and validation, you need at least:

| Device Type           | Purpose                              |
|-----------------------|--------------------------------------|
| Non-rooted stock AOSP | Baseline unprivileged extraction     |
| Rooted device         | Full privileged logical extraction   |
| Samsung device        | OEM plugin validation                |

### Test Device Preparation

1. **Factory reset** the test device before validation testing
2. **Connect to known WiFi networks** (create a controlled test environment):
   - At least 3 different WiFi networks with different security types
   - One open network
   - One WPA2-PSK network
   - One WPA3-SAE network (if supported)
3. **Enable mobile hotspot** at least once to generate hotspot artifacts
4. **Wait 24 hours** to accumulate network statistics and battery data
5. **Reboot the device** to ensure persistent artifacts are written to disk

---

## Configuration

### Default Configuration File

The default configuration is at `config/default.toml`. After installation, the
active configuration is at `~/.oracle/config/oracle.toml`.

### Key Configuration Options

```toml
[general]
investigation_base_dir = "~/.oracle/investigations"
default_acquisition_method = "PrivilegedLogical"

[audit]
database_path = "audit.db"
enable_crash_recovery = true

[evidence]
enable_deduplication = true
verify_on_read = true

[capability]
adb_binary_path = "adb"  # Or full path if not on PATH
adb_timeout_seconds = 30

[parser]
enable_oem_plugins = true
strict_validation = true

[confidence]
model_version = "1.0"
allow_examiner_overrides = true

[report]
include_executive_summary = true
include_technical_report = true
include_chain_of_custody = true
```

---

## Verification

After installation, verify the platform is working:

```bash
# Check ORACLE binary
oracle --version

# Run preflight checks
oracle verify-system

# Create a test investigation
oracle new-investigation --case-number TEST-001

# Connect a device and detect capabilities
oracle detect-capabilities --serial <device_serial>
```

---

## Troubleshooting

### ADB Not Found
```
Error: ADB binary not found on PATH
```
**Solution**: Install ADB via the platform tools package and ensure it's on your PATH.

### Device Unauthorized
```
Error: Device SERIAL is not authorized for ADB
```
**Solution**: Check the device screen for the RSA key prompt and tap "Allow".

### Permission Denied on Artifact
```
Warning: Cannot read /data/misc/wifi/WifiConfigStore.xml: Permission denied
```
**Solution**: This artifact requires root access. The capability detection will
report this. Use a rooted device or accept the limitation.

### SQLite Database Locked
```
Error: Database error: database is locked
```
**Solution**: Ensure no other ORACLE instance is running against the same
investigation directory. Close any sqlite3 CLI sessions.

---

## Updating ORACLE

```bash
cd oracle
git pull origin main
cargo build --release
```

The binary at `target/release/oracle` will be updated. If installed to
`/usr/local/bin`, re-copy the binary.
