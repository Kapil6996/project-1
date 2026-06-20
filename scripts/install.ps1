# ============================================================================
# ORACLE Android Network Forensics Platform — Windows Installation Script
# ============================================================================
#
# This script sets up a forensic workstation for ORACLE on Windows.
# It installs required dependencies, verifies ADB access, and builds the
# ORACLE binary from source.
#
# Usage:
#   Right-click → Run with PowerShell
#   or: powershell -ExecutionPolicy Bypass -File install.ps1
#
# Requirements:
#   - Windows 10/11 (64-bit)
#   - Internet access for dependency download
#   - Administrator privileges
#
# ============================================================================

$ErrorActionPreference = "Stop"

# ── Banner ───────────────────────────────────────────────────────────────────
function Show-Banner {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║         ORACLE — Android Network Forensics Platform         ║" -ForegroundColor Cyan
    Write-Host "║              Windows Installation Script v1.0               ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# ── Check Admin ──────────────────────────────────────────────────────────────
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal($currentUser)).IsInRole($adminRole)
    if (-not $isAdmin) {
        Write-Host "[!] This script requires Administrator privileges." -ForegroundColor Yellow
        Write-Host "    Right-click PowerShell → Run as Administrator" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "[✓] Running with Administrator privileges" -ForegroundColor Green
}

# ── Install Rust ─────────────────────────────────────────────────────────────
function Install-Rust {
    Write-Host "`n[1/6] Checking Rust toolchain..." -ForegroundColor Blue

    $rustc = Get-Command rustc -ErrorAction SilentlyContinue
    if ($rustc) {
        $version = & rustc --version
        Write-Host "[✓] Rust is installed: $version" -ForegroundColor Green
    } else {
        Write-Host "[!] Rust not found. Installing via rustup..." -ForegroundColor Yellow

        $rustupUrl = "https://win.rustup.rs/x86_64"
        $rustupInstaller = "$env:TEMP\rustup-init.exe"

        Invoke-WebRequest -Uri $rustupUrl -OutFile $rustupInstaller -UseBasicParsing
        & $rustupInstaller -y --default-toolchain stable

        # Refresh PATH
        $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
        Write-Host "[✓] Rust installed: $(rustc --version)" -ForegroundColor Green
    }
}

# ── Install ADB ──────────────────────────────────────────────────────────────
function Install-ADB {
    Write-Host "`n[2/6] Checking Android Debug Bridge (ADB)..." -ForegroundColor Blue

    $adb = Get-Command adb -ErrorAction SilentlyContinue
    if ($adb) {
        $version = & adb version | Select-Object -First 1
        Write-Host "[✓] ADB is installed: $version" -ForegroundColor Green
    } else {
        Write-Host "[!] ADB not found. Installing platform-tools..." -ForegroundColor Yellow

        $adbUrl = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
        $adbZip = "$env:TEMP\platform-tools.zip"
        $adbDir = "$env:LOCALAPPDATA\Android\platform-tools"

        Invoke-WebRequest -Uri $adbUrl -OutFile $adbZip -UseBasicParsing
        Expand-Archive -Path $adbZip -DestinationPath "$env:LOCALAPPDATA\Android" -Force

        # Add to PATH permanently
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($currentPath -notlike "*platform-tools*") {
            [Environment]::SetEnvironmentVariable("Path", "$currentPath;$adbDir", "User")
            $env:PATH = "$adbDir;$env:PATH"
        }

        Write-Host "[✓] ADB installed to $adbDir" -ForegroundColor Green
    }
}

# ── Check System Dependencies ────────────────────────────────────────────────
function Test-SystemDeps {
    Write-Host "`n[3/6] Checking system dependencies..." -ForegroundColor Blue

    # Git
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($git) {
        Write-Host "[✓] Git: $(git --version)" -ForegroundColor Green
    } else {
        Write-Host "[✗] Git is required. Download from https://git-scm.com/" -ForegroundColor Red
        exit 1
    }

    # Visual Studio Build Tools (for native compilation)
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vsWhere) {
        Write-Host "[✓] Visual Studio Build Tools detected" -ForegroundColor Green
    } else {
        Write-Host "[!] Visual Studio Build Tools may be needed for Rust compilation" -ForegroundColor Yellow
        Write-Host "    Install from: https://visualstudio.microsoft.com/visual-cpp-build-tools/" -ForegroundColor Yellow
    }
}

# ── Setup Directories ────────────────────────────────────────────────────────
function Setup-Directories {
    Write-Host "`n[4/6] Setting up ORACLE directory structure..." -ForegroundColor Blue

    $oracleHome = "$env:USERPROFILE\.oracle"
    New-Item -ItemType Directory -Force -Path "$oracleHome\investigations" | Out-Null
    New-Item -ItemType Directory -Force -Path "$oracleHome\config" | Out-Null
    New-Item -ItemType Directory -Force -Path "$oracleHome\logs" | Out-Null

    $scriptDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $defaultConfig = Join-Path $scriptDir "config\default.toml"
    $targetConfig = "$oracleHome\config\oracle.toml"

    if (-not (Test-Path $targetConfig)) {
        if (Test-Path $defaultConfig) {
            Copy-Item $defaultConfig $targetConfig
            Write-Host "[✓] Default configuration copied to $targetConfig" -ForegroundColor Green
        }
    } else {
        Write-Host "[✓] Configuration already exists at $targetConfig" -ForegroundColor Green
    }

    Write-Host "[✓] Directory structure created at $oracleHome" -ForegroundColor Green
}

# ── Build ORACLE ─────────────────────────────────────────────────────────────
function Build-Oracle {
    Write-Host "`n[5/6] Building ORACLE from source..." -ForegroundColor Blue

    $scriptDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Set-Location $scriptDir

    Write-Host "  Building in release mode (this may take several minutes)..." -ForegroundColor Gray
    & cargo build --release

    $binaryPath = Join-Path $scriptDir "target\release\oracle.exe"
    if (Test-Path $binaryPath) {
        Write-Host "[✓] ORACLE binary built successfully" -ForegroundColor Green
        Write-Host "  Binary location: $binaryPath" -ForegroundColor Cyan
    } else {
        Write-Host "[✗] Build failed. Check the output above for errors." -ForegroundColor Red
        exit 1
    }
}

# ── Run Diagnostics ──────────────────────────────────────────────────────────
function Run-Diagnostics {
    Write-Host "`n[6/6] Running self-diagnostics..." -ForegroundColor Blue

    # Check ADB devices
    Write-Host "  Checking for connected Android devices..." -ForegroundColor Gray
    try {
        $devices = & adb devices 2>&1 | Select-String "device$"
        $count = ($devices | Measure-Object).Count
        if ($count -gt 0) {
            Write-Host "[✓] $count Android device(s) detected" -ForegroundColor Green
        } else {
            Write-Host "[!] No Android devices connected" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[!] Could not query ADB devices" -ForegroundColor Yellow
    }

    # Test SQLite via Rust
    Write-Host "[✓] SQLite bundled via rusqlite (no system SQLite required)" -ForegroundColor Green
}

# ── Summary ──────────────────────────────────────────────────────────────────
function Show-Summary {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  ORACLE installation complete!" -ForegroundColor Green
    Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Quick Start:" -ForegroundColor Blue
    Write-Host "    1. Connect an Android device via USB"
    Write-Host "    2. Enable USB debugging on the device"
    Write-Host "    3. Run: oracle new-investigation --case-number CASE-001" -ForegroundColor Cyan
    Write-Host "    4. Run: oracle detect-capabilities --serial <device_serial>" -ForegroundColor Cyan
    Write-Host ""
}

# ── Main ─────────────────────────────────────────────────────────────────────
Show-Banner
Test-Admin
Install-Rust
Install-ADB
Test-SystemDeps
Setup-Directories
Build-Oracle
Run-Diagnostics
Show-Summary
