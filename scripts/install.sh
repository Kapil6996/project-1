#!/usr/bin/env bash
# ============================================================================
# ORACLE Android Network Forensics Platform — Unix Installation Script
# ============================================================================
#
# This script sets up a forensic workstation for ORACLE on macOS or Linux.
# It installs required dependencies, verifies ADB access, and builds the
# ORACLE binary from source.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
# Requirements:
#   - macOS 12+ or Ubuntu 22.04+ / Debian 12+
#   - Internet access for dependency download
#   - sudo privileges for system package installation
#
# ============================================================================

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ── Banner ───────────────────────────────────────────────────────────────────
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         ORACLE — Android Network Forensics Platform         ║"
echo "║                   Installation Script v1.0                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Detect OS ────────────────────────────────────────────────────────────────
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        echo -e "${GREEN}[✓]${NC} Detected macOS"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        echo -e "${GREEN}[✓]${NC} Detected Linux"
    else
        echo -e "${RED}[✗]${NC} Unsupported OS: $OSTYPE"
        exit 1
    fi
}

# ── Check and Install Rust ───────────────────────────────────────────────────
install_rust() {
    echo -e "\n${BLUE}[1/6]${NC} Checking Rust toolchain..."
    if command -v rustc &> /dev/null; then
        RUST_VERSION=$(rustc --version)
        echo -e "${GREEN}[✓]${NC} Rust is installed: $RUST_VERSION"
    else
        echo -e "${YELLOW}[!]${NC} Rust not found. Installing via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
        echo -e "${GREEN}[✓]${NC} Rust installed: $(rustc --version)"
    fi

    # Ensure minimum version (1.75+)
    RUST_MINOR=$(rustc --version | grep -oP '\d+\.(\d+)' | head -1 | cut -d. -f2)
    if [[ "$RUST_MINOR" -lt 75 ]]; then
        echo -e "${YELLOW}[!]${NC} Updating Rust to latest stable..."
        rustup update stable
    fi
}

# ── Check and Install ADB ───────────────────────────────────────────────────
install_adb() {
    echo -e "\n${BLUE}[2/6]${NC} Checking Android Debug Bridge (ADB)..."
    if command -v adb &> /dev/null; then
        ADB_VERSION=$(adb version | head -1)
        echo -e "${GREEN}[✓]${NC} ADB is installed: $ADB_VERSION"
    else
        echo -e "${YELLOW}[!]${NC} ADB not found. Installing..."
        if [[ "$OS" == "macos" ]]; then
            if command -v brew &> /dev/null; then
                brew install --cask android-platform-tools
            else
                echo -e "${RED}[✗]${NC} Homebrew not found. Install ADB manually:"
                echo "    https://developer.android.com/tools/releases/platform-tools"
                exit 1
            fi
        elif [[ "$OS" == "linux" ]]; then
            sudo apt-get update && sudo apt-get install -y android-tools-adb
        fi
        echo -e "${GREEN}[✓]${NC} ADB installed: $(adb version | head -1)"
    fi
}

# ── Check System Dependencies ────────────────────────────────────────────────
check_system_deps() {
    echo -e "\n${BLUE}[3/6]${NC} Checking system dependencies..."

    # SQLite (usually pre-installed)
    if command -v sqlite3 &> /dev/null; then
        echo -e "${GREEN}[✓]${NC} SQLite3: $(sqlite3 --version | awk '{print $1}')"
    else
        echo -e "${YELLOW}[!]${NC} SQLite3 not found. Installing..."
        if [[ "$OS" == "macos" ]]; then
            brew install sqlite3
        elif [[ "$OS" == "linux" ]]; then
            sudo apt-get install -y sqlite3 libsqlite3-dev
        fi
    fi

    # pkg-config (needed for native library linking)
    if command -v pkg-config &> /dev/null; then
        echo -e "${GREEN}[✓]${NC} pkg-config available"
    else
        echo -e "${YELLOW}[!]${NC} pkg-config not found. Installing..."
        if [[ "$OS" == "macos" ]]; then
            brew install pkg-config
        elif [[ "$OS" == "linux" ]]; then
            sudo apt-get install -y pkg-config
        fi
    fi

    # Git
    if command -v git &> /dev/null; then
        echo -e "${GREEN}[✓]${NC} Git: $(git --version)"
    else
        echo -e "${RED}[✗]${NC} Git is required. Install it first."
        exit 1
    fi
}

# ── Create Investigation Directory Structure ─────────────────────────────────
setup_directories() {
    echo -e "\n${BLUE}[4/6]${NC} Setting up ORACLE directory structure..."

    ORACLE_HOME="${ORACLE_HOME:-$HOME/.oracle}"
    mkdir -p "$ORACLE_HOME"/{investigations,config,logs}

    # Copy default config if not present
    SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
    if [[ ! -f "$ORACLE_HOME/config/oracle.toml" ]]; then
        if [[ -f "$SCRIPT_DIR/config/default.toml" ]]; then
            cp "$SCRIPT_DIR/config/default.toml" "$ORACLE_HOME/config/oracle.toml"
            echo -e "${GREEN}[✓]${NC} Default configuration copied to $ORACLE_HOME/config/oracle.toml"
        fi
    else
        echo -e "${GREEN}[✓]${NC} Configuration already exists at $ORACLE_HOME/config/oracle.toml"
    fi

    echo -e "${GREEN}[✓]${NC} Directory structure created at $ORACLE_HOME"
}

# ── Build ORACLE ─────────────────────────────────────────────────────────────
build_oracle() {
    echo -e "\n${BLUE}[5/6]${NC} Building ORACLE from source..."

    SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
    cd "$SCRIPT_DIR"

    echo -e "  Building in release mode (this may take a few minutes)..."
    cargo build --release 2>&1 | tail -5

    if [[ -f "target/release/oracle" ]]; then
        echo -e "${GREEN}[✓]${NC} ORACLE binary built successfully"
        echo -e "  Binary location: ${CYAN}$SCRIPT_DIR/target/release/oracle${NC}"

        # Optionally install to PATH
        echo ""
        read -p "  Install ORACLE to /usr/local/bin? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo cp target/release/oracle /usr/local/bin/oracle
            echo -e "${GREEN}[✓]${NC} ORACLE installed to /usr/local/bin/oracle"
        fi
    else
        echo -e "${RED}[✗]${NC} Build failed. Check the output above for errors."
        exit 1
    fi
}

# ── Run Self-Diagnostics ─────────────────────────────────────────────────────
run_diagnostics() {
    echo -e "\n${BLUE}[6/6]${NC} Running self-diagnostics..."

    SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
    ORACLE_BIN="$SCRIPT_DIR/target/release/oracle"

    if [[ -f "$ORACLE_BIN" ]]; then
        # Test basic execution
        if $ORACLE_BIN --help &> /dev/null; then
            echo -e "${GREEN}[✓]${NC} ORACLE binary executes correctly"
        else
            echo -e "${RED}[✗]${NC} ORACLE binary failed to execute"
        fi
    fi

    # Verify ADB can see devices
    echo -e "  Checking for connected Android devices..."
    DEVICE_COUNT=$(adb devices 2>/dev/null | grep -c "device$" || true)
    if [[ "$DEVICE_COUNT" -gt 0 ]]; then
        echo -e "${GREEN}[✓]${NC} $DEVICE_COUNT Android device(s) detected"
        adb devices -l 2>/dev/null | grep "device " | while read -r line; do
            echo -e "     ${CYAN}→${NC} $line"
        done
    else
        echo -e "${YELLOW}[!]${NC} No Android devices connected (connect a device to begin investigation)"
    fi

    # Test SQLite functionality
    TEMP_DB=$(mktemp /tmp/oracle_test_XXXXXX.db)
    if sqlite3 "$TEMP_DB" "CREATE TABLE test(id INTEGER); INSERT INTO test VALUES(1); SELECT * FROM test;" &> /dev/null; then
        echo -e "${GREEN}[✓]${NC} SQLite is functional"
    else
        echo -e "${RED}[✗]${NC} SQLite test failed"
    fi
    rm -f "$TEMP_DB"
}

# ── Summary ──────────────────────────────────────────────────────────────────
print_summary() {
    echo -e "\n${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  ORACLE installation complete!${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BLUE}Quick Start:${NC}"
    echo -e "    1. Connect an Android device via USB"
    echo -e "    2. Enable USB debugging on the device"
    echo -e "    3. Run: ${CYAN}oracle new-investigation --case-number CASE-001${NC}"
    echo -e "    4. Run: ${CYAN}oracle detect-capabilities --serial <device_serial>${NC}"
    echo -e ""
    echo -e "  ${BLUE}Documentation:${NC}"
    echo -e "    • Setup Guide:    ${CYAN}docs/SETUP_GUIDE.md${NC}"
    echo -e "    • SOP:            ${CYAN}docs/STANDARD_OPERATING_PROCEDURE.md${NC}"
    echo -e "    • Methodology:    ${CYAN}docs/FORENSIC_METHODOLOGY.md${NC}"
    echo ""
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
    detect_os
    install_rust
    install_adb
    check_system_deps
    setup_directories
    build_oracle
    run_diagnostics
    print_summary
}

main "$@"
