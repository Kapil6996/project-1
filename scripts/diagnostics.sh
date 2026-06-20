#!/usr/bin/env bash
# ============================================================================
# ORACLE — System Diagnostics / Self-Test
# ============================================================================
#
# Confirms all dependencies (ADB, SQLite, Rust runtime) are working.
# Run this before starting any investigation to verify system health.
#
# Usage: ./diagnostics.sh
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

check_pass() {
    echo -e "  ${GREEN}[PASS]${NC} $1"
    PASS=$((PASS + 1))
}

check_fail() {
    echo -e "  ${RED}[FAIL]${NC} $1"
    FAIL=$((FAIL + 1))
}

check_warn() {
    echo -e "  ${YELLOW}[WARN]${NC} $1"
    WARN=$((WARN + 1))
}

echo -e "${BLUE}ORACLE System Diagnostics${NC}"
echo "════════════════════════════════════════════"
echo ""

# ── 1. ORACLE Binary ────────────────────────────────────────────────────────
echo -e "${BLUE}[1] ORACLE Binary${NC}"
if command -v oracle &> /dev/null; then
    check_pass "ORACLE binary found: $(which oracle)"
    if oracle --version &> /dev/null; then
        check_pass "ORACLE executes correctly"
    else
        check_fail "ORACLE binary found but fails to execute"
    fi
else
    SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
    if [[ -f "$SCRIPT_DIR/target/release/oracle" ]]; then
        check_warn "ORACLE built but not on PATH: $SCRIPT_DIR/target/release/oracle"
    else
        check_fail "ORACLE binary not found (run 'cargo build --release')"
    fi
fi

# ── 2. ADB ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BLUE}[2] Android Debug Bridge (ADB)${NC}"
if command -v adb &> /dev/null; then
    ADB_VERSION=$(adb version 2>/dev/null | head -1)
    check_pass "ADB installed: $ADB_VERSION"

    # Check ADB server
    if adb devices &> /dev/null; then
        check_pass "ADB server is responsive"

        DEVICE_COUNT=$(adb devices 2>/dev/null | grep -c "device$" || true)
        if [[ "$DEVICE_COUNT" -gt 0 ]]; then
            check_pass "$DEVICE_COUNT device(s) connected and authorized"
        else
            UNAUTH=$(adb devices 2>/dev/null | grep -c "unauthorized" || true)
            if [[ "$UNAUTH" -gt 0 ]]; then
                check_warn "$UNAUTH device(s) connected but UNAUTHORIZED — accept RSA key on device"
            else
                check_warn "No Android devices connected"
            fi
        fi
    else
        check_fail "ADB server failed to start"
    fi
else
    check_fail "ADB not installed"
fi

# ── 3. SQLite ────────────────────────────────────────────────────────────────
echo ""
echo -e "${BLUE}[3] SQLite Database Engine${NC}"
if command -v sqlite3 &> /dev/null; then
    SQLITE_VERSION=$(sqlite3 --version 2>/dev/null | awk '{print $1}')
    check_pass "SQLite3 installed: v$SQLITE_VERSION"

    # Functional test
    TEMP_DB=$(mktemp /tmp/oracle_diag_XXXXXX.db)
    if sqlite3 "$TEMP_DB" "CREATE TABLE test(id INTEGER PRIMARY KEY, data TEXT); INSERT INTO test VALUES(1, 'oracle'); SELECT data FROM test;" 2>/dev/null | grep -q "oracle"; then
        check_pass "SQLite functional test passed"
    else
        check_fail "SQLite functional test failed"
    fi
    rm -f "$TEMP_DB"
else
    check_warn "System SQLite3 not found (bundled rusqlite will be used)"
fi

# ── 4. Rust Toolchain ────────────────────────────────────────────────────────
echo ""
echo -e "${BLUE}[4] Rust Toolchain${NC}"
if command -v rustc &> /dev/null; then
    check_pass "Rust compiler: $(rustc --version)"
    check_pass "Cargo: $(cargo --version)"
else
    check_warn "Rust toolchain not found (only needed for building from source)"
fi

# ── 5. Filesystem Permissions ────────────────────────────────────────────────
echo ""
echo -e "${BLUE}[5] Filesystem Permissions${NC}"

ORACLE_HOME="${ORACLE_HOME:-$HOME/.oracle}"
if [[ -d "$ORACLE_HOME" ]]; then
    check_pass "ORACLE home directory exists: $ORACLE_HOME"

    if [[ -w "$ORACLE_HOME" ]]; then
        check_pass "ORACLE home directory is writable"
    else
        check_fail "ORACLE home directory is NOT writable"
    fi

    if [[ -d "$ORACLE_HOME/investigations" ]]; then
        check_pass "Investigations directory exists"
    else
        check_warn "Investigations directory missing (will be created on first use)"
    fi

    if [[ -f "$ORACLE_HOME/config/oracle.toml" ]]; then
        check_pass "Configuration file present"
    else
        check_warn "Configuration file missing — defaults will be used"
    fi
else
    check_warn "ORACLE home directory not found at $ORACLE_HOME (run install.sh first)"
fi

# ── 6. Disk Space ────────────────────────────────────────────────────────────
echo ""
echo -e "${BLUE}[6] Disk Space${NC}"
if [[ "$OSTYPE" == "darwin"* ]]; then
    FREE_GB=$(df -g "$HOME" 2>/dev/null | tail -1 | awk '{print $4}')
else
    FREE_GB=$(df -BG "$HOME" 2>/dev/null | tail -1 | awk '{print $4}' | tr -d 'G')
fi

if [[ -n "$FREE_GB" ]] && [[ "$FREE_GB" -ge 50 ]]; then
    check_pass "${FREE_GB}GB free disk space (≥50GB recommended)"
elif [[ -n "$FREE_GB" ]] && [[ "$FREE_GB" -ge 10 ]]; then
    check_warn "${FREE_GB}GB free disk space (50GB+ recommended for large investigations)"
elif [[ -n "$FREE_GB" ]]; then
    check_fail "${FREE_GB}GB free disk space (CRITICALLY LOW — 50GB+ recommended)"
else
    check_warn "Could not determine free disk space"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo -e "  ${GREEN}PASSED: $PASS${NC}  |  ${YELLOW}WARNINGS: $WARN${NC}  |  ${RED}FAILED: $FAIL${NC}"
echo "════════════════════════════════════════════"

if [[ $FAIL -gt 0 ]]; then
    echo -e "\n${RED}System is NOT ready for forensic investigation.${NC}"
    echo "Fix the FAILED items above before proceeding."
    exit 1
elif [[ $WARN -gt 0 ]]; then
    echo -e "\n${YELLOW}System is ready with warnings.${NC}"
    echo "Review the WARNING items — they may affect certain investigations."
    exit 0
else
    echo -e "\n${GREEN}System is fully ready for forensic investigation.${NC}"
    exit 0
fi
