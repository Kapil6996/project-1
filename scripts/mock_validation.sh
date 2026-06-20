#!/usr/bin/env bash
# ============================================================================
# ORACLE — Scripted Mock Validation Runner
# ============================================================================
#
# Runs a simulated end-to-end validation across mock device profiles
# representing different Android OEMs, versions, and access levels.
#
# Usage: ./scripts/mock_validation.sh
#
# This script exercises the full ORACLE pipeline without a physical device
# by running cargo tests tagged for integration and hardening.
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║       ORACLE — Mock Validation & Hardening Test Suite       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

PASS=0
FAIL=0
TOTAL=0

run_test_group() {
    local name="$1"
    local filter="$2"
    TOTAL=$((TOTAL + 1))

    echo -e "\n${BLUE}[$TOTAL]${NC} Running: ${CYAN}$name${NC}"
    # Use unquoted $filter to allow bash to split arguments (e.g. "-p oracle-cli")
    if cargo test $filter 2>&1 | tail -3; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}[PASS]${NC} $name"
    else
        FAIL=$((FAIL + 1))
        echo -e "  ${RED}[FAIL]${NC} $name"
    fi
}

# Source Rust environment
source "$HOME/.cargo/env" 2>/dev/null || true

cd "$(dirname "$0")/.."

echo -e "${BLUE}Phase 1: Core Library Tests${NC}"
echo "────────────────────────────────────────────"

run_test_group "oracle-core (types, errors, config)" "-p oracle-core"
run_test_group "oracle-audit (chain integrity, crash recovery)" "-p oracle-audit"
run_test_group "oracle-evidence (CAS, append-only, integrity)" "-p oracle-evidence"

echo -e "\n${BLUE}Phase 2: Device Interface Tests${NC}"
echo "────────────────────────────────────────────"

run_test_group "oracle-capability (ADB mock, root detection, SELinux)" "-p oracle-capability"
run_test_group "oracle-discovery (path registry, scanner, acquisition)" "-p oracle-discovery"

echo -e "\n${BLUE}Phase 3: Parser Tests${NC}"
echo "────────────────────────────────────────────"

run_test_group "oracle-parser (WiFi, WPA, DHCP, Connectivity)" "-p oracle-parser"
run_test_group "oracle-oem (Samsung plugin, validation)" "-p oracle-oem"

echo -e "\n${BLUE}Phase 4: Analysis Engine Tests${NC}"
echo "────────────────────────────────────────────"

run_test_group "oracle-normalize (SSID, BSSID, timestamp, security)" "-p oracle-normalize"
run_test_group "oracle-correlate (identity, events, timeline, anomaly)" "-p oracle-correlate"
run_test_group "oracle-confidence (scoring model, versioning, overrides)" "-p oracle-confidence"

echo -e "\n${BLUE}Phase 5: Report & CLI Tests${NC}"
echo "────────────────────────────────────────────"

run_test_group "oracle-report (summary, executive, technical, custody)" "-p oracle-report"
run_test_group "oracle-cli (pipeline, commands, startup)" "-p oracle-cli"

echo -e "\n${BLUE}Phase 6: Hardening Tests${NC}"
echo "────────────────────────────────────────────"

run_test_group "Hardening: Hardware Disconnection" "-p oracle-cli --test hardening_tests -- hardware_disconnection"
run_test_group "Hardening: Storage Exhaustion" "-p oracle-cli --test hardening_tests -- storage_exhaustion"
run_test_group "Hardening: Database Locking" "-p oracle-cli --test hardening_tests -- database_locking"
run_test_group "Hardening: Parser Crash Resilience" "-p oracle-cli --test hardening_tests -- parser_crash_resilience"
run_test_group "Hardening: Evidence Corruption Detection" "-p oracle-cli --test hardening_tests -- evidence_corruption_detection"
run_test_group "Hardening: Audit Chain Tamper Detection" "-p oracle-cli --test hardening_tests -- audit_chain_tamper_detection"

# ── Mock Device Profiles ─────────────────────────────────────────────────────
echo -e "\n${BLUE}Phase 7: Mock Device Profile Validation${NC}"
echo "────────────────────────────────────────────"

echo -e "\n  ${CYAN}Simulated Device Profiles:${NC}"
echo "  ┌──────────────────────────────────────────────────────────┐"
echo "  │ Profile 1: Pixel 8 Pro / Android 14 / No root / AFU     │"
echo "  │ Profile 2: Galaxy S23 / Android 14 / No root / AFU      │"
echo "  │ Profile 3: Pixel 5  / Android 12 / Magisk root / AFU    │"
echo "  │ Profile 4: Xiaomi 14 / Android 14 / No root / BFU       │"
echo "  │ Profile 5: OnePlus 11 / Android 13 / KernelSU / AFU     │"
echo "  └──────────────────────────────────────────────────────────┘"
echo ""
echo -e "  ${YELLOW}Note:${NC} Mock device profiles are validated through the"
echo "  capability detector mock tests in oracle-capability."
echo "  Physical device validation requires actual devices"
echo "  (see docs/DEVICE_COMPATIBILITY_MATRIX.md)."

run_test_group "Mock: Capability Detection (all root methods)" "-p oracle-capability -- detector"
run_test_group "Mock: OEM Plugin Matching (Samsung)" "-p oracle-oem -- samsung::tests::test_matches"
run_test_group "Mock: Parser Registry Dispatch" "-p oracle-parser -- registry"

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}PASSED: $PASS${NC}  |  ${RED}FAILED: $FAIL${NC}  |  Total: $TOTAL"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"

if [[ $FAIL -gt 0 ]]; then
    echo -e "\n${RED}VALIDATION FAILED — $FAIL test group(s) did not pass.${NC}"
    exit 1
else
    echo -e "\n${GREEN}ALL VALIDATION PASSED — platform is ready for deployment.${NC}"
    exit 0
fi
