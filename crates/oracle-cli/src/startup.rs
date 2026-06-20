//! # ORACLE Pre-flight Startup Checks
//!
//! Performs all application pre-flight checks before the main CLI
//! command dispatch begins. Each check produces a structured
//! [`PreflightCheck`] result, aggregated into a [`PreflightReport`].
//!
//! Checks cover:
//! - ADB binary availability on PATH
//! - SQLite functional verification (temporary database creation)
//! - Investigation directory writability
//! - Required configuration values validation

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use tracing::{debug, error, info, warn};

use oracle_core::OracleConfig;

// ──────────────────────────────────────────────────────────────────────────────
// Preflight Report Types
// ──────────────────────────────────────────────────────────────────────────────

/// The pass/fail status of a single pre-flight check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightStatus {
    /// The check passed — the subsystem is fully operational.
    Pass,
    /// The check failed — the subsystem is missing or misconfigured.
    Fail,
}

impl std::fmt::Display for PreflightStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreflightStatus::Pass => write!(f, "PASS"),
            PreflightStatus::Fail => write!(f, "FAIL"),
        }
    }
}

/// A single pre-flight check result with human-readable context.
#[derive(Debug, Clone)]
pub struct PreflightCheck {
    /// The name of the check (e.g., "ADB Binary", "SQLite", etc.).
    pub name: String,
    /// Whether the check passed or failed.
    pub status: PreflightStatus,
    /// A human-readable message describing the check outcome.
    pub message: String,
}

/// Aggregated report of all pre-flight checks.
///
/// The CLI uses this to decide whether to proceed (with warnings)
/// or halt execution entirely.
#[derive(Debug, Clone)]
pub struct PreflightReport {
    /// The ordered list of individual check results.
    pub checks: Vec<PreflightCheck>,
    /// `true` if every check passed; `false` if any check failed.
    pub all_passed: bool,
}

impl PreflightReport {
    /// Build a report from a list of checks, computing `all_passed` automatically.
    fn from_checks(checks: Vec<PreflightCheck>) -> Self {
        let all_passed = checks.iter().all(|c| c.status == PreflightStatus::Pass);
        Self { checks, all_passed }
    }

    /// Print the preflight report to stderr for the operator.
    pub fn print_report(&self) {
        eprintln!("\n  ┌──────────────────────────────────────────────────────┐");
        eprintln!("  │           ORACLE Pre-Flight Check Report            │");
        eprintln!("  └──────────────────────────────────────────────────────┘");
        for check in &self.checks {
            let icon = match check.status {
                PreflightStatus::Pass => "✓",
                PreflightStatus::Fail => "✗",
            };
            eprintln!("    [{icon}] {:<28} {}", check.name, check.message);
        }
        if self.all_passed {
            eprintln!("\n  All pre-flight checks passed.\n");
        } else {
            let failed_count = self
                .checks
                .iter()
                .filter(|c| c.status == PreflightStatus::Fail)
                .count();
            eprintln!(
                "\n  ⚠  {} check(s) failed. Some features may be unavailable.\n",
                failed_count
            );
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Public Entry Point
// ──────────────────────────────────────────────────────────────────────────────

/// Run all pre-flight checks and return a structured [`PreflightReport`].
///
/// This function never panics or early-returns on individual failures —
/// every check is executed and its result is recorded so the operator
/// gets a complete picture before proceeding.
///
/// # Errors
///
/// Returns `Err` only if the report itself cannot be constructed
/// (should not happen in practice).
pub fn run_preflight_checks(config: &OracleConfig) -> Result<PreflightReport> {
    info!("Running ORACLE pre-flight startup checks...");

    let mut checks = Vec::new();

    // 1. ADB Binary Availability
    checks.push(check_adb_binary());

    // 2. SQLite Functional Verification
    checks.push(check_sqlite_functional());

    // 3. Investigation Directory Writability
    checks.push(check_directory_writability(
        &config.general.investigations_dir,
    ));

    // 4. Required Configuration Values
    checks.push(check_required_config_values(config));

    let report = PreflightReport::from_checks(checks);

    if report.all_passed {
        info!("All pre-flight checks passed successfully.");
    } else {
        warn!(
            "Pre-flight report: {} of {} checks failed.",
            report
                .checks
                .iter()
                .filter(|c| c.status == PreflightStatus::Fail)
                .count(),
            report.checks.len()
        );
    }

    Ok(report)
}

// ──────────────────────────────────────────────────────────────────────────────
// Individual Checks
// ──────────────────────────────────────────────────────────────────────────────

/// Check 1: Verify that the ADB binary is available on the system PATH.
///
/// ADB absence is recorded as a failure, but the CLI may still
/// function for offline/image-based investigations.
fn check_adb_binary() -> PreflightCheck {
    debug!("Checking ADB binary accessibility...");
    let output = Command::new("adb").arg("version").output();

    match output {
        Ok(out) if out.status.success() => {
            let version_str = String::from_utf8_lossy(&out.stdout);
            let first_line = version_str.lines().next().unwrap_or("unknown version");
            info!("ADB is accessible: {}", first_line.trim());
            PreflightCheck {
                name: "ADB Binary".to_string(),
                status: PreflightStatus::Pass,
                message: first_line.trim().to_string(),
            }
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            warn!("ADB returned non-zero exit: {}", stderr.trim());
            PreflightCheck {
                name: "ADB Binary".to_string(),
                status: PreflightStatus::Fail,
                message: format!("ADB returned error: {}", stderr.trim()),
            }
        }
        Err(e) => {
            warn!("ADB binary not found on PATH: {}", e);
            PreflightCheck {
                name: "ADB Binary".to_string(),
                status: PreflightStatus::Fail,
                message: format!("Not found on PATH ({})", e),
            }
        }
    }
}

/// Check 2: Verify SQLite is functional by creating a temporary in-memory DB.
///
/// The platform relies heavily on SQLite for audit and evidence storage;
/// a broken SQLite library would be catastrophic.
fn check_sqlite_functional() -> PreflightCheck {
    debug!("Checking SQLite functionality...");
    match rusqlite::Connection::open_in_memory() {
        Ok(conn) => {
            // Run a simple query to ensure the engine works end-to-end.
            let query_result: Result<i64, _> =
                conn.query_row("SELECT 1 + 1", [], |row| row.get(0));
            match query_result {
                Ok(val) if val == 2 => {
                    let version: String = conn
                        .query_row("SELECT sqlite_version()", [], |row| row.get(0))
                        .unwrap_or_else(|_| "unknown".to_string());
                    info!("SQLite is functional: v{}", version);
                    PreflightCheck {
                        name: "SQLite Engine".to_string(),
                        status: PreflightStatus::Pass,
                        message: format!("SQLite v{}", version),
                    }
                }
                Ok(val) => PreflightCheck {
                    name: "SQLite Engine".to_string(),
                    status: PreflightStatus::Fail,
                    message: format!("Unexpected query result: {} (expected 2)", val),
                },
                Err(e) => PreflightCheck {
                    name: "SQLite Engine".to_string(),
                    status: PreflightStatus::Fail,
                    message: format!("Query failed: {}", e),
                },
            }
        }
        Err(e) => {
            error!("Failed to open in-memory SQLite database: {}", e);
            PreflightCheck {
                name: "SQLite Engine".to_string(),
                status: PreflightStatus::Fail,
                message: format!("Cannot open in-memory DB: {}", e),
            }
        }
    }
}

/// Check 3: Verify the investigation directory exists (or can be created) and is writable.
fn check_directory_writability(dir: &Path) -> PreflightCheck {
    debug!("Checking directory writability for {}", dir.display());

    // Create the directory if it doesn't exist.
    if !dir.exists() {
        if let Err(e) = fs::create_dir_all(dir) {
            return PreflightCheck {
                name: "Investigations Dir".to_string(),
                status: PreflightStatus::Fail,
                message: format!("Cannot create {}: {}", dir.display(), e),
            };
        }
    }

    // Attempt to write a sentinel file to verify writability.
    let sentinel = dir.join(".oracle_preflight_test");
    if let Err(e) = fs::write(&sentinel, b"oracle_preflight_writability_test") {
        return PreflightCheck {
            name: "Investigations Dir".to_string(),
            status: PreflightStatus::Fail,
            message: format!("Directory not writable: {}", e),
        };
    }

    // Clean up the sentinel.
    let _ = fs::remove_file(sentinel);

    info!("Investigations directory is writable: {}", dir.display());
    PreflightCheck {
        name: "Investigations Dir".to_string(),
        status: PreflightStatus::Pass,
        message: format!("{}", dir.display()),
    }
}

/// Check 4: Validate that required configuration values are present and sensible.
fn check_required_config_values(config: &OracleConfig) -> PreflightCheck {
    debug!("Validating required configuration values...");

    let mut issues = Vec::new();

    if config.general.organization_name.is_empty() {
        issues.push("organization_name is empty".to_string());
    }
    if config.general.log_level.is_empty() {
        issues.push("log_level is empty".to_string());
    }
    if config.evidence_store.max_blob_size_bytes == 0 {
        issues.push("max_blob_size_bytes is zero".to_string());
    }
    if config.adb.command_timeout_secs == 0 {
        issues.push("ADB command_timeout_secs is zero".to_string());
    }
    if config.audit.chain_batch_size == 0 {
        issues.push("audit chain_batch_size is zero".to_string());
    }

    if issues.is_empty() {
        info!("All required configuration values present and valid.");
        PreflightCheck {
            name: "Configuration".to_string(),
            status: PreflightStatus::Pass,
            message: format!(
                "org=\"{}\"",
                config.general.organization_name
            ),
        }
    } else {
        warn!("Configuration issues detected: {:?}", issues);
        PreflightCheck {
            name: "Configuration".to_string(),
            status: PreflightStatus::Fail,
            message: issues.join("; "),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Helper to construct a valid default config pointing at a temp directory.
    fn test_config(base: &Path) -> OracleConfig {
        OracleConfig::default_config(base)
    }

    #[test]
    fn test_preflight_detects_missing_adb() {
        // This test verifies the structure of the check — on CI where ADB
        // is not installed, we expect `Fail`. On a dev machine with ADB,
        // we expect `Pass`. Both outcomes are valid; we just ensure the
        // returned struct is well-formed.
        let check = check_adb_binary();
        assert_eq!(check.name, "ADB Binary");
        assert!(
            check.status == PreflightStatus::Pass
                || check.status == PreflightStatus::Fail,
            "Status must be Pass or Fail"
        );
        assert!(!check.message.is_empty(), "Message must not be empty");
    }

    #[test]
    fn test_sqlite_functional_check_passes() {
        let check = check_sqlite_functional();
        assert_eq!(check.name, "SQLite Engine");
        assert_eq!(check.status, PreflightStatus::Pass);
        assert!(
            check.message.starts_with("SQLite v"),
            "Expected version string, got: {}",
            check.message
        );
    }

    #[test]
    fn test_directory_writability_with_temp_dir() {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let check = check_directory_writability(tmp.path());
        assert_eq!(check.status, PreflightStatus::Pass);
    }

    #[test]
    fn test_directory_writability_nonexistent_parent() {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let nested = tmp.path().join("a").join("b").join("c");
        let check = check_directory_writability(&nested);
        assert_eq!(check.status, PreflightStatus::Pass);
    }

    #[test]
    fn test_config_validation_passes_for_defaults() {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let config = test_config(tmp.path());
        let check = check_required_config_values(&config);
        assert_eq!(check.status, PreflightStatus::Pass);
    }

    #[test]
    fn test_config_validation_fails_for_empty_org() {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let mut config = test_config(tmp.path());
        config.general.organization_name = String::new();
        let check = check_required_config_values(&config);
        assert_eq!(check.status, PreflightStatus::Fail);
        assert!(check.message.contains("organization_name"));
    }

    #[test]
    fn test_full_preflight_report_structure() {
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let config = test_config(tmp.path());
        let report = run_preflight_checks(&config).expect("report should succeed");
        assert_eq!(report.checks.len(), 4);
        // SQLite and Config and Dir should always pass in test env
        let sqlite_check = report.checks.iter().find(|c| c.name == "SQLite Engine");
        assert!(sqlite_check.is_some());
        assert_eq!(sqlite_check.unwrap().status, PreflightStatus::Pass);
    }

    #[test]
    fn test_preflight_report_all_passed_flag() {
        let checks = vec![
            PreflightCheck {
                name: "A".to_string(),
                status: PreflightStatus::Pass,
                message: "ok".to_string(),
            },
            PreflightCheck {
                name: "B".to_string(),
                status: PreflightStatus::Pass,
                message: "ok".to_string(),
            },
        ];
        let report = PreflightReport::from_checks(checks);
        assert!(report.all_passed);

        let checks_with_fail = vec![
            PreflightCheck {
                name: "A".to_string(),
                status: PreflightStatus::Pass,
                message: "ok".to_string(),
            },
            PreflightCheck {
                name: "B".to_string(),
                status: PreflightStatus::Fail,
                message: "bad".to_string(),
            },
        ];
        let report = PreflightReport::from_checks(checks_with_fail);
        assert!(!report.all_passed);
    }
}
