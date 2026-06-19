//! # ORACLE Pre-flight Startup Checks
//!
//! Performs all application pre-flight checks before the main CLI
//! command dispatch begins. Failures here halt the application immediately
//! to prevent evidence corruption or incomplete audit trails.

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use tracing::{debug, error, info, warn};

use oracle_audit::{AuditLogVerifier, AuditLogWriter, ChainStatus};
use oracle_core::OracleConfig;
use oracle_oem::plugin::OemPluginRegistry;
use oracle_oem::validation::validate_plugin;

/// Performs all application pre-flight startup checks.
///
/// Returns `Ok(())` if all checks pass.
///
/// Checked items:
/// 1. ADB installation and accessibility verification
/// 2. Evidence store directory writability check
/// 3. Audit log integrity verification (if an existing database is found)
/// 4. OEM plugin presence and validation
pub fn run_preflight_checks(config: &OracleConfig) -> Result<()> {
    info!("Running ORACLE pre-flight startup checks...");

    // 1. ADB Installation and Accessibility Verification
    check_adb().context("ADB pre-flight check failed")?;

    // 2. Evidence Store Directory Writability Check
    check_directory_writability(&config.general.investigations_dir)
        .context("Evidence investigations directory is not writable")?;

    // 3. Audit Log Integrity Verification
    check_audit_log_integrity(config).context("Audit log integrity verification failed")?;

    // 4. OEM Plugin Presence and Validation
    check_oem_plugins().context("OEM plugin validation failed")?;

    info!("All pre-flight checks passed successfully.");
    Ok(())
}

/// Verifies that ADB is installed and accessible on the system PATH.
fn check_adb() -> Result<()> {
    debug!("Checking ADB accessibility...");
    let output = Command::new("adb").arg("version").output();

    match output {
        Ok(out) => {
            if out.status.success() {
                let version_str = String::from_utf8_lossy(&out.stdout);
                let first_line = version_str.lines().next().unwrap_or("unknown version");
                info!("ADB is accessible: {}", first_line.trim());
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(anyhow!(
                    "ADB command returned non-zero status: {}",
                    stderr.trim()
                ))
            }
        }
        Err(e) => {
            warn!(
                "ADB binary ('adb') was not found on the system PATH: {}. \
                 ORACLE will not be able to connect to live devices.",
                e
            );
            // ADB absence is a warning, not a fatal error — the user may be
            // working with filesystem images or offline evidence.
            Ok(())
        }
    }
}

/// Verifies that the specified directory exists (or can be created) and is writable.
fn check_directory_writability(dir: &Path) -> Result<()> {
    debug!("Checking directory writability for {}", dir.display());

    // Create the directory if it doesn't exist.
    if !dir.exists() {
        fs::create_dir_all(dir).with_context(|| {
            format!(
                "Failed to create investigations directory: {}",
                dir.display()
            )
        })?;
    }

    // Attempt to write a temp file to verify writability.
    let temp_file_path = dir.join(".oracle_writability_test");
    fs::write(&temp_file_path, b"oracle_writability_test").with_context(|| {
        format!(
            "Investigations directory is not writable: {}",
            dir.display()
        )
    })?;

    // Clean up.
    let _ = fs::remove_file(temp_file_path);

    info!("Investigations directory is writable: {}", dir.display());
    Ok(())
}

/// Checks the integrity of any existing audit database found in the investigations directory.
fn check_audit_log_integrity(config: &OracleConfig) -> Result<()> {
    let audit_db_path = config.general.investigations_dir.join("audit.db");

    if audit_db_path.exists() {
        info!(
            "Existing audit database detected at {}. Verifying integrity...",
            audit_db_path.display()
        );

        let writer = AuditLogWriter::new(&audit_db_path)
            .map_err(|e| anyhow!("Failed to open audit log: {}", e))?;

        let verifier = AuditLogVerifier::new(writer.connection());
        let report = verifier
            .verify_full()
            .map_err(|e| anyhow!("Failed to verify audit log: {}", e))?;

        if report.overall_status == ChainStatus::Broken {
            let msg = report
                .failure_description
                .unwrap_or_else(|| "Unknown chain breakage".to_string());
            error!(
                "CRITICAL: Audit log integrity compromise detected: {}",
                msg
            );
            return Err(anyhow!("Audit log integrity chain is broken: {}", msg));
        }

        info!(
            "Audit log integrity verified: intact ({} entries).",
            report.total_entries
        );
    } else {
        info!("No existing audit database found. A new one will be initialized upon investigation creation.");
    }

    Ok(())
}

/// Validates all default OEM plugins present in the registry.
fn check_oem_plugins() -> Result<()> {
    debug!("Validating OEM plugins...");
    let registry = OemPluginRegistry::default_registry();

    for plugin in registry.list_plugins() {
        validate_plugin(plugin.as_ref())
            .map_err(|e| anyhow!("Plugin validation failed for {}: {}", plugin.oem_name(), e))?;
        info!(
            "OEM Plugin '{}' validated successfully.",
            plugin.oem_name()
        );
    }

    Ok(())
}
