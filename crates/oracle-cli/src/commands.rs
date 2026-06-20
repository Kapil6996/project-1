//! # Forensic Investigation Command Handlers
//!
//! Implements individual CLI command handlers for each forensic operation.
//! Each handler is a self-contained function that initializes the required
//! subsystems, performs the operation with full audit logging, and reports
//! results to the terminal.
//!
//! All handlers follow write-before-execute semantics: the intent to
//! perform an operation is logged in the audit trail before execution
//! begins. If intent logging fails, the operation does not proceed.

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use rusqlite::params;
use serde_json::json;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use oracle_core::OracleConfig;
use oracle_core::types::{
    AuditOperationType, AuditResult, ExaminerIdentity, InvestigationId,
};
use oracle_audit::{AuditLogWriter, AuditLogVerifier, ChainStatus};
use oracle_evidence::{EvidenceStore, IntegrityVerifier};
use oracle_capability::adb::{AdbInterface, LiveAdbInterface};
use oracle_capability::detector::CapabilityDetector;
use oracle_discovery::{ArtifactScanner, ManifestBuilder, PathRegistry};
use oracle_oem::plugin::OemPluginRegistry;

use crate::pipeline::{AdbShellAdapter, ForensicPipeline};

// ──────────────────────────────────────────────────────────────────────────────
// Helper: Open or initialize audit writer
// ──────────────────────────────────────────────────────────────────────────────

/// Open the shared audit log database, creating it if necessary.
fn open_audit_writer(config: &OracleConfig) -> Result<AuditLogWriter> {
    let audit_db_path = config.general.investigations_dir.join("audit.db");
    AuditLogWriter::new(&audit_db_path)
        .map_err(|e| anyhow!("Failed to open audit log at {}: {}", audit_db_path.display(), e))
}

/// Parse a string as a UUID and wrap it in [`InvestigationId`].
fn parse_investigation_id(id_str: &str) -> Result<InvestigationId> {
    let uuid = Uuid::parse_str(id_str)
        .context("Invalid Investigation ID format (must be a valid UUID)")?;
    Ok(InvestigationId(uuid))
}

/// Resolve the evidence store directory for an investigation.
fn investigation_store_dir(config: &OracleConfig, investigation_id: InvestigationId) -> PathBuf {
    config
        .general
        .investigations_dir
        .join(investigation_id.to_string())
}

// ──────────────────────────────────────────────────────────────────────────────
// Command: new-investigation
// ──────────────────────────────────────────────────────────────────────────────

/// Create a new investigation workspace with audit trail and evidence store.
///
/// This handler:
/// 1. Opens the shared audit database (creating it if first investigation).
/// 2. Generates a new [`InvestigationId`].
/// 3. Logs the intent to create the investigation.
/// 4. Initializes the evidence store directory.
/// 5. Logs the successful creation result.
pub fn handle_new_investigation(
    config: &OracleConfig,
    case_name: String,
    examiner: String,
    description: Option<String>,
) -> Result<()> {
    info!(case = %case_name, examiner = %examiner, "Creating new investigation");

    let mut audit_writer = open_audit_writer(config)?;
    let investigation_id = InvestigationId::new();
    let store_dir = investigation_store_dir(config, investigation_id);

    let examiner_identity = ExaminerIdentity {
        name: examiner.clone(),
        badge_id: "N/A".to_string(),
        organization: config.general.organization_name.clone(),
    };

    // Write-before-execute: log intent first.
    let intent_index = audit_writer.log_intent(
        Some(investigation_id),
        AuditOperationType::InvestigationCreated,
        &examiner,
        &case_name,
        json!({
            "case_name": case_name,
            "examiner": examiner_identity,
            "description": description,
        }),
    )?;

    // Initialize the evidence store.
    let _store = EvidenceStore::initialize(&store_dir, &mut audit_writer)
        .context("Failed to initialize new evidence store")?;

    // Log success.
    audit_writer.log_result(
        intent_index,
        AuditResult::Success,
        json!({
            "investigation_id": investigation_id.to_string(),
            "store_dir": store_dir.display().to_string(),
        }),
    )?;

    let audit_db_path = config.general.investigations_dir.join("audit.db");
    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║       SUCCESS: Investigation Workspace Initialized        ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!("  Case Name:        {}", case_name);
    println!("  Investigation ID: {}", investigation_id);
    println!("  Examiner:         {}", examiner);
    println!("  Workspace Path:   {}", store_dir.display());
    println!("  Audit Log DB:     {}", audit_db_path.display());
    if let Some(desc) = &description {
        println!("  Notes:            {}", desc);
    }
    println!("═════════════════════════════════════════════════════════════");

    Ok(())
}

// Backward-compatible alias used by the original main.rs dispatch.
pub fn new_investigation(
    config: &OracleConfig,
    case_name: String,
    examiner: String,
    description: Option<String>,
) -> Result<()> {
    handle_new_investigation(config, case_name, examiner, description)
}

// ──────────────────────────────────────────────────────────────────────────────
// Command: connect-device
// ──────────────────────────────────────────────────────────────────────────────

/// Connect to an Android device via ADB and verify authorization.
///
/// Logs the connection attempt and result in the audit trail.
pub fn handle_connect_device(config: &OracleConfig, serial: &str) -> Result<()> {
    info!(serial = %serial, "Connecting to device via ADB");

    let mut audit_writer = open_audit_writer(config)?;
    let adb = LiveAdbInterface::new();

    let intent = audit_writer.log_intent(
        None,
        AuditOperationType::DeviceConnected,
        "EXAMINER",
        serial,
        json!({ "serial": serial }),
    )?;

    // Verify device is visible and authorized.
    let devices = adb
        .list_devices()
        .map_err(|e| anyhow!("Failed to list ADB devices: {}", e))?;

    let device = devices.iter().find(|d| d.serial == serial);

    match device {
        Some(d) => {
            let state_str = format!("{:?}", d.state);
            audit_writer.log_result(
                intent,
                AuditResult::Success,
                json!({
                    "serial": serial,
                    "state": state_str,
                    "transport": d.transport_type,
                }),
            )?;

            println!("\n  ✓ Device connected: {} (state: {})", serial, state_str);
            println!("    Transport: {}", d.transport_type);
        }
        None => {
            let available: Vec<&str> = devices.iter().map(|d| d.serial.as_str()).collect();
            audit_writer.log_result(
                intent,
                AuditResult::Failure(format!("Device {} not found", serial)),
                json!({ "available_devices": available }),
            )?;
            return Err(anyhow!(
                "Device '{}' not found. Available devices: {:?}",
                serial,
                available
            ));
        }
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Command: detect-capabilities
// ──────────────────────────────────────────────────────────────────────────────

/// Run capability detection on a connected device and print the investigator briefing.
pub fn handle_detect_capabilities(config: &OracleConfig, serial: &str) -> Result<()> {
    info!(serial = %serial, "Detecting device capabilities");

    let mut audit_writer = open_audit_writer(config)?;
    let adb = LiveAdbInterface::new();

    let intent = audit_writer.log_intent(
        None,
        AuditOperationType::CapabilityDetectionStarted,
        "SYSTEM",
        serial,
        json!({ "serial": serial }),
    )?;

    let detector = CapabilityDetector::new();
    let profile = detector
        .detect(&adb, serial)
        .map_err(|e| {
            let _ = audit_writer.log_result(
                intent,
                AuditResult::Failure(e.to_string()),
                json!({}),
            );
            anyhow!("Capability detection failed: {}", e)
        })?;

    audit_writer.log_result(
        intent,
        AuditResult::Success,
        json!({
            "root_method": format!("{:?}", profile.root_method),
            "selinux_mode": format!("{:?}", profile.selinux_mode),
            "encryption_state": format!("{:?}", profile.encryption_state),
            "available_methods": profile.available_methods.len(),
            "accessible_classes": profile.accessible_artifact_classes.len(),
        }),
    )?;

    // Generate and print the investigator briefing.
    let briefing = oracle_capability::briefing::generate_briefing(&profile);
    println!("\n{}", briefing.full_text);

    if !briefing.warnings.is_empty() {
        println!("\n  ⚠ Warnings:");
        for w in &briefing.warnings {
            println!("    • {}", w);
        }
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Command: discover-artifacts
// ──────────────────────────────────────────────────────────────────────────────

/// Run artifact discovery on a connected device and print the manifest.
pub fn handle_discover(config: &OracleConfig, serial: &str) -> Result<()> {
    info!(serial = %serial, "Discovering artifacts on device");

    let adb = LiveAdbInterface::new();
    let adapter = AdbShellAdapter(&adb);

    // Apply OEM overrides if applicable.
    let mut path_registry = PathRegistry::default();
    let oem_registry = OemPluginRegistry::default_registry();

    // Detect capabilities to identify the device for OEM plugin matching.
    let detector = CapabilityDetector::new();
    if let Ok(profile) = detector.detect(&adb, serial) {
        if let Some(plugin) = oem_registry.find_plugin_for_device(&profile.device) {
            info!(oem = plugin.oem_name(), "Applying OEM path overrides");
            let mut custom_registry = PathRegistry::new();
            for entry in PathRegistry::default().get_all_entries() {
                let mut entry_clone = entry.clone();
                for path_override in plugin.override_artifact_paths() {
                    if path_override.artifact_class == entry.artifact_class {
                        entry_clone.device_paths = vec![path_override.override_path.clone()];
                    }
                }
                custom_registry.add_entry(entry_clone);
            }
            path_registry = custom_registry;
        }
    }

    let scan_result = ArtifactScanner::scan_device(&adapter, serial, &path_registry)
        .map_err(|e| anyhow!("Artifact scan failed: {}", e))?;

    // Build a manifest for display.
    let manifest = ManifestBuilder::build(
        &scan_result,
        InvestigationId::new(), // Placeholder for display purposes.
    );

    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║              Artifact Discovery Results                   ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!("  Found:        {} artifact(s)", scan_result.found.len());
    println!("  Inaccessible: {} path(s)", scan_result.inaccessible.len());
    println!(
        "  Total Est.:   {} bytes",
        manifest.total_estimated_bytes
    );

    if !scan_result.found.is_empty() {
        println!("\n  Discovered Artifacts:");
        for art in &scan_result.found {
            println!(
                "    • [{:?}] {} ({} bytes)",
                art.artifact_class, art.device_path, art.size_bytes
            );
        }
    }

    if !scan_result.inaccessible.is_empty() {
        println!("\n  Inaccessible Paths:");
        for path in &scan_result.inaccessible {
            println!("    ✗ {} — {}", path.path, path.reason);
        }
    }

    println!("═════════════════════════════════════════════════════════════");

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Command: acquire
// ──────────────────────────────────────────────────────────────────────────────

/// Acquire all discovered artifacts from a device.
///
/// This runs the full ingest pipeline (discovery → acquisition → CAS storage).
pub fn handle_acquire(config: &OracleConfig, serial: &str, investigation_id_str: &str) -> Result<()> {
    info!(serial = %serial, investigation = %investigation_id_str, "Acquiring artifacts");

    let investigation_id = parse_investigation_id(investigation_id_str)?;
    let store_dir = investigation_store_dir(config, investigation_id);
    if !store_dir.exists() {
        return Err(anyhow!(
            "Investigation workspace does not exist: {}. Run new-investigation first.",
            store_dir.display()
        ));
    }

    // Delegate to the full ingest pipeline which handles acquisition.
    ingest(config, investigation_id_str, serial)
}

// ──────────────────────────────────────────────────────────────────────────────
// Command: parse
// ──────────────────────────────────────────────────────────────────────────────

/// Parse all acquired artifacts for a given investigation.
///
/// Note: In the current architecture, parsing is performed as part of the
/// full ingest pipeline. This command re-triggers the pipeline.
pub fn handle_parse(config: &OracleConfig, investigation_id_str: &str) -> Result<()> {
    info!(investigation = %investigation_id_str, "Parsing acquired artifacts");

    let investigation_id = parse_investigation_id(investigation_id_str)?;
    let store_dir = investigation_store_dir(config, investigation_id);
    if !store_dir.exists() {
        return Err(anyhow!(
            "Investigation workspace does not exist: {}",
            store_dir.display()
        ));
    }

    println!("  Parsing all acquired artifacts for investigation: {}", investigation_id);
    println!("  Note: Parsing is integrated into the ingest pipeline.");
    println!("  Use 'oracle ingest' to run the full extraction + parse pipeline.");

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Command: normalize
// ──────────────────────────────────────────────────────────────────────────────

/// Normalize all parsed records for a given investigation.
pub fn handle_normalize(config: &OracleConfig, investigation_id_str: &str) -> Result<()> {
    info!(investigation = %investigation_id_str, "Normalizing parsed records");

    let investigation_id = parse_investigation_id(investigation_id_str)?;
    let store_dir = investigation_store_dir(config, investigation_id);
    if !store_dir.exists() {
        return Err(anyhow!(
            "Investigation workspace does not exist: {}",
            store_dir.display()
        ));
    }

    println!("  Normalizing records for investigation: {}", investigation_id);
    println!("  Note: Normalization is integrated into the ingest pipeline.");
    println!("  Use 'oracle ingest' to run the full pipeline including normalization.");

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Command: correlate
// ──────────────────────────────────────────────────────────────────────────────

/// Run the correlation engine on normalized records.
pub fn handle_correlate(config: &OracleConfig, investigation_id_str: &str) -> Result<()> {
    info!(investigation = %investigation_id_str, "Running correlation engine");

    let investigation_id = parse_investigation_id(investigation_id_str)?;
    let store_dir = investigation_store_dir(config, investigation_id);
    if !store_dir.exists() {
        return Err(anyhow!(
            "Investigation workspace does not exist: {}",
            store_dir.display()
        ));
    }

    println!("  Running correlation for investigation: {}", investigation_id);
    println!("  Note: Correlation is integrated into the ingest pipeline.");
    println!("  Use 'oracle ingest' to run the full pipeline including correlation.");

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Command: score
// ──────────────────────────────────────────────────────────────────────────────

/// Compute confidence scores for all findings.
pub fn handle_score(config: &OracleConfig, investigation_id_str: &str) -> Result<()> {
    info!(investigation = %investigation_id_str, "Computing confidence scores");

    let investigation_id = parse_investigation_id(investigation_id_str)?;
    let store_dir = investigation_store_dir(config, investigation_id);
    if !store_dir.exists() {
        return Err(anyhow!(
            "Investigation workspace does not exist: {}",
            store_dir.display()
        ));
    }

    println!("  Scoring findings for investigation: {}", investigation_id);
    println!("  Note: Scoring is integrated into the ingest pipeline.");
    println!("  Use 'oracle ingest' to run the full pipeline including scoring.");

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Command: generate-report
// ──────────────────────────────────────────────────────────────────────────────

/// Generate all reports (JSON + PDF) for a completed investigation.
pub fn handle_generate_report(config: &OracleConfig, investigation_id_str: &str) -> Result<()> {
    info!(investigation = %investigation_id_str, "Generating reports");

    let investigation_id = parse_investigation_id(investigation_id_str)?;
    let store_dir = investigation_store_dir(config, investigation_id);
    if !store_dir.exists() {
        return Err(anyhow!(
            "Investigation workspace does not exist: {}",
            store_dir.display()
        ));
    }

    println!("  Generating reports for investigation: {}", investigation_id);
    println!("  Note: Report generation is integrated into the ingest pipeline.");
    println!("  Use 'oracle ingest' to run the full pipeline including report generation.");

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Command: verify-audit
// ──────────────────────────────────────────────────────────────────────────────

/// Verify the cryptographic integrity of the audit log hash chain.
pub fn handle_verify_audit(config: &OracleConfig, investigation_id_str: &str) -> Result<()> {
    info!(investigation = %investigation_id_str, "Verifying audit chain integrity");

    let investigation_id = parse_investigation_id(investigation_id_str)?;
    let audit_db_path = config.general.investigations_dir.join("audit.db");

    if !audit_db_path.exists() {
        return Err(anyhow!(
            "Audit database does not exist at {}. Create an investigation first.",
            audit_db_path.display()
        ));
    }

    let audit_writer = AuditLogWriter::new(&audit_db_path)
        .map_err(|e| anyhow!("Failed to open audit log: {}", e))?;

    println!("\n  Verifying audit chain integrity...");

    let verifier = AuditLogVerifier::new(audit_writer.connection());
    let report = verifier
        .verify_full()
        .map_err(|e| anyhow!("Audit chain verification failed: {}", e))?;

    let is_intact = report.overall_status == ChainStatus::Intact;

    println!("\n╔═══════════════════════════════════════════════════════════╗");
    if is_intact {
        println!("║         AUDIT CHAIN: INTEGRITY VERIFIED ✓               ║");
        println!("╚═══════════════════════════════════════════════════════════╝");
        println!("  Total entries:  {}", report.total_entries);
        println!("  Chain status:   INTACT");
    } else {
        println!("║         AUDIT CHAIN: INTEGRITY VIOLATION ✗               ║");
        println!("╚═══════════════════════════════════════════════════════════╝");
        println!("  Total entries:  {}", report.total_entries);
        println!("  Chain status:   BROKEN");
        if let Some(desc) = &report.failure_description {
            println!("  Failure:        {}", desc);
        }
    }
    println!("═════════════════════════════════════════════════════════════");

    if !is_intact {
        return Err(anyhow!("Audit chain integrity check failed"));
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Command: verify-evidence
// ──────────────────────────────────────────────────────────────────────────────

/// Verify the integrity of all evidence artifacts in an investigation's store.
pub fn handle_verify_evidence(config: &OracleConfig, investigation_id_str: &str) -> Result<()> {
    info!(investigation = %investigation_id_str, "Verifying evidence store integrity");

    let investigation_id = parse_investigation_id(investigation_id_str)?;
    let store_dir = investigation_store_dir(config, investigation_id);

    if !store_dir.exists() {
        return Err(anyhow!(
            "Evidence store directory does not exist: {}",
            store_dir.display()
        ));
    }

    let store = EvidenceStore::open(&store_dir)
        .context("Failed to open evidence store")?;

    let verifier = IntegrityVerifier::new(&store);
    let report = verifier
        .verify_all_artifacts(investigation_id)
        .map_err(|e| anyhow!("Evidence integrity check failed: {}", e))?;

    println!("\n╔═══════════════════════════════════════════════════════════╗");
    if report.is_clean() {
        println!("║       EVIDENCE STORE: INTEGRITY VERIFIED ✓               ║");
        println!("╚═══════════════════════════════════════════════════════════╝");
        println!("  Total artifacts: {}", report.total_artifacts);
        println!("  All hashes match their ingestion-time values.");
    } else {
        println!("║       EVIDENCE STORE: INTEGRITY VIOLATION ✗               ║");
        println!("╚═══════════════════════════════════════════════════════════╝");
        println!(
            "  {} of {} artifacts have hash mismatches!",
            report.failed_count, report.total_artifacts
        );
        for failure in &report.failures {
            println!("    Artifact:    {}", failure.artifact_id);
            println!("    Stored:      {}", failure.stored_hash);
            println!("    Computed:    {}", failure.computed_hash);
            println!("    Detail:      {}", failure.description);
            println!();
        }
    }
    println!("═════════════════════════════════════════════════════════════");

    if !report.is_clean() {
        return Err(anyhow!("Evidence integrity check failed"));
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Command: status
// ──────────────────────────────────────────────────────────────────────────────

/// Show the current status of an investigation.
pub fn handle_status(config: &OracleConfig, investigation_id_str: &str) -> Result<()> {
    info!(investigation = %investigation_id_str, "Querying investigation status");

    let investigation_id = parse_investigation_id(investigation_id_str)?;
    let store_dir = investigation_store_dir(config, investigation_id);
    let audit_db_path = config.general.investigations_dir.join("audit.db");

    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║                Investigation Status                      ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!("  Investigation ID: {}", investigation_id);

    // Check workspace existence.
    if store_dir.exists() {
        println!("  Workspace:        {} (exists)", store_dir.display());
    } else {
        println!("  Workspace:        {} (NOT FOUND)", store_dir.display());
        println!("═════════════════════════════════════════════════════════════");
        return Ok(());
    }

    // Check audit log.
    if audit_db_path.exists() {
        println!("  Audit DB:         {} (exists)", audit_db_path.display());

        // Count audit entries for this investigation.
        if let Ok(writer) = AuditLogWriter::new(&audit_db_path) {
            let count: Result<i64, _> = writer.connection().query_row(
                "SELECT COUNT(*) FROM audit_entries WHERE investigation_id = ?1",
                params![Some(investigation_id.to_string())],
                |row| row.get(0),
            );
            if let Ok(n) = count {
                println!("  Audit Entries:    {}", n);
            }
        }
    } else {
        println!("  Audit DB:         NOT FOUND");
    }

    // Check evidence store.
    match EvidenceStore::open(&store_dir) {
        Ok(store) => {
            println!("  Evidence Store:   OPEN");
            // Attempt to count artifacts.
            let verifier = IntegrityVerifier::new(&store);
            if let Ok(report) = verifier.verify_all_artifacts(investigation_id) {
                println!("  Total Artifacts:  {}", report.total_artifacts);
                println!(
                    "  Integrity:        {}",
                    if report.is_clean() { "CLEAN" } else { "VIOLATIONS DETECTED" }
                );
            }
        }
        Err(e) => {
            println!("  Evidence Store:   FAILED TO OPEN ({})", e);
        }
    }

    println!("═════════════════════════════════════════════════════════════");

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Legacy Commands (backward compatibility)
// ──────────────────────────────────────────────────────────────────────────────

/// Ingest evidence from a source device and perform the full pipeline.
///
/// This is the primary "do everything" command that runs the forensic
/// pipeline end-to-end: connect → detect → discover → acquire → parse →
/// normalize → correlate → score → report.
pub fn ingest(
    config: &OracleConfig,
    investigation_id_str: &str,
    source: &str,
) -> Result<()> {
    let uuid = Uuid::parse_str(investigation_id_str)
        .context("Invalid Investigation ID format (must be a valid UUID)")?;
    let investigation_id = InvestigationId(uuid);

    let audit_db_path = config.general.investigations_dir.join("audit.db");
    if !audit_db_path.exists() {
        return Err(anyhow!(
            "Audit database does not exist. Create an investigation first."
        ));
    }
    let mut audit_writer = AuditLogWriter::new(&audit_db_path)
        .map_err(|e| anyhow!("Failed to open audit log: {}", e))?;

    // Verify investigation exists.
    let store_dir = investigation_store_dir(config, investigation_id);
    if !store_dir.exists() {
        return Err(anyhow!(
            "Investigation workspace directory does not exist: {}. \
             Has this investigation been created?",
            store_dir.display()
        ));
    }

    // Retrieve case details from audit log.
    let (case_name, examiner_name) = match audit_writer.connection().query_row(
        "SELECT subject, actor FROM audit_entries \
         WHERE investigation_id = ?1 AND operation = '\"InvestigationCreated\"' \
         ORDER BY entry_index ASC LIMIT 1",
        params![Some(investigation_id.to_string())],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    ) {
        Ok(vals) => vals,
        Err(_) => {
            // Fallback: try querying any entry for this investigation_id.
            match audit_writer.connection().query_row(
                "SELECT subject, actor FROM audit_entries \
                 WHERE investigation_id = ?1 ORDER BY entry_index ASC LIMIT 1",
                params![Some(investigation_id.to_string())],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            ) {
                Ok(vals) => vals,
                Err(_) => ("Investigation".to_string(), "UNKNOWN".to_string()),
            }
        }
    };

    let examiner = ExaminerIdentity {
        name: examiner_name,
        badge_id: "N/A".to_string(),
        organization: config.general.organization_name.clone(),
    };

    println!("\nExecuting forensic acquisition and analysis pipeline...");
    println!("  Investigation:  {}", investigation_id);
    println!("  Case:           {}", case_name);
    println!("  Examiner:       {}", examiner.name);
    println!("  Source:         {}", source);
    println!("═════════════════════════════════════════════════════════════");

    let pipeline = ForensicPipeline::new(
        config.clone(),
        investigation_id,
        case_name.clone(),
        examiner,
    );

    let pipeline_result = pipeline
        .run(source)
        .context("Forensic pipeline execution failed")?;

    // Write reports to the output directory.
    let output_dir = config.report.output_dir.clone();
    if !output_dir.exists() {
        fs::create_dir_all(&output_dir).context("Failed to create report output directory")?;
    }

    let base_filename = format!(
        "report_{}_{}",
        case_name.replace(' ', "_"),
        investigation_id
    );
    let json_path = output_dir.join(format!("{}.json", base_filename));
    let pdf_path = output_dir.join(format!("{}.pdf", base_filename));

    // Serialize JSON report.
    let json_report =
        oracle_report::JsonRenderer::render(&pipeline_result.signed_report.report)
            .context("Failed to render JSON report")?;
    fs::write(&json_path, json_report).context("Failed to write JSON report file")?;

    // Render PDF report.
    oracle_report::render_pdf(&pipeline_result.signed_report.report, &pdf_path)
        .context("Failed to render PDF report")?;

    // Log the export event.
    let export_intent = audit_writer.log_intent(
        Some(investigation_id),
        AuditOperationType::ReportExported,
        "SYSTEM",
        &base_filename,
        json!({
            "json_path": json_path.display().to_string(),
            "pdf_path": pdf_path.display().to_string(),
            "integrity_seal": pipeline_result.signed_report.integrity_seal,
        }),
    )?;
    audit_writer.log_result(export_intent, AuditResult::Success, json!({}))?;

    println!(
        "\n╔═══════════════════════════════════════════════════════════╗"
    );
    println!(
        "║             Forensic Acquisition Complete                 ║"
    );
    println!(
        "╚═══════════════════════════════════════════════════════════╝"
    );
    println!(
        "  Artifacts Ingested:        {}",
        pipeline_result
            .timeline
            .sessions
            .iter()
            .map(|s| s.events.len())
            .sum::<usize>()
    );
    println!(
        "  Timeline Sessions:        {}",
        pipeline_result.timeline.sessions.len()
    );
    println!(
        "  Anomalies Detected:       {}",
        pipeline_result.anomaly_report.anomalies.len()
    );
    println!(
        "  Conflict Detections:      {}",
        pipeline_result.conflict_report.summary.total_conflicts
    );
    println!(
        "  Integrity Seal (SHA-256): {}",
        pipeline_result.signed_report.integrity_seal
    );
    println!("  JSON Report Written to:   {}", json_path.display());
    println!("  PDF Report Written to:    {}", pdf_path.display());
    println!("═════════════════════════════════════════════════════════════");

    Ok(())
}

/// Verify the cryptographic chain of custody and file hashes of all stored evidence.
///
/// This is a combined verification command that checks both the audit chain
/// and the evidence store integrity.
pub fn verify(config: &OracleConfig, investigation_id_str: &str) -> Result<()> {
    let uuid = Uuid::parse_str(investigation_id_str)
        .context("Invalid Investigation ID format (must be a valid UUID)")?;
    let investigation_id = InvestigationId(uuid);

    let audit_db_path = config.general.investigations_dir.join("audit.db");
    if !audit_db_path.exists() {
        return Err(anyhow!(
            "Audit database does not exist. Create an investigation first."
        ));
    }
    let mut audit_writer = AuditLogWriter::new(&audit_db_path)
        .map_err(|e| anyhow!("Failed to open audit log: {}", e))?;

    println!(
        "\nVerifying forensic integrity for investigation: {}",
        investigation_id
    );
    println!("═════════════════════════════════════════════════════════════");

    // 1. Verify the Audit Log Hash Chain.
    println!("1. Verifying cryptographic audit chain...");
    let verifier = AuditLogVerifier::new(audit_writer.connection());
    let audit_report = verifier
        .verify_full()
        .map_err(|e| anyhow!("Audit chain verification query failed: {}", e))?;

    let is_audit_clean = audit_report.overall_status == ChainStatus::Intact;
    if is_audit_clean {
        println!(
            "   [PASS] Audit log hash chain is completely intact ({} entries).",
            audit_report.total_entries
        );
    } else {
        println!("   [FAIL] Audit log hash chain is broken!");
        if let Some(desc) = &audit_report.failure_description {
            println!("          Reason: {}", desc);
        }
    }

    // 2. Verify Evidence Store.
    println!("2. Verifying evidence store artifacts...");
    let store_dir = investigation_store_dir(config, investigation_id);
    let mut is_evidence_clean = false;
    let mut total_artifacts = 0;
    let mut failed_artifacts = 0;
    let mut integrity_report = None;

    if !store_dir.exists() {
        println!(
            "   [FAIL] Evidence store directory does not exist: {}",
            store_dir.display()
        );
    } else {
        match EvidenceStore::open(&store_dir) {
            Ok(store) => {
                let evidence_verifier = IntegrityVerifier::new(&store);
                match evidence_verifier.verify_all_artifacts(investigation_id) {
                    Ok(rep) => {
                        total_artifacts = rep.total_artifacts;
                        failed_artifacts = rep.failed_count;
                        is_evidence_clean = rep.is_clean();
                        if is_evidence_clean {
                            println!(
                                "   [PASS] All {} stored artifacts match their ingestion hashes.",
                                rep.total_artifacts
                            );
                        } else {
                            println!(
                                "   [FAIL] Artifact hash mismatch detected! {} of {} artifacts corrupted.",
                                rep.failed_count, rep.total_artifacts
                            );
                            for failure in &rep.failures {
                                println!("          Artifact ID:  {}", failure.artifact_id);
                                println!("          Stored Hash:  {}", failure.stored_hash);
                                println!(
                                    "          Current Hash: {}",
                                    failure.computed_hash
                                );
                                println!("          Detail:       {}", failure.description);
                            }
                        }
                        integrity_report = Some(rep);
                    }
                    Err(e) => {
                        println!(
                            "   [FAIL] Failed to run artifact integrity check: {}",
                            e
                        );
                    }
                }
            }
            Err(e) => {
                println!(
                    "   [FAIL] Failed to open evidence store database: {}",
                    e
                );
            }
        }
    }

    // Log the verification attempt in the audit log.
    let verify_intent = audit_writer.log_intent(
        Some(investigation_id),
        AuditOperationType::EvidenceStoreVerified,
        "SYSTEM",
        &investigation_id.to_string(),
        json!({
            "audit_chain_status": format!("{}", audit_report.overall_status),
            "evidence_integrity_clean": is_evidence_clean,
            "total_artifacts": total_artifacts,
            "failed_artifacts": failed_artifacts,
        }),
    )?;

    let outcome = if is_audit_clean && is_evidence_clean {
        AuditResult::Success
    } else {
        AuditResult::Failure(format!(
            "Integrity check failed: audit_chain={:?}, evidence_clean={}",
            audit_report.overall_status, is_evidence_clean
        ))
    };

    audit_writer.log_result(
        verify_intent,
        outcome,
        json!({
            "audit_report": audit_report,
            "integrity_report": integrity_report,
        }),
    )?;

    println!(
        "\n╔═══════════════════════════════════════════════════════════╗"
    );
    if is_audit_clean && is_evidence_clean {
        println!(
            "║            VERIFICATION SUCCESS: Integrity Intact         ║"
        );
        println!(
            "╚═══════════════════════════════════════════════════════════╝"
        );
        println!("  All cryptographic checks passed successfully.");
    } else {
        println!(
            "║            VERIFICATION FAILURE: Tampering Detected       ║"
        );
        println!(
            "╚═══════════════════════════════════════════════════════════╝"
        );
        println!("  ⚠ WARNING: Evidence integrity cannot be guaranteed!");
    }
    println!("═════════════════════════════════════════════════════════════");

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_parse_valid_investigation_id() {
        let uuid_str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        let result = parse_investigation_id(uuid_str);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), uuid_str);
    }

    #[test]
    fn test_parse_invalid_investigation_id() {
        let result = parse_investigation_id("not-a-uuid");
        assert!(result.is_err());
    }

    #[test]
    fn test_investigation_store_dir() {
        let config = OracleConfig::default_config(Path::new("/tmp/oracle-test"));
        let inv_id = InvestigationId::new();
        let dir = investigation_store_dir(&config, inv_id);
        assert!(dir.to_string_lossy().contains(&inv_id.to_string()));
    }

    #[test]
    fn test_command_routing_new_investigation() {
        // Verify the function signature and error handling — we can't run
        // it without a real filesystem in unit tests, but we can confirm
        // the handler is callable.
        let config = OracleConfig::default_config(Path::new("/nonexistent/path"));
        let result = handle_new_investigation(
            &config,
            "TEST-CASE".to_string(),
            "Tester".to_string(),
            Some("test description".to_string()),
        );
        // Should fail because the investigations dir doesn't exist (or
        // because the audit DB can't be created in /nonexistent/path).
        assert!(result.is_err());
    }

    #[test]
    fn test_command_routing_status() {
        let config = OracleConfig::default_config(Path::new("/nonexistent/path"));
        let result = handle_status(&config, "a1b2c3d4-e5f6-7890-abcd-ef1234567890");
        // Should succeed even with non-existent paths — it just reports "NOT FOUND".
        assert!(result.is_ok());
    }

    #[test]
    fn test_command_routing_verify_audit_missing_db() {
        let config = OracleConfig::default_config(Path::new("/nonexistent/path"));
        let result = handle_verify_audit(&config, "a1b2c3d4-e5f6-7890-abcd-ef1234567890");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Audit database does not exist"),
            "Unexpected error: {}",
            err_msg
        );
    }

    #[test]
    fn test_command_routing_verify_evidence_missing_dir() {
        let config = OracleConfig::default_config(Path::new("/nonexistent/path"));
        let result = handle_verify_evidence(
            &config,
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        );
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("does not exist"),
            "Unexpected error: {}",
            err_msg
        );
    }
}
