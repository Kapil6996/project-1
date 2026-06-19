//! # Forensic Investigation Command Handlers
//!
//! Implements CLI command handlers for initializing investigations, ingesting device
//! artifacts, and verifying cryptographic chain of custody.

use std::fs;
use std::path::PathBuf;
use anyhow::{anyhow, Context, Result};
use rusqlite::params;
use serde_json::json;
use tracing::{info, warn, error};

use oracle_core::OracleConfig;
use oracle_core::types::{
    InvestigationId, ExaminerIdentity, AuditOperationType, AuditResult,
};
use oracle_audit::{AuditLogWriter, AuditLogVerifier, ChainStatus};
use oracle_evidence::{EvidenceStore, IntegrityVerifier};
use crate::pipeline::InvestigationPipeline;
use uuid::Uuid;

/// Create a new investigation workspace and global audit trail entry.
pub fn new_investigation(
    config: &OracleConfig,
    case_name: String,
    examiner: String,
    description: Option<String>,
) -> Result<()> {
    info!("Initializing new investigation...");
    let audit_db_path = config.general.investigations_dir.join("audit.db");
    let mut audit_writer = AuditLogWriter::new(&audit_db_path)
        .map_err(|e| anyhow!("Failed to open audit log: {}", e))?;

    let investigation_id = InvestigationId::new();
    let store_dir = config.general.investigations_dir.join(investigation_id.to_string());

    let examiner_identity = ExaminerIdentity {
        name: examiner.clone(),
        badge_id: "N/A".to_string(),
        organization: config.general.organization_name.clone(),
    };

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

    // Initialize the evidence store
    let _store = EvidenceStore::initialize(&store_dir, &mut audit_writer)
        .context("Failed to initialize new evidence store")?;

    audit_writer.log_result(
        intent_index,
        AuditResult::Success,
        json!({
            "investigation_id": investigation_id.to_string(),
            "store_dir": store_dir.display().to_string(),
        }),
    )?;

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

/// Ingest evidence from a source device or file path and perform pipeline execution.
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
        return Err(anyhow!("Audit database does not exist. Create an investigation first."));
    }
    let mut audit_writer = AuditLogWriter::new(&audit_db_path)
        .map_err(|e| anyhow!("Failed to open audit log: {}", e))?;

    // Verify investigation exists by opening the store
    let store_dir = config.general.investigations_dir.join(investigation_id.to_string());
    if !store_dir.exists() {
        return Err(anyhow!(
            "Investigation workspace directory does not exist: {}. Has this investigation been created?",
            store_dir.display()
        ));
    }

    // Retrieve case details from audit log to maintain context
    let (case_name, examiner_name) = match audit_writer.connection().query_row(
        "SELECT subject, actor FROM audit_entries WHERE investigation_id = ?1 AND operation = '\"InvestigationCreated\"' ORDER BY entry_index ASC LIMIT 1",
        params![Some(investigation_id.to_string())],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    ) {
        Ok(vals) => vals,
        Err(_) => {
            // Fallback: try querying any entry for this investigation_id
            match audit_writer.connection().query_row(
                "SELECT subject, actor FROM audit_entries WHERE investigation_id = ?1 ORDER BY entry_index ASC LIMIT 1",
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

    let pipeline = InvestigationPipeline::new(
        config.clone(),
        investigation_id,
        case_name.clone(),
        examiner,
    );

    let pipeline_result = pipeline.run(source)
        .context("Forensic pipeline execution failed")?;

    // Write reports to the output directory
    let output_dir = config.report.output_dir.clone();
    if !output_dir.exists() {
        fs::create_dir_all(&output_dir)
            .context("Failed to create report output directory")?;
    }

    let base_filename = format!("report_{}_{}", case_name.replace(" ", "_"), investigation_id);
    let json_path = output_dir.join(format!("{}.json", base_filename));
    let pdf_path = output_dir.join(format!("{}.pdf", base_filename));

    // Serialize JSON report
    let json_report = oracle_report::JsonRenderer::render(&pipeline_result.signed_report.report)
        .context("Failed to render JSON report")?;
    fs::write(&json_path, json_report)
        .context("Failed to write JSON report file")?;

    // Render PDF report
    oracle_report::render_pdf(&pipeline_result.signed_report.report, &pdf_path)
        .context("Failed to render PDF report")?;

    // Log the export event
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
    audit_writer.log_result(
        export_intent,
        AuditResult::Success,
        json!({}),
    )?;

    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║             Forensic Acquisition Complete                 ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!("  Artifacts Ingested:        {}", pipeline_result.timeline.sessions.iter().map(|s| s.events.len()).sum::<usize>());
    println!("  Timeline Sessions:        {}", pipeline_result.timeline.sessions.len());
    println!("  Anomalies Detected:       {}", pipeline_result.anomaly_report.anomalies.len());
    println!("  Conflict Detections:      {}", pipeline_result.conflict_report.summary.total_conflicts);
    println!("  Integrity Seal (SHA-256): {}", pipeline_result.signed_report.integrity_seal);
    println!("  JSON Report Written to:   {}", json_path.display());
    println!("  PDF Report Written to:    {}", pdf_path.display());
    println!("═════════════════════════════════════════════════════════════");

    Ok(())
}

/// Verify the cryptographic chain of custody and file hashes of all stored evidence.
pub fn verify(
    config: &OracleConfig,
    investigation_id_str: &str,
) -> Result<()> {
    let uuid = Uuid::parse_str(investigation_id_str)
        .context("Invalid Investigation ID format (must be a valid UUID)")?;
    let investigation_id = InvestigationId(uuid);

    let audit_db_path = config.general.investigations_dir.join("audit.db");
    if !audit_db_path.exists() {
        return Err(anyhow!("Audit database does not exist. Create an investigation first."));
    }
    let mut audit_writer = AuditLogWriter::new(&audit_db_path)
        .map_err(|e| anyhow!("Failed to open audit log: {}", e))?;

    println!("\nVerifying forensic integrity for investigation: {}", investigation_id);
    println!("═════════════════════════════════════════════════════════════");

    // 1. Verify the Audit Log Hash Chain
    println!("1. Verifying cryptographic audit chain...");
    let verifier = AuditLogVerifier::new(audit_writer.connection());
    let audit_report = verifier.verify_full()
        .map_err(|e| anyhow!("Audit chain verification query failed: {}", e))?;

    let is_audit_clean = audit_report.overall_status == ChainStatus::Intact;
    if is_audit_clean {
        println!("   [PASS] Audit log hash chain is completely intact ({} entries).", audit_report.total_entries);
    } else {
        println!("   [FAIL] Audit log hash chain is broken!");
        if let Some(desc) = &audit_report.failure_description {
            println!("          Reason: {}", desc);
        }
    }

    // 2. Verify Evidence Store
    println!("2. Verifying evidence store artifacts...");
    let store_dir = config.general.investigations_dir.join(investigation_id.to_string());
    let mut is_evidence_clean = false;
    let mut total_artifacts = 0;
    let mut failed_artifacts = 0;
    let mut integrity_report = None;

    if !store_dir.exists() {
        println!("   [FAIL] Evidence store directory does not exist: {}", store_dir.display());
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
                            println!("   [PASS] All {} stored artifacts match their ingestion hashes.", rep.total_artifacts);
                        } else {
                            println!("   [FAIL] Artifact hash mismatch detected! {} of {} artifacts corrupted.", rep.failed_count, rep.total_artifacts);
                            for failure in &rep.failures {
                                println!("          Artifact ID:  {}", failure.artifact_id);
                                println!("          Stored Hash:  {}", failure.stored_hash);
                                println!("          Current Hash: {}", failure.computed_hash);
                                println!("          Detail:       {}", failure.description);
                            }
                        }
                        integrity_report = Some(rep);
                    }
                    Err(e) => {
                        println!("   [FAIL] Failed to run artifact integrity check: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("   [FAIL] Failed to open evidence store database: {}", e);
            }
        }
    }

    // Log the verification attempt in the audit log
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

    println!("\n╔═══════════════════════════════════════════════════════════╗");
    if is_audit_clean && is_evidence_clean {
        println!("║            VERIFICATION SUCCESS: Integrity Intact         ║");
        println!("╚═══════════════════════════════════════════════════════════╝");
        println!("  All cryptographic checks passed successfully.");
    } else {
        println!("║            VERIFICATION FAILURE: Tampering Detected       ║");
        println!("╚═══════════════════════════════════════════════════════════╝");
        println!("  ⚠ WARNING: Evidence integrity cannot be guaranteed!");
    }
    println!("═════════════════════════════════════════════════════════════");

    Ok(())
}
