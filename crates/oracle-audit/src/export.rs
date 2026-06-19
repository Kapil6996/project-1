//! # Audit Log Export
//!
//! Exports the full audit log to a self-verifying JSON file suitable for
//! archival, court submission, or inter-agency transfer.
//!
//! The exported file contains:
//!
//! 1. All audit entries in chronological order.
//! 2. A [`VerificationReport`] proving chain integrity at time of export.
//! 3. A SHA-256 hash of the complete JSON payload (excluding the hash itself).

use std::path::Path;

use chrono::Utc;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use tracing::info;

use oracle_core::error::{OracleError, OracleResult};
use oracle_core::ForensicHash;

use crate::entry::AuditEntry;
use crate::verifier::{AuditLogVerifier, VerificationReport};
use crate::writer::read_all_entries_from_conn;

// ──────────────────────────────────────────────────────────────────────────────
// Export Structures
// ──────────────────────────────────────────────────────────────────────────────

/// The complete exported audit log, including integrity proofs.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditLogExport {
    /// Format version for forward compatibility.
    pub export_version: String,
    /// UTC timestamp when the export was generated.
    pub exported_at: String,
    /// All audit entries in chronological order.
    pub entries: Vec<AuditEntry>,
    /// Verification report generated immediately before export.
    pub verification: VerificationReport,
    /// SHA-256 hash of the JSON serialisation of all preceding fields.
    /// Computed over the `entries` and `verification` sections.
    pub export_hash: String,
}

/// Payload used to compute the `export_hash`. Contains everything except
/// the hash itself to avoid circular dependency.
#[derive(Serialize)]
struct HashableExportPayload<'a> {
    export_version: &'a str,
    exported_at: &'a str,
    entries: &'a [AuditEntry],
    verification: &'a VerificationReport,
}

// ──────────────────────────────────────────────────────────────────────────────
// Export Function
// ──────────────────────────────────────────────────────────────────────────────

/// Export the full audit log to a JSON file at the given path.
///
/// The function:
///
/// 1. Runs the chain verifier to produce a [`VerificationReport`].
/// 2. Reads all entries from the database.
/// 3. Serializes the entire payload to JSON.
/// 4. Computes a SHA-256 hash of the payload.
/// 5. Writes the final JSON (including the hash) to disk.
///
/// # Arguments
///
/// * `conn` — A shared reference to the audit database connection.
/// * `output_path` — The filesystem path for the output JSON file.
///
/// # Errors
///
/// * [`OracleError::DatabaseError`] — if the database cannot be read.
/// * [`OracleError::SerializationError`] — if JSON serialization fails.
/// * [`OracleError::IoError`] — if the output file cannot be written.
pub fn export_audit_log(conn: &Connection, output_path: &Path) -> OracleResult<AuditLogExport> {
    // Step 1: Run verification.
    let verifier = AuditLogVerifier::new(conn);
    let verification = verifier.verify_full()?;

    // Step 2: Read all entries.
    let entries = read_all_entries_from_conn(conn)?;

    let export_version = "1.0.0".to_string();
    let exported_at = Utc::now().to_rfc3339();

    // Step 3: Compute hash over the payload (excluding export_hash).
    let hashable = HashableExportPayload {
        export_version: &export_version,
        exported_at: &exported_at,
        entries: &entries,
        verification: &verification,
    };
    let hashable_bytes = serde_json::to_vec(&hashable)?;
    let export_hash = ForensicHash::from_bytes(&hashable_bytes).to_hex();

    // Step 4: Build the complete export.
    let export = AuditLogExport {
        export_version,
        exported_at,
        entries,
        verification,
        export_hash,
    };

    // Step 5: Write to disk.
    let json_bytes = serde_json::to_vec_pretty(&export)?;
    std::fs::write(output_path, &json_bytes).map_err(|e| OracleError::IoError {
        path: output_path.to_path_buf(),
        source: e,
    })?;

    info!(
        path = %output_path.display(),
        entries = export.entries.len(),
        status = %export.verification.overall_status,
        "Audit log exported"
    );

    Ok(export)
}

/// Verify that an exported JSON file's `export_hash` matches its content.
///
/// # Arguments
///
/// * `export` — A previously deserialized [`AuditLogExport`].
///
/// # Returns
///
/// `Ok(true)` if the hash is valid, `Ok(false)` if it has been tampered with.
///
/// # Errors
///
/// Returns [`OracleError::SerializationError`] if the hashable payload cannot
/// be serialized.
pub fn verify_export_hash(export: &AuditLogExport) -> OracleResult<bool> {
    let hashable = HashableExportPayload {
        export_version: &export.export_version,
        exported_at: &export.exported_at,
        entries: &export.entries,
        verification: &export.verification,
    };
    let hashable_bytes = serde_json::to_vec(&hashable)?;
    let recomputed = ForensicHash::from_bytes(&hashable_bytes).to_hex();
    Ok(recomputed == export.export_hash)
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::ChainStatus;
    use crate::writer::AuditLogWriter;
    use oracle_core::types::AuditOperationType;
    use serde_json::json;
    use tempfile::TempDir;

    fn temp_writer() -> (AuditLogWriter, TempDir) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("audit.db");
        let writer = AuditLogWriter::new(&db_path).unwrap();
        (writer, dir)
    }

    #[test]
    fn test_export_produces_valid_json() {
        let (mut writer, dir) = temp_writer();

        for i in 0..5 {
            writer
                .log_intent(
                    None,
                    AuditOperationType::ExaminerNoteAdded,
                    "Examiner A",
                    &format!("Note #{}", i),
                    json!({"i": i}),
                )
                .unwrap();
        }

        let export_path = dir.path().join("export.json");
        let export = export_audit_log(writer.connection(), &export_path).unwrap();

        assert_eq!(export.entries.len(), 5);
        assert_eq!(export.verification.overall_status, ChainStatus::Intact);

        // Verify the file was written and is valid JSON.
        let file_bytes = std::fs::read(&export_path).unwrap();
        let parsed: AuditLogExport = serde_json::from_slice(&file_bytes).unwrap();
        assert_eq!(parsed.entries.len(), 5);
    }

    #[test]
    fn test_export_hash_is_valid() {
        let (mut writer, dir) = temp_writer();

        for i in 0..3 {
            writer
                .log_intent(
                    None,
                    AuditOperationType::ExaminerNoteAdded,
                    "Examiner A",
                    &format!("Note #{}", i),
                    json!({}),
                )
                .unwrap();
        }

        let export_path = dir.path().join("export.json");
        let export = export_audit_log(writer.connection(), &export_path).unwrap();

        assert!(
            verify_export_hash(&export).unwrap(),
            "Export hash must verify correctly"
        );
    }

    #[test]
    fn test_export_hash_detects_tampering() {
        let (mut writer, dir) = temp_writer();

        writer
            .log_intent(
                None,
                AuditOperationType::SystemStartup,
                "SYSTEM",
                "Platform",
                json!({}),
            )
            .unwrap();

        let export_path = dir.path().join("export.json");
        let mut export = export_audit_log(writer.connection(), &export_path).unwrap();

        // Tamper with the exported data.
        export.entries[0].actor = "EVIL_ACTOR".to_string();

        assert!(
            !verify_export_hash(&export).unwrap(),
            "Tampered export must fail hash verification"
        );
    }

    #[test]
    fn test_export_with_verification_proof() {
        let (mut writer, dir) = temp_writer();

        for i in 0..10 {
            writer
                .log_intent(
                    None,
                    AuditOperationType::ExaminerNoteAdded,
                    "Examiner A",
                    &format!("Note #{}", i),
                    json!({}),
                )
                .unwrap();
        }

        let export_path = dir.path().join("export.json");
        let export = export_audit_log(writer.connection(), &export_path).unwrap();

        assert_eq!(export.verification.total_entries, 10);
        assert_eq!(export.verification.verified_entries, 10);
        assert_eq!(export.verification.overall_status, ChainStatus::Intact);
        assert!(export.verification.first_broken_entry.is_none());
    }

    #[test]
    fn test_export_empty_log() {
        let (writer, dir) = temp_writer();

        let export_path = dir.path().join("export.json");
        let export = export_audit_log(writer.connection(), &export_path).unwrap();

        assert_eq!(export.entries.len(), 0);
        assert_eq!(export.verification.overall_status, ChainStatus::Intact);
        assert!(verify_export_hash(&export).unwrap());
    }
}
