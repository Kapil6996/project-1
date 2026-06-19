//! # Audit Log Verifier
//!
//! Provides [`AuditLogVerifier`], a **read-only** component that walks the
//! cryptographic hash chain stored in the audit database and detects any
//! tampering, insertion, deletion, or corruption.
//!
//! ## Verification Process
//!
//! For every entry (in `entry_index` order) the verifier:
//!
//! 1. Checks that `previous_hash` matches the `entry_hash` of the preceding entry
//!    (or all-zeros for the genesis entry).
//! 2. Recomputes the entry hash from the stored content and compares it to the
//!    stored `entry_hash`.
//!
//! If either check fails the chain is broken and the exact breakpoint is recorded.

use chrono::{DateTime, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use oracle_core::error::{OracleError, OracleResult};
use oracle_core::ForensicHash;

use crate::writer::read_all_entries_from_conn;

// ──────────────────────────────────────────────────────────────────────────────
// Verification Report
// ──────────────────────────────────────────────────────────────────────────────

/// The overall integrity status of the audit chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainStatus {
    /// Every entry's hash is valid and correctly chains to its predecessor.
    Intact,
    /// At least one entry's hash does not match or the chain link is broken.
    Broken,
}

impl std::fmt::Display for ChainStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainStatus::Intact => write!(f, "INTACT"),
            ChainStatus::Broken => write!(f, "BROKEN"),
        }
    }
}

/// A comprehensive report produced by [`AuditLogVerifier::verify_full()`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Total number of entries examined.
    pub total_entries: u64,
    /// Number of entries whose hash was successfully verified.
    pub verified_entries: u64,
    /// The index of the first entry where the chain is broken, if any.
    pub first_broken_entry: Option<u64>,
    /// Human-readable description of the first failure, if any.
    pub failure_description: Option<String>,
    /// UTC timestamp when the verification was performed.
    pub verification_timestamp: DateTime<Utc>,
    /// Overall chain integrity status.
    pub overall_status: ChainStatus,
}

// ──────────────────────────────────────────────────────────────────────────────
// Verifier
// ──────────────────────────────────────────────────────────────────────────────

/// Read-only verifier for the cryptographic audit chain.
///
/// The verifier **never** modifies the audit database. It borrows the
/// connection immutably and produces a [`VerificationReport`].
pub struct AuditLogVerifier<'a> {
    /// Shared reference to the SQLite connection.
    conn: &'a Connection,
}

impl<'a> AuditLogVerifier<'a> {
    /// Create a new verifier bound to the given database connection.
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Walk the entire chain and return an error at the first breakpoint.
    ///
    /// Returns `Ok(())` if the chain is fully intact.
    ///
    /// # Errors
    ///
    /// * [`OracleError::AuditChainBroken`] — at the first mismatched entry.
    /// * [`OracleError::DatabaseError`] — if the database cannot be read.
    pub fn verify_chain(&self) -> OracleResult<()> {
        let entries = read_all_entries_from_conn(self.conn)?;

        let mut expected_prev_hash = ForensicHash::GENESIS.to_hex();

        for entry in &entries {
            // 1. Check that this entry's previous_hash matches the previous
            //    entry's entry_hash.
            if entry.previous_hash != expected_prev_hash {
                return Err(OracleError::AuditChainBroken {
                    entry_index: entry.entry_index,
                    expected: expected_prev_hash,
                    found: entry.previous_hash.clone(),
                });
            }

            // 2. Recompute the entry hash and compare.
            let recomputed = entry.compute_hash()?;
            if recomputed != entry.entry_hash {
                return Err(OracleError::AuditChainBroken {
                    entry_index: entry.entry_index,
                    expected: recomputed,
                    found: entry.entry_hash.clone(),
                });
            }

            expected_prev_hash = entry.entry_hash.clone();
        }

        Ok(())
    }

    /// Verify the entire chain and produce a detailed [`VerificationReport`].
    ///
    /// Unlike [`verify_chain()`], this method never returns `Err` for chain
    /// breakage — instead it records the failure in the report.
    ///
    /// # Errors
    ///
    /// Returns `Err` only for database I/O failures.
    pub fn verify_full(&self) -> OracleResult<VerificationReport> {
        let entries = read_all_entries_from_conn(self.conn)?;
        let total_entries = entries.len() as u64;
        let mut verified_entries: u64 = 0;
        let mut first_broken_entry: Option<u64> = None;
        let mut failure_description: Option<String> = None;

        let mut expected_prev_hash = ForensicHash::GENESIS.to_hex();

        for entry in &entries {
            // Check previous_hash linkage.
            if entry.previous_hash != expected_prev_hash {
                if first_broken_entry.is_none() {
                    first_broken_entry = Some(entry.entry_index);
                    failure_description = Some(format!(
                        "Entry {} previous_hash mismatch: expected {}, found {}",
                        entry.entry_index, expected_prev_hash, entry.previous_hash
                    ));
                }
                break;
            }

            // Recompute and compare entry hash.
            match entry.compute_hash() {
                Ok(recomputed) => {
                    if recomputed != entry.entry_hash {
                        if first_broken_entry.is_none() {
                            first_broken_entry = Some(entry.entry_index);
                            failure_description = Some(format!(
                                "Entry {} hash mismatch: recomputed {}, stored {}",
                                entry.entry_index, recomputed, entry.entry_hash
                            ));
                        }
                        break;
                    }
                }
                Err(e) => {
                    if first_broken_entry.is_none() {
                        first_broken_entry = Some(entry.entry_index);
                        failure_description =
                            Some(format!("Entry {} hash computation failed: {}", entry.entry_index, e));
                    }
                    break;
                }
            }

            verified_entries += 1;
            expected_prev_hash = entry.entry_hash.clone();
        }

        let overall_status = if first_broken_entry.is_some() {
            ChainStatus::Broken
        } else {
            ChainStatus::Intact
        };

        Ok(VerificationReport {
            total_entries,
            verified_entries,
            first_broken_entry,
            failure_description,
            verification_timestamp: Utc::now(),
            overall_status,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::AuditLogWriter;
    use oracle_core::types::{AuditOperationType, AuditResult};
    use serde_json::json;
    use tempfile::TempDir;

    fn temp_writer() -> (AuditLogWriter, TempDir) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("audit.db");
        let writer = AuditLogWriter::new(&db_path).unwrap();
        (writer, dir)
    }

    #[test]
    fn test_verify_chain_on_empty_log() {
        let (writer, _dir) = temp_writer();
        let verifier = AuditLogVerifier::new(writer.connection());
        verifier.verify_chain().unwrap();
    }

    #[test]
    fn test_verify_chain_intact_after_writes() {
        let (mut writer, _dir) = temp_writer();
        for i in 0..20 {
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

        let verifier = AuditLogVerifier::new(writer.connection());
        verifier.verify_chain().unwrap();
    }

    #[test]
    fn test_verify_full_produces_intact_report() {
        let (mut writer, _dir) = temp_writer();
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

        let verifier = AuditLogVerifier::new(writer.connection());
        let report = verifier.verify_full().unwrap();

        assert_eq!(report.total_entries, 10);
        assert_eq!(report.verified_entries, 10);
        assert_eq!(report.overall_status, ChainStatus::Intact);
        assert!(report.first_broken_entry.is_none());
    }

    #[test]
    fn test_tamper_middle_entry_breaks_chain() {
        let (mut writer, _dir) = temp_writer();
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

        // Tamper with entry at index 5 by changing its actor field.
        writer
            .connection()
            .execute(
                "UPDATE audit_entries SET actor = 'TAMPERED' WHERE entry_index = 5",
                [],
            )
            .unwrap();

        let verifier = AuditLogVerifier::new(writer.connection());
        let result = verifier.verify_chain();
        assert!(result.is_err());

        match result.unwrap_err() {
            OracleError::AuditChainBroken { entry_index, .. } => {
                assert_eq!(entry_index, 5, "Chain should break at the tampered entry");
            }
            other => panic!("Expected AuditChainBroken, got: {:?}", other),
        }
    }

    #[test]
    fn test_delete_entry_breaks_chain() {
        let (mut writer, _dir) = temp_writer();
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

        // Delete entry at index 3.
        writer
            .connection()
            .execute(
                "DELETE FROM audit_entries WHERE entry_index = 3",
                [],
            )
            .unwrap();

        let verifier = AuditLogVerifier::new(writer.connection());
        let report = verifier.verify_full().unwrap();

        assert_eq!(report.overall_status, ChainStatus::Broken);
        // The chain breaks at entry 4 because entry 4's previous_hash references
        // entry 3 which no longer exists, so entry 4's previous_hash won't
        // match the hash of entry 2 (which is now the preceding entry).
        assert_eq!(report.first_broken_entry, Some(4));
    }

    #[test]
    fn test_verify_full_report_broken_has_description() {
        let (mut writer, _dir) = temp_writer();
        for i in 0..5 {
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

        // Tamper.
        writer
            .connection()
            .execute(
                "UPDATE audit_entries SET subject = 'EVIL' WHERE entry_index = 2",
                [],
            )
            .unwrap();

        let verifier = AuditLogVerifier::new(writer.connection());
        let report = verifier.verify_full().unwrap();

        assert_eq!(report.overall_status, ChainStatus::Broken);
        assert!(report.failure_description.is_some());
        assert!(
            report
                .failure_description
                .as_ref()
                .unwrap()
                .contains("hash mismatch")
        );
    }
}
