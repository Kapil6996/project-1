//! # Audit Log Writer
//!
//! Provides the [`AuditLogWriter`] which appends cryptographically chained
//! entries to a SQLite database.
//!
//! ## Write-Before-Execute Protocol
//!
//! Every auditable operation follows this sequence:
//!
//! 1. **`log_intent()`** — record the *intent* to perform the operation with
//!    `result = Pending`. If this write fails the operation **must not**
//!    proceed.
//! 2. **Execute** the operation.
//! 3. **`log_result()`** — record the outcome by appending a *new* entry that
//!    references the intent entry's index. The original row is **never**
//!    mutated (append-only guarantee).
//!
//! ## Crash Recovery
//!
//! On startup the writer calls [`AuditLogWriter::recover_incomplete()`] to
//! detect any `Pending` entries without a matching completion and records a
//! [`AuditOperationType::SystemCrashRecovery`] entry for each one.

use std::path::Path;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde_json::json;
use tracing::{debug, info, warn};
use uuid::Uuid;

use oracle_core::error::{OracleError, OracleResult};
use oracle_core::types::{AuditOperationType, AuditResult, InvestigationId};
use oracle_core::ForensicHash;

use crate::entry::AuditEntry;

// ──────────────────────────────────────────────────────────────────────────────
// Schema
// ──────────────────────────────────────────────────────────────────────────────

/// The SQL DDL executed exactly once when the database is first created.
const CREATE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS audit_entries (
    entry_id        TEXT    NOT NULL PRIMARY KEY,
    entry_index     INTEGER NOT NULL UNIQUE,
    timestamp       TEXT    NOT NULL,
    investigation_id TEXT,
    operation       TEXT    NOT NULL,
    actor           TEXT    NOT NULL,
    subject         TEXT    NOT NULL,
    details         TEXT    NOT NULL,
    result          TEXT    NOT NULL,
    previous_hash   TEXT    NOT NULL,
    entry_hash      TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_entry_index ON audit_entries (entry_index);
CREATE INDEX IF NOT EXISTS idx_audit_investigation ON audit_entries (investigation_id);
CREATE INDEX IF NOT EXISTS idx_audit_operation ON audit_entries (operation);
"#;

// ──────────────────────────────────────────────────────────────────────────────
// Writer
// ──────────────────────────────────────────────────────────────────────────────

/// Append-only audit log writer backed by SQLite in WAL mode.
///
/// # Thread Safety
///
/// `AuditLogWriter` holds a mutable SQLite connection and is therefore
/// `!Sync`. In a multi-threaded context, wrap it in a `Mutex`.
pub struct AuditLogWriter {
    /// The SQLite connection to the audit database.
    conn: Connection,
    /// Hex-encoded SHA-256 hash of the most recently appended entry.
    /// Used as the `previous_hash` for the next entry.
    last_hash: String,
    /// The index of the most recently appended entry.
    /// The next entry will have `next_index + 1`.
    next_index: u64,
}

impl AuditLogWriter {
    /// Open (or create) the audit log database at the given path.
    ///
    /// On first run the schema is created. On subsequent runs the writer
    /// reads the last entry to initialize the hash chain state and then
    /// runs crash recovery.
    ///
    /// # Errors
    ///
    /// Returns [`OracleError::DatabaseError`] if the SQLite database cannot
    /// be opened or the schema cannot be applied.
    pub fn new(db_path: &Path) -> OracleResult<Self> {
        let conn = Connection::open(db_path).map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to open audit database at {}: {}", db_path.display(), e),
        })?;

        // Enable WAL mode for better concurrent read performance.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to set WAL mode: {}", e),
            })?;

        // Foreign keys on for referential integrity.
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to enable foreign keys: {}", e),
            })?;

        // Create schema if first run.
        conn.execute_batch(CREATE_SCHEMA)
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to create audit schema: {}", e),
            })?;

        // Recover chain state from existing entries.
        let (last_hash, next_index) = Self::read_chain_head(&conn)?;

        debug!(
            next_index = next_index,
            last_hash = %last_hash,
            "Audit log writer initialized"
        );

        let mut writer = Self {
            conn,
            last_hash,
            next_index,
        };

        // Recover any incomplete (Pending) entries from a prior crash.
        writer.recover_incomplete()?;

        Ok(writer)
    }

    /// Read the last entry's hash and determine the next index.
    ///
    /// If the database is empty, returns the genesis hash and index 0.
    fn read_chain_head(conn: &Connection) -> OracleResult<(String, u64)> {
        let row: Option<(String, u64)> = conn
            .query_row(
                "SELECT entry_hash, entry_index FROM audit_entries ORDER BY entry_index DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to read chain head: {}", e),
            })?;

        match row {
            Some((hash, index)) => Ok((hash, index + 1)),
            None => Ok((ForensicHash::GENESIS.to_hex(), 0)),
        }
    }

    /// Record the *intent* to perform an operation (write-before-execute).
    ///
    /// The entry is stored with `result = Pending`. If this method returns
    /// an error, the caller **must not** proceed with the operation.
    ///
    /// Returns the `entry_index` of the written intent entry.
    ///
    /// # Errors
    ///
    /// Returns [`OracleError::AuditWriteFailed`] if the entry cannot be
    /// persisted.
    pub fn log_intent(
        &mut self,
        investigation_id: Option<InvestigationId>,
        operation: AuditOperationType,
        actor: &str,
        subject: &str,
        details: serde_json::Value,
    ) -> OracleResult<u64> {
        let entry = AuditEntry::new(
            self.next_index,
            investigation_id,
            operation,
            actor.to_string(),
            subject.to_string(),
            details,
            AuditResult::Pending,
            self.last_hash.clone(),
        )?;

        let index = entry.entry_index;
        self.append_entry_inner(&entry)?;

        info!(
            entry_index = index,
            operation = ?entry.operation,
            actor = %actor,
            "Audit intent logged"
        );

        Ok(index)
    }

    /// Record the *result* of a previously logged intent.
    ///
    /// This appends a **new** entry referencing the intent entry. The
    /// original intent row is never modified (append-only guarantee).
    ///
    /// # Arguments
    ///
    /// * `intent_index` — The `entry_index` returned by [`log_intent()`].
    /// * `result` — The outcome of the operation.
    /// * `result_details` — Additional structured metadata about the outcome.
    ///
    /// # Errors
    ///
    /// Returns [`OracleError::AuditWriteFailed`] if the entry cannot be
    /// persisted, or if the referenced intent entry does not exist.
    pub fn log_result(
        &mut self,
        intent_index: u64,
        result: AuditResult,
        result_details: serde_json::Value,
    ) -> OracleResult<u64> {
        // Read the original intent entry to copy its metadata.
        let intent = self.read_entry_by_index(intent_index)?;

        let details = json!({
            "intent_entry_index": intent_index,
            "intent_entry_id": intent.entry_id.to_string(),
            "result_details": result_details,
        });

        let entry = AuditEntry::new(
            self.next_index,
            intent.investigation_id,
            intent.operation.clone(),
            intent.actor.clone(),
            intent.subject.clone(),
            details,
            result,
            self.last_hash.clone(),
        )?;

        let index = entry.entry_index;
        self.append_entry_inner(&entry)?;

        info!(
            entry_index = index,
            intent_index = intent_index,
            result = ?entry.result,
            "Audit result logged"
        );

        Ok(index)
    }

    /// Append a fully formed entry to the database within a transaction.
    ///
    /// Updates `last_hash` and `next_index` only after the transaction
    /// commits successfully.
    fn append_entry_inner(&mut self, entry: &AuditEntry) -> OracleResult<()> {
        let tx = self.conn.transaction().map_err(|e| OracleError::AuditWriteFailed {
            reason: format!("Failed to begin transaction: {}", e),
        })?;

        Self::insert_entry(&tx, entry)?;

        tx.commit().map_err(|e| OracleError::AuditWriteFailed {
            reason: format!("Failed to commit audit entry: {}", e),
        })?;

        self.last_hash = entry.entry_hash.clone();
        self.next_index = entry.entry_index + 1;

        Ok(())
    }

    /// Insert a single entry row inside an existing transaction.
    fn insert_entry(tx: &Transaction<'_>, entry: &AuditEntry) -> OracleResult<()> {
        let investigation_id_str = entry
            .investigation_id
            .as_ref()
            .map(|id| id.0.to_string());

        let operation_json = serde_json::to_string(&entry.operation)?;
        let result_json = serde_json::to_string(&entry.result)?;
        let details_json = serde_json::to_string(&entry.details)?;
        let timestamp_str = entry.timestamp.to_rfc3339();

        tx.execute(
            "INSERT INTO audit_entries (
                entry_id, entry_index, timestamp, investigation_id,
                operation, actor, subject, details, result,
                previous_hash, entry_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                entry.entry_id.to_string(),
                entry.entry_index,
                timestamp_str,
                investigation_id_str,
                operation_json,
                entry.actor,
                entry.subject,
                details_json,
                result_json,
                entry.previous_hash,
                entry.entry_hash,
            ],
        )
        .map_err(|e| OracleError::AuditWriteFailed {
            reason: format!("Failed to insert audit entry at index {}: {}", entry.entry_index, e),
        })?;

        Ok(())
    }

    /// Detect entries with `result = Pending` that have no corresponding
    /// completion entry, and record a `SystemCrashRecovery` entry for each.
    ///
    /// This is called automatically during [`AuditLogWriter::new()`].
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be queried or the recovery
    /// entries cannot be written.
    pub fn recover_incomplete(&mut self) -> OracleResult<()> {
        let incomplete_indices = self.find_incomplete_entries()?;

        if incomplete_indices.is_empty() {
            debug!("No incomplete audit entries found — clean startup");
            return Ok(());
        }

        warn!(
            count = incomplete_indices.len(),
            "Incomplete audit entries detected — recording crash recovery"
        );

        for intent_index in incomplete_indices {
            let intent = self.read_entry_by_index(intent_index)?;

            let details = json!({
                "recovered_intent_index": intent_index,
                "recovered_intent_id": intent.entry_id.to_string(),
                "recovered_operation": serde_json::to_string(&intent.operation)
                    .unwrap_or_else(|_| "unknown".to_string()),
                "recovery_reason": "Process crash detected — intent entry has no corresponding result entry",
            });

            let recovery_entry = AuditEntry::new(
                self.next_index,
                intent.investigation_id,
                AuditOperationType::SystemCrashRecovery,
                "SYSTEM".to_string(),
                format!("Crash recovery for intent entry {}", intent_index),
                details,
                AuditResult::Success,
                self.last_hash.clone(),
            )?;

            self.append_entry_inner(&recovery_entry)?;

            info!(
                recovered_index = intent_index,
                "Crash recovery entry written"
            );
        }

        Ok(())
    }

    /// Find all entries whose `result` is `Pending` and for which no
    /// subsequent entry references them as an `intent_entry_index`.
    fn find_incomplete_entries(&self) -> OracleResult<Vec<u64>> {
        // First, collect all entry indices with Pending result.
        let mut stmt = self
            .conn
            .prepare(
                "SELECT entry_index FROM audit_entries WHERE result = '\"Pending\"' ORDER BY entry_index ASC",
            )
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to prepare incomplete entries query: {}", e),
            })?;

        let pending_indices: Vec<u64> = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to query pending entries: {}", e),
            })?
            .filter_map(|r| r.ok())
            .collect();

        if pending_indices.is_empty() {
            return Ok(Vec::new());
        }

        // For each pending entry, check if any later entry references it
        // in its details JSON as `intent_entry_index`.
        let mut incomplete = Vec::new();
        for idx in pending_indices {
            let has_completion: bool = self
                .conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM audit_entries WHERE entry_index > ?1 AND details LIKE ?2",
                    params![idx, format!("%\"intent_entry_index\":{}%", idx)],
                    |row| row.get(0),
                )
                .map_err(|e| OracleError::DatabaseError {
                    reason: format!("Failed to check completion for entry {}: {}", idx, e),
                })?;

            // Also check for crash recovery entries that reference this intent.
            let has_recovery: bool = self
                .conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM audit_entries WHERE entry_index > ?1 AND details LIKE ?2",
                    params![idx, format!("%\"recovered_intent_index\":{}%", idx)],
                    |row| row.get(0),
                )
                .map_err(|e| OracleError::DatabaseError {
                    reason: format!("Failed to check recovery for entry {}: {}", idx, e),
                })?;

            if !has_completion && !has_recovery {
                incomplete.push(idx);
            }
        }

        Ok(incomplete)
    }

    /// Read a single entry by its index.
    ///
    /// # Errors
    ///
    /// Returns [`OracleError::AuditWriteFailed`] if the entry does not exist.
    fn read_entry_by_index(&self, index: u64) -> OracleResult<AuditEntry> {
        read_entry_by_index_from_conn(&self.conn, index)
    }

    /// Read all entries from the database, ordered by `entry_index`.
    ///
    /// This is used by the verifier and export modules.
    pub fn read_all_entries(&self) -> OracleResult<Vec<AuditEntry>> {
        read_all_entries_from_conn(&self.conn)
    }

    /// Return a reference to the underlying SQLite connection.
    ///
    /// This is exposed for the verifier and export modules to perform
    /// read-only queries without requiring mutable access to the writer.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Return the current chain head hash.
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    /// Return the next entry index that will be assigned.
    pub fn next_index(&self) -> u64 {
        self.next_index
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Free functions for reading entries from a connection (used by verifier, etc.)
// ──────────────────────────────────────────────────────────────────────────────

/// Read a single entry by its `entry_index` from the given connection.
///
/// # Errors
///
/// Returns [`OracleError::AuditWriteFailed`] if the entry does not exist.
pub(crate) fn read_entry_by_index_from_conn(
    conn: &Connection,
    index: u64,
) -> OracleResult<AuditEntry> {
    conn.query_row(
        "SELECT entry_id, entry_index, timestamp, investigation_id,
                operation, actor, subject, details, result,
                previous_hash, entry_hash
         FROM audit_entries WHERE entry_index = ?1",
        params![index],
        |row| row_to_entry(row),
    )
    .map_err(|e| OracleError::AuditWriteFailed {
        reason: format!("Audit entry at index {} not found: {}", index, e),
    })
}

/// Read all entries ordered by `entry_index` from the given connection.
pub(crate) fn read_all_entries_from_conn(conn: &Connection) -> OracleResult<Vec<AuditEntry>> {
    let mut stmt = conn
        .prepare(
            "SELECT entry_id, entry_index, timestamp, investigation_id,
                    operation, actor, subject, details, result,
                    previous_hash, entry_hash
             FROM audit_entries ORDER BY entry_index ASC",
        )
        .map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to prepare read_all query: {}", e),
        })?;

    let entries = stmt
        .query_map([], |row| row_to_entry(row))
        .map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to execute read_all query: {}", e),
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to read audit entries: {}", e),
        })?;

    Ok(entries)
}

/// Convert a rusqlite `Row` into an `AuditEntry`.
fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
    let entry_id_str: String = row.get(0)?;
    let entry_index: u64 = row.get(1)?;
    let timestamp_str: String = row.get(2)?;
    let investigation_id_str: Option<String> = row.get(3)?;
    let operation_str: String = row.get(4)?;
    let actor: String = row.get(5)?;
    let subject: String = row.get(6)?;
    let details_str: String = row.get(7)?;
    let result_str: String = row.get(8)?;
    let previous_hash: String = row.get(9)?;
    let entry_hash: String = row.get(10)?;

    let entry_id = Uuid::parse_str(&entry_id_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?;

    let timestamp: DateTime<Utc> = DateTime::parse_from_rfc3339(&timestamp_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e)))?;

    let investigation_id = investigation_id_str
        .map(|s| {
            Uuid::parse_str(&s).map(InvestigationId).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
            })
        })
        .transpose()?;

    let operation: AuditOperationType = serde_json::from_str(&operation_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e)))?;

    let details: serde_json::Value = serde_json::from_str(&details_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e)))?;

    let result: AuditResult = serde_json::from_str(&result_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(e)))?;

    Ok(AuditEntry {
        entry_id,
        entry_index,
        timestamp,
        investigation_id,
        operation,
        actor,
        subject,
        details,
        result,
        previous_hash,
        entry_hash,
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    /// Create a writer backed by a temp directory.
    fn temp_writer() -> (AuditLogWriter, TempDir) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("audit.db");
        let writer = AuditLogWriter::new(&db_path).unwrap();
        (writer, dir)
    }

    #[test]
    fn test_new_writer_starts_at_index_zero() {
        let (writer, _dir) = temp_writer();
        assert_eq!(writer.next_index(), 0);
        assert_eq!(writer.last_hash(), ForensicHash::GENESIS.to_hex());
    }

    #[test]
    fn test_log_intent_and_result() {
        let (mut writer, _dir) = temp_writer();

        let intent_idx = writer
            .log_intent(
                None,
                AuditOperationType::InvestigationCreated,
                "Examiner A",
                "Case #1",
                json!({"case": 1}),
            )
            .unwrap();

        assert_eq!(intent_idx, 0);
        assert_eq!(writer.next_index(), 1);

        let result_idx = writer
            .log_result(intent_idx, AuditResult::Success, json!({"duration_ms": 42}))
            .unwrap();

        assert_eq!(result_idx, 1);
        assert_eq!(writer.next_index(), 2);
    }

    #[test]
    fn test_hash_chain_valid_after_100_entries() {
        let (mut writer, _dir) = temp_writer();

        for i in 0..100 {
            writer
                .log_intent(
                    None,
                    AuditOperationType::ExaminerNoteAdded,
                    "Examiner B",
                    &format!("Note #{}", i),
                    json!({"note_number": i}),
                )
                .unwrap();
        }

        // Read all entries and verify the chain manually.
        let entries = writer.read_all_entries().unwrap();
        assert_eq!(entries.len(), 100);

        let mut expected_prev = ForensicHash::GENESIS.to_hex();
        for entry in &entries {
            assert_eq!(entry.previous_hash, expected_prev);
            assert!(entry.verify_hash().unwrap(), "Entry {} hash verification failed", entry.entry_index);
            expected_prev = entry.entry_hash.clone();
        }
    }

    #[test]
    fn test_genesis_entry_has_all_zero_previous_hash() {
        let (mut writer, _dir) = temp_writer();

        writer
            .log_intent(
                None,
                AuditOperationType::SystemStartup,
                "SYSTEM",
                "Platform startup",
                json!({}),
            )
            .unwrap();

        let entries = writer.read_all_entries().unwrap();
        assert_eq!(entries[0].previous_hash, ForensicHash::GENESIS.to_hex());
    }

    #[test]
    fn test_writer_resumes_chain_after_reopen() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("audit.db");

        let last_hash;
        let next_index;

        // First session: write some complete entries (intent + result pairs).
        {
            let mut writer = AuditLogWriter::new(&db_path).unwrap();
            let idx1 = writer
                .log_intent(
                    None,
                    AuditOperationType::SystemStartup,
                    "SYSTEM",
                    "Startup",
                    json!({}),
                )
                .unwrap();
            writer
                .log_result(
                    idx1,
                    AuditResult::Success,
                    json!({"message": "Startup complete"}),
                )
                .unwrap();
            let idx2 = writer
                .log_intent(
                    None,
                    AuditOperationType::InvestigationCreated,
                    "Examiner A",
                    "Case #1",
                    json!({}),
                )
                .unwrap();
            writer
                .log_result(
                    idx2,
                    AuditResult::Success,
                    json!({"message": "Case #1 created"}),
                )
                .unwrap();
            last_hash = writer.last_hash().to_string();
            next_index = writer.next_index();
        }

        // Second session: reopen and verify chain continuity.
        {
            let writer = AuditLogWriter::new(&db_path).unwrap();
            assert_eq!(writer.last_hash(), last_hash);
            assert_eq!(writer.next_index(), next_index);
        }
    }

    #[test]
    fn test_crash_recovery_detects_incomplete_entries() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("audit.db");

        // First session: log an intent but NOT a result (simulating a crash).
        {
            let mut writer = AuditLogWriter::new(&db_path).unwrap();
            writer
                .log_intent(
                    None,
                    AuditOperationType::ArtifactAcquisitionStarted,
                    "Examiner A",
                    "Device X",
                    json!({"device": "X"}),
                )
                .unwrap();
            // No log_result() call — simulating crash.
        }

        // Second session: reopen — recover_incomplete should fire.
        {
            let writer = AuditLogWriter::new(&db_path).unwrap();
            let entries = writer.read_all_entries().unwrap();

            // Should have: original intent + recovery entry.
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[1].operation, AuditOperationType::SystemCrashRecovery);
        }
    }

    #[test]
    fn test_append_only_guarantee() {
        let (mut writer, _dir) = temp_writer();

        let intent_idx = writer
            .log_intent(
                None,
                AuditOperationType::InvestigationCreated,
                "Examiner A",
                "Case #1",
                json!({}),
            )
            .unwrap();

        writer
            .log_result(intent_idx, AuditResult::Success, json!({}))
            .unwrap();

        let entries = writer.read_all_entries().unwrap();
        // The intent entry at index 0 still has Pending result.
        assert_eq!(entries[0].result, AuditResult::Pending);
        // The result entry at index 1 has Success.
        assert_eq!(entries[1].result, AuditResult::Success);
    }
}
