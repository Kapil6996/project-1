//! # Evidence Store
//!
//! The primary entry point for the ORACLE Evidence Store subsystem.
//!
//! [`EvidenceStore`] manages the SQLite metadata database and the base
//! evidence directory on the filesystem. It provides factory methods to
//! create a new store ([`initialize`](EvidenceStore::initialize)) or
//! reopen an existing one ([`open`](EvidenceStore::open)).
//!
//! ## Schema
//!
//! The metadata database contains three tables:
//!
//! - **`artifacts`** — Content-addressable artifact metadata including hash,
//!   file size, acquisition method, and the stored filesystem path.
//! - **`parsed_records`** — Parsed evidence records linked to their source
//!   artifact with full provenance (parser ID, version, source reference).
//! - **`normalized_records`** — Normalized evidence records after cleaning
//!   and unification, preserving provenance to their parsed origin.
//!
//! All three tables are append-only: no `UPDATE` or `DELETE` statements are
//! ever executed against them.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use serde_json::json;
use tracing::{debug, info};

use oracle_audit::AuditLogWriter;
use oracle_core::error::{OracleError, OracleResult};
use oracle_core::types::{AuditOperationType, AuditResult};

// ──────────────────────────────────────────────────────────────────────────────
// Schema DDL
// ──────────────────────────────────────────────────────────────────────────────

/// SQL DDL for the evidence store metadata database.
///
/// Executed exactly once when the store is first created via
/// [`EvidenceStore::initialize`].
const CREATE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id         TEXT    NOT NULL PRIMARY KEY,
    investigation_id    TEXT    NOT NULL,
    artifact_class      TEXT    NOT NULL,
    original_path       TEXT    NOT NULL,
    acquisition_method  TEXT    NOT NULL,
    sha256_hash         TEXT    NOT NULL,
    file_size           INTEGER NOT NULL,
    stored_path         TEXT    NOT NULL,
    acquired_at         TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_investigation
    ON artifacts (investigation_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_hash
    ON artifacts (sha256_hash);
CREATE INDEX IF NOT EXISTS idx_artifacts_class
    ON artifacts (artifact_class);

CREATE TABLE IF NOT EXISTS parsed_records (
    record_id           TEXT    NOT NULL PRIMARY KEY,
    artifact_id         TEXT    NOT NULL,
    investigation_id    TEXT    NOT NULL,
    parser_id           TEXT    NOT NULL,
    parser_version      TEXT    NOT NULL,
    evidence_layer      TEXT    NOT NULL,
    record_type         TEXT    NOT NULL,
    record_data_json    TEXT    NOT NULL,
    source_ref_json     TEXT    NOT NULL,
    created_at          TEXT    NOT NULL,
    FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id)
);

CREATE INDEX IF NOT EXISTS idx_parsed_artifact
    ON parsed_records (artifact_id);
CREATE INDEX IF NOT EXISTS idx_parsed_investigation
    ON parsed_records (investigation_id);
CREATE INDEX IF NOT EXISTS idx_parsed_type
    ON parsed_records (record_type);

CREATE TABLE IF NOT EXISTS normalized_records (
    record_id           TEXT    NOT NULL PRIMARY KEY,
    artifact_id         TEXT    NOT NULL,
    investigation_id    TEXT    NOT NULL,
    parser_id           TEXT    NOT NULL,
    parser_version      TEXT    NOT NULL,
    evidence_layer      TEXT    NOT NULL,
    record_type         TEXT    NOT NULL,
    record_data_json    TEXT    NOT NULL,
    source_ref_json     TEXT    NOT NULL,
    created_at          TEXT    NOT NULL,
    FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id)
);

CREATE INDEX IF NOT EXISTS idx_normalized_artifact
    ON normalized_records (artifact_id);
CREATE INDEX IF NOT EXISTS idx_normalized_investigation
    ON normalized_records (investigation_id);
CREATE INDEX IF NOT EXISTS idx_normalized_type
    ON normalized_records (record_type);
"#;

/// The filename of the SQLite metadata database within the evidence store directory.
const METADATA_DB_FILENAME: &str = "evidence_metadata.db";

/// The subdirectory within the evidence store that holds the CAS blobs.
pub const CAS_SUBDIR: &str = "cas";

// ──────────────────────────────────────────────────────────────────────────────
// EvidenceStore
// ──────────────────────────────────────────────────────────────────────────────

/// The ORACLE Evidence Store.
///
/// Manages the SQLite metadata database and the base evidence directory.
/// All write operations are append-only and audit-logged.
///
/// # Thread Safety
///
/// The internal SQLite connection is wrapped in an `Arc<Mutex<Connection>>`
/// so that multiple modules (CAS, Records, Integrity) can share it safely.
pub struct EvidenceStore {
    /// The SQLite connection, shared across sub-modules.
    pub(crate) conn: Arc<Mutex<Connection>>,
    /// The base directory of the evidence store on the filesystem.
    pub(crate) base_dir: PathBuf,
}

impl EvidenceStore {
    /// Create a new evidence store at the given base directory.
    ///
    /// This method:
    /// 1. Logs intent to the audit writer (write-before-execute).
    /// 2. Creates the directory structure (`base_dir/`, `base_dir/cas/`).
    /// 3. Creates the SQLite metadata database with the full schema.
    /// 4. Logs the result to the audit writer.
    ///
    /// # Errors
    ///
    /// - [`OracleError::IoError`] if the directory cannot be created.
    /// - [`OracleError::DatabaseError`] if the SQLite database cannot be opened.
    /// - [`OracleError::AuditWriteFailed`] if the audit log cannot be written.
    pub fn initialize(
        base_dir: &Path,
        audit_writer: &mut AuditLogWriter,
    ) -> OracleResult<Self> {
        // ── Step 1: Log intent ──
        let intent_idx = audit_writer.log_intent(
            None,
            AuditOperationType::EvidenceStoreCreated,
            "SYSTEM",
            &format!("Evidence store at {}", base_dir.display()),
            json!({
                "base_dir": base_dir.display().to_string(),
                "action": "initialize",
            }),
        )?;

        // ── Step 2: Create directory structure ──
        std::fs::create_dir_all(base_dir).map_err(|e| OracleError::IoError {
            path: base_dir.to_path_buf(),
            source: e,
        })?;

        let cas_dir = base_dir.join(CAS_SUBDIR);
        std::fs::create_dir_all(&cas_dir).map_err(|e| OracleError::IoError {
            path: cas_dir.clone(),
            source: e,
        })?;

        debug!(
            base_dir = %base_dir.display(),
            "Evidence store directory structure created"
        );

        // ── Step 3: Create metadata database ──
        let db_path = base_dir.join(METADATA_DB_FILENAME);
        let conn = Self::open_connection(&db_path)?;

        conn.execute_batch(CREATE_SCHEMA)
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to create evidence schema: {}", e),
            })?;

        info!(
            db_path = %db_path.display(),
            "Evidence metadata database created"
        );

        // ── Step 4: Log result ──
        audit_writer.log_result(
            intent_idx,
            AuditResult::Success,
            json!({
                "db_path": db_path.display().to_string(),
                "cas_dir": cas_dir.display().to_string(),
            }),
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            base_dir: base_dir.to_path_buf(),
        })
    }

    /// Open an existing evidence store at the given base directory.
    ///
    /// Verifies that the metadata database exists and contains the expected
    /// schema tables (`artifacts`, `parsed_records`, `normalized_records`).
    ///
    /// # Errors
    ///
    /// - [`OracleError::EvidenceStoreCorrupted`] if the base directory or
    ///   metadata database does not exist, or if the schema is missing.
    /// - [`OracleError::DatabaseError`] if the database cannot be opened.
    pub fn open(base_dir: &Path) -> OracleResult<Self> {
        // Verify the base directory exists.
        if !base_dir.exists() {
            return Err(OracleError::EvidenceStoreCorrupted {
                reason: format!(
                    "Evidence store base directory does not exist: {}",
                    base_dir.display()
                ),
            });
        }

        // Verify the CAS subdirectory exists.
        let cas_dir = base_dir.join(CAS_SUBDIR);
        if !cas_dir.exists() {
            return Err(OracleError::EvidenceStoreCorrupted {
                reason: format!(
                    "CAS subdirectory does not exist: {}",
                    cas_dir.display()
                ),
            });
        }

        // Open the metadata database.
        let db_path = base_dir.join(METADATA_DB_FILENAME);
        if !db_path.exists() {
            return Err(OracleError::EvidenceStoreCorrupted {
                reason: format!(
                    "Metadata database does not exist: {}",
                    db_path.display()
                ),
            });
        }

        let conn = Self::open_connection(&db_path)?;

        // Verify the schema tables exist.
        Self::verify_schema(&conn)?;

        info!(
            base_dir = %base_dir.display(),
            "Evidence store opened"
        );

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            base_dir: base_dir.to_path_buf(),
        })
    }

    /// Open a SQLite connection with WAL mode and foreign key enforcement.
    fn open_connection(db_path: &Path) -> OracleResult<Connection> {
        let conn = Connection::open(db_path).map_err(|e| OracleError::DatabaseError {
            reason: format!(
                "Failed to open evidence database at {}: {}",
                db_path.display(),
                e
            ),
        })?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to set WAL mode: {}", e),
            })?;

        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to enable foreign keys: {}", e),
            })?;

        Ok(conn)
    }

    /// Verify that all required schema tables exist in the database.
    fn verify_schema(conn: &Connection) -> OracleResult<()> {
        let required_tables = ["artifacts", "parsed_records", "normalized_records"];

        for table_name in &required_tables {
            let exists: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name=?1",
                    rusqlite::params![table_name],
                    |row| row.get(0),
                )
                .map_err(|e| OracleError::DatabaseError {
                    reason: format!("Failed to check for table '{}': {}", table_name, e),
                })?;

            if !exists {
                return Err(OracleError::EvidenceStoreCorrupted {
                    reason: format!("Required table '{}' is missing from the schema", table_name),
                });
            }
        }

        Ok(())
    }

    /// Returns the base directory path of this evidence store.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Returns the path to the CAS subdirectory.
    pub fn cas_dir(&self) -> PathBuf {
        self.base_dir.join(CAS_SUBDIR)
    }

    /// Returns a clone of the shared database connection.
    pub(crate) fn conn(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Create an audit writer backed by a temp directory.
    fn temp_audit_writer(dir: &Path) -> AuditLogWriter {
        let db_path = dir.join("audit.db");
        AuditLogWriter::new(&db_path).unwrap()
    }

    #[test]
    fn test_initialize_creates_directory_structure() {
        let dir = TempDir::new().unwrap();
        let evidence_dir = dir.path().join("evidence");
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        let mut audit = temp_audit_writer(&audit_dir);

        let store = EvidenceStore::initialize(&evidence_dir, &mut audit).unwrap();

        assert!(evidence_dir.exists());
        assert!(evidence_dir.join(CAS_SUBDIR).exists());
        assert!(evidence_dir.join(METADATA_DB_FILENAME).exists());
        assert_eq!(store.base_dir(), evidence_dir);
    }

    #[test]
    fn test_open_existing_store() {
        let dir = TempDir::new().unwrap();
        let evidence_dir = dir.path().join("evidence");
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        let mut audit = temp_audit_writer(&audit_dir);

        // Initialize first.
        let _store = EvidenceStore::initialize(&evidence_dir, &mut audit).unwrap();

        // Reopen.
        let store = EvidenceStore::open(&evidence_dir).unwrap();
        assert_eq!(store.base_dir(), evidence_dir);
    }

    #[test]
    fn test_open_nonexistent_returns_error() {
        let result = EvidenceStore::open(Path::new("/tmp/nonexistent_evidence_store_12345"));
        assert!(result.is_err());
    }

    #[test]
    fn test_open_missing_schema_returns_error() {
        let dir = TempDir::new().unwrap();
        let evidence_dir = dir.path().join("evidence");

        // Create the directory structure but NOT the schema.
        std::fs::create_dir_all(evidence_dir.join(CAS_SUBDIR)).unwrap();
        let db_path = evidence_dir.join(METADATA_DB_FILENAME);
        let _conn = Connection::open(&db_path).unwrap();

        let result = EvidenceStore::open(&evidence_dir);
        assert!(result.is_err());
    }
}
