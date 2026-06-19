//! # Content-Addressable Storage (CAS)
//!
//! Stores forensic artifacts on the filesystem, keyed by their SHA-256 hash.
//!
//! ## Storage Layout
//!
//! Artifacts are written to a sharded directory structure to avoid
//! filesystem performance issues with flat directories:
//!
//! ```text
//! cas/
//!   ab/
//!     cd/
//!       abcdef0123456789...  (full 64-char hex filename)
//! ```
//!
//! The first two hex characters form the first directory level, the next
//! two form the second, and the full hash is the filename.
//!
//! ## Append-Only Guarantee
//!
//! Once an artifact is stored, it cannot be updated or deleted through
//! this API. Any attempt to modify an existing artifact returns
//! [`OracleError::EvidenceModificationAttempt`].
//!
//! ## Deduplication
//!
//! If an artifact with the same SHA-256 hash already exists, the store
//! returns the existing [`ArtifactId`] without writing duplicate bytes.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::json;
use tracing::{debug, info, warn};
use uuid::Uuid;

use oracle_core::error::{OracleError, OracleResult};
use oracle_core::types::{AcquisitionMethod, ArtifactClass, ArtifactId, InvestigationId};
use oracle_core::ForensicHash;

use crate::store::EvidenceStore;

// ──────────────────────────────────────────────────────────────────────────────
// ContentAddressableStore
// ──────────────────────────────────────────────────────────────────────────────

/// Content-addressable artifact storage backed by the filesystem and SQLite.
///
/// This struct borrows the shared database connection and CAS directory
/// from the parent [`EvidenceStore`].
pub struct ContentAddressableStore {
    /// Shared SQLite connection for metadata operations.
    conn: Arc<Mutex<Connection>>,
    /// Root directory for CAS blobs.
    cas_dir: PathBuf,
}

impl ContentAddressableStore {
    /// Create a new CAS handle from an existing [`EvidenceStore`].
    pub fn new(store: &EvidenceStore) -> Self {
        Self {
            conn: store.conn(),
            cas_dir: store.cas_dir(),
        }
    }

    /// Store a forensic artifact in the content-addressable store.
    ///
    /// Computes the SHA-256 hash of the raw bytes, stores the bytes in the
    /// hash-based directory structure, and records metadata in SQLite.
    ///
    /// If an artifact with the same hash already exists (deduplication),
    /// the existing [`ArtifactId`] is returned without writing duplicate bytes.
    ///
    /// # Arguments
    ///
    /// * `investigation_id` — The investigation this artifact belongs to.
    /// * `artifact_class` — Classification of the forensic artifact.
    /// * `original_path` — The original path on the source device.
    /// * `raw_bytes` — The raw artifact content.
    /// * `acquisition_method` — How this artifact was acquired.
    ///
    /// # Returns
    ///
    /// The [`ArtifactId`] assigned to this artifact (new or existing).
    ///
    /// # Errors
    ///
    /// - [`OracleError::IoError`] if the file cannot be written.
    /// - [`OracleError::DatabaseError`] if the metadata cannot be inserted.
    pub fn store_artifact(
        &self,
        investigation_id: InvestigationId,
        artifact_class: ArtifactClass,
        original_path: &str,
        raw_bytes: &[u8],
        acquisition_method: AcquisitionMethod,
    ) -> OracleResult<ArtifactId> {
        // Compute SHA-256 hash using ForensicHash.
        let hash = ForensicHash::from_bytes(raw_bytes);
        let hash_hex = hash.to_hex();

        // Check for deduplication: if an artifact with this hash already exists,
        // return the existing ArtifactId.
        if let Some(existing_id) = self.find_artifact_by_hash(&hash_hex)? {
            info!(
                hash = %hash_hex,
                artifact_id = %existing_id,
                "Artifact already exists (deduplication) — returning existing ID"
            );
            return Ok(existing_id);
        }

        // Compute the stored path on the filesystem.
        let stored_path = self.hash_to_path(&hash_hex);

        // Create the parent directories.
        if let Some(parent) = stored_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| OracleError::IoError {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        // Write the raw bytes to the filesystem.
        std::fs::write(&stored_path, raw_bytes).map_err(|e| OracleError::IoError {
            path: stored_path.clone(),
            source: e,
        })?;

        debug!(
            hash = %hash_hex,
            stored_path = %stored_path.display(),
            size = raw_bytes.len(),
            "Artifact written to CAS"
        );

        // Generate a new ArtifactId and insert metadata.
        let artifact_id = ArtifactId::new();
        let now = Utc::now();

        let artifact_class_json = serde_json::to_string(&artifact_class)?;
        let acquisition_method_json = serde_json::to_string(&acquisition_method)?;

        let conn = self.conn.lock().map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to acquire database lock: {}", e),
        })?;

        conn.execute(
            "INSERT INTO artifacts (
                artifact_id, investigation_id, artifact_class, original_path,
                acquisition_method, sha256_hash, file_size, stored_path, acquired_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                artifact_id.0.to_string(),
                investigation_id.0.to_string(),
                artifact_class_json,
                original_path,
                acquisition_method_json,
                hash_hex,
                raw_bytes.len() as i64,
                stored_path.display().to_string(),
                now.to_rfc3339(),
            ],
        )
        .map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to insert artifact metadata: {}", e),
        })?;

        info!(
            artifact_id = %artifact_id,
            hash = %hash_hex,
            investigation_id = %investigation_id,
            "Artifact stored successfully"
        );

        Ok(artifact_id)
    }

    /// Retrieve the raw bytes of a stored artifact and verify its hash integrity.
    ///
    /// Re-reads the stored file, recomputes the SHA-256 hash, and compares
    /// it with the hash recorded at ingestion time. If the hashes differ,
    /// returns [`OracleError::EvidenceHashMismatch`].
    ///
    /// # Arguments
    ///
    /// * `artifact_id` — The artifact to retrieve.
    ///
    /// # Returns
    ///
    /// The raw bytes of the artifact if integrity is verified.
    ///
    /// # Errors
    ///
    /// - [`OracleError::EvidenceHashMismatch`] if the stored file has been tampered with.
    /// - [`OracleError::DatabaseError`] if the artifact metadata is not found.
    /// - [`OracleError::IoError`] if the stored file cannot be read.
    pub fn retrieve_artifact(&self, artifact_id: ArtifactId) -> OracleResult<Vec<u8>> {
        let (stored_hash, stored_path) = self.get_artifact_metadata(artifact_id)?;

        // Read the raw bytes from the filesystem.
        let raw_bytes = std::fs::read(&stored_path).map_err(|e| OracleError::IoError {
            path: PathBuf::from(&stored_path),
            source: e,
        })?;

        // Verify hash integrity.
        let computed_hash = ForensicHash::from_bytes(&raw_bytes);
        let computed_hex = computed_hash.to_hex();

        if computed_hex != stored_hash {
            warn!(
                artifact_id = %artifact_id,
                stored_hash = %stored_hash,
                computed_hash = %computed_hex,
                "INTEGRITY VIOLATION: artifact hash mismatch"
            );
            return Err(OracleError::EvidenceHashMismatch {
                artifact_id: artifact_id.0,
                stored_hash,
                computed_hash: computed_hex,
            });
        }

        debug!(
            artifact_id = %artifact_id,
            hash = %stored_hash,
            "Artifact retrieved and integrity verified"
        );

        Ok(raw_bytes)
    }

    /// Check if an artifact with the given SHA-256 hash already exists.
    ///
    /// Used for deduplication: if `true`, the caller can skip ingestion
    /// and reuse the existing artifact.
    pub fn artifact_exists(&self, sha256_hash: &str) -> OracleResult<bool> {
        Ok(self.find_artifact_by_hash(sha256_hash)?.is_some())
    }

    /// Attempt to delete an artifact. This is **always** rejected because
    /// the evidence store is append-only.
    ///
    /// # Errors
    ///
    /// Always returns [`OracleError::EvidenceModificationAttempt`].
    pub fn delete_artifact(&self, artifact_id: ArtifactId) -> OracleResult<()> {
        Err(OracleError::EvidenceModificationAttempt {
            record_id: artifact_id.0,
        })
    }

    /// Attempt to update an artifact. This is **always** rejected because
    /// the evidence store is append-only.
    ///
    /// # Errors
    ///
    /// Always returns [`OracleError::EvidenceModificationAttempt`].
    pub fn update_artifact(
        &self,
        artifact_id: ArtifactId,
        _new_bytes: &[u8],
    ) -> OracleResult<()> {
        Err(OracleError::EvidenceModificationAttempt {
            record_id: artifact_id.0,
        })
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Find an artifact by its SHA-256 hash, returning its ArtifactId if found.
    fn find_artifact_by_hash(&self, sha256_hash: &str) -> OracleResult<Option<ArtifactId>> {
        let conn = self.conn.lock().map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to acquire database lock: {}", e),
        })?;

        let result: Option<String> = conn
            .query_row(
                "SELECT artifact_id FROM artifacts WHERE sha256_hash = ?1 LIMIT 1",
                params![sha256_hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to query artifact by hash: {}", e),
            })?;

        match result {
            Some(id_str) => {
                let uuid = Uuid::parse_str(&id_str).map_err(|e| OracleError::DatabaseError {
                    reason: format!("Invalid artifact_id UUID in database: {}", e),
                })?;
                Ok(Some(ArtifactId(uuid)))
            }
            None => Ok(None),
        }
    }

    /// Retrieve the stored hash and filesystem path for an artifact.
    pub(crate) fn get_artifact_metadata(
        &self,
        artifact_id: ArtifactId,
    ) -> OracleResult<(String, String)> {
        let conn = self.conn.lock().map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to acquire database lock: {}", e),
        })?;

        conn.query_row(
            "SELECT sha256_hash, stored_path FROM artifacts WHERE artifact_id = ?1",
            params![artifact_id.0.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|e| OracleError::DatabaseError {
            reason: format!("Artifact {} not found: {}", artifact_id, e),
        })
    }

    /// Compute the filesystem path for a given hash.
    ///
    /// Layout: `cas/<first_2_chars>/<next_2_chars>/<full_hash>`
    fn hash_to_path(&self, hash_hex: &str) -> PathBuf {
        let prefix1 = &hash_hex[..2];
        let prefix2 = &hash_hex[2..4];
        self.cas_dir.join(prefix1).join(prefix2).join(hash_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::EvidenceStore;
    use oracle_audit::AuditLogWriter;
    use tempfile::TempDir;

    /// Helper: create a temp evidence store with audit writer.
    fn setup() -> (EvidenceStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let evidence_dir = dir.path().join("evidence");
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        let mut audit = AuditLogWriter::new(&audit_dir.join("audit.db")).unwrap();
        let store = EvidenceStore::initialize(&evidence_dir, &mut audit).unwrap();
        (store, dir)
    }

    #[test]
    fn test_store_and_retrieve_artifact() {
        let (store, _dir) = setup();
        let cas = ContentAddressableStore::new(&store);

        let investigation_id = InvestigationId::new();
        let raw_bytes = b"test artifact content for CAS";

        let artifact_id = cas
            .store_artifact(
                investigation_id,
                ArtifactClass::WifiConfigStore,
                "/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml",
                raw_bytes,
                AcquisitionMethod::PrivilegedLogical,
            )
            .unwrap();

        // Retrieve and verify.
        let retrieved = cas.retrieve_artifact(artifact_id).unwrap();
        assert_eq!(retrieved, raw_bytes);
    }

    #[test]
    fn test_deduplication_returns_existing_id() {
        let (store, _dir) = setup();
        let cas = ContentAddressableStore::new(&store);

        let investigation_id = InvestigationId::new();
        let raw_bytes = b"duplicate content";

        let id1 = cas
            .store_artifact(
                investigation_id,
                ArtifactClass::WifiConfigStore,
                "/path/a",
                raw_bytes,
                AcquisitionMethod::PrivilegedLogical,
            )
            .unwrap();

        let id2 = cas
            .store_artifact(
                investigation_id,
                ArtifactClass::WifiConfigStore,
                "/path/b",
                raw_bytes,
                AcquisitionMethod::PrivilegedLogical,
            )
            .unwrap();

        // Same hash → same ArtifactId.
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_artifact_exists_check() {
        let (store, _dir) = setup();
        let cas = ContentAddressableStore::new(&store);

        let investigation_id = InvestigationId::new();
        let raw_bytes = b"exists check content";
        let hash = ForensicHash::from_bytes(raw_bytes).to_hex();

        assert!(!cas.artifact_exists(&hash).unwrap());

        cas.store_artifact(
            investigation_id,
            ArtifactClass::DhcpLeases,
            "/path/c",
            raw_bytes,
            AcquisitionMethod::AdbBackup,
        )
        .unwrap();

        assert!(cas.artifact_exists(&hash).unwrap());
    }

    #[test]
    fn test_delete_rejected() {
        let (store, _dir) = setup();
        let cas = ContentAddressableStore::new(&store);

        let investigation_id = InvestigationId::new();
        let artifact_id = cas
            .store_artifact(
                investigation_id,
                ArtifactClass::KernelLogs,
                "/path/d",
                b"undeletable",
                AcquisitionMethod::PrivilegedLogical,
            )
            .unwrap();

        let result = cas.delete_artifact(artifact_id);
        assert!(result.is_err());
        match result {
            Err(OracleError::EvidenceModificationAttempt { .. }) => {} // expected
            other => panic!("Expected EvidenceModificationAttempt, got: {:?}", other),
        }
    }

    #[test]
    fn test_update_rejected() {
        let (store, _dir) = setup();
        let cas = ContentAddressableStore::new(&store);

        let investigation_id = InvestigationId::new();
        let artifact_id = cas
            .store_artifact(
                investigation_id,
                ArtifactClass::KernelLogs,
                "/path/e",
                b"original",
                AcquisitionMethod::PrivilegedLogical,
            )
            .unwrap();

        let result = cas.update_artifact(artifact_id, b"modified");
        assert!(result.is_err());
        match result {
            Err(OracleError::EvidenceModificationAttempt { .. }) => {} // expected
            other => panic!("Expected EvidenceModificationAttempt, got: {:?}", other),
        }
    }

    #[test]
    fn test_tampered_artifact_detected_on_retrieve() {
        let (store, dir) = setup();
        let cas = ContentAddressableStore::new(&store);

        let investigation_id = InvestigationId::new();
        let raw_bytes = b"original evidence content";

        let artifact_id = cas
            .store_artifact(
                investigation_id,
                ArtifactClass::ConnectivityLogs,
                "/path/f",
                raw_bytes,
                AcquisitionMethod::PrivilegedLogical,
            )
            .unwrap();

        // Tamper with the stored file on disk.
        let (_, stored_path) = cas.get_artifact_metadata(artifact_id).unwrap();
        std::fs::write(&stored_path, b"TAMPERED DATA").unwrap();

        // Retrieval should detect the mismatch.
        let result = cas.retrieve_artifact(artifact_id);
        assert!(result.is_err());
        match result {
            Err(OracleError::EvidenceHashMismatch { .. }) => {} // expected
            other => panic!("Expected EvidenceHashMismatch, got: {:?}", other),
        }
    }
}
