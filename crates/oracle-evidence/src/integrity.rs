//! # Evidence Store Integrity Verification
//!
//! Provides on-demand integrity checks for stored forensic artifacts and
//! provenance chain verification for evidence records.
//!
//! ## Verification Operations
//!
//! - **Artifact integrity**: Re-reads a stored file from the CAS, recomputes
//!   its SHA-256 hash, and compares it with the hash recorded at ingestion.
//!   Detects both corruption and tampering.
//!
//! - **Provenance chain**: Verifies that a parsed record's source artifact
//!   exists and its hash matches the hash recorded in the record's
//!   [`SourceReference`](oracle_core::types::SourceReference).
//!
//! - **Batch verification**: Verifies all artifacts for an investigation,
//!   producing an [`IntegrityReport`] suitable for court presentation.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;

use oracle_core::error::{OracleError, OracleResult};
use oracle_core::types::{ArtifactId, InvestigationId, RecordId};
use oracle_core::ForensicHash;

use crate::store::EvidenceStore;

// ──────────────────────────────────────────────────────────────────────────────
// IntegrityReport
// ──────────────────────────────────────────────────────────────────────────────

/// A failure entry in an integrity report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityFailure {
    /// The artifact that failed verification.
    pub artifact_id: ArtifactId,
    /// The hash that was stored at ingestion time.
    pub stored_hash: String,
    /// The hash computed from the current file on disk.
    pub computed_hash: String,
    /// A human-readable description of the failure.
    pub description: String,
}

/// The result of a batch integrity verification.
///
/// This report is designed to be serialized and included in forensic
/// reports and court disclosures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    /// Total number of artifacts checked.
    pub total_artifacts: usize,
    /// Number of artifacts that passed verification.
    pub verified_count: usize,
    /// Number of artifacts that failed verification.
    pub failed_count: usize,
    /// Details of each failure.
    pub failures: Vec<IntegrityFailure>,
}

impl IntegrityReport {
    /// Returns `true` if all artifacts passed verification.
    pub fn is_clean(&self) -> bool {
        self.failed_count == 0
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// IntegrityVerifier
// ──────────────────────────────────────────────────────────────────────────────

/// Integrity verification engine for the ORACLE Evidence Store.
///
/// Performs on-demand hash verification of stored artifacts and provenance
/// chain validation of evidence records.
pub struct IntegrityVerifier {
    /// Shared SQLite connection.
    conn: Arc<Mutex<Connection>>,
}

impl IntegrityVerifier {
    /// Create a new verifier from an existing [`EvidenceStore`].
    pub fn new(store: &EvidenceStore) -> Self {
        Self {
            conn: store.conn(),
        }
    }

    /// Verify the integrity of a single artifact.
    ///
    /// Re-reads the stored file from the CAS, recomputes its SHA-256 hash,
    /// and compares it with the hash recorded in the metadata database.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the hash matches, `Ok(false)` if it does not.
    ///
    /// # Errors
    ///
    /// - [`OracleError::DatabaseError`] if the artifact is not found.
    /// - [`OracleError::IoError`] if the stored file cannot be read.
    pub fn verify_artifact_integrity(
        &self,
        artifact_id: ArtifactId,
    ) -> OracleResult<bool> {
        let (stored_hash, stored_path) = self.get_artifact_hash_and_path(artifact_id)?;

        let path = PathBuf::from(&stored_path);
        let computed_hash = ForensicHash::from_file(&path)?;
        let computed_hex = computed_hash.to_hex();

        if computed_hex != stored_hash {
            warn!(
                artifact_id = %artifact_id,
                stored_hash = %stored_hash,
                computed_hash = %computed_hex,
                "INTEGRITY VIOLATION: artifact hash mismatch"
            );
            return Ok(false);
        }

        debug!(
            artifact_id = %artifact_id,
            hash = %stored_hash,
            "Artifact integrity verified"
        );

        Ok(true)
    }

    /// Verify all artifacts belonging to an investigation.
    ///
    /// Produces an [`IntegrityReport`] with the results.
    ///
    /// # Errors
    ///
    /// - [`OracleError::DatabaseError`] if the database cannot be queried.
    pub fn verify_all_artifacts(
        &self,
        investigation_id: InvestigationId,
    ) -> OracleResult<IntegrityReport> {
        let artifacts = self.list_artifacts_for_investigation(investigation_id)?;

        let total_artifacts = artifacts.len();
        let mut verified_count = 0;
        let mut failures = Vec::new();

        for (artifact_id, stored_hash, stored_path) in &artifacts {
            let path = PathBuf::from(stored_path);

            match ForensicHash::from_file(&path) {
                Ok(computed_hash) => {
                    let computed_hex = computed_hash.to_hex();
                    if computed_hex == *stored_hash {
                        verified_count += 1;
                    } else {
                        failures.push(IntegrityFailure {
                            artifact_id: *artifact_id,
                            stored_hash: stored_hash.clone(),
                            computed_hash: computed_hex,
                            description: "Hash mismatch: artifact may have been tampered with"
                                .to_string(),
                        });
                    }
                }
                Err(e) => {
                    failures.push(IntegrityFailure {
                        artifact_id: *artifact_id,
                        stored_hash: stored_hash.clone(),
                        computed_hash: String::new(),
                        description: format!("Failed to read artifact file: {}", e),
                    });
                }
            }
        }

        let failed_count = failures.len();

        let report = IntegrityReport {
            total_artifacts,
            verified_count,
            failed_count,
            failures,
        };

        info!(
            investigation_id = %investigation_id,
            total = total_artifacts,
            verified = verified_count,
            failed = failed_count,
            "Investigation integrity verification complete"
        );

        Ok(report)
    }

    /// Verify the provenance chain for a parsed record.
    ///
    /// Checks that:
    /// 1. The record's source artifact exists in the evidence store.
    /// 2. The artifact's current hash matches the hash recorded in the
    ///    record's source reference.
    ///
    /// # Errors
    ///
    /// - [`OracleError::ProvenanceChainBroken`] if the artifact does not
    ///   exist or its hash does not match.
    /// - [`OracleError::DatabaseError`] if the record is not found.
    pub fn verify_provenance_chain(
        &self,
        record_id: RecordId,
    ) -> OracleResult<bool> {
        let conn = self.conn.lock().map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to acquire database lock: {}", e),
        })?;

        // Look up the record's artifact_id and source_ref_json.
        let (artifact_id_str, source_ref_json): (String, String) = conn
            .query_row(
                "SELECT artifact_id, source_ref_json FROM parsed_records WHERE record_id = ?1",
                params![record_id.0.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Parsed record {} not found: {}", record_id, e),
            })?;

        let artifact_uuid = Uuid::parse_str(&artifact_id_str).map_err(|e| {
            OracleError::DatabaseError {
                reason: format!("Invalid artifact_id in record: {}", e),
            }
        })?;
        let artifact_id = ArtifactId(artifact_uuid);

        // Parse the source reference to get the expected hash.
        let source_ref: oracle_core::types::SourceReference =
            serde_json::from_str(&source_ref_json)?;

        // Verify the artifact exists and get its current stored hash.
        let (current_hash, stored_path) = self.get_artifact_hash_and_path_inner(&conn, artifact_id)
            .map_err(|_| OracleError::ProvenanceChainBroken {
                record_id: record_id.0,
                reason: format!(
                    "Source artifact {} does not exist in the evidence store",
                    artifact_id
                ),
            })?;

        // Verify the artifact's hash matches the hash in the source reference.
        if current_hash != source_ref.artifact_hash {
            return Err(OracleError::ProvenanceChainBroken {
                record_id: record_id.0,
                reason: format!(
                    "Artifact {} hash mismatch: source_ref records {}, store has {}",
                    artifact_id, source_ref.artifact_hash, current_hash
                ),
            });
        }

        // Additionally verify the file on disk matches.
        let path = PathBuf::from(&stored_path);
        let computed_hash = ForensicHash::from_file(&path)?;
        let computed_hex = computed_hash.to_hex();

        if computed_hex != current_hash {
            return Err(OracleError::ProvenanceChainBroken {
                record_id: record_id.0,
                reason: format!(
                    "Artifact {} file integrity violation: stored hash {}, computed {}",
                    artifact_id, current_hash, computed_hex
                ),
            });
        }

        debug!(
            record_id = %record_id,
            artifact_id = %artifact_id,
            "Provenance chain verified"
        );

        Ok(true)
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Retrieve the stored hash and filesystem path for an artifact.
    fn get_artifact_hash_and_path(
        &self,
        artifact_id: ArtifactId,
    ) -> OracleResult<(String, String)> {
        let conn = self.conn.lock().map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to acquire database lock: {}", e),
        })?;

        self.get_artifact_hash_and_path_inner(&conn, artifact_id)
    }

    /// Inner helper that takes an already-locked connection.
    fn get_artifact_hash_and_path_inner(
        &self,
        conn: &Connection,
        artifact_id: ArtifactId,
    ) -> OracleResult<(String, String)> {
        conn.query_row(
            "SELECT sha256_hash, stored_path FROM artifacts WHERE artifact_id = ?1",
            params![artifact_id.0.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|e| OracleError::DatabaseError {
            reason: format!("Artifact {} not found: {}", artifact_id, e),
        })
    }

    /// List all artifacts for a given investigation.
    fn list_artifacts_for_investigation(
        &self,
        investigation_id: InvestigationId,
    ) -> OracleResult<Vec<(ArtifactId, String, String)>> {
        let conn = self.conn.lock().map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to acquire database lock: {}", e),
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT artifact_id, sha256_hash, stored_path
                 FROM artifacts
                 WHERE investigation_id = ?1",
            )
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to prepare query: {}", e),
            })?;

        let artifacts = stmt
            .query_map(params![investigation_id.0.to_string()], |row| {
                let id_str: String = row.get(0)?;
                let hash: String = row.get(1)?;
                let path: String = row.get(2)?;
                Ok((id_str, hash, path))
            })
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to execute query: {}", e),
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to read artifacts: {}", e),
            })?;

        // Convert string UUIDs to ArtifactId.
        let mut result = Vec::with_capacity(artifacts.len());
        for (id_str, hash, path) in artifacts {
            let uuid = Uuid::parse_str(&id_str).map_err(|e| OracleError::DatabaseError {
                reason: format!("Invalid artifact_id UUID in database: {}", e),
            })?;
            result.push((ArtifactId(uuid), hash, path));
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cas::ContentAddressableStore;
    use crate::records::{ParsedRecord, RecordStore};
    use crate::store::EvidenceStore;
    use chrono::Utc;
    use oracle_audit::AuditLogWriter;
    use oracle_core::types::{
        AcquisitionMethod, ArtifactClass, EvidenceLayer, SourceReference,
    };
    use serde_json::json;
    use tempfile::TempDir;

    /// Helper: create a temp evidence store.
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
    fn test_verify_artifact_integrity_clean() {
        let (store, _dir) = setup();
        let cas = ContentAddressableStore::new(&store);
        let verifier = IntegrityVerifier::new(&store);

        let investigation_id = InvestigationId::new();
        let raw_bytes = b"integrity test content";

        let artifact_id = cas
            .store_artifact(
                investigation_id,
                ArtifactClass::WifiConfigStore,
                "/test/clean",
                raw_bytes,
                AcquisitionMethod::PrivilegedLogical,
            )
            .unwrap();

        assert!(verifier.verify_artifact_integrity(artifact_id).unwrap());
    }

    #[test]
    fn test_verify_artifact_integrity_tampered() {
        let (store, _dir) = setup();
        let cas = ContentAddressableStore::new(&store);
        let verifier = IntegrityVerifier::new(&store);

        let investigation_id = InvestigationId::new();
        let raw_bytes = b"original content to tamper";

        let artifact_id = cas
            .store_artifact(
                investigation_id,
                ArtifactClass::KernelLogs,
                "/test/tamper",
                raw_bytes,
                AcquisitionMethod::PrivilegedLogical,
            )
            .unwrap();

        // Tamper with the file on disk.
        let (_, stored_path) = cas.get_artifact_metadata(artifact_id).unwrap();
        std::fs::write(&stored_path, b"TAMPERED!!!").unwrap();

        assert!(!verifier.verify_artifact_integrity(artifact_id).unwrap());
    }

    #[test]
    fn test_verify_all_artifacts_mixed() {
        let (store, _dir) = setup();
        let cas = ContentAddressableStore::new(&store);
        let verifier = IntegrityVerifier::new(&store);

        let investigation_id = InvestigationId::new();

        // Store 3 artifacts.
        let id1 = cas
            .store_artifact(
                investigation_id,
                ArtifactClass::WifiConfigStore,
                "/a",
                b"artifact 1 content",
                AcquisitionMethod::PrivilegedLogical,
            )
            .unwrap();

        let id2 = cas
            .store_artifact(
                investigation_id,
                ArtifactClass::DhcpLeases,
                "/b",
                b"artifact 2 content",
                AcquisitionMethod::PrivilegedLogical,
            )
            .unwrap();

        let id3 = cas
            .store_artifact(
                investigation_id,
                ArtifactClass::KernelLogs,
                "/c",
                b"artifact 3 content",
                AcquisitionMethod::PrivilegedLogical,
            )
            .unwrap();

        // Tamper with artifact 2.
        let (_, path2) = cas.get_artifact_metadata(id2).unwrap();
        std::fs::write(&path2, b"CORRUPTED").unwrap();

        let report = verifier.verify_all_artifacts(investigation_id).unwrap();

        assert_eq!(report.total_artifacts, 3);
        assert_eq!(report.verified_count, 2);
        assert_eq!(report.failed_count, 1);
        assert!(!report.is_clean());
        assert_eq!(report.failures[0].artifact_id, id2);
    }

    #[test]
    fn test_verify_provenance_chain_valid() {
        let (store, _dir) = setup();
        let cas = ContentAddressableStore::new(&store);
        let record_store = RecordStore::new(&store);
        let verifier = IntegrityVerifier::new(&store);

        let investigation_id = InvestigationId::new();
        let raw_bytes = b"provenance test artifact";
        let hash = ForensicHash::from_bytes(raw_bytes).to_hex();

        let artifact_id = cas
            .store_artifact(
                investigation_id,
                ArtifactClass::WifiConfigStore,
                "/test/provenance",
                raw_bytes,
                AcquisitionMethod::PrivilegedLogical,
            )
            .unwrap();

        let record = ParsedRecord {
            record_id: RecordId::new(),
            artifact_id,
            investigation_id,
            parser_id: "test-parser".to_string(),
            parser_version: "1.0.0".to_string(),
            evidence_layer: EvidenceLayer::Parsed,
            record_type: "wifi_network".to_string(),
            record_data: json!({"ssid": "test"}),
            source_ref: SourceReference {
                artifact_id,
                artifact_hash: hash,
                parser_id: "test-parser".to_string(),
                parser_version: "1.0.0".to_string(),
                byte_offset: Some(0),
                byte_length: Some(24),
                db_row_id: None,
                parsed_at: Utc::now(),
            },
            created_at: Utc::now(),
        };

        let record_id = record_store.store_parsed_record(&record).unwrap();

        assert!(verifier.verify_provenance_chain(record_id).unwrap());
    }

    #[test]
    fn test_verify_provenance_chain_broken_by_tampering() {
        let (store, _dir) = setup();
        let cas = ContentAddressableStore::new(&store);
        let record_store = RecordStore::new(&store);
        let verifier = IntegrityVerifier::new(&store);

        let investigation_id = InvestigationId::new();
        let raw_bytes = b"provenance tamper test";
        let hash = ForensicHash::from_bytes(raw_bytes).to_hex();

        let artifact_id = cas
            .store_artifact(
                investigation_id,
                ArtifactClass::WifiConfigStore,
                "/test/provenance/tamper",
                raw_bytes,
                AcquisitionMethod::PrivilegedLogical,
            )
            .unwrap();

        let record = ParsedRecord {
            record_id: RecordId::new(),
            artifact_id,
            investigation_id,
            parser_id: "test-parser".to_string(),
            parser_version: "1.0.0".to_string(),
            evidence_layer: EvidenceLayer::Parsed,
            record_type: "test".to_string(),
            record_data: json!({}),
            source_ref: SourceReference {
                artifact_id,
                artifact_hash: hash,
                parser_id: "test-parser".to_string(),
                parser_version: "1.0.0".to_string(),
                byte_offset: None,
                byte_length: None,
                db_row_id: None,
                parsed_at: Utc::now(),
            },
            created_at: Utc::now(),
        };

        let record_id = record_store.store_parsed_record(&record).unwrap();

        // Tamper with the artifact on disk.
        let (_, stored_path) = cas.get_artifact_metadata(artifact_id).unwrap();
        std::fs::write(&stored_path, b"TAMPERED!!!").unwrap();

        let result = verifier.verify_provenance_chain(record_id);
        assert!(result.is_err());
        match result {
            Err(OracleError::ProvenanceChainBroken { .. }) => {} // expected
            other => panic!("Expected ProvenanceChainBroken, got: {:?}", other),
        }
    }

    #[test]
    fn test_integrity_report_all_clean() {
        let (store, _dir) = setup();
        let cas = ContentAddressableStore::new(&store);
        let verifier = IntegrityVerifier::new(&store);

        let investigation_id = InvestigationId::new();

        for i in 0..5 {
            cas.store_artifact(
                investigation_id,
                ArtifactClass::WifiConfigStore,
                &format!("/clean/{}", i),
                format!("clean artifact {}", i).as_bytes(),
                AcquisitionMethod::PrivilegedLogical,
            )
            .unwrap();
        }

        let report = verifier.verify_all_artifacts(investigation_id).unwrap();

        assert_eq!(report.total_artifacts, 5);
        assert_eq!(report.verified_count, 5);
        assert_eq!(report.failed_count, 0);
        assert!(report.is_clean());
    }
}
