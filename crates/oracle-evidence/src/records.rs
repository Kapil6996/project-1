//! # Parsed and Normalized Record Storage
//!
//! Provides append-only storage for parsed and normalized evidence records,
//! each linked to their source artifact with full provenance metadata.
//!
//! ## Record Types
//!
//! - **[`ParsedRecord`]**: A structured record extracted from a raw artifact
//!   by a parser. Contains the parser ID, version, evidence layer, and the
//!   parsed data as a [`serde_json::Value`].
//!
//! - **[`NormalizedRecord`]**: A cleaned and unified record derived from a
//!   parsed record. Carries the same provenance metadata as the parsed
//!   record it was derived from.
//!
//! ## Append-Only Guarantee
//!
//! Both record tables are strictly append-only. No `UPDATE` or `DELETE`
//! operations are ever performed. Any attempt to modify or delete a record
//! returns [`OracleError::EvidenceModificationAttempt`].

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use uuid::Uuid;

use oracle_core::error::{OracleError, OracleResult};
use oracle_core::types::{
    ArtifactId, EvidenceLayer, InvestigationId, RecordId, SourceReference,
};

use crate::store::EvidenceStore;

// ──────────────────────────────────────────────────────────────────────────────
// Record Structs
// ──────────────────────────────────────────────────────────────────────────────

/// A parsed evidence record extracted from a raw artifact.
///
/// Each parsed record carries full provenance back to the exact bytes
/// in the source artifact that produced it, including parser identity
/// and version for reproducibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedRecord {
    /// Unique identifier for this record.
    pub record_id: RecordId,
    /// The artifact from which this record was parsed.
    pub artifact_id: ArtifactId,
    /// The investigation this record belongs to.
    pub investigation_id: InvestigationId,
    /// The identifier of the parser that produced this record.
    pub parser_id: String,
    /// The exact version of the parser.
    pub parser_version: String,
    /// The evidence processing layer (should be [`EvidenceLayer::Parsed`]).
    pub evidence_layer: EvidenceLayer,
    /// The type of record (e.g., "wifi_network", "dhcp_lease").
    pub record_type: String,
    /// The parsed record data as a JSON value.
    pub record_data: serde_json::Value,
    /// Full source reference linking back to the artifact bytes.
    pub source_ref: SourceReference,
    /// Timestamp when this record was created.
    pub created_at: DateTime<Utc>,
}

/// A normalized evidence record, cleaned and unified from a parsed record.
///
/// Normalized records undergo schema unification (e.g., timestamp
/// normalization, SSID deduplication) and are ready for correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedRecord {
    /// Unique identifier for this record.
    pub record_id: RecordId,
    /// The artifact from which the source parsed record was extracted.
    pub artifact_id: ArtifactId,
    /// The investigation this record belongs to.
    pub investigation_id: InvestigationId,
    /// The identifier of the normalizer/parser that produced this record.
    pub parser_id: String,
    /// The exact version of the normalizer/parser.
    pub parser_version: String,
    /// The evidence processing layer (should be [`EvidenceLayer::Normalized`]).
    pub evidence_layer: EvidenceLayer,
    /// The type of record (e.g., "wifi_network", "dhcp_lease").
    pub record_type: String,
    /// The normalized record data as a JSON value.
    pub record_data: serde_json::Value,
    /// Full source reference linking back to the artifact bytes.
    pub source_ref: SourceReference,
    /// Timestamp when this record was created.
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// RecordStore
// ──────────────────────────────────────────────────────────────────────────────

/// Storage API for parsed and normalized evidence records.
///
/// All operations are append-only and verified against the parent artifact.
pub struct RecordStore {
    /// Shared SQLite connection.
    conn: Arc<Mutex<Connection>>,
}

impl RecordStore {
    /// Create a new `RecordStore` from an existing [`EvidenceStore`].
    pub fn new(store: &EvidenceStore) -> Self {
        Self {
            conn: store.conn(),
        }
    }

    // ── Parsed Records ──────────────────────────────────────────────────

    /// Store a parsed evidence record.
    ///
    /// The record must reference a valid `artifact_id` that exists in the
    /// `artifacts` table. A new [`RecordId`] is generated and returned.
    ///
    /// # Errors
    ///
    /// - [`OracleError::DatabaseError`] if the artifact_id does not exist
    ///   or the insert fails.
    pub fn store_parsed_record(&self, record: &ParsedRecord) -> OracleResult<RecordId> {
        let conn = self.conn.lock().map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to acquire database lock: {}", e),
        })?;

        // Verify the artifact exists.
        self.verify_artifact_exists(&conn, record.artifact_id)?;

        let record_data_json = serde_json::to_string(&record.record_data)?;
        let source_ref_json = serde_json::to_string(&record.source_ref)?;
        let evidence_layer_json = serde_json::to_string(&record.evidence_layer)?;

        conn.execute(
            "INSERT INTO parsed_records (
                record_id, artifact_id, investigation_id, parser_id,
                parser_version, evidence_layer, record_type,
                record_data_json, source_ref_json, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                record.record_id.0.to_string(),
                record.artifact_id.0.to_string(),
                record.investigation_id.0.to_string(),
                record.parser_id,
                record.parser_version,
                evidence_layer_json,
                record.record_type,
                record_data_json,
                source_ref_json,
                record.created_at.to_rfc3339(),
            ],
        )
        .map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to insert parsed record: {}", e),
        })?;

        debug!(
            record_id = %record.record_id,
            artifact_id = %record.artifact_id,
            record_type = %record.record_type,
            "Parsed record stored"
        );

        Ok(record.record_id)
    }

    /// Store a normalized evidence record.
    ///
    /// The record must reference a valid `artifact_id` that exists in the
    /// `artifacts` table. A new [`RecordId`] is generated and returned.
    ///
    /// # Errors
    ///
    /// - [`OracleError::DatabaseError`] if the artifact_id does not exist
    ///   or the insert fails.
    pub fn store_normalized_record(&self, record: &NormalizedRecord) -> OracleResult<RecordId> {
        let conn = self.conn.lock().map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to acquire database lock: {}", e),
        })?;

        // Verify the artifact exists.
        self.verify_artifact_exists(&conn, record.artifact_id)?;

        let record_data_json = serde_json::to_string(&record.record_data)?;
        let source_ref_json = serde_json::to_string(&record.source_ref)?;
        let evidence_layer_json = serde_json::to_string(&record.evidence_layer)?;

        conn.execute(
            "INSERT INTO normalized_records (
                record_id, artifact_id, investigation_id, parser_id,
                parser_version, evidence_layer, record_type,
                record_data_json, source_ref_json, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                record.record_id.0.to_string(),
                record.artifact_id.0.to_string(),
                record.investigation_id.0.to_string(),
                record.parser_id,
                record.parser_version,
                evidence_layer_json,
                record.record_type,
                record_data_json,
                source_ref_json,
                record.created_at.to_rfc3339(),
            ],
        )
        .map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to insert normalized record: {}", e),
        })?;

        debug!(
            record_id = %record.record_id,
            artifact_id = %record.artifact_id,
            record_type = %record.record_type,
            "Normalized record stored"
        );

        Ok(record.record_id)
    }

    /// Attempt to delete a parsed record. **Always** rejected.
    ///
    /// # Errors
    ///
    /// Always returns [`OracleError::EvidenceModificationAttempt`].
    pub fn delete_parsed_record(&self, record_id: RecordId) -> OracleResult<()> {
        Err(OracleError::EvidenceModificationAttempt {
            record_id: record_id.0,
        })
    }

    /// Attempt to update a parsed record. **Always** rejected.
    ///
    /// # Errors
    ///
    /// Always returns [`OracleError::EvidenceModificationAttempt`].
    pub fn update_parsed_record(&self, record_id: RecordId) -> OracleResult<()> {
        Err(OracleError::EvidenceModificationAttempt {
            record_id: record_id.0,
        })
    }

    // ── Query Methods ───────────────────────────────────────────────────

    /// Retrieve all parsed records from a given artifact.
    pub fn get_records_by_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> OracleResult<Vec<ParsedRecord>> {
        let conn = self.conn.lock().map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to acquire database lock: {}", e),
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT record_id, artifact_id, investigation_id, parser_id,
                        parser_version, evidence_layer, record_type,
                        record_data_json, source_ref_json, created_at
                 FROM parsed_records
                 WHERE artifact_id = ?1
                 ORDER BY created_at ASC",
            )
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to prepare query: {}", e),
            })?;

        let records = stmt
            .query_map(params![artifact_id.0.to_string()], |row| {
                row_to_parsed_record(row)
            })
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to execute query: {}", e),
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to read parsed records: {}", e),
            })?;

        Ok(records)
    }

    /// Retrieve all parsed records for an investigation.
    pub fn get_records_by_investigation(
        &self,
        investigation_id: InvestigationId,
    ) -> OracleResult<Vec<ParsedRecord>> {
        let conn = self.conn.lock().map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to acquire database lock: {}", e),
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT record_id, artifact_id, investigation_id, parser_id,
                        parser_version, evidence_layer, record_type,
                        record_data_json, source_ref_json, created_at
                 FROM parsed_records
                 WHERE investigation_id = ?1
                 ORDER BY created_at ASC",
            )
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to prepare query: {}", e),
            })?;

        let records = stmt
            .query_map(
                params![investigation_id.0.to_string()],
                |row| row_to_parsed_record(row),
            )
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to execute query: {}", e),
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to read parsed records: {}", e),
            })?;

        Ok(records)
    }

    /// Retrieve all parsed records of a given type.
    pub fn get_records_by_type(
        &self,
        record_type: &str,
    ) -> OracleResult<Vec<ParsedRecord>> {
        let conn = self.conn.lock().map_err(|e| OracleError::DatabaseError {
            reason: format!("Failed to acquire database lock: {}", e),
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT record_id, artifact_id, investigation_id, parser_id,
                        parser_version, evidence_layer, record_type,
                        record_data_json, source_ref_json, created_at
                 FROM parsed_records
                 WHERE record_type = ?1
                 ORDER BY created_at ASC",
            )
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to prepare query: {}", e),
            })?;

        let records = stmt
            .query_map(params![record_type], |row| row_to_parsed_record(row))
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to execute query: {}", e),
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to read parsed records: {}", e),
            })?;

        Ok(records)
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Verify that an artifact with the given ID exists in the database.
    fn verify_artifact_exists(
        &self,
        conn: &Connection,
        artifact_id: ArtifactId,
    ) -> OracleResult<()> {
        let exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM artifacts WHERE artifact_id = ?1",
                params![artifact_id.0.to_string()],
                |row| row.get(0),
            )
            .map_err(|e| OracleError::DatabaseError {
                reason: format!("Failed to verify artifact existence: {}", e),
            })?;

        if !exists {
            return Err(OracleError::ProvenanceChainBroken {
                record_id: Uuid::nil(),
                reason: format!(
                    "Referenced artifact {} does not exist in the evidence store",
                    artifact_id
                ),
            });
        }

        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Row Conversion
// ──────────────────────────────────────────────────────────────────────────────

/// Convert a rusqlite `Row` into a [`ParsedRecord`].
fn row_to_parsed_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<ParsedRecord> {
    let record_id_str: String = row.get(0)?;
    let artifact_id_str: String = row.get(1)?;
    let investigation_id_str: String = row.get(2)?;
    let parser_id: String = row.get(3)?;
    let parser_version: String = row.get(4)?;
    let evidence_layer_str: String = row.get(5)?;
    let record_type: String = row.get(6)?;
    let record_data_str: String = row.get(7)?;
    let source_ref_str: String = row.get(8)?;
    let created_at_str: String = row.get(9)?;

    let record_id = Uuid::parse_str(&record_id_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(e),
        ))?;

    let artifact_id = Uuid::parse_str(&artifact_id_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Text,
            Box::new(e),
        ))?;

    let investigation_id = Uuid::parse_str(&investigation_id_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Text,
            Box::new(e),
        ))?;

    let evidence_layer: EvidenceLayer = serde_json::from_str(&evidence_layer_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
            5,
            rusqlite::types::Type::Text,
            Box::new(e),
        ))?;

    let record_data: serde_json::Value = serde_json::from_str(&record_data_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
            7,
            rusqlite::types::Type::Text,
            Box::new(e),
        ))?;

    let source_ref: SourceReference = serde_json::from_str(&source_ref_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
            8,
            rusqlite::types::Type::Text,
            Box::new(e),
        ))?;

    let created_at: DateTime<Utc> = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
            9,
            rusqlite::types::Type::Text,
            Box::new(e),
        ))?;

    Ok(ParsedRecord {
        record_id: RecordId(record_id),
        artifact_id: ArtifactId(artifact_id),
        investigation_id: InvestigationId(investigation_id),
        parser_id,
        parser_version,
        evidence_layer,
        record_type,
        record_data,
        source_ref,
        created_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cas::ContentAddressableStore;
    use crate::store::EvidenceStore;
    use oracle_audit::AuditLogWriter;
    use oracle_core::types::AcquisitionMethod;
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

    /// Helper: create a sample SourceReference.
    fn sample_source_ref(artifact_id: ArtifactId, hash: &str) -> SourceReference {
        SourceReference {
            artifact_id,
            artifact_hash: hash.to_string(),
            parser_id: "test-parser".to_string(),
            parser_version: "1.0.0".to_string(),
            byte_offset: Some(0),
            byte_length: Some(100),
            db_row_id: None,
            parsed_at: Utc::now(),
        }
    }

    /// Helper: store a sample artifact and return its ID + hash.
    fn store_sample_artifact(store: &EvidenceStore) -> (ArtifactId, InvestigationId, String) {
        let cas = ContentAddressableStore::new(store);
        let investigation_id = InvestigationId::new();
        let raw_bytes = b"sample artifact for record tests";
        let hash = oracle_core::ForensicHash::from_bytes(raw_bytes).to_hex();

        let artifact_id = cas
            .store_artifact(
                investigation_id,
                oracle_core::types::ArtifactClass::WifiConfigStore,
                "/test/path",
                raw_bytes,
                AcquisitionMethod::PrivilegedLogical,
            )
            .unwrap();

        (artifact_id, investigation_id, hash)
    }

    #[test]
    fn test_store_and_query_parsed_record() {
        let (store, _dir) = setup();
        let (artifact_id, investigation_id, hash) = store_sample_artifact(&store);
        let record_store = RecordStore::new(&store);

        let record = ParsedRecord {
            record_id: RecordId::new(),
            artifact_id,
            investigation_id,
            parser_id: "wifi-config-parser".to_string(),
            parser_version: "1.0.0".to_string(),
            evidence_layer: EvidenceLayer::Parsed,
            record_type: "wifi_network".to_string(),
            record_data: json!({"ssid": "TestNetwork", "security": "WPA2"}),
            source_ref: sample_source_ref(artifact_id, &hash),
            created_at: Utc::now(),
        };

        let stored_id = record_store.store_parsed_record(&record).unwrap();
        assert_eq!(stored_id, record.record_id);

        // Query by artifact.
        let by_artifact = record_store.get_records_by_artifact(artifact_id).unwrap();
        assert_eq!(by_artifact.len(), 1);
        assert_eq!(by_artifact[0].record_type, "wifi_network");

        // Query by investigation.
        let by_inv = record_store
            .get_records_by_investigation(investigation_id)
            .unwrap();
        assert_eq!(by_inv.len(), 1);

        // Query by type.
        let by_type = record_store.get_records_by_type("wifi_network").unwrap();
        assert_eq!(by_type.len(), 1);
    }

    #[test]
    fn test_store_normalized_record() {
        let (store, _dir) = setup();
        let (artifact_id, investigation_id, hash) = store_sample_artifact(&store);
        let record_store = RecordStore::new(&store);

        let record = NormalizedRecord {
            record_id: RecordId::new(),
            artifact_id,
            investigation_id,
            parser_id: "normalizer-v1".to_string(),
            parser_version: "1.0.0".to_string(),
            evidence_layer: EvidenceLayer::Normalized,
            record_type: "wifi_network".to_string(),
            record_data: json!({"ssid": "TestNetwork", "security": "WPA2-PSK"}),
            source_ref: sample_source_ref(artifact_id, &hash),
            created_at: Utc::now(),
        };

        let stored_id = record_store.store_normalized_record(&record).unwrap();
        assert_eq!(stored_id, record.record_id);
    }

    #[test]
    fn test_record_references_nonexistent_artifact_rejected() {
        let (store, _dir) = setup();
        let record_store = RecordStore::new(&store);

        let fake_artifact_id = ArtifactId::new();
        let investigation_id = InvestigationId::new();

        let record = ParsedRecord {
            record_id: RecordId::new(),
            artifact_id: fake_artifact_id,
            investigation_id,
            parser_id: "test-parser".to_string(),
            parser_version: "1.0.0".to_string(),
            evidence_layer: EvidenceLayer::Parsed,
            record_type: "test".to_string(),
            record_data: json!({}),
            source_ref: sample_source_ref(fake_artifact_id, "fakehash"),
            created_at: Utc::now(),
        };

        let result = record_store.store_parsed_record(&record);
        assert!(result.is_err());
    }

    #[test]
    fn test_append_only_no_delete() {
        let (store, _dir) = setup();
        let (artifact_id, investigation_id, hash) = store_sample_artifact(&store);
        let record_store = RecordStore::new(&store);

        let record = ParsedRecord {
            record_id: RecordId::new(),
            artifact_id,
            investigation_id,
            parser_id: "test".to_string(),
            parser_version: "1.0.0".to_string(),
            evidence_layer: EvidenceLayer::Parsed,
            record_type: "test".to_string(),
            record_data: json!({}),
            source_ref: sample_source_ref(artifact_id, &hash),
            created_at: Utc::now(),
        };

        let record_id = record_store.store_parsed_record(&record).unwrap();

        // Attempt delete.
        let result = record_store.delete_parsed_record(record_id);
        assert!(result.is_err());
        match result {
            Err(OracleError::EvidenceModificationAttempt { .. }) => {}
            other => panic!("Expected EvidenceModificationAttempt, got: {:?}", other),
        }

        // Attempt update.
        let result = record_store.update_parsed_record(record_id);
        assert!(result.is_err());
        match result {
            Err(OracleError::EvidenceModificationAttempt { .. }) => {}
            other => panic!("Expected EvidenceModificationAttempt, got: {:?}", other),
        }
    }

    #[test]
    fn test_multiple_records_per_artifact() {
        let (store, _dir) = setup();
        let (artifact_id, investigation_id, hash) = store_sample_artifact(&store);
        let record_store = RecordStore::new(&store);

        for i in 0..5 {
            let record = ParsedRecord {
                record_id: RecordId::new(),
                artifact_id,
                investigation_id,
                parser_id: "multi-parser".to_string(),
                parser_version: "1.0.0".to_string(),
                evidence_layer: EvidenceLayer::Parsed,
                record_type: format!("record_type_{}", i),
                record_data: json!({"index": i}),
                source_ref: sample_source_ref(artifact_id, &hash),
                created_at: Utc::now(),
            };
            record_store.store_parsed_record(&record).unwrap();
        }

        let records = record_store.get_records_by_artifact(artifact_id).unwrap();
        assert_eq!(records.len(), 5);
    }
}
