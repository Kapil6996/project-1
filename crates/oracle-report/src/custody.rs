//! # Chain of Custody Document Generator (V2)
//!
//! Produces a structured [`CustodyDocumentV2`] from audit log entries,
//! providing a court-ready evidence timeline with full traceability to the
//! cryptographically chained audit log.
//!
//! This module complements the existing [`crate::custody_report`] module by
//! offering a more structured, serializable document model that integrates
//! directly with the JSON export pipeline and report signing system.

use chrono::{DateTime, Utc};
use oracle_audit::entry::AuditEntry;
use oracle_core::types::InvestigationId;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use tracing::info;

// ──────────────────────────────────────────────────────────────────────────────
// Data Structures
// ──────────────────────────────────────────────────────────────────────────────

/// A single entry in the chain of custody timeline.
///
/// Each entry traces back to a specific audit log entry via the
/// `audit_entry_reference` field, enabling independent verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEntry {
    /// UTC timestamp of the custody action.
    pub timestamp: DateTime<Utc>,
    /// Description of the action taken (e.g., "Artifact acquired", "Parser executed").
    pub action: String,
    /// The person or system that performed the action.
    pub actor: String,
    /// Additional details about the action.
    pub details: String,
    /// Reference to the source audit entry (formatted as "#{index} ({entry_id})").
    pub audit_entry_reference: String,
}

/// Device metadata included in the custody document for identification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Human-readable device description.
    pub description: String,
    /// Device serial number, if known.
    pub serial: Option<String>,
}

/// Integrity verification status of the audit chain at document generation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityStatus {
    /// All audit chain hashes verified successfully.
    Verified,
    /// Some entries failed hash verification.
    PartialFailure,
    /// Verification was not performed (e.g., audit log unavailable).
    NotVerified,
}

impl std::fmt::Display for IntegrityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrityStatus::Verified => write!(f, "VERIFIED"),
            IntegrityStatus::PartialFailure => write!(f, "PARTIAL FAILURE"),
            IntegrityStatus::NotVerified => write!(f, "NOT VERIFIED"),
        }
    }
}

/// A structured chain of custody document.
///
/// Contains a chronological evidence timeline derived from the audit log,
/// along with investigation metadata and integrity verification status.
/// This is the serializable counterpart suitable for JSON export and
/// report signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyDocumentV2 {
    /// The investigation this document pertains to.
    pub investigation_id: InvestigationId,
    /// Name of the examiner who conducted the investigation.
    pub examiner: String,
    /// Information about the target device.
    pub device_info: DeviceInfo,
    /// Chronological timeline of all custody-relevant events.
    pub evidence_timeline: Vec<CustodyEntry>,
    /// Status of audit chain integrity verification at generation time.
    pub integrity_verification_status: IntegrityStatus,
    /// UTC timestamp of when this document was generated.
    pub generated_at: DateTime<Utc>,
    /// SHA-256 hash of the document content for tamper evidence.
    pub document_hash: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Generator
// ──────────────────────────────────────────────────────────────────────────────

/// Generates a [`CustodyDocumentV2`] from raw audit log entries.
///
/// The generator transforms audit entries into a structured custody timeline,
/// filtering to the specified investigation and computing a tamper-evident
/// document hash.
pub struct CustodyDocumentGenerator;

impl CustodyDocumentGenerator {
    /// Generate a chain of custody document.
    ///
    /// # Arguments
    ///
    /// * `audit_entries` — All audit log entries (the generator filters by investigation).
    /// * `investigation_id` — The investigation to generate the custody document for.
    /// * `examiner` — Name of the examiner.
    /// * `device_info` — Target device metadata.
    /// * `integrity_status` — Result of audit chain verification.
    ///
    /// # Returns
    ///
    /// A [`CustodyDocumentV2`] with a complete evidence timeline and integrity hash.
    pub fn generate(
        audit_entries: &[AuditEntry],
        investigation_id: InvestigationId,
        examiner: &str,
        device_info: DeviceInfo,
        integrity_status: IntegrityStatus,
    ) -> CustodyDocumentV2 {
        info!(
            investigation = %investigation_id,
            entries = audit_entries.len(),
            "Generating chain of custody document"
        );

        // Filter entries relevant to this investigation.
        let relevant_entries: Vec<&AuditEntry> = audit_entries
            .iter()
            .filter(|e| {
                e.investigation_id
                    .as_ref()
                    .map_or(true, |id| *id == investigation_id)
            })
            .collect();

        // Transform audit entries into custody entries.
        let evidence_timeline: Vec<CustodyEntry> = relevant_entries
            .iter()
            .map(|entry| CustodyEntry {
                timestamp: entry.timestamp,
                action: format!("{:?}", entry.operation),
                actor: entry.actor.clone(),
                details: format!("{}: {}", entry.subject, entry.result_summary()),
                audit_entry_reference: format!("#{} ({})", entry.entry_index, entry.entry_id),
            })
            .collect();

        let generated_at = Utc::now();

        // Compute document hash over the timeline content.
        let document_hash = Self::compute_hash(
            &investigation_id,
            examiner,
            &evidence_timeline,
            generated_at,
        );

        CustodyDocumentV2 {
            investigation_id,
            examiner: examiner.to_string(),
            device_info,
            evidence_timeline,
            integrity_verification_status: integrity_status,
            generated_at,
            document_hash,
        }
    }

    /// Compute SHA-256 hash of the custody document content.
    fn compute_hash(
        investigation_id: &InvestigationId,
        examiner: &str,
        timeline: &[CustodyEntry],
        generated_at: DateTime<Utc>,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(investigation_id.to_string().as_bytes());
        hasher.update(b"|");
        hasher.update(examiner.as_bytes());
        hasher.update(b"|");
        hasher.update(generated_at.timestamp().to_le_bytes());
        hasher.update(b"|");

        for entry in timeline {
            hasher.update(entry.timestamp.timestamp().to_le_bytes());
            hasher.update(b"|");
            hasher.update(entry.action.as_bytes());
            hasher.update(b"|");
            hasher.update(entry.actor.as_bytes());
            hasher.update(b"|");
            hasher.update(entry.audit_entry_reference.as_bytes());
            hasher.update(b"|");
        }

        hex::encode(hasher.finalize())
    }
}

/// Extension trait for AuditEntry to produce a human-readable result summary.
trait AuditEntryExt {
    /// Produce a short human-readable summary of the audit result.
    fn result_summary(&self) -> String;
}

impl AuditEntryExt for AuditEntry {
    fn result_summary(&self) -> String {
        use oracle_core::types::AuditResult;
        match &self.result {
            AuditResult::Success => "Success".to_string(),
            AuditResult::Failure(reason) => format!("Failed: {}", reason),
            AuditResult::Pending => "Pending".to_string(),
            AuditResult::Skipped(reason) => format!("Skipped: {}", reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_core::types::{AuditOperationType, AuditResult, InvestigationId};
    use serde_json::json;
    use uuid::Uuid;

    /// Build a minimal audit entry for testing without requiring the full
    /// hash-chain machinery. In tests we don't verify the chain hash.
    fn make_test_entry(
        index: u64,
        investigation_id: Option<InvestigationId>,
        operation: AuditOperationType,
        actor: &str,
        subject: &str,
    ) -> AuditEntry {
        AuditEntry {
            entry_id: Uuid::new_v4(),
            entry_index: index,
            timestamp: Utc::now(),
            investigation_id,
            operation,
            actor: actor.to_string(),
            subject: subject.to_string(),
            details: json!({}),
            result: AuditResult::Success,
            previous_hash: "0".repeat(64),
            entry_hash: "0".repeat(64),
        }
    }

    #[test]
    fn test_custody_document_references_audit_entries() {
        let inv_id = InvestigationId::new();
        let entries = vec![
            make_test_entry(
                0,
                Some(inv_id),
                AuditOperationType::DeviceConnected,
                "SYSTEM",
                "Samsung SM-S928B",
            ),
            make_test_entry(
                1,
                Some(inv_id),
                AuditOperationType::ArtifactAcquisitionStarted,
                "Examiner A",
                "WiFi config",
            ),
        ];

        let device = DeviceInfo {
            description: "Samsung Galaxy S24 Ultra".to_string(),
            serial: Some("R5CX12345".to_string()),
        };

        let doc = CustodyDocumentGenerator::generate(
            &entries,
            inv_id,
            "Examiner A",
            device,
            IntegrityStatus::Verified,
        );

        assert_eq!(doc.evidence_timeline.len(), 2);
        assert_eq!(doc.investigation_id, inv_id);
        assert_eq!(doc.examiner, "Examiner A");
        assert_eq!(
            doc.integrity_verification_status,
            IntegrityStatus::Verified,
        );

        // Verify each custody entry references its source audit entry.
        assert!(doc.evidence_timeline[0]
            .audit_entry_reference
            .contains("#0"));
        assert!(doc.evidence_timeline[1]
            .audit_entry_reference
            .contains("#1"));
    }

    #[test]
    fn test_custody_document_hash_is_valid_sha256() {
        let inv_id = InvestigationId::new();
        let entries = vec![make_test_entry(
            0,
            Some(inv_id),
            AuditOperationType::InvestigationCreated,
            "Examiner B",
            "Test case",
        )];

        let doc = CustodyDocumentGenerator::generate(
            &entries,
            inv_id,
            "Examiner B",
            DeviceInfo {
                description: "Test device".to_string(),
                serial: None,
            },
            IntegrityStatus::Verified,
        );

        assert_eq!(doc.document_hash.len(), 64);
        assert!(doc.document_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_custody_document_filters_by_investigation() {
        let inv_a = InvestigationId::new();
        let inv_b = InvestigationId::new();

        let entries = vec![
            make_test_entry(
                0,
                Some(inv_a),
                AuditOperationType::DeviceConnected,
                "SYSTEM",
                "Device A",
            ),
            make_test_entry(
                1,
                Some(inv_b),
                AuditOperationType::DeviceConnected,
                "SYSTEM",
                "Device B",
            ),
            // System event (no investigation) should be included.
            make_test_entry(
                2,
                None,
                AuditOperationType::SystemStartup,
                "SYSTEM",
                "Platform",
            ),
        ];

        let doc = CustodyDocumentGenerator::generate(
            &entries,
            inv_a,
            "Examiner C",
            DeviceInfo {
                description: "Device A".to_string(),
                serial: None,
            },
            IntegrityStatus::NotVerified,
        );

        // Should include inv_a entry + system event (no inv_id = included).
        assert_eq!(doc.evidence_timeline.len(), 2);
    }

    #[test]
    fn test_custody_document_empty_entries() {
        let inv_id = InvestigationId::new();

        let doc = CustodyDocumentGenerator::generate(
            &[],
            inv_id,
            "Examiner D",
            DeviceInfo {
                description: "Empty device".to_string(),
                serial: None,
            },
            IntegrityStatus::NotVerified,
        );

        assert!(doc.evidence_timeline.is_empty());
        assert_eq!(doc.document_hash.len(), 64);
    }
}
