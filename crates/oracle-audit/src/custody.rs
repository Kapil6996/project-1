//! # Chain of Custody Record Builder
//!
//! Produces a court-ready [`ChainOfCustodyRecord`] by reading the audit log
//! and categorising every entry into device interactions, examiner actions,
//! or system events.
//!
//! Every event in the custody record references its source audit entry,
//! ensuring complete forensic traceability.

use chrono::{DateTime, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use oracle_core::error::OracleResult;
use oracle_core::types::{AuditOperationType, InvestigationId};

use crate::entry::AuditEntry;
use crate::writer::read_all_entries_from_conn;

// ──────────────────────────────────────────────────────────────────────────────
// Custody Event Types
// ──────────────────────────────────────────────────────────────────────────────

/// Classification of a custody event for filtering and presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustodyEventCategory {
    /// An event involving physical or logical interaction with the target device.
    DeviceInteraction,
    /// An action performed by a human examiner.
    ExaminerAction,
    /// An automated system event (startup, shutdown, recovery, verification).
    SystemEvent,
    /// An evidence processing event (parsing, normalization, correlation).
    EvidenceProcessing,
}

/// A single event in the chain of custody timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEvent {
    /// Unique identifier of the source audit entry.
    pub source_entry_id: Uuid,
    /// Index of the source audit entry.
    pub source_entry_index: u64,
    /// UTC timestamp of the event.
    pub timestamp: DateTime<Utc>,
    /// Category of this event.
    pub category: CustodyEventCategory,
    /// The original audit operation type.
    pub operation: AuditOperationType,
    /// The actor who performed the action.
    pub actor: String,
    /// Human-readable description of what was done.
    pub description: String,
    /// The investigation this event belongs to, if any.
    pub investigation_id: Option<InvestigationId>,
}

/// A complete chain of custody record for an investigation.
///
/// Contains a chronological timeline of all events, plus pre-filtered
/// views for device interactions, examiner actions, and system events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustodyRecord {
    /// The investigation this custody record covers, if filtering by one.
    pub investigation_id: Option<InvestigationId>,
    /// Full chronological timeline of all events.
    pub timeline: Vec<CustodyEvent>,
    /// Events involving the target device.
    pub device_interactions: Vec<CustodyEvent>,
    /// Events performed by human examiners.
    pub examiner_actions: Vec<CustodyEvent>,
    /// Automated system events.
    pub system_events: Vec<CustodyEvent>,
    /// Evidence processing events.
    pub evidence_processing: Vec<CustodyEvent>,
    /// When this record was generated.
    pub generated_at: DateTime<Utc>,
    /// Total number of events in the timeline.
    pub total_events: u64,
}

// ──────────────────────────────────────────────────────────────────────────────
// Builder
// ──────────────────────────────────────────────────────────────────────────────

/// Builds a [`ChainOfCustodyRecord`] from the audit log.
///
/// The builder reads the audit log via a shared database connection and
/// categorizes each entry. It never modifies the audit log.
pub struct ChainOfCustodyBuilder<'a> {
    /// Shared reference to the audit database connection.
    conn: &'a Connection,
}

impl<'a> ChainOfCustodyBuilder<'a> {
    /// Create a new builder bound to the given database connection.
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Build a chain of custody record from the full audit log.
    ///
    /// Optionally filters to a specific investigation. Pass `None` to
    /// include all events.
    ///
    /// # Errors
    ///
    /// Returns an error if the audit database cannot be read.
    pub fn build_from_audit_log(
        &self,
        investigation_id: Option<InvestigationId>,
    ) -> OracleResult<ChainOfCustodyRecord> {
        let entries = read_all_entries_from_conn(self.conn)?;

        let filtered_entries: Vec<&AuditEntry> = entries
            .iter()
            .filter(|e| {
                match &investigation_id {
                    Some(inv_id) => {
                        // Include entries matching this investigation, plus
                        // system-level events (which have no investigation_id).
                        e.investigation_id.as_ref().map_or(true, |eid| eid == inv_id)
                    }
                    None => true,
                }
            })
            .collect();

        let timeline: Vec<CustodyEvent> = filtered_entries
            .iter()
            .map(|e| entry_to_custody_event(e))
            .collect();

        let device_interactions: Vec<CustodyEvent> = timeline
            .iter()
            .filter(|e| e.category == CustodyEventCategory::DeviceInteraction)
            .cloned()
            .collect();

        let examiner_actions: Vec<CustodyEvent> = timeline
            .iter()
            .filter(|e| e.category == CustodyEventCategory::ExaminerAction)
            .cloned()
            .collect();

        let system_events: Vec<CustodyEvent> = timeline
            .iter()
            .filter(|e| e.category == CustodyEventCategory::SystemEvent)
            .cloned()
            .collect();

        let evidence_processing: Vec<CustodyEvent> = timeline
            .iter()
            .filter(|e| e.category == CustodyEventCategory::EvidenceProcessing)
            .cloned()
            .collect();

        let total_events = timeline.len() as u64;

        Ok(ChainOfCustodyRecord {
            investigation_id,
            timeline,
            device_interactions,
            examiner_actions,
            system_events,
            evidence_processing,
            generated_at: Utc::now(),
            total_events,
        })
    }
}

/// Classify an audit operation into a custody event category.
fn classify_operation(op: &AuditOperationType) -> CustodyEventCategory {
    match op {
        // Device interactions
        AuditOperationType::DeviceConnected
        | AuditOperationType::DeviceDisconnected
        | AuditOperationType::CapabilityDetectionStarted
        | AuditOperationType::CapabilityDetectionCompleted
        | AuditOperationType::CapabilityProfileAcknowledged
        | AuditOperationType::ArtifactAcquisitionStarted
        | AuditOperationType::ArtifactAcquisitionCompleted
        | AuditOperationType::ArtifactAcquisitionFailed => CustodyEventCategory::DeviceInteraction,

        // Examiner actions
        AuditOperationType::InvestigationCreated
        | AuditOperationType::InvestigationOpened
        | AuditOperationType::InvestigationClosed
        | AuditOperationType::ExaminerOverrideApplied
        | AuditOperationType::ExaminerNoteAdded
        | AuditOperationType::ReportGenerationStarted
        | AuditOperationType::ReportGenerationCompleted
        | AuditOperationType::ReportExported => CustodyEventCategory::ExaminerAction,

        // Evidence processing
        AuditOperationType::ParserExecutionStarted
        | AuditOperationType::ParserExecutionCompleted
        | AuditOperationType::ParserExecutionFailed
        | AuditOperationType::NormalizationStarted
        | AuditOperationType::NormalizationCompleted
        | AuditOperationType::CorrelationStarted
        | AuditOperationType::CorrelationCompleted
        | AuditOperationType::ConfidenceScoreComputed
        | AuditOperationType::EvidenceStoreCreated
        | AuditOperationType::EvidenceStoreVerified
        | AuditOperationType::EvidenceIntegrityViolation => CustodyEventCategory::EvidenceProcessing,

        // System events
        AuditOperationType::SystemStartup
        | AuditOperationType::SystemShutdown
        | AuditOperationType::SystemCrashRecovery
        | AuditOperationType::AuditChainVerified
        | AuditOperationType::PluginLoaded
        | AuditOperationType::PluginValidationFailed => CustodyEventCategory::SystemEvent,

        // Custom operations default to examiner actions.
        AuditOperationType::Custom(_) => CustodyEventCategory::ExaminerAction,
    }
}

/// Convert an `AuditEntry` into a `CustodyEvent`.
fn entry_to_custody_event(entry: &AuditEntry) -> CustodyEvent {
    let category = classify_operation(&entry.operation);

    let description = format!(
        "{}: {} (result: {:?})",
        entry.actor, entry.subject, entry.result
    );

    CustodyEvent {
        source_entry_id: entry.entry_id,
        source_entry_index: entry.entry_index,
        timestamp: entry.timestamp,
        category,
        operation: entry.operation.clone(),
        actor: entry.actor.clone(),
        description,
        investigation_id: entry.investigation_id,
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::AuditLogWriter;
    use oracle_core::types::{AuditOperationType, AuditResult, InvestigationId};
    use serde_json::json;
    use tempfile::TempDir;

    fn temp_writer() -> (AuditLogWriter, TempDir) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("audit.db");
        let writer = AuditLogWriter::new(&db_path).unwrap();
        (writer, dir)
    }

    #[test]
    fn test_empty_audit_log_produces_empty_record() {
        let (writer, _dir) = temp_writer();
        let builder = ChainOfCustodyBuilder::new(writer.connection());
        let record = builder.build_from_audit_log(None).unwrap();

        assert_eq!(record.total_events, 0);
        assert!(record.timeline.is_empty());
    }

    #[test]
    fn test_device_events_correctly_classified() {
        let (mut writer, _dir) = temp_writer();

        // Log device events.
        writer
            .log_intent(
                None,
                AuditOperationType::DeviceConnected,
                "SYSTEM",
                "Samsung SM-S928B",
                json!({"serial": "R5CX12345"}),
            )
            .unwrap();

        writer
            .log_intent(
                None,
                AuditOperationType::ArtifactAcquisitionStarted,
                "Examiner A",
                "WiFi config",
                json!({"path": "/data/misc/wifi"}),
            )
            .unwrap();

        // Log a system event.
        writer
            .log_intent(
                None,
                AuditOperationType::SystemStartup,
                "SYSTEM",
                "Platform",
                json!({}),
            )
            .unwrap();

        let builder = ChainOfCustodyBuilder::new(writer.connection());
        let record = builder.build_from_audit_log(None).unwrap();

        assert_eq!(record.total_events, 3);
        assert_eq!(record.device_interactions.len(), 2);
        assert_eq!(record.system_events.len(), 1);
        assert!(record.examiner_actions.is_empty());
    }

    #[test]
    fn test_filter_by_investigation() {
        let (mut writer, _dir) = temp_writer();

        let inv_a = InvestigationId::new();
        let inv_b = InvestigationId::new();

        writer
            .log_intent(
                Some(inv_a),
                AuditOperationType::InvestigationCreated,
                "Examiner A",
                "Case A",
                json!({}),
            )
            .unwrap();

        writer
            .log_intent(
                Some(inv_b),
                AuditOperationType::InvestigationCreated,
                "Examiner B",
                "Case B",
                json!({}),
            )
            .unwrap();

        // System event (no investigation_id).
        writer
            .log_intent(
                None,
                AuditOperationType::SystemStartup,
                "SYSTEM",
                "Platform",
                json!({}),
            )
            .unwrap();

        let builder = ChainOfCustodyBuilder::new(writer.connection());

        // Filter to investigation A: should include inv_a events + system events.
        let record = builder.build_from_audit_log(Some(inv_a)).unwrap();
        // Should include: inv_a entry + system event (no inv_id = included).
        assert_eq!(record.total_events, 2);
        assert_eq!(record.examiner_actions.len(), 1);
        assert_eq!(record.system_events.len(), 1);
    }

    #[test]
    fn test_custody_event_references_source_entry() {
        let (mut writer, _dir) = temp_writer();

        writer
            .log_intent(
                None,
                AuditOperationType::DeviceConnected,
                "SYSTEM",
                "Pixel 8",
                json!({}),
            )
            .unwrap();

        let entries = writer.read_all_entries().unwrap();
        let builder = ChainOfCustodyBuilder::new(writer.connection());
        let record = builder.build_from_audit_log(None).unwrap();

        assert_eq!(record.timeline[0].source_entry_id, entries[0].entry_id);
        assert_eq!(record.timeline[0].source_entry_index, entries[0].entry_index);
    }

    #[test]
    fn test_examiner_actions_classified() {
        let (mut writer, _dir) = temp_writer();

        writer
            .log_intent(
                None,
                AuditOperationType::ExaminerNoteAdded,
                "Examiner C",
                "Observation",
                json!({"note": "Device screen was cracked"}),
            )
            .unwrap();

        writer
            .log_intent(
                None,
                AuditOperationType::ExaminerOverrideApplied,
                "Examiner C",
                "Confidence override",
                json!({}),
            )
            .unwrap();

        let builder = ChainOfCustodyBuilder::new(writer.connection());
        let record = builder.build_from_audit_log(None).unwrap();

        assert_eq!(record.examiner_actions.len(), 2);
        assert_eq!(record.device_interactions.len(), 0);
    }

    #[test]
    fn test_evidence_processing_classified() {
        let (mut writer, _dir) = temp_writer();

        writer
            .log_intent(
                None,
                AuditOperationType::ParserExecutionStarted,
                "SYSTEM",
                "WifiConfigStore parser",
                json!({}),
            )
            .unwrap();

        writer
            .log_intent(
                None,
                AuditOperationType::NormalizationCompleted,
                "SYSTEM",
                "WiFi records",
                json!({}),
            )
            .unwrap();

        let builder = ChainOfCustodyBuilder::new(writer.connection());
        let record = builder.build_from_audit_log(None).unwrap();

        assert_eq!(record.evidence_processing.len(), 2);
    }
}
