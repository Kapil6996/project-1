//! # Chain of Custody Document Generator
//!
//! Transforms a [`ChainOfCustodyRecord`] from the audit subsystem into a
//! formatted document suitable for court submission. The document presents
//! a chronological timeline of all actions taken on the evidence, categorised
//! by actor and operation type.
//!
//! This module bridges the raw audit data from `oracle-audit` and the
//! report generation pipeline, adding human-readable formatting, section
//! headers, and a tamper-evident document hash.

use chrono::{DateTime, Utc};
use oracle_audit::{ChainOfCustodyRecord, CustodyEvent, CustodyEventCategory};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use tracing::info;

/// A formatted chain of custody document ready for rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyDocument {
    /// Case number this document pertains to.
    pub case_number: String,
    /// When the document was generated.
    pub generated_at: DateTime<Utc>,
    /// Total number of custody events in the timeline.
    pub total_events: u64,
    /// The full formatted text of the custody document.
    pub formatted_text: String,
    /// SHA-256 hash of the formatted text for tamper evidence.
    pub document_hash: String,
}

/// Builds a [`CustodyDocument`] from an audit-subsystem custody record.
pub struct CustodyDocumentBuilder {
    case_number: String,
    examiner_name: String,
    examiner_organization: String,
}

impl CustodyDocumentBuilder {
    /// Create a new custody document builder.
    pub fn new(case_number: &str, examiner_name: &str, examiner_organization: &str) -> Self {
        Self {
            case_number: case_number.to_string(),
            examiner_name: examiner_name.to_string(),
            examiner_organization: examiner_organization.to_string(),
        }
    }

    /// Build the custody document from a [`ChainOfCustodyRecord`].
    pub fn build(&self, record: &ChainOfCustodyRecord) -> CustodyDocument {
        info!(
            case = %self.case_number,
            events = record.total_events,
            "Building chain of custody document"
        );

        let mut text = String::with_capacity(4096);

        // ── Header ──
        text.push_str("═══════════════════════════════════════════════════════════════════\n");
        text.push_str("                      CHAIN OF CUSTODY RECORD\n");
        text.push_str("═══════════════════════════════════════════════════════════════════\n\n");

        text.push_str(&format!("Case Number:    {}\n", self.case_number));
        text.push_str(&format!("Examiner:       {}\n", self.examiner_name));
        text.push_str(&format!("Organization:   {}\n", self.examiner_organization));
        text.push_str(&format!(
            "Generated:      {}\n",
            record.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        text.push_str(&format!("Total Events:   {}\n", record.total_events));
        text.push_str("\n");

        // ── Certification Statement ──
        text.push_str("CERTIFICATION: This document is a complete and unaltered record of\n");
        text.push_str("all actions performed on the evidence during the investigation. The\n");
        text.push_str("timeline below was generated from the cryptographically chained\n");
        text.push_str("ORACLE audit log. Any modification to this document will invalidate\n");
        text.push_str("the document hash printed at the end.\n\n");

        // ── Section 1: Device Interactions ──
        if !record.device_interactions.is_empty() {
            text.push_str("───────────────────────────────────────────────────────────────────\n");
            text.push_str("SECTION 1: DEVICE INTERACTIONS\n");
            text.push_str("───────────────────────────────────────────────────────────────────\n\n");
            Self::render_events(&mut text, &record.device_interactions);
        }

        // ── Section 2: Examiner Actions ──
        if !record.examiner_actions.is_empty() {
            text.push_str("───────────────────────────────────────────────────────────────────\n");
            text.push_str("SECTION 2: EXAMINER ACTIONS\n");
            text.push_str("───────────────────────────────────────────────────────────────────\n\n");
            Self::render_events(&mut text, &record.examiner_actions);
        }

        // ── Section 3: Evidence Processing ──
        if !record.evidence_processing.is_empty() {
            text.push_str("───────────────────────────────────────────────────────────────────\n");
            text.push_str("SECTION 3: EVIDENCE PROCESSING\n");
            text.push_str("───────────────────────────────────────────────────────────────────\n\n");
            Self::render_events(&mut text, &record.evidence_processing);
        }

        // ── Section 4: System Events ──
        if !record.system_events.is_empty() {
            text.push_str("───────────────────────────────────────────────────────────────────\n");
            text.push_str("SECTION 4: SYSTEM EVENTS\n");
            text.push_str("───────────────────────────────────────────────────────────────────\n\n");
            Self::render_events(&mut text, &record.system_events);
        }

        // ── Full Chronological Timeline ──
        text.push_str("═══════════════════════════════════════════════════════════════════\n");
        text.push_str("COMPLETE CHRONOLOGICAL TIMELINE\n");
        text.push_str("═══════════════════════════════════════════════════════════════════\n\n");

        for (idx, event) in record.timeline.iter().enumerate() {
            text.push_str(&format!(
                "  [{:04}] {} | {} | {}\n",
                idx + 1,
                event.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                Self::category_label(event.category),
                event.description,
            ));
        }

        text.push_str("\n");

        // ── Footer ──
        text.push_str("═══════════════════════════════════════════════════════════════════\n");
        text.push_str("END OF CHAIN OF CUSTODY RECORD\n");
        text.push_str("═══════════════════════════════════════════════════════════════════\n");

        // Compute document hash.
        let document_hash = Self::compute_hash(&text);

        text.push_str(&format!("\nDocument Hash (SHA-256): {}\n", document_hash));

        CustodyDocument {
            case_number: self.case_number.clone(),
            generated_at: Utc::now(),
            total_events: record.total_events,
            formatted_text: text,
            document_hash,
        }
    }

    /// Render a list of events into the output text.
    fn render_events(output: &mut String, events: &[CustodyEvent]) {
        for event in events {
            output.push_str(&format!(
                "  [{}] {}\n",
                event.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                event.description,
            ));
            output.push_str(&format!(
                "        Actor: {}  |  Audit Entry: #{} ({})\n\n",
                event.actor,
                event.source_entry_index,
                event.source_entry_id,
            ));
        }
    }

    /// Human-readable label for a custody event category.
    fn category_label(category: CustodyEventCategory) -> &'static str {
        match category {
            CustodyEventCategory::DeviceInteraction => "DEVICE    ",
            CustodyEventCategory::ExaminerAction => "EXAMINER  ",
            CustodyEventCategory::EvidenceProcessing => "PROCESSING",
            CustodyEventCategory::SystemEvent => "SYSTEM    ",
        }
    }

    /// Compute SHA-256 hash of the document text.
    fn compute_hash(text: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(text.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_audit::ChainOfCustodyRecord;

    fn empty_record() -> ChainOfCustodyRecord {
        ChainOfCustodyRecord {
            investigation_id: None,
            timeline: Vec::new(),
            device_interactions: Vec::new(),
            examiner_actions: Vec::new(),
            system_events: Vec::new(),
            evidence_processing: Vec::new(),
            generated_at: Utc::now(),
            total_events: 0,
        }
    }

    #[test]
    fn test_custody_document_empty_record() {
        let builder = CustodyDocumentBuilder::new(
            "CASE-2024-001",
            "Test Examiner",
            "Forensic Lab",
        );
        let doc = builder.build(&empty_record());

        assert_eq!(doc.case_number, "CASE-2024-001");
        assert_eq!(doc.total_events, 0);
        assert!(doc.formatted_text.contains("CHAIN OF CUSTODY RECORD"));
        assert!(doc.formatted_text.contains("CASE-2024-001"));
    }

    #[test]
    fn test_custody_document_hash_is_valid() {
        let builder = CustodyDocumentBuilder::new(
            "CASE-HASH",
            "Examiner A",
            "Lab A",
        );
        let doc = builder.build(&empty_record());

        assert_eq!(doc.document_hash.len(), 64);
        assert!(doc.document_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_custody_document_contains_certification() {
        let builder = CustodyDocumentBuilder::new(
            "CASE-CERT",
            "Examiner B",
            "Lab B",
        );
        let doc = builder.build(&empty_record());

        assert!(doc.formatted_text.contains("CERTIFICATION"));
        assert!(doc.formatted_text.contains("cryptographically chained"));
    }

    #[test]
    fn test_custody_document_with_events() {
        use oracle_audit::{CustodyEvent, CustodyEventCategory};
        use oracle_core::types::AuditOperationType;
        use uuid::Uuid;

        let event = CustodyEvent {
            source_entry_id: Uuid::new_v4(),
            source_entry_index: 1,
            timestamp: Utc::now(),
            category: CustodyEventCategory::DeviceInteraction,
            operation: AuditOperationType::DeviceConnected,
            actor: "SYSTEM".to_string(),
            description: "SYSTEM: Samsung SM-S928B (result: Pending)".to_string(),
            investigation_id: None,
        };

        let record = ChainOfCustodyRecord {
            investigation_id: None,
            timeline: vec![event.clone()],
            device_interactions: vec![event],
            examiner_actions: Vec::new(),
            system_events: Vec::new(),
            evidence_processing: Vec::new(),
            generated_at: Utc::now(),
            total_events: 1,
        };

        let builder = CustodyDocumentBuilder::new(
            "CASE-EVENT",
            "Examiner C",
            "Lab C",
        );
        let doc = builder.build(&record);

        assert_eq!(doc.total_events, 1);
        assert!(doc.formatted_text.contains("DEVICE INTERACTIONS"));
        assert!(doc.formatted_text.contains("Samsung SM-S928B"));
    }
}
