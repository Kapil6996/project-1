//! # Report Data Types
//!
//! Core types for the report generation pipeline. These structures represent
//! the complete investigation report data model before rendering to PDF or JSON.

use chrono::{DateTime, Utc};
use oracle_core::types::{
    ConfidenceClassification, ExaminerIdentity, InvestigationId, SecurityProtocol,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a generated report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReportId(pub Uuid);

impl ReportId {
    pub fn new() -> Self {
        ReportId(Uuid::new_v4())
    }
}

impl Default for ReportId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ReportId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The type of report being generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportType {
    /// Executive summary — high-level findings for non-technical audiences.
    Executive,
    /// Technical findings — detailed analysis with full evidence citations.
    Technical,
    /// Evidence appendix — complete artifact inventory with hashes.
    EvidenceAppendix,
    /// Chain of custody — audit trail document.
    ChainOfCustody,
    /// Complete report — all sections combined.
    Complete,
}

impl std::fmt::Display for ReportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportType::Executive => write!(f, "Executive Summary"),
            ReportType::Technical => write!(f, "Technical Findings"),
            ReportType::EvidenceAppendix => write!(f, "Evidence Appendix"),
            ReportType::ChainOfCustody => write!(f, "Chain of Custody"),
            ReportType::Complete => write!(f, "Complete Report"),
        }
    }
}

/// A single forensic finding for inclusion in the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportFinding {
    /// Sequential finding number (F-001, F-002, etc.)
    pub finding_number: String,
    /// One-line summary of the finding.
    pub title: String,
    /// Detailed narrative description.
    pub description: String,
    /// Network SSID involved (if applicable).
    pub network_ssid: Option<String>,
    /// Network BSSID involved (if applicable).
    pub network_bssid: Option<String>,
    /// Security protocol observed.
    pub security_protocol: Option<SecurityProtocol>,
    /// When the event occurred.
    pub event_time: Option<DateTime<Utc>>,
    /// Confidence score for this finding.
    pub confidence_score: f64,
    /// Court-facing classification.
    pub confidence_classification: ConfidenceClassification,
    /// Number of corroborating sources.
    pub corroboration_count: usize,
    /// Names/descriptions of corroborating sources.
    pub corroborating_sources: Vec<String>,
    /// Active contradictions for this finding.
    pub contradictions: Vec<String>,
    /// Whether this finding was overridden by an examiner.
    pub examiner_override: bool,
}

/// An evidence artifact entry for the evidence appendix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEntry {
    /// Sequential evidence number (E-001, E-002, etc.)
    pub evidence_number: String,
    /// Original filename or path on the device.
    pub original_path: String,
    /// SHA-256 hash of the artifact.
    pub sha256_hash: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// When the artifact was acquired.
    pub acquired_at: DateTime<Utc>,
    /// Artifact class description.
    pub artifact_class: String,
    /// How many findings reference this artifact.
    pub referenced_by_findings: Vec<String>,
}

/// Report metadata and investigation context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    /// Report unique identifier.
    pub report_id: ReportId,
    /// Investigation identifier.
    pub investigation_id: InvestigationId,
    /// Report type.
    pub report_type: ReportType,
    /// Case number or reference.
    pub case_number: String,
    /// The forensic examiner who conducted the investigation.
    pub examiner: ExaminerIdentity,
    /// When the report was generated.
    pub generated_at: DateTime<Utc>,
    /// ORACLE platform version.
    pub platform_version: String,
    /// Confidence model version used.
    pub model_version: String,
}

/// The complete investigation summary for the executive report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationSummary {
    /// Case number.
    pub case_number: String,
    /// Brief description of the investigation purpose.
    pub purpose: String,
    /// Device examined (manufacturer + model + serial).
    pub device_description: String,
    /// Date range of the investigation window.
    pub investigation_window: String,
    /// Total number of artifacts acquired.
    pub total_artifacts: usize,
    /// Total number of findings.
    pub total_findings: usize,
    /// Number of high-confidence findings.
    pub high_confidence_findings: usize,
    /// Number of contradicted findings.
    pub contradicted_findings: usize,
    /// Number of anomalies detected.
    pub anomalies_detected: usize,
    /// Key findings summary (top 5).
    pub key_findings: Vec<String>,
}

/// A complete forensic report ready for rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicReport {
    /// Report metadata.
    pub metadata: ReportMetadata,
    /// Investigation summary.
    pub summary: InvestigationSummary,
    /// All findings, ordered by finding number.
    pub findings: Vec<ReportFinding>,
    /// Evidence appendix entries.
    pub evidence_entries: Vec<EvidenceEntry>,
    /// Methodology disclosure text.
    pub methodology_disclosure: String,
    /// Cryptographic signature of the report (SHA-256 of the JSON content).
    pub report_hash: Option<String>,
}
