//! # Technical Findings Report
//!
//! Generates a detailed technical report for forensic experts, defense counsel,
//! and peer reviewers. Unlike the executive report, the technical report includes
//! full artifact inventories, parser metadata, byte-level provenance references,
//! and the complete confidence score distribution.
//!
//! This report is designed to withstand Daubert/Frye challenges by providing
//! complete transparency into the forensic analysis pipeline.

use oracle_core::types::{ArtifactClass, ArtifactId, ConfidenceClassification};
use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// Data Structures
// ──────────────────────────────────────────────────────────────────────────────

/// Detailed metadata for a single forensic artifact.
///
/// Provides the technical reviewer with full provenance information including
/// the parser used, the number of records extracted, and the cryptographic
/// hash of the original file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactDetail {
    /// Unique identifier for this artifact within the evidence store.
    pub artifact_id: ArtifactId,
    /// Classification of the artifact (e.g., WifiConfigStore, DhcpLeases).
    pub class: ArtifactClass,
    /// Original path of the artifact on the target device.
    pub original_path: String,
    /// SHA-256 hash of the raw artifact bytes at time of acquisition.
    pub sha256: String,
    /// Size of the artifact in bytes.
    pub file_size: u64,
    /// Identifier of the parser that processed this artifact.
    pub parser_used: String,
    /// Number of evidence records extracted by the parser.
    pub records_extracted: u32,
}

/// Summary of the normalization pipeline's output.
///
/// Documents how many records were processed through each normalization
/// stage, enabling reviewers to identify any data loss or transformation
/// issues.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizationSummary {
    /// Total number of raw parsed records before normalization.
    pub total_parsed: u32,
    /// Total number of records after normalization.
    pub total_normalized: u32,
    /// Number of records dropped during normalization (e.g., duplicates, invalids).
    pub records_dropped: u32,
    /// Percentage of records successfully normalized.
    pub normalization_rate: f64,
}

/// Summary of correlation engine findings.
///
/// Captures how many connection events were reconstructed and how many
/// distinct sessions were identified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationSummary {
    /// Total number of reconstructed connection events.
    pub total_events_reconstructed: u32,
    /// Number of unique network sessions identified.
    pub total_sessions: u32,
    /// Number of temporal gaps detected between sessions.
    pub gaps_detected: u32,
    /// Number of session overlaps (potential anomalies).
    pub overlaps_detected: u32,
}

/// Distribution of confidence scores across all findings.
///
/// Provides a statistical overview of how evidence quality is distributed,
/// which is critical for assessing the overall reliability of the investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceDistribution {
    /// Number of findings classified as Definitive (≥ 0.95).
    pub definitive: u32,
    /// Number of findings classified as High (0.80–0.94).
    pub high: u32,
    /// Number of findings classified as Moderate (0.50–0.79).
    pub moderate: u32,
    /// Number of findings classified as Low (< 0.50).
    pub low: u32,
    /// Number of findings with active contradictions.
    pub contradicted: u32,
}

/// The complete technical findings report.
///
/// Contains every detail a forensic peer reviewer would need to independently
/// verify the investigation's conclusions: artifact inventories, parser metadata,
/// normalization statistics, correlation results, anomalies, and the full
/// confidence score distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnicalReport {
    /// Detailed information for every artifact processed.
    pub all_artifacts: Vec<ArtifactDetail>,
    /// Total number of parsed records across all artifacts.
    pub all_parsed_records_count: u32,
    /// Summary of the normalization pipeline.
    pub normalization_summary: NormalizationSummary,
    /// Summary of correlation engine results.
    pub correlation_findings: CorrelationSummary,
    /// Anomalies detected during analysis (free-form descriptions).
    pub anomalies: Vec<String>,
    /// Distribution of confidence classifications across all findings.
    pub confidence_distribution: ConfidenceDistribution,
}

// ──────────────────────────────────────────────────────────────────────────────
// Report Generator
// ──────────────────────────────────────────────────────────────────────────────

/// Input data for the technical report generator.
///
/// Bundles all the raw data needed to produce a [`TechnicalReport`].
/// Callers construct this from the outputs of the parsing, normalization,
/// and correlation pipelines.
#[derive(Debug, Clone)]
pub struct TechnicalReportInput {
    /// Detailed metadata for each artifact.
    pub artifacts: Vec<ArtifactDetail>,
    /// Total number of parsed records.
    pub total_parsed_records: u32,
    /// Total number of normalized records.
    pub total_normalized_records: u32,
    /// Number of records dropped during normalization.
    pub records_dropped: u32,
    /// Correlation results summary.
    pub correlation: CorrelationSummary,
    /// Detected anomalies.
    pub anomalies: Vec<String>,
    /// All confidence classifications for distribution computation.
    pub confidence_classifications: Vec<ConfidenceClassification>,
}

/// Generates a [`TechnicalReport`] from investigation pipeline outputs.
///
/// The generator computes derived statistics (normalization rate, confidence
/// distribution) from the raw input data.
pub struct TechnicalReportGenerator;

impl TechnicalReportGenerator {
    /// Generate a technical report from the provided input data.
    ///
    /// # Arguments
    ///
    /// * `input` — Aggregated data from parsing, normalization, correlation, and
    ///   confidence scoring pipelines.
    ///
    /// # Returns
    ///
    /// A fully populated [`TechnicalReport`] with computed statistics.
    pub fn generate(input: TechnicalReportInput) -> TechnicalReport {
        let normalization_rate = if input.total_parsed_records > 0 {
            f64::from(input.total_normalized_records) / f64::from(input.total_parsed_records)
        } else {
            0.0
        };

        let normalization_summary = NormalizationSummary {
            total_parsed: input.total_parsed_records,
            total_normalized: input.total_normalized_records,
            records_dropped: input.records_dropped,
            normalization_rate,
        };

        let confidence_distribution = Self::compute_distribution(&input.confidence_classifications);

        TechnicalReport {
            all_artifacts: input.artifacts,
            all_parsed_records_count: input.total_parsed_records,
            normalization_summary,
            correlation_findings: input.correlation,
            anomalies: input.anomalies,
            confidence_distribution,
        }
    }

    /// Compute the confidence score distribution from classifications.
    fn compute_distribution(classifications: &[ConfidenceClassification]) -> ConfidenceDistribution {
        let mut dist = ConfidenceDistribution {
            definitive: 0,
            high: 0,
            moderate: 0,
            low: 0,
            contradicted: 0,
        };

        for class in classifications {
            match class {
                ConfidenceClassification::Definitive => dist.definitive += 1,
                ConfidenceClassification::High => dist.high += 1,
                ConfidenceClassification::Moderate => dist.moderate += 1,
                ConfidenceClassification::Low => dist.low += 1,
                ConfidenceClassification::Contradicted => dist.contradicted += 1,
            }
        }

        dist
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_core::types::{ArtifactClass, ArtifactId, ConfidenceClassification};

    fn sample_artifact(idx: usize) -> ArtifactDetail {
        ArtifactDetail {
            artifact_id: ArtifactId::new(),
            class: if idx % 2 == 0 {
                ArtifactClass::WifiConfigStore
            } else {
                ArtifactClass::DhcpLeases
            },
            original_path: format!("/data/misc/wifi/artifact_{}.xml", idx),
            sha256: format!("{:064x}", idx),
            file_size: 2048 * (idx as u64 + 1),
            parser_used: format!("parser_v{}", idx),
            records_extracted: (idx as u32 + 1) * 10,
        }
    }

    fn sample_input() -> TechnicalReportInput {
        TechnicalReportInput {
            artifacts: vec![sample_artifact(0), sample_artifact(1), sample_artifact(2)],
            total_parsed_records: 100,
            total_normalized_records: 95,
            records_dropped: 5,
            correlation: CorrelationSummary {
                total_events_reconstructed: 47,
                total_sessions: 8,
                gaps_detected: 2,
                overlaps_detected: 1,
            },
            anomalies: vec![
                "Clock skew detected on artifact_1.xml".to_string(),
                "Duplicate BSSID across different SSIDs".to_string(),
            ],
            confidence_classifications: vec![
                ConfidenceClassification::Definitive,
                ConfidenceClassification::High,
                ConfidenceClassification::High,
                ConfidenceClassification::Moderate,
                ConfidenceClassification::Low,
                ConfidenceClassification::Contradicted,
            ],
        }
    }

    #[test]
    fn test_technical_report_artifact_count() {
        let input = sample_input();
        let report = TechnicalReportGenerator::generate(input);

        assert_eq!(report.all_artifacts.len(), 3);
        assert_eq!(report.all_parsed_records_count, 100);
    }

    #[test]
    fn test_technical_report_normalization_rate() {
        let input = sample_input();
        let report = TechnicalReportGenerator::generate(input);

        assert!((report.normalization_summary.normalization_rate - 0.95).abs() < f64::EPSILON);
        assert_eq!(report.normalization_summary.records_dropped, 5);
    }

    #[test]
    fn test_technical_report_confidence_distribution() {
        let input = sample_input();
        let report = TechnicalReportGenerator::generate(input);

        assert_eq!(report.confidence_distribution.definitive, 1);
        assert_eq!(report.confidence_distribution.high, 2);
        assert_eq!(report.confidence_distribution.moderate, 1);
        assert_eq!(report.confidence_distribution.low, 1);
        assert_eq!(report.confidence_distribution.contradicted, 1);
    }

    #[test]
    fn test_technical_report_anomalies() {
        let input = sample_input();
        let report = TechnicalReportGenerator::generate(input);

        assert_eq!(report.anomalies.len(), 2);
        assert!(report.anomalies[0].contains("Clock skew"));
    }

    #[test]
    fn test_technical_report_correlation_findings() {
        let input = sample_input();
        let report = TechnicalReportGenerator::generate(input);

        assert_eq!(report.correlation_findings.total_sessions, 8);
        assert_eq!(report.correlation_findings.gaps_detected, 2);
        assert_eq!(report.correlation_findings.overlaps_detected, 1);
    }

    #[test]
    fn test_technical_report_empty_input() {
        let input = TechnicalReportInput {
            artifacts: Vec::new(),
            total_parsed_records: 0,
            total_normalized_records: 0,
            records_dropped: 0,
            correlation: CorrelationSummary {
                total_events_reconstructed: 0,
                total_sessions: 0,
                gaps_detected: 0,
                overlaps_detected: 0,
            },
            anomalies: Vec::new(),
            confidence_classifications: Vec::new(),
        };

        let report = TechnicalReportGenerator::generate(input);

        assert!(report.all_artifacts.is_empty());
        assert_eq!(report.all_parsed_records_count, 0);
        assert_eq!(report.normalization_summary.normalization_rate, 0.0);
        assert_eq!(report.confidence_distribution.definitive, 0);
    }
}
