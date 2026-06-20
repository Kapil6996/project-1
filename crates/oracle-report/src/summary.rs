//! # Investigation Summary Builder
//!
//! Constructs a high-level [`InvestigationSummary`] from investigation data
//! including timeline events, confidence scores, and case metadata. The summary
//! serves as the foundation for both executive and technical reports.
//!
//! The builder automatically extracts key findings by filtering for high-confidence
//! events, counts unique networks, and computes aggregate statistics suitable for
//! court presentation.

use chrono::{DateTime, Utc};
use oracle_confidence::scorer::ConfidenceScore;
use oracle_core::types::{ConfidenceClassification, InvestigationId};
use oracle_correlate::timeline::Timeline;
use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// Data Structures
// ──────────────────────────────────────────────────────────────────────────────

/// A single forensic finding distilled from correlated evidence.
///
/// Each finding carries a confidence classification and a count of how many
/// independent pieces of evidence support it, enabling the examiner and the
/// court to assess the strength of the claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Human-readable description of the finding.
    pub description: String,
    /// Court-facing confidence classification for this finding.
    pub confidence: ConfidenceClassification,
    /// Number of independent evidence items supporting this finding.
    pub supporting_evidence_count: u32,
}

/// Case-level information provided by the examiner at investigation start.
///
/// This metadata is embedded verbatim in every generated report for
/// traceability and chain-of-custody purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseInfo {
    /// Case or docket number assigned by the forensic laboratory.
    pub case_number: String,
    /// Full legal name of the examiner conducting the investigation.
    pub examiner_name: String,
    /// Human-readable description of the target device.
    pub device_summary: String,
}

/// A comprehensive summary of an investigation's results.
///
/// Aggregates timeline statistics, network counts, and key findings into a
/// single structure suitable for inclusion in executive reports, JSON exports,
/// and court filings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationSummaryV2 {
    /// The investigation this summary belongs to.
    pub investigation_id: InvestigationId,
    /// Case or docket number.
    pub case_number: String,
    /// Name of the examiner who conducted the investigation.
    pub examiner_name: String,
    /// Human-readable device description (manufacturer + model + serial).
    pub device_summary: String,
    /// Total number of forensic artifacts processed.
    pub total_artifacts: u32,
    /// Total number of unique Wi-Fi networks discovered.
    pub total_networks_found: u32,
    /// Total number of connection events reconstructed.
    pub total_connections: u32,
    /// Key findings extracted from the investigation, sorted by confidence.
    pub key_findings: Vec<Finding>,
    /// UTC timestamp of when this summary was generated.
    pub generated_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Summary Builder
// ──────────────────────────────────────────────────────────────────────────────

/// Builds an [`InvestigationSummaryV2`] from investigation components.
///
/// The builder collects timeline data, confidence scores, and case metadata,
/// then synthesizes them into a unified summary. Key findings are automatically
/// extracted from sessions with high-confidence scores.
pub struct SummaryBuilder;

impl SummaryBuilder {
    /// Build an investigation summary from the provided data.
    ///
    /// # Arguments
    ///
    /// * `investigation_id` — The unique investigation identifier.
    /// * `case_info` — Examiner-provided case metadata.
    /// * `timeline` — The unified forensic timeline from the correlation engine.
    /// * `scores` — Confidence scores computed for each correlated finding.
    ///
    /// # Returns
    ///
    /// A fully populated [`InvestigationSummaryV2`] with key findings derived
    /// from the highest-confidence timeline sessions.
    pub fn build(
        investigation_id: InvestigationId,
        case_info: &CaseInfo,
        timeline: &Timeline,
        scores: &[ConfidenceScore],
    ) -> InvestigationSummaryV2 {
        // Count unique networks from timeline sessions.
        let unique_networks: std::collections::HashSet<_> = timeline
            .sessions
            .iter()
            .map(|s| &s.network_id)
            .collect();

        let total_connections = timeline.total_events as u32;

        // Extract key findings from timeline sessions paired with scores.
        // Each session with a matching score (or a reasonable default) produces
        // a finding if the confidence is at least Moderate.
        let mut findings = Vec::new();

        for (idx, session) in timeline.sessions.iter().enumerate() {
            let score_value = scores
                .get(idx)
                .map(|s| s.score)
                .unwrap_or(session.confidence);

            let classification = ConfidenceClassification::from_score(score_value);

            // Only surface Moderate-or-better findings as "key" findings.
            if classification >= ConfidenceClassification::Moderate {
                let description = format!(
                    "Network \"{}\" connection session detected ({} event(s), confidence {:.2})",
                    session.network_label,
                    session.events.len(),
                    score_value,
                );

                findings.push(Finding {
                    description,
                    confidence: classification,
                    supporting_evidence_count: session.events.len() as u32,
                });
            }
        }

        // Sort findings by confidence (highest first), then by evidence count.
        findings.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| b.supporting_evidence_count.cmp(&a.supporting_evidence_count))
        });

        InvestigationSummaryV2 {
            investigation_id,
            case_number: case_info.case_number.clone(),
            examiner_name: case_info.examiner_name.clone(),
            device_summary: case_info.device_summary.clone(),
            total_artifacts: 0, // Will be set by the caller or report generator.
            total_networks_found: unique_networks.len() as u32,
            total_connections,
            key_findings: findings,
            generated_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use oracle_confidence::scorer::{ConfidenceScore, FactorBreakdown, ScoreId};
    use oracle_core::types::InvestigationId;
    use oracle_correlate::events::{ConnectionEvent, ConnectionEventId, ConnectionEventType, EventEvidence};
    use oracle_correlate::timeline::{TimelineBuilder, Timeline};
    use oracle_correlate::types::NetworkIdentityId;
    use oracle_core::types::{ArtifactId, NetworkRole, RecordId, SecurityProtocol};

    fn make_event(
        event_type: ConnectionEventType,
        net_id: NetworkIdentityId,
        label: &str,
        ts: DateTime<Utc>,
    ) -> ConnectionEvent {
        ConnectionEvent {
            id: ConnectionEventId::new(),
            event_type,
            network_id: net_id,
            network_label: label.to_string(),
            timestamp: ts,
            security_protocol: SecurityProtocol::Wpa2Psk,
            network_role: NetworkRole::DeviceAsClient,
            ip_address: None,
            evidence: vec![EventEvidence {
                artifact_id: ArtifactId::new(),
                record_id: RecordId::new(),
                description: "test".to_string(),
                timestamp: ts,
                confidence: 0.85,
            }],
            corroboration_count: 2,
            confidence: 0.85,
        }
    }

    fn make_score(score: f64) -> ConfidenceScore {
        ConfidenceScore {
            id: ScoreId::new(),
            model_version: "1.0.0".to_string(),
            score,
            classification: ConfidenceClassification::from_score(score),
            factors: FactorBreakdown {
                source_reliability: 0.90,
                temporal_consistency: 0.80,
                corroboration: 0.75,
                freshness: 1.0,
            },
            contradiction_applied: false,
            raw_weighted_sum: score,
            computed_at: Utc::now(),
        }
    }

    fn sample_timeline() -> Timeline {
        let net_a = NetworkIdentityId::new();
        let net_b = NetworkIdentityId::new();
        let ts = Utc::now();

        let events = vec![
            make_event(ConnectionEventType::Connected, net_a, "HomeWiFi", ts),
            make_event(
                ConnectionEventType::DhcpLeaseAcquired,
                net_a,
                "HomeWiFi",
                ts + Duration::seconds(5),
            ),
            make_event(
                ConnectionEventType::Disconnected,
                net_a,
                "HomeWiFi",
                ts + Duration::minutes(30),
            ),
            make_event(
                ConnectionEventType::Connected,
                net_b,
                "CoffeeShop",
                ts + Duration::hours(2),
            ),
        ];

        TimelineBuilder::new().build(events)
    }

    #[test]
    fn test_summary_generation_with_sample_data() {
        let timeline = sample_timeline();
        let scores = vec![make_score(0.92), make_score(0.75)];
        let case_info = CaseInfo {
            case_number: "CASE-2024-001".to_string(),
            examiner_name: "Dr. Jane Smith".to_string(),
            device_summary: "Samsung Galaxy S24 Ultra (SN: R5CX12345)".to_string(),
        };
        let inv_id = InvestigationId::new();

        let summary = SummaryBuilder::build(inv_id, &case_info, &timeline, &scores);

        assert_eq!(summary.case_number, "CASE-2024-001");
        assert_eq!(summary.examiner_name, "Dr. Jane Smith");
        assert_eq!(summary.investigation_id, inv_id);
        assert_eq!(summary.total_networks_found, 2);
        assert_eq!(summary.total_connections, 4);
        assert!(!summary.key_findings.is_empty());
        // The first finding should have the highest confidence.
        assert!(summary.key_findings[0].confidence >= summary.key_findings.last().map_or(
            ConfidenceClassification::Low,
            |f| f.confidence,
        ));
    }

    #[test]
    fn test_summary_empty_timeline() {
        let timeline = TimelineBuilder::new().build(Vec::new());
        let scores: Vec<ConfidenceScore> = Vec::new();
        let case_info = CaseInfo {
            case_number: "CASE-EMPTY".to_string(),
            examiner_name: "Examiner A".to_string(),
            device_summary: "Unknown device".to_string(),
        };

        let summary = SummaryBuilder::build(InvestigationId::new(), &case_info, &timeline, &scores);

        assert_eq!(summary.total_networks_found, 0);
        assert_eq!(summary.total_connections, 0);
        assert!(summary.key_findings.is_empty());
    }

    #[test]
    fn test_summary_findings_sorted_by_confidence() {
        let net_a = NetworkIdentityId::new();
        let net_b = NetworkIdentityId::new();
        let ts = Utc::now();

        let events = vec![
            make_event(ConnectionEventType::Connected, net_a, "LowConf", ts),
            make_event(
                ConnectionEventType::Connected,
                net_b,
                "HighConf",
                ts + Duration::hours(2),
            ),
        ];
        let timeline = TimelineBuilder::new().build(events);
        // First session gets low score, second gets high score.
        let scores = vec![make_score(0.55), make_score(0.97)];
        let case_info = CaseInfo {
            case_number: "CASE-SORT".to_string(),
            examiner_name: "Examiner B".to_string(),
            device_summary: "Test Device".to_string(),
        };

        let summary = SummaryBuilder::build(InvestigationId::new(), &case_info, &timeline, &scores);

        assert!(summary.key_findings.len() >= 2);
        assert!(summary.key_findings[0].confidence >= summary.key_findings[1].confidence);
    }
}
