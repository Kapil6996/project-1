//! # Executive Report Generator
//!
//! Produces an executive-level forensic report suitable for non-technical
//! audiences such as prosecutors, judges, and senior investigators. The report
//! presents a high-level network overview, timeline highlights, and a
//! methodology statement in plain language.
//!
//! The executive report deliberately omits raw artifact hashes, parser details,
//! and byte-level provenance — those belong in the [`crate::technical`] report.

use chrono::{DateTime, Utc};
use oracle_core::types::{ConfidenceClassification, NetworkRole, SecurityProtocol};
use oracle_correlate::timeline::Timeline;
use serde::{Deserialize, Serialize};

use crate::summary::InvestigationSummaryV2;

// ──────────────────────────────────────────────────────────────────────────────
// Data Structures
// ──────────────────────────────────────────────────────────────────────────────

/// The significance level of a timeline highlight.
///
/// Used to flag events that deserve special attention in the executive summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Significance {
    /// Event with major forensic implications (e.g., first connection to a suspect network).
    High,
    /// Event of moderate interest (e.g., network transition).
    Medium,
    /// Event of minor note (e.g., routine DHCP lease renewal).
    Low,
}

impl std::fmt::Display for Significance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Significance::High => write!(f, "HIGH"),
            Significance::Medium => write!(f, "MEDIUM"),
            Significance::Low => write!(f, "LOW"),
        }
    }
}

/// Summary of a single network encountered during the investigation.
///
/// Provides the executive audience with a quick overview of each network's
/// identity, security posture, and the device's relationship to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSummary {
    /// The network's SSID (human-readable name).
    pub ssid: String,
    /// The network's BSSID (MAC address of the access point).
    pub bssid: String,
    /// Security protocol in use on this network.
    pub security: SecurityProtocol,
    /// Earliest observed interaction with this network.
    pub first_seen: DateTime<Utc>,
    /// Most recent observed interaction with this network.
    pub last_seen: DateTime<Utc>,
    /// Whether the device was a client or acting as a hotspot.
    pub role: NetworkRole,
    /// Confidence classification for the network identification.
    pub confidence: ConfidenceClassification,
}

/// A highlighted event from the timeline selected for executive attention.
///
/// Timeline highlights are curated from the full timeline to surface the
/// most forensically significant events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineHighlight {
    /// UTC timestamp of the event.
    pub timestamp: DateTime<Utc>,
    /// Human-readable description of the event.
    pub description: String,
    /// Forensic significance rating.
    pub significance: Significance,
}

/// The complete executive report.
///
/// Assembles the investigation summary, network overview, timeline highlights,
/// and methodology statement into a single document suitable for court
/// presentation or senior leadership briefing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveReport {
    /// Investigation summary with aggregate statistics.
    pub summary: InvestigationSummaryV2,
    /// Overview of all networks encountered, sorted by first-seen time.
    pub network_overview: Vec<NetworkSummary>,
    /// Curated timeline highlights, sorted chronologically.
    pub timeline_highlights: Vec<TimelineHighlight>,
    /// Methodology disclosure statement explaining tools and techniques used.
    pub methodology_statement: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Report Generator
// ──────────────────────────────────────────────────────────────────────────────

/// The ORACLE platform version embedded in methodology disclosures.
const PLATFORM_VERSION: &str = "1.0.0-alpha.1";

/// Generates an [`ExecutiveReport`] from investigation components.
///
/// The generator takes a pre-built summary, network metadata, and the raw
/// timeline, and produces a polished executive report with automatically
/// generated methodology disclosure and curated highlights.
pub struct ExecutiveReportGenerator;

impl ExecutiveReportGenerator {
    /// Generate an executive report from the provided data.
    ///
    /// # Arguments
    ///
    /// * `summary` — The investigation summary produced by [`SummaryBuilder`](crate::summary::SummaryBuilder).
    /// * `networks` — Network summaries for each discovered network.
    /// * `timeline` — The unified forensic timeline from the correlation engine.
    ///
    /// # Returns
    ///
    /// A fully assembled [`ExecutiveReport`] ready for rendering or export.
    pub fn generate(
        summary: InvestigationSummaryV2,
        networks: Vec<NetworkSummary>,
        timeline: &Timeline,
    ) -> ExecutiveReport {
        let highlights = Self::extract_highlights(timeline);
        let methodology = Self::generate_methodology(&summary);

        ExecutiveReport {
            summary,
            network_overview: networks,
            timeline_highlights: highlights,
            methodology_statement: methodology,
        }
    }

    /// Extract timeline highlights from session data.
    ///
    /// Heuristic: session starts are Medium significance, session starts with
    /// high confidence are High significance, gaps and overlaps are High.
    fn extract_highlights(timeline: &Timeline) -> Vec<TimelineHighlight> {
        let mut highlights = Vec::new();

        // Highlight session starts.
        for session in &timeline.sessions {
            let significance = if session.confidence >= 0.90 {
                Significance::High
            } else if session.confidence >= 0.60 {
                Significance::Medium
            } else {
                Significance::Low
            };

            highlights.push(TimelineHighlight {
                timestamp: session.start_time,
                description: format!(
                    "Connection session started on network \"{}\" (confidence: {:.2})",
                    session.network_label, session.confidence,
                ),
                significance,
            });
        }

        // Highlight gaps (always High significance — device unaccounted for).
        for gap in &timeline.gaps {
            highlights.push(TimelineHighlight {
                timestamp: gap.start_time,
                description: format!(
                    "Activity gap detected: no network events for {} minutes",
                    gap.duration.num_minutes(),
                ),
                significance: Significance::High,
            });
        }

        // Highlight overlaps (always High significance — forensic anomaly).
        for overlap in &timeline.overlaps {
            highlights.push(TimelineHighlight {
                timestamp: overlap.overlap_start,
                description: format!(
                    "Simultaneous connection anomaly: \"{}\" and \"{}\" overlap for {} seconds",
                    overlap.network_a_label,
                    overlap.network_b_label,
                    (overlap.overlap_end - overlap.overlap_start).num_seconds(),
                ),
                significance: Significance::High,
            });
        }

        // Sort chronologically.
        highlights.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        highlights
    }

    /// Generate the methodology disclosure text.
    fn generate_methodology(summary: &InvestigationSummaryV2) -> String {
        format!(
            "METHODOLOGY DISCLOSURE\n\
             \n\
             This executive report was generated by the ORACLE Android Network Forensics \
             Platform version {}.\n\
             \n\
             The investigation examined forensic artifacts extracted from the target device \
             described as \"{}\". All network connection events were reconstructed from \
             multiple independent artifact sources and cross-correlated to establish a \
             unified timeline.\n\
             \n\
             Confidence scores were computed using the ORACLE Confidence Model v1.0.0, \
             which evaluates four factors: Source Reliability (30%), Temporal Consistency \
             (25%), Corroboration (30%), and Artifact Freshness (15%). Findings marked \
             \"DEFINITIVE\" (score ≥ 0.95) are supported by multiple independent sources \
             with no contradictions.\n\
             \n\
             All artifact integrity was verified using SHA-256 cryptographic hashing. \
             All timestamps were normalized to Coordinated Universal Time (UTC). \
             A complete chain of custody record is maintained via the ORACLE audit \
             subsystem's cryptographically chained append-only log.\n\
             \n\
             Report prepared by {} for case {}.",
            PLATFORM_VERSION,
            summary.device_summary,
            summary.examiner_name,
            summary.case_number,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use oracle_core::types::InvestigationId;
    use oracle_correlate::events::{
        ConnectionEvent, ConnectionEventId, ConnectionEventType, EventEvidence,
    };
    use oracle_correlate::timeline::TimelineBuilder;
    use oracle_correlate::types::NetworkIdentityId;
    use oracle_core::types::{ArtifactId, NetworkRole, RecordId, SecurityProtocol};

    use crate::summary::{CaseInfo, Finding, InvestigationSummaryV2};

    fn make_event(
        event_type: ConnectionEventType,
        net_id: NetworkIdentityId,
        label: &str,
        ts: DateTime<Utc>,
        confidence: f64,
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
                description: "test evidence".to_string(),
                timestamp: ts,
                confidence,
            }],
            corroboration_count: 2,
            confidence,
        }
    }

    fn sample_summary() -> InvestigationSummaryV2 {
        InvestigationSummaryV2 {
            investigation_id: InvestigationId::new(),
            case_number: "CASE-EXEC-001".to_string(),
            examiner_name: "Dr. Jane Smith".to_string(),
            device_summary: "Samsung Galaxy S24 Ultra (SN: R5CX12345)".to_string(),
            total_artifacts: 12,
            total_networks_found: 3,
            total_connections: 47,
            key_findings: vec![
                Finding {
                    description: "Connected to suspect network".to_string(),
                    confidence: ConfidenceClassification::Definitive,
                    supporting_evidence_count: 5,
                },
            ],
            generated_at: Utc::now(),
        }
    }

    fn sample_networks() -> Vec<NetworkSummary> {
        let now = Utc::now();
        vec![
            NetworkSummary {
                ssid: "HomeWiFi".to_string(),
                bssid: "AA:BB:CC:DD:EE:01".to_string(),
                security: SecurityProtocol::Wpa2Psk,
                first_seen: now - Duration::hours(48),
                last_seen: now - Duration::hours(1),
                role: NetworkRole::DeviceAsClient,
                confidence: ConfidenceClassification::Definitive,
            },
            NetworkSummary {
                ssid: "CoffeeShop".to_string(),
                bssid: "11:22:33:44:55:66".to_string(),
                security: SecurityProtocol::Open,
                first_seen: now - Duration::hours(24),
                last_seen: now - Duration::hours(20),
                role: NetworkRole::DeviceAsClient,
                confidence: ConfidenceClassification::High,
            },
        ]
    }

    #[test]
    fn test_executive_report_includes_network_overview() {
        let summary = sample_summary();
        let networks = sample_networks();
        let timeline = TimelineBuilder::new().build(Vec::new());

        let report = ExecutiveReportGenerator::generate(summary, networks, &timeline);

        assert_eq!(report.network_overview.len(), 2);
        assert_eq!(report.network_overview[0].ssid, "HomeWiFi");
        assert_eq!(report.network_overview[1].ssid, "CoffeeShop");
    }

    #[test]
    fn test_executive_report_methodology_present() {
        let summary = sample_summary();
        let timeline = TimelineBuilder::new().build(Vec::new());

        let report = ExecutiveReportGenerator::generate(summary, Vec::new(), &timeline);

        assert!(report.methodology_statement.contains("METHODOLOGY DISCLOSURE"));
        assert!(report.methodology_statement.contains("SHA-256"));
        assert!(report.methodology_statement.contains("Dr. Jane Smith"));
    }

    #[test]
    fn test_executive_report_highlights_sessions() {
        let net_a = NetworkIdentityId::new();
        let ts = Utc::now();

        let events = vec![
            make_event(ConnectionEventType::Connected, net_a, "TestNet", ts, 0.92),
            make_event(
                ConnectionEventType::Disconnected,
                net_a,
                "TestNet",
                ts + Duration::minutes(15),
                0.92,
            ),
        ];
        let timeline = TimelineBuilder::new().build(events);
        let summary = sample_summary();

        let report = ExecutiveReportGenerator::generate(summary, Vec::new(), &timeline);

        assert!(!report.timeline_highlights.is_empty());
        assert!(report.timeline_highlights[0]
            .description
            .contains("TestNet"));
    }

    #[test]
    fn test_executive_report_highlights_gaps() {
        let net_a = NetworkIdentityId::new();
        let ts = Utc::now();

        let events = vec![
            make_event(ConnectionEventType::Connected, net_a, "Net1", ts, 0.85),
            make_event(
                ConnectionEventType::Disconnected,
                net_a,
                "Net1",
                ts + Duration::minutes(5),
                0.85,
            ),
            // 3-hour gap exceeds session timeout
            make_event(
                ConnectionEventType::Connected,
                net_a,
                "Net1",
                ts + Duration::hours(3),
                0.85,
            ),
        ];
        let timeline = TimelineBuilder::new().build(events);
        let summary = sample_summary();

        let report = ExecutiveReportGenerator::generate(summary, Vec::new(), &timeline);

        let gap_highlights: Vec<_> = report
            .timeline_highlights
            .iter()
            .filter(|h| h.description.contains("gap"))
            .collect();
        assert!(
            !gap_highlights.is_empty(),
            "Should detect the 3-hour gap as a highlight"
        );
    }
}
