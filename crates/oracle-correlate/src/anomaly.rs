//! # Anomaly Detector & Contradiction Handler
//!
//! Identifies temporal anomalies and logical contradictions in the forensic
//! timeline and evidence corpus. These findings are critical for court
//! presentation — both for strengthening the investigation's credibility
//! (by disclosing anomalies proactively) and for flagging potential evidence
//! tampering or acquisition errors.
//!
//! # Detection Categories
//!
//! - **Temporal Anomalies:** Events in impossible order, timestamps in the future,
//!   simultaneous connections to incompatible networks.
//! - **Evidence Contradictions:** Sources directly disagreeing on a material fact.
//! - **Clock Drift Patterns:** Systematic drift indicating device clock manipulation.
//! - **Coverage Gaps:** Unexplained periods with no evidence at all.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::events::ConnectionEvent;
use crate::timeline::{Timeline, TimelineOverlap, TimelineGap};

// ──────────────────────────────────────────────────────────────────────────────
// Anomaly Types
// ──────────────────────────────────────────────────────────────────────────────

/// Unique identifier for a detected anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AnomalyId(pub Uuid);

impl AnomalyId {
    pub fn new() -> Self {
        AnomalyId(Uuid::new_v4())
    }
}

impl Default for AnomalyId {
    fn default() -> Self {
        Self::new()
    }
}

/// Severity of a detected anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnomalySeverity {
    /// Informational — may be normal behavior.
    Info,
    /// Warning — unusual but has plausible explanations.
    Warning,
    /// Critical — may indicate tampering, corruption, or significant error.
    Critical,
}

impl std::fmt::Display for AnomalySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnomalySeverity::Info => write!(f, "INFO"),
            AnomalySeverity::Warning => write!(f, "WARNING"),
            AnomalySeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// The category of anomaly detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyCategory {
    /// Events appear in an impossible temporal order.
    TemporalOrderViolation,
    /// Device appears connected to multiple incompatible networks simultaneously.
    SimultaneousConnection,
    /// A very long gap in activity was detected.
    ExtendedActivityGap,
    /// A connection event has very low confidence.
    LowConfidenceEvent,
    /// Very short session that may be spurious.
    MicroSession,
    /// Connection to a known suspicious network pattern.
    SuspiciousNetwork,
}

impl std::fmt::Display for AnomalyCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnomalyCategory::TemporalOrderViolation => write!(f, "TEMPORAL_ORDER_VIOLATION"),
            AnomalyCategory::SimultaneousConnection => write!(f, "SIMULTANEOUS_CONNECTION"),
            AnomalyCategory::ExtendedActivityGap => write!(f, "EXTENDED_ACTIVITY_GAP"),
            AnomalyCategory::LowConfidenceEvent => write!(f, "LOW_CONFIDENCE_EVENT"),
            AnomalyCategory::MicroSession => write!(f, "MICRO_SESSION"),
            AnomalyCategory::SuspiciousNetwork => write!(f, "SUSPICIOUS_NETWORK"),
        }
    }
}

/// A detected anomaly in the forensic evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    /// Unique identifier.
    pub id: AnomalyId,
    /// Category of the anomaly.
    pub category: AnomalyCategory,
    /// Severity level.
    pub severity: AnomalySeverity,
    /// Human-readable description.
    pub description: String,
    /// Forensic recommendation for the examiner.
    pub recommendation: String,
    /// When the anomaly was detected.
    pub detected_at: DateTime<Utc>,
}

/// Complete anomaly analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyReport {
    /// All detected anomalies.
    pub anomalies: Vec<Anomaly>,
    /// Summary counts.
    pub critical_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    /// When this report was generated.
    pub generated_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Anomaly Detector
// ──────────────────────────────────────────────────────────────────────────────

/// Thresholds for anomaly detection.
const LOW_CONFIDENCE_THRESHOLD: f64 = 0.40;
const MICRO_SESSION_MAX_SECS: i64 = 10;
const EXTENDED_GAP_HOURS: i64 = 24;

/// Analyzes a forensic timeline for anomalies and contradictions.
pub struct AnomalyDetector;

impl AnomalyDetector {
    /// Run all anomaly detection checks against a timeline.
    pub fn analyze(timeline: &Timeline) -> AnomalyReport {
        let mut anomalies = Vec::new();

        Self::check_temporal_order(&timeline.sessions, &mut anomalies);
        Self::check_overlaps(&timeline.overlaps, &mut anomalies);
        Self::check_gaps(&timeline.gaps, &mut anomalies);
        Self::check_low_confidence_events(timeline, &mut anomalies);
        Self::check_micro_sessions(timeline, &mut anomalies);

        let critical_count = anomalies.iter().filter(|a| a.severity == AnomalySeverity::Critical).count();
        let warning_count = anomalies.iter().filter(|a| a.severity == AnomalySeverity::Warning).count();
        let info_count = anomalies.iter().filter(|a| a.severity == AnomalySeverity::Info).count();

        AnomalyReport {
            anomalies,
            critical_count,
            warning_count,
            info_count,
            generated_at: Utc::now(),
        }
    }

    /// Check for temporal order violations within sessions.
    fn check_temporal_order(
        sessions: &[crate::timeline::TimelineSession],
        anomalies: &mut Vec<Anomaly>,
    ) {
        for session in sessions {
            for window in session.events.windows(2) {
                if window[0].timestamp > window[1].timestamp {
                    anomalies.push(Anomaly {
                        id: AnomalyId::new(),
                        category: AnomalyCategory::TemporalOrderViolation,
                        severity: AnomalySeverity::Critical,
                        description: format!(
                            "Event at {} occurs AFTER subsequent event at {} within session \
                             for network \"{}\". This violates temporal causality.",
                            window[0].timestamp.format("%H:%M:%S"),
                            window[1].timestamp.format("%H:%M:%S"),
                            session.network_label
                        ),
                        recommendation: "Verify the acquisition timestamps and check for \
                            clock manipulation on the device.".to_string(),
                        detected_at: Utc::now(),
                    });
                }
            }
        }
    }

    /// Flag overlapping sessions as anomalies.
    fn check_overlaps(overlaps: &[TimelineOverlap], anomalies: &mut Vec<Anomaly>) {
        for overlap in overlaps {
            let duration_secs = (overlap.overlap_end - overlap.overlap_start).num_seconds();
            let severity = if duration_secs > 300 {
                AnomalySeverity::Warning
            } else {
                AnomalySeverity::Info
            };

            anomalies.push(Anomaly {
                id: AnomalyId::new(),
                category: AnomalyCategory::SimultaneousConnection,
                severity,
                description: format!(
                    "Device appears connected to \"{}\" and \"{}\" simultaneously for {} seconds.",
                    overlap.network_a_label, overlap.network_b_label, duration_secs
                ),
                recommendation: "Check if one network was a hotspot and the other a client \
                    connection, which is a valid dual-mode scenario. Otherwise, investigate \
                    log timing artifacts.".to_string(),
                detected_at: Utc::now(),
            });
        }
    }

    /// Flag extended gaps as anomalies.
    fn check_gaps(gaps: &[TimelineGap], anomalies: &mut Vec<Anomaly>) {
        for gap in gaps {
            if gap.duration > Duration::hours(EXTENDED_GAP_HOURS) {
                anomalies.push(Anomaly {
                    id: AnomalyId::new(),
                    category: AnomalyCategory::ExtendedActivityGap,
                    severity: AnomalySeverity::Warning,
                    description: format!(
                        "No network activity observed for {:.1} hours ({} to {}).",
                        gap.duration.num_minutes() as f64 / 60.0,
                        gap.start_time.format("%Y-%m-%d %H:%M"),
                        gap.end_time.format("%Y-%m-%d %H:%M"),
                    ),
                    recommendation: "The device may have been powered off, in airplane mode, \
                        using cellular data only, or evidence may have been deleted.".to_string(),
                    detected_at: Utc::now(),
                });
            }
        }
    }

    /// Flag events with very low confidence.
    fn check_low_confidence_events(timeline: &Timeline, anomalies: &mut Vec<Anomaly>) {
        for session in &timeline.sessions {
            for event in &session.events {
                if event.confidence < LOW_CONFIDENCE_THRESHOLD {
                    anomalies.push(Anomaly {
                        id: AnomalyId::new(),
                        category: AnomalyCategory::LowConfidenceEvent,
                        severity: AnomalySeverity::Info,
                        description: format!(
                            "Event {} for network \"{}\" at {} has low confidence ({:.2}). \
                             It is supported by {} source(s).",
                            event.event_type,
                            session.network_label,
                            event.timestamp.format("%H:%M:%S"),
                            event.confidence,
                            event.corroboration_count
                        ),
                        recommendation: "Consider whether this event should be included \
                            in the forensic report or flagged as unverified.".to_string(),
                        detected_at: Utc::now(),
                    });
                }
            }
        }
    }

    /// Flag micro-sessions (very short sessions that may be spurious).
    fn check_micro_sessions(timeline: &Timeline, anomalies: &mut Vec<Anomaly>) {
        for session in &timeline.sessions {
            if session.duration.num_seconds() > 0
                && session.duration.num_seconds() < MICRO_SESSION_MAX_SECS
                && session.events.len() <= 1
            {
                anomalies.push(Anomaly {
                    id: AnomalyId::new(),
                    category: AnomalyCategory::MicroSession,
                    severity: AnomalySeverity::Info,
                    description: format!(
                        "Very short session ({} seconds) detected for network \"{}\" \
                         with only {} event(s). May be a failed connection attempt.",
                        session.duration.num_seconds(),
                        session.network_label,
                        session.events.len()
                    ),
                    recommendation: "Review whether this represents a genuine connection \
                        or a transient association attempt.".to_string(),
                    detected_at: Utc::now(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{ConnectionEventId, ConnectionEventType, EventEvidence};
    use crate::timeline::{SessionId, TimelineSession, TimelineGap, TimelineOverlap};
    use crate::types::NetworkIdentityId;
    use oracle_core::types::{ArtifactId, NetworkRole, RecordId, SecurityProtocol};

    fn make_event(
        ts: DateTime<Utc>,
        label: &str,
        confidence: f64,
    ) -> ConnectionEvent {
        ConnectionEvent {
            id: ConnectionEventId::new(),
            event_type: ConnectionEventType::Connected,
            network_id: NetworkIdentityId::new(),
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
                confidence,
            }],
            corroboration_count: 1,
            confidence,
        }
    }

    #[test]
    fn test_empty_timeline_no_anomalies() {
        let timeline = Timeline {
            sessions: Vec::new(),
            gaps: Vec::new(),
            overlaps: Vec::new(),
            total_events: 0,
            earliest: None,
            latest: None,
            built_at: Utc::now(),
        };
        let report = AnomalyDetector::analyze(&timeline);
        assert!(report.anomalies.is_empty());
    }

    #[test]
    fn test_overlap_detected_as_anomaly() {
        let timeline = Timeline {
            sessions: Vec::new(),
            gaps: Vec::new(),
            overlaps: vec![TimelineOverlap {
                session_a: SessionId::new(),
                session_b: SessionId::new(),
                network_a_label: "NetA".to_string(),
                network_b_label: "NetB".to_string(),
                overlap_start: Utc::now(),
                overlap_end: Utc::now() + Duration::minutes(10),
                explanation: "test".to_string(),
            }],
            total_events: 0,
            earliest: None,
            latest: None,
            built_at: Utc::now(),
        };
        let report = AnomalyDetector::analyze(&timeline);
        assert!(report.anomalies.iter().any(|a| a.category == AnomalyCategory::SimultaneousConnection));
    }

    #[test]
    fn test_extended_gap_detected() {
        let ts = Utc::now();
        let timeline = Timeline {
            sessions: Vec::new(),
            gaps: vec![TimelineGap {
                start_time: ts,
                end_time: ts + Duration::hours(48),
                duration: Duration::hours(48),
                explanation: "test gap".to_string(),
            }],
            overlaps: Vec::new(),
            total_events: 0,
            earliest: None,
            latest: None,
            built_at: Utc::now(),
        };
        let report = AnomalyDetector::analyze(&timeline);
        assert!(report.anomalies.iter().any(|a| a.category == AnomalyCategory::ExtendedActivityGap));
    }

    #[test]
    fn test_low_confidence_event_flagged() {
        let ts = Utc::now();
        let net_id = NetworkIdentityId::new();
        let timeline = Timeline {
            sessions: vec![TimelineSession {
                id: SessionId::new(),
                network_id: net_id,
                network_label: "WeakNet".to_string(),
                start_time: ts,
                end_time: ts + Duration::minutes(5),
                duration: Duration::minutes(5),
                events: vec![make_event(ts, "WeakNet", 0.2)],
                confidence: 0.2,
            }],
            gaps: Vec::new(),
            overlaps: Vec::new(),
            total_events: 1,
            earliest: Some(ts),
            latest: Some(ts),
            built_at: Utc::now(),
        };
        let report = AnomalyDetector::analyze(&timeline);
        assert!(report.anomalies.iter().any(|a| a.category == AnomalyCategory::LowConfidenceEvent));
    }
}
