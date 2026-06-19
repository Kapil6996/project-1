//! # Unified Timeline Builder
//!
//! Constructs a single chronological timeline from all reconstructed connection
//! events. The timeline is the primary deliverable for the forensic examiner
//! and the core structure used in court reports.
//!
//! # Features
//!
//! - **Session Detection:** Groups related events into "sessions" — a session
//!   begins with a connection event and ends with a disconnection or a gap
//!   exceeding the session timeout.
//! - **Gap Detection:** Identifies temporal gaps where no network activity was
//!   observed (device may have been powered off, in airplane mode, or using
//!   cellular data).
//! - **Overlap Detection:** Flags impossible overlaps (connected to two networks
//!   simultaneously without hotspot mode).

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::events::{ConnectionEvent, ConnectionEventType};
use crate::types::NetworkIdentityId;

// ──────────────────────────────────────────────────────────────────────────────
// Timeline Types
// ──────────────────────────────────────────────────────────────────────────────

/// Default session timeout in minutes. If no event is seen for this long,
/// the current session is closed.
const DEFAULT_SESSION_TIMEOUT_MINS: i64 = 30;

/// Unique identifier for a timeline session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        SessionId(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A contiguous session of network activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineSession {
    /// Unique identifier for this session.
    pub id: SessionId,
    /// The network this session pertains to.
    pub network_id: NetworkIdentityId,
    /// Human-readable network label.
    pub network_label: String,
    /// When the session started (first event in the session).
    pub start_time: DateTime<Utc>,
    /// When the session ended (last event or session timeout).
    pub end_time: DateTime<Utc>,
    /// Duration of the session.
    pub duration: Duration,
    /// All events within this session, in chronological order.
    pub events: Vec<ConnectionEvent>,
    /// Highest confidence among the session's events.
    pub confidence: f64,
}

/// A gap in network activity — no events observed during this window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineGap {
    /// When the gap started.
    pub start_time: DateTime<Utc>,
    /// When the gap ended.
    pub end_time: DateTime<Utc>,
    /// Duration of the gap.
    pub duration: Duration,
    /// Human-readable explanation.
    pub explanation: String,
}

/// An overlap where the device appears connected to multiple networks simultaneously.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineOverlap {
    /// The overlapping sessions.
    pub session_a: SessionId,
    pub session_b: SessionId,
    /// Labels for the overlapping networks.
    pub network_a_label: String,
    pub network_b_label: String,
    /// The overlap window.
    pub overlap_start: DateTime<Utc>,
    pub overlap_end: DateTime<Utc>,
    /// Human-readable explanation.
    pub explanation: String,
}

/// The complete unified timeline for an investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeline {
    /// All sessions, sorted chronologically.
    pub sessions: Vec<TimelineSession>,
    /// Detected gaps between sessions.
    pub gaps: Vec<TimelineGap>,
    /// Detected overlaps between sessions.
    pub overlaps: Vec<TimelineOverlap>,
    /// Total number of events across all sessions.
    pub total_events: usize,
    /// Earliest event in the timeline.
    pub earliest: Option<DateTime<Utc>>,
    /// Latest event in the timeline.
    pub latest: Option<DateTime<Utc>>,
    /// When this timeline was built.
    pub built_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Timeline Builder
// ──────────────────────────────────────────────────────────────────────────────

/// Builds a unified forensic timeline from reconstructed connection events.
pub struct TimelineBuilder {
    session_timeout: Duration,
}

impl TimelineBuilder {
    /// Create a new timeline builder with the default session timeout.
    pub fn new() -> Self {
        TimelineBuilder {
            session_timeout: Duration::minutes(DEFAULT_SESSION_TIMEOUT_MINS),
        }
    }

    /// Create a timeline builder with a custom session timeout.
    pub fn with_timeout_mins(mins: i64) -> Self {
        TimelineBuilder {
            session_timeout: Duration::minutes(mins),
        }
    }

    /// Build the timeline from a set of connection events.
    ///
    /// Events must already be sorted chronologically (as output by
    /// `EventReconstructor::finalize()`).
    pub fn build(&self, events: Vec<ConnectionEvent>) -> Timeline {
        if events.is_empty() {
            return Timeline {
                sessions: Vec::new(),
                gaps: Vec::new(),
                overlaps: Vec::new(),
                total_events: 0,
                earliest: None,
                latest: None,
                built_at: Utc::now(),
            };
        }

        let total_events = events.len();
        let earliest = Some(events.first().unwrap().timestamp);
        let latest = Some(events.last().unwrap().timestamp);

        // Group events into sessions
        let sessions = self.build_sessions(events);

        // Detect gaps between sessions
        let gaps = self.detect_gaps(&sessions);

        // Detect overlaps between sessions
        let overlaps = self.detect_overlaps(&sessions);

        Timeline {
            sessions,
            gaps,
            overlaps,
            total_events,
            earliest,
            latest,
            built_at: Utc::now(),
        }
    }

    /// Group events into sessions by network and temporal proximity.
    fn build_sessions(&self, events: Vec<ConnectionEvent>) -> Vec<TimelineSession> {
        let mut sessions: Vec<TimelineSession> = Vec::new();

        for event in events {
            let merged = self.try_extend_session(&mut sessions, &event);
            if !merged {
                // Start a new session
                let session = TimelineSession {
                    id: SessionId::new(),
                    network_id: event.network_id,
                    network_label: event.network_label.clone(),
                    start_time: event.timestamp,
                    end_time: event.timestamp,
                    duration: Duration::zero(),
                    events: vec![event.clone()],
                    confidence: event.confidence,
                };
                sessions.push(session);
            }
        }

        // Finalize durations
        for session in &mut sessions {
            session.duration = session.end_time - session.start_time;
        }

        // Sort by start time
        sessions.sort_by(|a, b| a.start_time.cmp(&b.start_time));
        sessions
    }

    /// Try to extend an existing session with a new event.
    fn try_extend_session(
        &self,
        sessions: &mut [TimelineSession],
        event: &ConnectionEvent,
    ) -> bool {
        for session in sessions.iter_mut().rev() {
            // Same network and within timeout window
            if session.network_id == event.network_id {
                let gap = event.timestamp - session.end_time;
                if gap <= self.session_timeout && gap >= Duration::zero() {
                    // Explicit disconnection ends the session
                    if matches!(
                        event.event_type,
                        ConnectionEventType::Disconnected | ConnectionEventType::HotspotStopped
                    ) {
                        session.end_time = event.timestamp;
                        session.events.push(event.clone());
                        session.confidence = session.confidence.max(event.confidence);
                        return true;
                    }

                    session.end_time = event.timestamp;
                    session.events.push(event.clone());
                    session.confidence = session.confidence.max(event.confidence);
                    return true;
                }
            }
        }
        false
    }

    /// Detect gaps between sessions.
    fn detect_gaps(&self, sessions: &[TimelineSession]) -> Vec<TimelineGap> {
        let mut gaps = Vec::new();

        for window in sessions.windows(2) {
            let prev_end = window[0].end_time;
            let next_start = window[1].start_time;
            let gap_duration = next_start - prev_end;

            // Only report gaps exceeding the session timeout
            if gap_duration > self.session_timeout {
                gaps.push(TimelineGap {
                    start_time: prev_end,
                    end_time: next_start,
                    duration: gap_duration,
                    explanation: format!(
                        "No network activity observed for {} minutes between sessions.",
                        gap_duration.num_minutes()
                    ),
                });
            }
        }

        gaps
    }

    /// Detect overlapping sessions (connected to multiple networks simultaneously).
    fn detect_overlaps(&self, sessions: &[TimelineSession]) -> Vec<TimelineOverlap> {
        let mut overlaps = Vec::new();

        for i in 0..sessions.len() {
            for j in (i + 1)..sessions.len() {
                let a = &sessions[i];
                let b = &sessions[j];

                // Skip same-network sessions
                if a.network_id == b.network_id {
                    continue;
                }

                // Check for temporal overlap
                let overlap_start = a.start_time.max(b.start_time);
                let overlap_end = a.end_time.min(b.end_time);

                if overlap_start < overlap_end {
                    overlaps.push(TimelineOverlap {
                        session_a: a.id,
                        session_b: b.id,
                        network_a_label: a.network_label.clone(),
                        network_b_label: b.network_label.clone(),
                        overlap_start,
                        overlap_end,
                        explanation: format!(
                            "Device appears connected to both \"{}\" and \"{}\" simultaneously \
                             for {} seconds. This may indicate a hotspot+client dual-mode scenario, \
                             a log timing artifact, or data inconsistency.",
                            a.network_label,
                            b.network_label,
                            (overlap_end - overlap_start).num_seconds()
                        ),
                    });
                }
            }
        }

        overlaps
    }
}

impl Default for TimelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{ConnectionEventId, EventEvidence};
    use crate::types::NetworkIdentityId;
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
                confidence: 0.8,
            }],
            corroboration_count: 1,
            confidence: 0.8,
        }
    }

    #[test]
    fn test_empty_timeline() {
        let builder = TimelineBuilder::new();
        let timeline = builder.build(Vec::new());
        assert!(timeline.sessions.is_empty());
        assert_eq!(timeline.total_events, 0);
    }

    #[test]
    fn test_single_session() {
        let builder = TimelineBuilder::new();
        let net_id = NetworkIdentityId::new();
        let ts = Utc::now();

        let events = vec![
            make_event(ConnectionEventType::Connected, net_id, "Home", ts),
            make_event(
                ConnectionEventType::DhcpLeaseAcquired,
                net_id,
                "Home",
                ts + Duration::seconds(5),
            ),
            make_event(
                ConnectionEventType::Disconnected,
                net_id,
                "Home",
                ts + Duration::minutes(10),
            ),
        ];

        let timeline = builder.build(events);
        assert_eq!(timeline.sessions.len(), 1);
        assert_eq!(timeline.sessions[0].events.len(), 3);
        assert_eq!(timeline.total_events, 3);
    }

    #[test]
    fn test_two_sessions_with_gap() {
        let builder = TimelineBuilder::new();
        let net_id = NetworkIdentityId::new();
        let ts = Utc::now();

        let events = vec![
            make_event(ConnectionEventType::Connected, net_id, "Home", ts),
            make_event(
                ConnectionEventType::Disconnected,
                net_id,
                "Home",
                ts + Duration::minutes(10),
            ),
            // Gap of 2 hours
            make_event(
                ConnectionEventType::Connected,
                net_id,
                "Home",
                ts + Duration::hours(2),
            ),
        ];

        let timeline = builder.build(events);
        assert_eq!(timeline.sessions.len(), 2);
        assert_eq!(timeline.gaps.len(), 1, "should detect the 2-hour gap");
    }

    #[test]
    fn test_overlap_detection() {
        let builder = TimelineBuilder::new();
        let net_a = NetworkIdentityId::new();
        let net_b = NetworkIdentityId::new();
        let ts = Utc::now();

        let events = vec![
            make_event(ConnectionEventType::Connected, net_a, "NetA", ts),
            // NetB starts while NetA is still within session window
            make_event(
                ConnectionEventType::Connected,
                net_b,
                "NetB",
                ts + Duration::minutes(5),
            ),
            make_event(
                ConnectionEventType::Disconnected,
                net_a,
                "NetA",
                ts + Duration::minutes(10),
            ),
            make_event(
                ConnectionEventType::Disconnected,
                net_b,
                "NetB",
                ts + Duration::minutes(15),
            ),
        ];

        let timeline = builder.build(events);
        assert!(!timeline.overlaps.is_empty(), "should detect the overlap");
    }

    #[test]
    fn test_chronological_session_order() {
        let builder = TimelineBuilder::new();
        let ts = Utc::now();

        let events = vec![
            make_event(
                ConnectionEventType::Connected,
                NetworkIdentityId::new(),
                "Later",
                ts + Duration::hours(5),
            ),
            make_event(
                ConnectionEventType::Connected,
                NetworkIdentityId::new(),
                "Earlier",
                ts,
            ),
        ];

        let timeline = builder.build(events);
        assert!(timeline.sessions[0].start_time <= timeline.sessions[1].start_time);
    }
}
