//! # Connection Event Reconstructor
//!
//! Reconstructs discrete Wi-Fi connection/disconnection events from normalized
//! forensic artifacts. Raw artifacts don't always contain explicit "connected"
//! or "disconnected" events — the reconstructor infers them from:
//!
//! - DHCP lease acquisitions and renewals
//! - WPA supplicant state changes
//! - Connectivity log entries
//! - Battery stats network usage windows
//!
//! Each reconstructed event carries a list of all the source evidence that
//! contributed to it, enabling forensic transparency.

use chrono::{DateTime, Utc};
use oracle_core::types::{ArtifactId, NetworkRole, RecordId, SecurityProtocol};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::NetworkIdentityId;

// ──────────────────────────────────────────────────────────────────────────────
// Event Types
// ──────────────────────────────────────────────────────────────────────────────

/// Unique identifier for a reconstructed connection event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectionEventId(pub Uuid);

impl ConnectionEventId {
    pub fn new() -> Self {
        ConnectionEventId(Uuid::new_v4())
    }
}

impl Default for ConnectionEventId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ConnectionEventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The type of connection event inferred from the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionEventType {
    /// Device connected to a Wi-Fi network.
    Connected,
    /// Device disconnected from a Wi-Fi network.
    Disconnected,
    /// DHCP lease was acquired or renewed (implies connection active).
    DhcpLeaseAcquired,
    /// DHCP lease expired (implies disconnection or network change).
    DhcpLeaseExpired,
    /// Network handoff — device transitioned between APs on the same SSID.
    Handoff,
    /// Hotspot was activated on the device.
    HotspotStarted,
    /// Hotspot was deactivated on the device.
    HotspotStopped,
}

impl std::fmt::Display for ConnectionEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionEventType::Connected => write!(f, "CONNECTED"),
            ConnectionEventType::Disconnected => write!(f, "DISCONNECTED"),
            ConnectionEventType::DhcpLeaseAcquired => write!(f, "DHCP_LEASE_ACQUIRED"),
            ConnectionEventType::DhcpLeaseExpired => write!(f, "DHCP_LEASE_EXPIRED"),
            ConnectionEventType::Handoff => write!(f, "HANDOFF"),
            ConnectionEventType::HotspotStarted => write!(f, "HOTSPOT_STARTED"),
            ConnectionEventType::HotspotStopped => write!(f, "HOTSPOT_STOPPED"),
        }
    }
}

/// A single piece of evidence contributing to a reconstructed event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEvidence {
    /// The artifact this evidence was extracted from.
    pub artifact_id: ArtifactId,
    /// The specific record within the artifact.
    pub record_id: RecordId,
    /// Human-readable description of what this evidence says.
    pub description: String,
    /// The timestamp extracted from this specific piece of evidence.
    pub timestamp: DateTime<Utc>,
    /// Confidence in this individual piece of evidence (0.0–1.0).
    pub confidence: f64,
}

/// A reconstructed Wi-Fi connection or disconnection event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEvent {
    /// Unique identifier for this event.
    pub id: ConnectionEventId,
    /// The type of event reconstructed.
    pub event_type: ConnectionEventType,
    /// The resolved network identity this event pertains to.
    pub network_id: NetworkIdentityId,
    /// Human-readable network label (SSID or BSSID).
    pub network_label: String,
    /// The best-estimate timestamp for when this event occurred.
    pub timestamp: DateTime<Utc>,
    /// The security protocol in use during this event.
    pub security_protocol: SecurityProtocol,
    /// Whether the device was operating as client or hotspot.
    pub network_role: NetworkRole,
    /// IP address assigned during this connection (if known from DHCP).
    pub ip_address: Option<String>,
    /// All evidence that contributed to reconstructing this event.
    pub evidence: Vec<EventEvidence>,
    /// Number of independent sources corroborating this event.
    pub corroboration_count: usize,
    /// Combined confidence in this event (0.0–1.0).
    pub confidence: f64,
}

// ──────────────────────────────────────────────────────────────────────────────
// Event Reconstructor
// ──────────────────────────────────────────────────────────────────────────────

/// Window tolerance in seconds for grouping evidence into the same event.
const EVENT_WINDOW_SECS: i64 = 120; // 2 minutes

/// Reconstructs discrete connection events from normalized evidence.
pub struct EventReconstructor {
    events: Vec<ConnectionEvent>,
}

impl EventReconstructor {
    /// Create a new event reconstructor.
    pub fn new() -> Self {
        EventReconstructor {
            events: Vec::new(),
        }
    }

    /// Record evidence of a connection event. If evidence falls within the
    /// temporal window of an existing event for the same network, it is merged.
    /// Otherwise a new event is created.
    pub fn record_evidence(
        &mut self,
        event_type: ConnectionEventType,
        network_id: NetworkIdentityId,
        network_label: &str,
        security_protocol: SecurityProtocol,
        network_role: NetworkRole,
        evidence: EventEvidence,
        ip_address: Option<String>,
    ) {
        let ts = evidence.timestamp;

        // Try to merge with an existing event within the time window
        if let Some(existing) = self.find_mergeable_event(
            event_type,
            &network_id,
            ts,
        ) {
            existing.evidence.push(evidence);
            existing.corroboration_count = existing.evidence.len();
            existing.confidence = Self::compute_confidence(&existing.evidence);
            // Update IP if this evidence provides one and existing doesn't have one
            if existing.ip_address.is_none() && ip_address.is_some() {
                existing.ip_address = ip_address;
            }
            return;
        }

        // Create a new event
        let confidence = Self::compute_confidence(std::slice::from_ref(&evidence));
        let event = ConnectionEvent {
            id: ConnectionEventId::new(),
            event_type,
            network_id,
            network_label: network_label.to_string(),
            timestamp: ts,
            security_protocol,
            network_role,
            ip_address,
            evidence: vec![evidence],
            corroboration_count: 1,
            confidence,
        };

        self.events.push(event);
    }

    /// Finalize and return all reconstructed events, sorted chronologically.
    pub fn finalize(mut self) -> Vec<ConnectionEvent> {
        self.events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        self.events
    }

    /// Return current event count.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Find an existing event that can be merged with new evidence.
    fn find_mergeable_event(
        &mut self,
        event_type: ConnectionEventType,
        network_id: &NetworkIdentityId,
        timestamp: DateTime<Utc>,
    ) -> Option<&mut ConnectionEvent> {
        self.events.iter_mut().find(|e| {
            e.event_type == event_type
                && e.network_id == *network_id
                && (e.timestamp - timestamp).num_seconds().unsigned_abs() <= EVENT_WINDOW_SECS as u64
        })
    }

    /// Compute combined confidence from multiple evidence pieces.
    fn compute_confidence(evidence: &[EventEvidence]) -> f64 {
        if evidence.is_empty() {
            return 0.0;
        }
        // Combined confidence using the "noisy OR" model:
        // P(event) = 1 - ∏(1 - P_i)
        let complement_product: f64 = evidence
            .iter()
            .map(|e| 1.0 - e.confidence)
            .product();
        (1.0 - complement_product).min(0.99) // Cap at 0.99
    }
}

impl Default for EventReconstructor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_core::types::{ArtifactId, RecordId};

    fn make_evidence(ts: DateTime<Utc>, confidence: f64) -> EventEvidence {
        EventEvidence {
            artifact_id: ArtifactId::new(),
            record_id: RecordId::new(),
            description: "test evidence".to_string(),
            timestamp: ts,
            confidence,
        }
    }

    #[test]
    fn test_single_event() {
        let mut recon = EventReconstructor::new();
        let net_id = NetworkIdentityId::new();
        let ts = Utc::now();

        recon.record_evidence(
            ConnectionEventType::Connected,
            net_id,
            "HomeNet",
            SecurityProtocol::Wpa2Psk,
            NetworkRole::DeviceAsClient,
            make_evidence(ts, 0.8),
            Some("192.168.1.100".to_string()),
        );

        let events = recon.finalize();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, ConnectionEventType::Connected);
        assert_eq!(events[0].ip_address.as_deref(), Some("192.168.1.100"));
    }

    #[test]
    fn test_corroborating_evidence_merges() {
        let mut recon = EventReconstructor::new();
        let net_id = NetworkIdentityId::new();
        let ts = Utc::now();

        recon.record_evidence(
            ConnectionEventType::Connected,
            net_id,
            "HomeNet",
            SecurityProtocol::Wpa2Psk,
            NetworkRole::DeviceAsClient,
            make_evidence(ts, 0.6),
            None,
        );
        // Second evidence 30 seconds later — within the 2-minute window
        recon.record_evidence(
            ConnectionEventType::Connected,
            net_id,
            "HomeNet",
            SecurityProtocol::Wpa2Psk,
            NetworkRole::DeviceAsClient,
            make_evidence(ts + chrono::Duration::seconds(30), 0.7),
            None,
        );

        let events = recon.finalize();
        assert_eq!(events.len(), 1, "should merge into one event");
        assert_eq!(events[0].corroboration_count, 2);
        assert!(events[0].confidence > 0.6, "combined confidence should exceed individual");
    }

    #[test]
    fn test_different_networks_separate_events() {
        let mut recon = EventReconstructor::new();
        let ts = Utc::now();

        recon.record_evidence(
            ConnectionEventType::Connected,
            NetworkIdentityId::new(),
            "NetA",
            SecurityProtocol::Wpa2Psk,
            NetworkRole::DeviceAsClient,
            make_evidence(ts, 0.8),
            None,
        );
        recon.record_evidence(
            ConnectionEventType::Connected,
            NetworkIdentityId::new(),
            "NetB",
            SecurityProtocol::Open,
            NetworkRole::DeviceAsClient,
            make_evidence(ts, 0.7),
            None,
        );

        let events = recon.finalize();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn test_events_outside_window_not_merged() {
        let mut recon = EventReconstructor::new();
        let net_id = NetworkIdentityId::new();
        let ts = Utc::now();

        recon.record_evidence(
            ConnectionEventType::Connected,
            net_id,
            "HomeNet",
            SecurityProtocol::Wpa2Psk,
            NetworkRole::DeviceAsClient,
            make_evidence(ts, 0.8),
            None,
        );
        // 5 minutes later — outside the 2-minute window
        recon.record_evidence(
            ConnectionEventType::Connected,
            net_id,
            "HomeNet",
            SecurityProtocol::Wpa2Psk,
            NetworkRole::DeviceAsClient,
            make_evidence(ts + chrono::Duration::minutes(5), 0.8),
            None,
        );

        let events = recon.finalize();
        assert_eq!(events.len(), 2, "should be separate events");
    }

    #[test]
    fn test_noisy_or_confidence() {
        let evidence = vec![
            make_evidence(Utc::now(), 0.5),
            make_evidence(Utc::now(), 0.5),
        ];
        let conf = EventReconstructor::compute_confidence(&evidence);
        // 1 - (0.5 * 0.5) = 0.75
        assert!((conf - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_chronological_sort() {
        let mut recon = EventReconstructor::new();
        let ts = Utc::now();

        // Add later event first
        recon.record_evidence(
            ConnectionEventType::Disconnected,
            NetworkIdentityId::new(),
            "NetA",
            SecurityProtocol::Wpa2Psk,
            NetworkRole::DeviceAsClient,
            make_evidence(ts + chrono::Duration::hours(1), 0.8),
            None,
        );
        recon.record_evidence(
            ConnectionEventType::Connected,
            NetworkIdentityId::new(),
            "NetA",
            SecurityProtocol::Wpa2Psk,
            NetworkRole::DeviceAsClient,
            make_evidence(ts, 0.8),
            None,
        );

        let events = recon.finalize();
        assert!(events[0].timestamp <= events[1].timestamp, "should be chronological");
    }
}
