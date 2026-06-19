//! # Network Identity Types
//!
//! Canonical types for representing resolved Wi-Fi network identities
//! as derived by the [`super::identity`] resolver.

use chrono::{DateTime, Utc};
use oracle_core::types::{ArtifactId, RecordId, SecurityProtocol};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a resolved network identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkIdentityId(pub Uuid);

impl NetworkIdentityId {
    pub fn new() -> Self {
        NetworkIdentityId(Uuid::new_v4())
    }
}

impl Default for NetworkIdentityId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for NetworkIdentityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A source evidence claim about a network (SSID + BSSID pair, or partial).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkClaim {
    /// The artifact from which this claim originates.
    pub artifact_id: ArtifactId,
    /// The record within the artifact.
    pub record_id: RecordId,
    /// Human-readable source description (e.g., "wpa_supplicant.conf").
    pub source_description: String,
    /// The normalized SSID, if available.
    pub ssid: Option<String>,
    /// The normalized BSSID in canonical form, if available.
    pub bssid: Option<String>,
    /// The normalized security protocol, if available.
    pub security_protocol: Option<SecurityProtocol>,
    /// When this claim was last seen active (if known).
    pub last_seen: Option<DateTime<Utc>>,
    /// Whether this BSSID was locally-administered (MAC randomization).
    pub is_locally_administered: bool,
}

/// A fully resolved, de-duplicated Wi-Fi network identity.
///
/// Multiple source claims about the same network are merged into a single
/// `ResolvedNetwork`. The confidence reflects how many independent sources
/// corroborate the identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedNetwork {
    /// Unique identifier for this resolved network.
    pub id: NetworkIdentityId,
    /// The canonical (most frequently seen / highest-confidence) SSID.
    pub canonical_ssid: Option<String>,
    /// All distinct SSIDs observed for this network.
    pub observed_ssids: Vec<String>,
    /// The canonical BSSID (if known and not randomized).
    pub canonical_bssid: Option<String>,
    /// All distinct BSSIDs observed for this network.
    pub observed_bssids: Vec<String>,
    /// The resolved security protocol.
    pub security_protocol: SecurityProtocol,
    /// Whether any BSSID associated is locally administered (MAC randomized).
    pub has_randomized_mac: bool,
    /// All source claims that contributed to this resolution.
    pub source_claims: Vec<NetworkClaim>,
    /// Corroboration score: how many independent sources confirm this identity.
    pub source_count: usize,
    /// Confidence in this identity (0.0–1.0).
    pub confidence: f64,
    /// When the network was first observed across all sources.
    pub first_seen: Option<DateTime<Utc>>,
    /// When the network was last seen across all sources.
    pub last_seen: Option<DateTime<Utc>>,
}
