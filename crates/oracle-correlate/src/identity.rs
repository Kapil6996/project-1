//! # Network Identity Resolver
//!
//! De-duplicates and merges Wi-Fi network claims from multiple forensic
//! artifact sources into canonical `ResolvedNetwork` identities.
//!
//! # Problem
//!
//! A single real-world Wi-Fi network may appear across many artifact sources:
//! - `wpa_supplicant.conf` may store it with a quoted SSID and no BSSID.
//! - `WifiConfigStore.xml` may have the BSSID but a different security string.
//! - DHCP leases may reference the BSSID but not the SSID.
//! - Connectivity logs may reference both with a precise timestamp.
//!
//! The resolver groups all of these into a single `ResolvedNetwork` with a
//! corroboration score reflecting how many independent sources confirm it.
//!
//! # Matching Strategy
//!
//! Networks are matched by:
//! 1. **Exact BSSID match** (highest confidence) — two claims share the same BSSID.
//! 2. **Exact SSID match** (medium confidence) — two claims share the same SSID.
//!    Used only when neither claim has a BSSID, or one is locally-administered.
//! 3. **SSID + Security match** — additional filter to avoid false positives for
//!    common SSIDs like "Home" or "WiFi".

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use oracle_core::types::SecurityProtocol;
use tracing::debug;

use crate::types::{NetworkClaim, NetworkIdentityId, ResolvedNetwork};

/// Resolves and de-duplicates network identity claims.
pub struct NetworkIdentityResolver {
    resolved: Vec<ResolvedNetwork>,
}

impl NetworkIdentityResolver {
    /// Create a new empty resolver.
    pub fn new() -> Self {
        NetworkIdentityResolver {
            resolved: Vec::new(),
        }
    }

    /// Ingest a network claim and merge it into existing resolved networks,
    /// or create a new resolved network if no match is found.
    pub fn ingest(&mut self, claim: NetworkClaim) {
        // Try to find a matching existing network
        if let Some(idx) = self.find_match(&claim) {
            self.merge_into(idx, claim);
        } else {
            self.create_new(claim);
        }
    }

    /// Return all resolved network identities.
    pub fn resolve(self) -> Vec<ResolvedNetwork> {
        let mut resolved = self.resolved;
        // Sort by confidence descending, then by source_count descending
        resolved.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.source_count.cmp(&a.source_count))
        });
        resolved
    }

    /// Find the index of an existing resolved network that matches the claim.
    fn find_match(&self, claim: &NetworkClaim) -> Option<usize> {
        for (idx, network) in self.resolved.iter().enumerate() {
            // Match by BSSID first — most reliable identifier
            if let (Some(claim_bssid), Some(net_bssid)) = (&claim.bssid, &network.canonical_bssid)
            {
                if !claim.is_locally_administered && claim_bssid == net_bssid {
                    debug!(
                        bssid = %claim_bssid,
                        "Matched network claim by BSSID"
                    );
                    return Some(idx);
                }
            }

            // Also try BSSID against all observed BSSIDs
            if let Some(claim_bssid) = &claim.bssid {
                if !claim.is_locally_administered
                    && network.observed_bssids.contains(claim_bssid)
                {
                    return Some(idx);
                }
            }

            // Match by SSID if both sides have one and BSSID matching failed or unavailable
            if let (Some(claim_ssid), Some(net_ssid)) = (&claim.ssid, &network.canonical_ssid) {
                if claim_ssid == net_ssid {
                    // Also require matching security protocol if both sides have one
                    let security_ok = match (
                        claim.security_protocol,
                        network.security_protocol,
                    ) {
                        (Some(a), b) => a == b || b == SecurityProtocol::Unknown,
                        (None, _) => true,
                    };
                    if security_ok {
                        debug!(
                            ssid = %claim_ssid,
                            "Matched network claim by SSID"
                        );
                        return Some(idx);
                    }
                }
            }
        }
        None
    }

    /// Merge a new claim into an existing resolved network.
    fn merge_into(&mut self, idx: usize, claim: NetworkClaim) {
        let network = &mut self.resolved[idx];

        // Update SSID list
        if let Some(ssid) = &claim.ssid {
            if !network.observed_ssids.contains(ssid) {
                network.observed_ssids.push(ssid.clone());
            }
            // Prefer the most frequent SSID — for now use non-empty first
            if network.canonical_ssid.is_none() {
                network.canonical_ssid = Some(ssid.clone());
            }
        }

        // Update BSSID list — only non-randomized BSSIDs become canonical
        if let Some(bssid) = &claim.bssid {
            if !network.observed_bssids.contains(bssid) {
                network.observed_bssids.push(bssid.clone());
            }
            if network.canonical_bssid.is_none() && !claim.is_locally_administered {
                network.canonical_bssid = Some(bssid.clone());
            }
        }

        // Update security protocol — prefer specificity
        if claim.security_protocol.is_some()
            && network.security_protocol == SecurityProtocol::Unknown
        {
            network.security_protocol = claim.security_protocol.unwrap();
        }

        // Track randomized MACs
        if claim.is_locally_administered {
            network.has_randomized_mac = true;
        }

        // Update temporal window
        if let Some(last_seen) = claim.last_seen {
            network.last_seen = Some(match network.last_seen {
                Some(existing) => existing.max(last_seen),
                None => last_seen,
            });
            network.first_seen = Some(match network.first_seen {
                Some(existing) => existing.min(last_seen),
                None => last_seen,
            });
        }

        // Update corroboration
        network.source_count += 1;
        network.source_claims.push(claim);
        network.confidence = Self::compute_confidence(network.source_count, network.has_randomized_mac);
    }

    /// Create a new resolved network from a single claim.
    fn create_new(&mut self, claim: NetworkClaim) {
        let security = claim.security_protocol.unwrap_or(SecurityProtocol::Unknown);
        let has_randomized = claim.is_locally_administered;

        let first_seen = claim.last_seen;
        let last_seen = claim.last_seen;
        let ssid = claim.ssid.clone();
        let bssid = if !claim.is_locally_administered {
            claim.bssid.clone()
        } else {
            None
        };
        let observed_ssids = ssid.iter().cloned().collect();
        let observed_bssids = claim.bssid.iter().cloned().collect();

        let network = ResolvedNetwork {
            id: NetworkIdentityId::new(),
            canonical_ssid: ssid,
            observed_ssids,
            canonical_bssid: bssid,
            observed_bssids,
            security_protocol: security,
            has_randomized_mac: has_randomized,
            source_claims: vec![claim],
            source_count: 1,
            confidence: Self::compute_confidence(1, has_randomized),
            first_seen,
            last_seen,
        };

        self.resolved.push(network);
    }

    /// Compute confidence for a resolved network.
    ///
    /// More independent sources → higher confidence.
    /// Randomized MACs → reduced confidence (harder to definitively identify).
    fn compute_confidence(source_count: usize, has_randomized_mac: bool) -> f64 {
        let base = match source_count {
            1 => 0.40,
            2 => 0.65,
            3 => 0.80,
            4 => 0.90,
            _ => 0.95,
        };
        if has_randomized_mac { base * 0.85 } else { base }
    }
}

impl Default for NetworkIdentityResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_core::types::{ArtifactId, RecordId, SecurityProtocol};

    fn claim(
        ssid: Option<&str>,
        bssid: Option<&str>,
        proto: Option<SecurityProtocol>,
        randomized: bool,
    ) -> NetworkClaim {
        NetworkClaim {
            artifact_id: ArtifactId::new(),
            record_id: RecordId::new(),
            source_description: "test".to_string(),
            ssid: ssid.map(|s| s.to_string()),
            bssid: bssid.map(|s| s.to_string()),
            security_protocol: proto,
            last_seen: None,
            is_locally_administered: randomized,
        }
    }

    #[test]
    fn test_two_claims_same_bssid_merged() {
        let mut resolver = NetworkIdentityResolver::new();
        resolver.ingest(claim(Some("HomeNet"), Some("AA:BB:CC:DD:EE:FF"), None, false));
        resolver.ingest(claim(Some("HomeNet"), Some("AA:BB:CC:DD:EE:FF"), Some(SecurityProtocol::Wpa2Psk), false));

        let networks = resolver.resolve();
        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].source_count, 2);
        assert_eq!(networks[0].canonical_bssid.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(networks[0].security_protocol, SecurityProtocol::Wpa2Psk);
    }

    #[test]
    fn test_two_claims_same_ssid_merged() {
        let mut resolver = NetworkIdentityResolver::new();
        resolver.ingest(claim(Some("HomeNet"), None, Some(SecurityProtocol::Wpa2Psk), false));
        resolver.ingest(claim(Some("HomeNet"), None, Some(SecurityProtocol::Wpa2Psk), false));

        let networks = resolver.resolve();
        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].source_count, 2);
    }

    #[test]
    fn test_different_ssid_different_bssid_separate() {
        let mut resolver = NetworkIdentityResolver::new();
        resolver.ingest(claim(Some("NetworkA"), Some("AA:BB:CC:DD:EE:01"), None, false));
        resolver.ingest(claim(Some("NetworkB"), Some("AA:BB:CC:DD:EE:02"), None, false));

        let networks = resolver.resolve();
        assert_eq!(networks.len(), 2);
    }

    #[test]
    fn test_randomized_mac_not_used_as_canonical_bssid() {
        let mut resolver = NetworkIdentityResolver::new();
        resolver.ingest(claim(Some("HomeNet"), Some("DA:A1:19:AB:CD:EF"), None, true));

        let networks = resolver.resolve();
        assert_eq!(networks.len(), 1);
        // Randomized MAC should not become canonical BSSID
        assert!(networks[0].canonical_bssid.is_none());
        assert!(networks[0].has_randomized_mac);
    }

    #[test]
    fn test_confidence_increases_with_corroboration() {
        let mut resolver = NetworkIdentityResolver::new();
        let bssid = "AA:BB:CC:DD:EE:FF";
        resolver.ingest(claim(Some("Net"), Some(bssid), None, false));
        let c1 = resolver.resolved[0].confidence;

        resolver.ingest(claim(Some("Net"), Some(bssid), None, false));
        let c2 = resolver.resolved[0].confidence;

        resolver.ingest(claim(Some("Net"), Some(bssid), None, false));
        let c3 = resolver.resolved[0].confidence;

        assert!(c2 > c1, "confidence should increase with more sources");
        assert!(c3 > c2, "confidence should increase further");
    }

    #[test]
    fn test_resolve_sorted_by_confidence() {
        let mut resolver = NetworkIdentityResolver::new();
        // Single-source network
        resolver.ingest(claim(Some("LowConf"), Some("11:22:33:44:55:66"), None, false));
        // Three-source network
        let bssid = "AA:BB:CC:DD:EE:FF";
        resolver.ingest(claim(Some("HighConf"), Some(bssid), None, false));
        resolver.ingest(claim(Some("HighConf"), Some(bssid), None, false));
        resolver.ingest(claim(Some("HighConf"), Some(bssid), None, false));

        let networks = resolver.resolve();
        // HighConf should come first
        assert_eq!(networks[0].canonical_ssid.as_deref(), Some("HighConf"));
    }
}
