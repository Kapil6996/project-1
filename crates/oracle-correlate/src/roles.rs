//! # Hotspot vs Client Distinguisher
//!
//! Determines whether the device was acting as a Wi-Fi client (connecting to
//! an external access point) or as a mobile hotspot (acting as the access point).
//!
//! This is a critical forensic distinction:
//! - **Client mode** → the device was *at* a location with that Wi-Fi network.
//! - **Hotspot mode** → the device *created* a network; it says nothing about
//!   the device's geographic location relative to a Wi-Fi infrastructure AP.
//!
//! # Detection Signals
//!
//! | Signal                       | Client | Hotspot |
//! |------------------------------|--------|---------|
//! | `wpa_supplicant.conf` entry  | ✓      |         |
//! | `WifiConfigStore.xml` entry  | ✓      |         |
//! | DHCP lease received          | ✓      |         |
//! | `hostapd.conf` present       |        | ✓       |
//! | Tethering config present     |        | ✓       |
//! | IP in `192.168.43.x` range   |        | ✓       |
//! | `dnsmasq` DHCP server active |        | ✓       |

use oracle_core::types::NetworkRole;
use serde::{Deserialize, Serialize};

/// An individual signal for or against a particular network role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleSignal {
    /// Human-readable description of this signal.
    pub description: String,
    /// The role this signal supports.
    pub supports: NetworkRole,
    /// Confidence weight of this signal (0.0–1.0).
    pub weight: f64,
    /// Source of this signal.
    pub source: String,
}

/// The result of a network role classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleClassification {
    /// The determined network role.
    pub role: NetworkRole,
    /// Confidence in the classification (0.0–1.0).
    pub confidence: f64,
    /// All signals that contributed to the classification.
    pub signals: Vec<RoleSignal>,
    /// Human-readable rationale for the classification.
    pub rationale: String,
}

/// Classifies whether the device was acting as a Wi-Fi client or hotspot.
pub struct RoleClassifier;

impl RoleClassifier {
    /// Classify the network role based on accumulated signals.
    ///
    /// Uses a weighted vote: each signal contributes its weight to either
    /// the "client" or "hotspot" bucket. The role with the higher total wins.
    /// If the margin is too narrow, `Ambiguous` is returned.
    pub fn classify(signals: &[RoleSignal]) -> RoleClassification {
        if signals.is_empty() {
            return RoleClassification {
                role: NetworkRole::Ambiguous,
                confidence: 0.0,
                signals: Vec::new(),
                rationale: "No signals available for role classification.".to_string(),
            };
        }

        let mut client_score: f64 = 0.0;
        let mut hotspot_score: f64 = 0.0;

        for signal in signals {
            match signal.supports {
                NetworkRole::DeviceAsClient => client_score += signal.weight,
                NetworkRole::DeviceAsHotspot => hotspot_score += signal.weight,
                NetworkRole::Ambiguous => {
                    // Ambiguous signals contribute equally to both
                    client_score += signal.weight * 0.5;
                    hotspot_score += signal.weight * 0.5;
                }
            }
        }

        let total = client_score + hotspot_score;
        if total == 0.0 {
            return RoleClassification {
                role: NetworkRole::Ambiguous,
                confidence: 0.0,
                signals: signals.to_vec(),
                rationale: "All signals had zero weight.".to_string(),
            };
        }

        let client_ratio = client_score / total;
        let hotspot_ratio = hotspot_score / total;

        // Require at least 65% of the weighted vote to declare a winner
        const THRESHOLD: f64 = 0.65;

        if client_ratio >= THRESHOLD {
            RoleClassification {
                role: NetworkRole::DeviceAsClient,
                confidence: client_ratio,
                signals: signals.to_vec(),
                rationale: format!(
                    "Device classified as CLIENT with {:.0}% weighted signal support. \
                     {} signal(s) support client mode.",
                    client_ratio * 100.0,
                    signals.iter().filter(|s| s.supports == NetworkRole::DeviceAsClient).count()
                ),
            }
        } else if hotspot_ratio >= THRESHOLD {
            RoleClassification {
                role: NetworkRole::DeviceAsHotspot,
                confidence: hotspot_ratio,
                signals: signals.to_vec(),
                rationale: format!(
                    "Device classified as HOTSPOT with {:.0}% weighted signal support. \
                     {} signal(s) support hotspot mode.",
                    hotspot_ratio * 100.0,
                    signals.iter().filter(|s| s.supports == NetworkRole::DeviceAsHotspot).count()
                ),
            }
        } else {
            RoleClassification {
                role: NetworkRole::Ambiguous,
                confidence: client_ratio.max(hotspot_ratio),
                signals: signals.to_vec(),
                rationale: format!(
                    "Insufficient signal separation — client: {:.0}%, hotspot: {:.0}%. \
                     Examiner review required.",
                    client_ratio * 100.0,
                    hotspot_ratio * 100.0
                ),
            }
        }
    }

    // ── Signal Constructors ─────────────────────────────────────────────

    /// Signal: artifact found in `wpa_supplicant.conf` → strong client indicator.
    pub fn signal_wpa_supplicant_entry(source: &str) -> RoleSignal {
        RoleSignal {
            description: "Network entry found in wpa_supplicant.conf (client-mode config)".to_string(),
            supports: NetworkRole::DeviceAsClient,
            weight: 0.9,
            source: source.to_string(),
        }
    }

    /// Signal: artifact found in `WifiConfigStore.xml` → strong client indicator.
    pub fn signal_wifi_config_store_entry(source: &str) -> RoleSignal {
        RoleSignal {
            description: "Network entry found in WifiConfigStore.xml (client-mode config)".to_string(),
            supports: NetworkRole::DeviceAsClient,
            weight: 0.9,
            source: source.to_string(),
        }
    }

    /// Signal: DHCP lease received → strong client indicator.
    pub fn signal_dhcp_lease_received(source: &str) -> RoleSignal {
        RoleSignal {
            description: "DHCP lease received (device obtained IP from external DHCP server)".to_string(),
            supports: NetworkRole::DeviceAsClient,
            weight: 0.95,
            source: source.to_string(),
        }
    }

    /// Signal: hostapd configuration present → strong hotspot indicator.
    pub fn signal_hostapd_config(source: &str) -> RoleSignal {
        RoleSignal {
            description: "hostapd configuration detected (device was running as AP)".to_string(),
            supports: NetworkRole::DeviceAsHotspot,
            weight: 0.95,
            source: source.to_string(),
        }
    }

    /// Signal: tethering/mobile hotspot setting active → strong hotspot indicator.
    pub fn signal_tethering_active(source: &str) -> RoleSignal {
        RoleSignal {
            description: "Tethering/mobile hotspot setting was active".to_string(),
            supports: NetworkRole::DeviceAsHotspot,
            weight: 0.90,
            source: source.to_string(),
        }
    }

    /// Signal: IP address in Android default hotspot range (192.168.43.x).
    pub fn signal_hotspot_ip_range(ip: &str, source: &str) -> RoleSignal {
        let is_hotspot_ip = ip.starts_with("192.168.43.");
        RoleSignal {
            description: format!(
                "IP address {} {} Android default hotspot range (192.168.43.x)",
                ip,
                if is_hotspot_ip { "is in" } else { "is NOT in" }
            ),
            supports: if is_hotspot_ip {
                NetworkRole::DeviceAsHotspot
            } else {
                NetworkRole::DeviceAsClient
            },
            weight: if is_hotspot_ip { 0.80 } else { 0.30 },
            source: source.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strong_client_signals() {
        let signals = vec![
            RoleClassifier::signal_wpa_supplicant_entry("wpa_supplicant.conf"),
            RoleClassifier::signal_dhcp_lease_received("dhclient.leases"),
        ];
        let result = RoleClassifier::classify(&signals);
        assert_eq!(result.role, NetworkRole::DeviceAsClient);
        assert!(result.confidence >= 0.65);
    }

    #[test]
    fn test_strong_hotspot_signals() {
        let signals = vec![
            RoleClassifier::signal_hostapd_config("hostapd.conf"),
            RoleClassifier::signal_tethering_active("settings.db"),
        ];
        let result = RoleClassifier::classify(&signals);
        assert_eq!(result.role, NetworkRole::DeviceAsHotspot);
        assert!(result.confidence >= 0.65);
    }

    #[test]
    fn test_ambiguous_signals() {
        let signals = vec![
            RoleClassifier::signal_wpa_supplicant_entry("wpa_supplicant.conf"),
            RoleClassifier::signal_hostapd_config("hostapd.conf"),
        ];
        let result = RoleClassifier::classify(&signals);
        // Roughly equal weights → should be ambiguous
        assert_eq!(result.role, NetworkRole::Ambiguous);
    }

    #[test]
    fn test_no_signals() {
        let result = RoleClassifier::classify(&[]);
        assert_eq!(result.role, NetworkRole::Ambiguous);
        assert_eq!(result.confidence, 0.0);
    }

    #[test]
    fn test_hotspot_ip_range_detection() {
        let signal = RoleClassifier::signal_hotspot_ip_range("192.168.43.1", "dhcp");
        assert_eq!(signal.supports, NetworkRole::DeviceAsHotspot);

        let signal = RoleClassifier::signal_hotspot_ip_range("192.168.1.100", "dhcp");
        assert_eq!(signal.supports, NetworkRole::DeviceAsClient);
    }

    #[test]
    fn test_classification_has_rationale() {
        let signals = vec![
            RoleClassifier::signal_dhcp_lease_received("dhclient.leases"),
        ];
        let result = RoleClassifier::classify(&signals);
        assert!(!result.rationale.is_empty());
        assert!(result.rationale.contains("CLIENT"));
    }
}
