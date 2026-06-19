//! # Known-Path Registry
//!
//! Provides a registry of known Android filesystem paths where forensically
//! relevant network artifacts are located. The registry maps each
//! [`ArtifactClass`] to its device-side paths, required access level, and
//! volatility classification.
//!
//! The registry is pre-populated with all paths known to the ORACLE platform
//! and serves as the input to the [`ArtifactScanner`](crate::scanner::ArtifactScanner).

use oracle_core::types::{ArtifactClass, VolatilityClass};
use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// Path Entry
// ──────────────────────────────────────────────────────────────────────────────

/// A single entry in the known-path registry describing where an artifact
/// class resides on an Android device.
///
/// Each entry may map to multiple device paths because Android vendors and
/// OS versions relocate configuration files across releases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPathEntry {
    /// The artifact classification this path entry corresponds to.
    pub artifact_class: ArtifactClass,
    /// One or more absolute device-side paths where this artifact may be found.
    pub device_paths: Vec<String>,
    /// Minimum access level required to read this artifact:
    /// `"root"`, `"shell"`, or `"unprivileged"`.
    pub required_access: String,
    /// Volatility classification governing acquisition priority.
    pub volatility: VolatilityClass,
    /// Human-readable description of this artifact for reporting.
    pub description: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Path Registry
// ──────────────────────────────────────────────────────────────────────────────

/// A collection of [`ArtifactPathEntry`] values that the discovery engine
/// uses to scan a device filesystem.
///
/// The default instance is pre-populated with all known Android network
/// artifact paths. Investigators can extend it at runtime if vendor-specific
/// paths are discovered during an examination.
#[derive(Debug, Clone)]
pub struct PathRegistry {
    entries: Vec<ArtifactPathEntry>,
}

impl PathRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a custom entry to the registry.
    pub fn add_entry(&mut self, entry: ArtifactPathEntry) {
        self.entries.push(entry);
    }

    /// Retrieve all path entries for a given [`ArtifactClass`].
    ///
    /// Returns an empty slice when no paths are registered for the class.
    pub fn get_paths_for_class(&self, class: ArtifactClass) -> Vec<&ArtifactPathEntry> {
        self.entries
            .iter()
            .filter(|e| e.artifact_class == class)
            .collect()
    }

    /// Return a reference to every entry in the registry.
    pub fn get_all_entries(&self) -> &[ArtifactPathEntry] {
        &self.entries
    }
}

impl Default for PathRegistry {
    /// Construct a registry pre-populated with **all** known Android network
    /// artifact paths.
    ///
    /// These paths are sourced from the ORACLE forensic methodology and cover
    /// stock AOSP, Samsung One UI, Xiaomi HyperOS, and Google Pixel firmware
    /// variants across Android 8–15.
    fn default() -> Self {
        let entries = vec![
            // ── WPA Supplicant ──────────────────────────────────────────
            ArtifactPathEntry {
                artifact_class: ArtifactClass::WpaSupplicant,
                device_paths: vec![
                    "/data/misc/wifi/wpa_supplicant.conf".to_string(),
                ],
                required_access: "root".to_string(),
                volatility: VolatilityClass::Persistent,
                description: "WPA supplicant configuration containing saved Wi-Fi \
                              networks, PSKs, and connection history (legacy, pre-Android 8)"
                    .to_string(),
            },
            // ── WifiConfigStore ─────────────────────────────────────────
            ArtifactPathEntry {
                artifact_class: ArtifactClass::WifiConfigStore,
                device_paths: vec![
                    "/data/misc/wifi/WifiConfigStore.xml".to_string(),
                    "/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml".to_string(),
                ],
                required_access: "root".to_string(),
                volatility: VolatilityClass::Persistent,
                description: "Android 8+ WifiConfigStore XML containing saved networks, \
                              security settings, and randomized MAC configuration"
                    .to_string(),
            },
            // ── DHCP Leases ─────────────────────────────────────────────
            ArtifactPathEntry {
                artifact_class: ArtifactClass::DhcpLeases,
                device_paths: vec![
                    "/data/misc/dhcp/dnsmasq.leases".to_string(),
                ],
                required_access: "root".to_string(),
                volatility: VolatilityClass::SemiVolatile,
                description: "DHCP lease records issued by the device when operating \
                              as a mobile hotspot (dnsmasq lease file)"
                    .to_string(),
            },
            // ── Battery Stats ───────────────────────────────────────────
            ArtifactPathEntry {
                artifact_class: ArtifactClass::BatteryStats,
                device_paths: vec![
                    "/data/system/batterystats.bin".to_string(),
                    "/data/system/batterystats-daily.xml".to_string(),
                ],
                required_access: "root".to_string(),
                volatility: VolatilityClass::SemiVolatile,
                description: "Battery statistics with network radio usage, Wi-Fi wake \
                              locks, and connectivity state transitions"
                    .to_string(),
            },
            // ── Connectivity Logs ───────────────────────────────────────
            ArtifactPathEntry {
                artifact_class: ArtifactClass::ConnectivityLogs,
                device_paths: vec![
                    "/data/system/netstats/".to_string(),
                ],
                required_access: "root".to_string(),
                volatility: VolatilityClass::SemiVolatile,
                description: "Per-UID and per-interface network statistics collected \
                              by the system NetworkStatsService"
                    .to_string(),
            },
            // ── Kernel Logs ─────────────────────────────────────────────
            ArtifactPathEntry {
                artifact_class: ArtifactClass::KernelLogs,
                device_paths: vec![
                    "/proc/kmsg".to_string(),
                ],
                required_access: "root".to_string(),
                volatility: VolatilityClass::Volatile,
                description: "Kernel ring buffer (dmesg) containing Wi-Fi driver \
                              events, network interface state changes, and \
                              MAC address assignments"
                    .to_string(),
            },
            // ── Hostapd Logs ────────────────────────────────────────────
            ArtifactPathEntry {
                artifact_class: ArtifactClass::HostapdLogs,
                device_paths: vec![
                    "/data/misc/wifi/hostapd.conf".to_string(),
                ],
                required_access: "root".to_string(),
                volatility: VolatilityClass::Persistent,
                description: "Hostapd configuration for the device's software access \
                              point (mobile hotspot SSID, channel, and security)"
                    .to_string(),
            },
            // ── DNS Cache ───────────────────────────────────────────────
            ArtifactPathEntry {
                artifact_class: ArtifactClass::DnsCache,
                device_paths: vec![
                    "/data/misc/net/rt_tables".to_string(),
                ],
                required_access: "root".to_string(),
                volatility: VolatilityClass::Volatile,
                description: "Routing table configuration used by the DNS resolver \
                              and network namespace isolation"
                    .to_string(),
            },
            // ── Network Policy ──────────────────────────────────────────
            ArtifactPathEntry {
                artifact_class: ArtifactClass::NetworkPolicy,
                device_paths: vec![
                    "/data/system/netpolicy.xml".to_string(),
                ],
                required_access: "root".to_string(),
                volatility: VolatilityClass::Persistent,
                description: "Network policy rules including per-UID data restrictions, \
                              metered network settings, and background data limits"
                    .to_string(),
            },
            // ── Build Properties ────────────────────────────────────────
            ArtifactPathEntry {
                artifact_class: ArtifactClass::BuildProp,
                device_paths: vec![
                    "/system/build.prop".to_string(),
                    "/vendor/build.prop".to_string(),
                ],
                required_access: "shell".to_string(),
                volatility: VolatilityClass::Persistent,
                description: "Build properties containing device manufacturer, model, \
                              Android version, API level, and firmware fingerprint"
                    .to_string(),
            },
        ];

        Self { entries }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// All non-Unknown [`ArtifactClass`] variants must have at least one
    /// entry in the default registry.
    #[test]
    fn test_default_registry_covers_all_known_artifact_classes() {
        let registry = PathRegistry::default();

        let expected_classes = [
            ArtifactClass::WpaSupplicant,
            ArtifactClass::WifiConfigStore,
            ArtifactClass::DhcpLeases,
            ArtifactClass::BatteryStats,
            ArtifactClass::ConnectivityLogs,
            ArtifactClass::KernelLogs,
            ArtifactClass::HostapdLogs,
            ArtifactClass::DnsCache,
            ArtifactClass::NetworkPolicy,
            ArtifactClass::BuildProp,
        ];

        for class in &expected_classes {
            let entries = registry.get_paths_for_class(*class);
            assert!(
                !entries.is_empty(),
                "PathRegistry::default() must contain entries for {:?}",
                class
            );
        }
    }

    /// The [`ArtifactClass::Unknown`] variant should NOT have registered paths.
    #[test]
    fn test_unknown_class_has_no_default_paths() {
        let registry = PathRegistry::default();
        let entries = registry.get_paths_for_class(ArtifactClass::Unknown);
        assert!(
            entries.is_empty(),
            "Unknown artifact class should not have default paths"
        );
    }

    /// Verify specific known paths are present.
    #[test]
    fn test_specific_paths_present() {
        let registry = PathRegistry::default();

        let wpa = registry.get_paths_for_class(ArtifactClass::WpaSupplicant);
        assert!(wpa.iter().any(|e| e
            .device_paths
            .contains(&"/data/misc/wifi/wpa_supplicant.conf".to_string())));

        let wifi = registry.get_paths_for_class(ArtifactClass::WifiConfigStore);
        assert!(wifi.iter().any(|e| e
            .device_paths
            .contains(&"/data/misc/wifi/WifiConfigStore.xml".to_string())));
        assert!(wifi.iter().any(|e| e.device_paths.contains(
            &"/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml".to_string()
        )));

        let build = registry.get_paths_for_class(ArtifactClass::BuildProp);
        assert!(build
            .iter()
            .any(|e| e.device_paths.contains(&"/system/build.prop".to_string())));
        assert!(build
            .iter()
            .any(|e| e.device_paths.contains(&"/vendor/build.prop".to_string())));
    }

    /// Verify `get_all_entries()` returns the expected count.
    #[test]
    fn test_get_all_entries_count() {
        let registry = PathRegistry::default();
        // We register 10 artifact classes, each with one ArtifactPathEntry.
        assert_eq!(registry.get_all_entries().len(), 10);
    }

    /// Custom entries can be added at runtime.
    #[test]
    fn test_add_custom_entry() {
        let mut registry = PathRegistry::default();
        let initial = registry.get_all_entries().len();

        registry.add_entry(ArtifactPathEntry {
            artifact_class: ArtifactClass::Unknown,
            device_paths: vec!["/data/vendor/custom_artifact.db".to_string()],
            required_access: "root".to_string(),
            volatility: VolatilityClass::Persistent,
            description: "Vendor-specific artifact discovered during examination".to_string(),
        });

        assert_eq!(registry.get_all_entries().len(), initial + 1);
        assert_eq!(
            registry
                .get_paths_for_class(ArtifactClass::Unknown)
                .len(),
            1
        );
    }
}
