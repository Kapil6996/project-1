//! # Artifact Manifest
//!
//! Builds a structured manifest of all artifacts discovered during a device
//! scan. The manifest ties discovered artifacts to a specific investigation
//! and provides an estimated total byte count for acquisition planning.

use chrono::{DateTime, Utc};
use oracle_core::types::InvestigationId;
use serde::{Deserialize, Serialize};

use crate::scanner::{DiscoveredArtifact, ScanResult};

// ──────────────────────────────────────────────────────────────────────────────
// Artifact Manifest
// ──────────────────────────────────────────────────────────────────────────────

/// A complete manifest of artifacts discovered on a device, ready for
/// acquisition.
///
/// The manifest is the contract between the discovery engine and the
/// acquisition coordinator: it declares exactly which artifacts to pull,
/// in what order, and at what estimated cost.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactManifest {
    /// The investigation this manifest belongs to.
    pub investigation_id: InvestigationId,
    /// All artifacts confirmed present and readable on the device.
    pub discovered_artifacts: Vec<DiscoveredArtifact>,
    /// Sum of known file sizes across all discovered artifacts.
    /// Artifacts with unknown sizes are excluded from this total.
    pub total_estimated_bytes: u64,
    /// Timestamp when this manifest was created.
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Manifest Builder
// ──────────────────────────────────────────────────────────────────────────────

/// Constructs an [`ArtifactManifest`] from a completed [`ScanResult`].
///
/// The builder filters for readable artifacts (those in `ScanResult::found`)
/// and computes aggregate statistics for the acquisition coordinator.
pub struct ManifestBuilder;

impl ManifestBuilder {
    /// Build an [`ArtifactManifest`] from scan results.
    ///
    /// # Arguments
    /// * `scan_result` — The output of [`ArtifactScanner::scan_device()`](crate::scanner::ArtifactScanner::scan_device).
    /// * `investigation_id` — The investigation to associate this manifest with.
    pub fn build(scan_result: &ScanResult, investigation_id: InvestigationId) -> ArtifactManifest {
        let total_estimated_bytes: u64 = scan_result
            .found
            .iter()
            .filter_map(|a| a.file_size)
            .sum();

        ArtifactManifest {
            investigation_id,
            discovered_artifacts: scan_result.found.clone(),
            total_estimated_bytes,
            created_at: Utc::now(),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::DiscoveredArtifact;
    use oracle_core::types::ArtifactClass;

    #[test]
    fn test_manifest_builder_basic() {
        let scan_result = ScanResult {
            found: vec![
                DiscoveredArtifact {
                    artifact_class: ArtifactClass::WpaSupplicant,
                    device_path: "/data/misc/wifi/wpa_supplicant.conf".to_string(),
                    file_size: Some(4096),
                },
                DiscoveredArtifact {
                    artifact_class: ArtifactClass::BuildProp,
                    device_path: "/system/build.prop".to_string(),
                    file_size: Some(2048),
                },
            ],
            inaccessible: vec![],
        };

        let inv_id = InvestigationId::new();
        let manifest = ManifestBuilder::build(&scan_result, inv_id);

        assert_eq!(manifest.investigation_id, inv_id);
        assert_eq!(manifest.discovered_artifacts.len(), 2);
        assert_eq!(manifest.total_estimated_bytes, 4096 + 2048);
    }

    #[test]
    fn test_manifest_builder_empty_scan() {
        let scan_result = ScanResult {
            found: vec![],
            inaccessible: vec![],
        };

        let inv_id = InvestigationId::new();
        let manifest = ManifestBuilder::build(&scan_result, inv_id);

        assert!(manifest.discovered_artifacts.is_empty());
        assert_eq!(manifest.total_estimated_bytes, 0);
    }

    #[test]
    fn test_manifest_builder_with_unknown_sizes() {
        let scan_result = ScanResult {
            found: vec![
                DiscoveredArtifact {
                    artifact_class: ArtifactClass::KernelLogs,
                    device_path: "/proc/kmsg".to_string(),
                    file_size: None, // volatile, no meaningful size
                },
                DiscoveredArtifact {
                    artifact_class: ArtifactClass::BuildProp,
                    device_path: "/system/build.prop".to_string(),
                    file_size: Some(1024),
                },
            ],
            inaccessible: vec![],
        };

        let inv_id = InvestigationId::new();
        let manifest = ManifestBuilder::build(&scan_result, inv_id);

        assert_eq!(manifest.discovered_artifacts.len(), 2);
        // Only the known-size artifact contributes to the total.
        assert_eq!(manifest.total_estimated_bytes, 1024);
    }
}
