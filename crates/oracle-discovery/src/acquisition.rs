//! # Acquisition Coordinator
//!
//! Orchestrates the retrieval of discovered artifacts from an Android device.
//!
//! The coordinator pulls each artifact byte-for-byte via ADB, computes a
//! SHA-256 integrity hash using [`ForensicHash`], and produces an
//! [`AcquisitionReport`] summarizing successes, failures, total bytes, and
//! elapsed time.
//!
//! All acquisition operations are designed to be non-destructive — they use
//! `cat` or `dd` to read device files without modifying them.

use std::time::Instant;

use chrono::{DateTime, Utc};
use oracle_core::error::{OracleError, OracleResult};
use oracle_core::types::ArtifactClass;
use oracle_core::ForensicHash;
use serde::{Deserialize, Serialize};

use crate::manifest::ArtifactManifest;
use crate::scanner::{AdbShell, DiscoveredArtifact};

// ──────────────────────────────────────────────────────────────────────────────
// Acquired Artifact
// ──────────────────────────────────────────────────────────────────────────────

/// A single artifact that has been successfully acquired from the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquiredArtifact {
    /// The classification of the acquired artifact.
    pub artifact_class: ArtifactClass,
    /// The device-side path this artifact was pulled from.
    pub device_path: String,
    /// SHA-256 hash of the raw bytes, computed at acquisition time.
    pub sha256_hash: String,
    /// The raw artifact bytes.
    #[serde(skip_serializing, skip_deserializing)]
    pub raw_bytes: Vec<u8>,
    /// Timestamp when acquisition completed.
    pub acquired_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Failed Artifact
// ──────────────────────────────────────────────────────────────────────────────

/// An artifact that could not be acquired, with the reason for failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedArtifact {
    /// The classification of the artifact that failed acquisition.
    pub artifact_class: ArtifactClass,
    /// The device-side path that was attempted.
    pub device_path: String,
    /// Human-readable reason for the failure.
    pub reason: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Acquisition Report
// ──────────────────────────────────────────────────────────────────────────────

/// The complete report produced after acquiring all artifacts from a manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionReport {
    /// Artifacts that were successfully acquired.
    pub successful: Vec<AcquiredArtifact>,
    /// Artifacts that failed acquisition.
    pub failed: Vec<FailedArtifact>,
    /// Total bytes acquired across all successful artifacts.
    pub total_bytes: u64,
    /// Wall-clock duration of the entire acquisition process.
    pub duration: std::time::Duration,
}

// ──────────────────────────────────────────────────────────────────────────────
// Acquisition Coordinator
// ──────────────────────────────────────────────────────────────────────────────

/// Coordinates the acquisition of forensic artifacts from an Android device.
///
/// The coordinator iterates over the manifest's discovered artifacts, pulls
/// each one via ADB shell, computes integrity hashes, and collects results
/// into an [`AcquisitionReport`].
pub struct AcquisitionCoordinator;

impl AcquisitionCoordinator {
    /// Acquire a single artifact from the device.
    ///
    /// Uses `cat` to read the file contents via ADB shell. The raw bytes
    /// are hashed with [`ForensicHash::from_bytes()`] to establish a
    /// chain-of-custody hash at the moment of acquisition.
    ///
    /// # Arguments
    /// * `adb` — ADB shell implementation.
    /// * `serial` — ADB device serial number.
    /// * `artifact` — The discovered artifact to acquire.
    ///
    /// # Errors
    /// Returns [`OracleError::AdbCommandFailed`] if the pull operation fails.
    pub fn acquire_artifact(
        adb: &dyn AdbShell,
        serial: &str,
        artifact: &DiscoveredArtifact,
    ) -> OracleResult<AcquiredArtifact> {
        let cmd = format!("cat '{}'", artifact.device_path);
        let output = adb.shell_command(serial, &cmd)?;
        let raw_bytes = output.into_bytes();

        let hash = ForensicHash::from_bytes(&raw_bytes);

        Ok(AcquiredArtifact {
            artifact_class: artifact.artifact_class,
            device_path: artifact.device_path.clone(),
            sha256_hash: hash.to_hex(),
            raw_bytes,
            acquired_at: Utc::now(),
        })
    }

    /// Acquire all artifacts listed in a manifest.
    ///
    /// Iterates over every artifact in the manifest and attempts acquisition.
    /// Failures are captured in the report rather than short-circuiting the
    /// entire operation — forensic best practice demands collecting as much
    /// evidence as possible even when individual artifacts are unavailable.
    ///
    /// # Arguments
    /// * `adb` — ADB shell implementation.
    /// * `serial` — ADB device serial number.
    /// * `manifest` — The artifact manifest to acquire.
    pub fn acquire_all(
        adb: &dyn AdbShell,
        serial: &str,
        manifest: &ArtifactManifest,
    ) -> AcquisitionReport {
        let start = Instant::now();
        let mut successful = Vec::new();
        let mut failed = Vec::new();
        let mut total_bytes: u64 = 0;

        for artifact in &manifest.discovered_artifacts {
            match Self::acquire_artifact(adb, serial, artifact) {
                Ok(acquired) => {
                    total_bytes = total_bytes.saturating_add(acquired.raw_bytes.len() as u64);
                    successful.push(acquired);
                }
                Err(e) => {
                    failed.push(FailedArtifact {
                        artifact_class: artifact.artifact_class,
                        device_path: artifact.device_path.clone(),
                        reason: e.to_string(),
                    });
                }
            }
        }

        let duration = start.elapsed();

        AcquisitionReport {
            successful,
            failed,
            total_bytes,
            duration,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ManifestBuilder;
    use crate::scanner::{DiscoveredArtifact, MockAdbShell, ScanResult};
    use oracle_core::types::InvestigationId;

    const TEST_SERIAL: &str = "MOCK123456";

    #[test]
    fn test_acquire_single_artifact() {
        let mut adb = MockAdbShell::new();
        let artifact = DiscoveredArtifact {
            artifact_class: ArtifactClass::BuildProp,
            device_path: "/system/build.prop".to_string(),
            file_size: Some(128),
        };

        let fake_content = "ro.product.model=Pixel 8\nro.build.fingerprint=google/...\n";
        adb.add_command_response(
            TEST_SERIAL,
            "cat '/system/build.prop'",
            fake_content,
        );

        let acquired = AcquisitionCoordinator::acquire_artifact(&adb, TEST_SERIAL, &artifact)
            .expect("acquisition should succeed");

        assert_eq!(acquired.artifact_class, ArtifactClass::BuildProp);
        assert_eq!(acquired.device_path, "/system/build.prop");
        assert_eq!(acquired.raw_bytes, fake_content.as_bytes());

        // Verify the hash matches ForensicHash computation.
        let expected_hash = ForensicHash::from_bytes(fake_content.as_bytes()).to_hex();
        assert_eq!(acquired.sha256_hash, expected_hash);
    }

    #[test]
    fn test_acquire_all_mixed() {
        let mut adb = MockAdbShell::new();

        let wpa_content = "network={\n  ssid=\"TestWifi\"\n}\n";
        adb.add_command_response(
            TEST_SERIAL,
            "cat '/data/misc/wifi/wpa_supplicant.conf'",
            wpa_content,
        );
        // No response for build.prop → will fail.

        let scan_result = ScanResult {
            found: vec![
                DiscoveredArtifact {
                    artifact_class: ArtifactClass::WpaSupplicant,
                    device_path: "/data/misc/wifi/wpa_supplicant.conf".to_string(),
                    file_size: Some(64),
                },
                DiscoveredArtifact {
                    artifact_class: ArtifactClass::BuildProp,
                    device_path: "/system/build.prop".to_string(),
                    file_size: Some(128),
                },
            ],
            inaccessible: vec![],
        };

        let inv_id = InvestigationId::new();
        let manifest = ManifestBuilder::build(&scan_result, inv_id);

        let report = AcquisitionCoordinator::acquire_all(&adb, TEST_SERIAL, &manifest);

        assert_eq!(report.successful.len(), 1);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(
            report.successful[0].artifact_class,
            ArtifactClass::WpaSupplicant
        );
        assert_eq!(report.failed[0].artifact_class, ArtifactClass::BuildProp);
        assert_eq!(report.total_bytes, wpa_content.len() as u64);
    }

    #[test]
    fn test_acquire_all_empty_manifest() {
        let adb = MockAdbShell::new();
        let scan_result = ScanResult {
            found: vec![],
            inaccessible: vec![],
        };

        let inv_id = InvestigationId::new();
        let manifest = ManifestBuilder::build(&scan_result, inv_id);
        let report = AcquisitionCoordinator::acquire_all(&adb, TEST_SERIAL, &manifest);

        assert!(report.successful.is_empty());
        assert!(report.failed.is_empty());
        assert_eq!(report.total_bytes, 0);
    }

    #[test]
    fn test_acquisition_report_duration() {
        let adb = MockAdbShell::new();
        let scan_result = ScanResult {
            found: vec![],
            inaccessible: vec![],
        };

        let inv_id = InvestigationId::new();
        let manifest = ManifestBuilder::build(&scan_result, inv_id);
        let report = AcquisitionCoordinator::acquire_all(&adb, TEST_SERIAL, &manifest);

        // Duration should be very small for an empty manifest.
        assert!(report.duration.as_secs() < 1);
    }
}
