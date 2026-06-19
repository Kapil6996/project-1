//! # Device Filesystem Scanner
//!
//! Scans an Android device's filesystem for known forensic artifacts using
//! the [`PathRegistry`](crate::registry::PathRegistry) as a discovery guide.
//!
//! The scanner operates through an [`AdbShell`] trait abstraction so that
//! production code can use a real ADB bridge while tests inject a
//! [`MockAdbShell`] for deterministic, offline verification.

use oracle_core::error::{OracleError, OracleResult};
use oracle_core::types::ArtifactClass;

use crate::registry::PathRegistry;
use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// ADB Shell Abstraction
// ──────────────────────────────────────────────────────────────────────────────

/// Abstraction over ADB shell interactions.
///
/// All device-side filesystem probes go through this trait so that
/// the scanner remains testable without a physical device.
pub trait AdbShell {
    /// Execute an arbitrary shell command on the target device.
    ///
    /// # Arguments
    /// * `serial` — ADB device serial number.
    /// * `cmd` — Shell command to execute (e.g., `"ls -la /data/misc/wifi/"`).
    ///
    /// # Errors
    /// Returns [`OracleError::AdbCommandFailed`] if the command execution fails.
    fn shell_command(&self, serial: &str, cmd: &str) -> OracleResult<String>;

    /// Check whether a file or directory exists at the given device path.
    ///
    /// # Arguments
    /// * `serial` — ADB device serial number.
    /// * `path` — Absolute path on the device to check.
    fn check_file_exists(&self, serial: &str, path: &str) -> OracleResult<bool>;

    /// Check whether a file at the given path is readable by the current
    /// ADB shell user.
    ///
    /// # Arguments
    /// * `serial` — ADB device serial number.
    /// * `path` — Absolute path on the device to check.
    fn check_file_readable(&self, serial: &str, path: &str) -> OracleResult<bool>;
}

// ──────────────────────────────────────────────────────────────────────────────
// Scan Results
// ──────────────────────────────────────────────────────────────────────────────

/// An artifact whose presence was confirmed on the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredArtifact {
    /// The classification of this artifact.
    pub artifact_class: ArtifactClass,
    /// The device-side path where the artifact was found.
    pub device_path: String,
    /// File size in bytes, if retrievable.
    pub file_size: Option<u64>,
}

/// A path that exists on the device but could not be read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InaccessiblePath {
    /// The classification of the artifact at this path.
    pub artifact_class: ArtifactClass,
    /// The device-side path that was inaccessible.
    pub device_path: String,
    /// Human-readable reason the path could not be read.
    pub reason: String,
}

/// The complete result of scanning a device for forensic artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Artifacts that were found and are readable.
    pub found: Vec<DiscoveredArtifact>,
    /// Paths that exist but cannot be read under the current access level.
    pub inaccessible: Vec<InaccessiblePath>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Artifact Scanner
// ──────────────────────────────────────────────────────────────────────────────

/// Scans a device's filesystem for known forensic artifacts.
///
/// The scanner iterates over every path in the [`PathRegistry`], probes
/// for existence, and then checks readability. The result is a [`ScanResult`]
/// partitioning artifacts into "found" and "inaccessible" sets.
pub struct ArtifactScanner;

impl ArtifactScanner {
    /// Scan the target device for all artifacts in the registry.
    ///
    /// # Arguments
    /// * `adb` — ADB shell implementation (real or mock).
    /// * `serial` — ADB serial of the target device.
    /// * `registry` — The path registry to scan against.
    ///
    /// # Errors
    /// Returns an error only if the ADB transport itself fails. Individual
    /// file-level failures are captured in [`ScanResult::inaccessible`].
    pub fn scan_device(
        adb: &dyn AdbShell,
        serial: &str,
        registry: &PathRegistry,
    ) -> OracleResult<ScanResult> {
        let mut found = Vec::new();
        let mut inaccessible = Vec::new();

        for entry in registry.get_all_entries() {
            for path in &entry.device_paths {
                let exists = adb.check_file_exists(serial, path)?;
                if !exists {
                    continue;
                }

                let readable = adb.check_file_readable(serial, path)?;
                if !readable {
                    inaccessible.push(InaccessiblePath {
                        artifact_class: entry.artifact_class,
                        device_path: path.clone(),
                        reason: format!(
                            "File exists but is not readable (requires {} access)",
                            entry.required_access
                        ),
                    });
                    continue;
                }

                // Attempt to retrieve file size via `stat`.
                let file_size = Self::query_file_size(adb, serial, path);

                found.push(DiscoveredArtifact {
                    artifact_class: entry.artifact_class,
                    device_path: path.clone(),
                    file_size,
                });
            }
        }

        Ok(ScanResult { found, inaccessible })
    }

    /// Query the file size in bytes using `stat -c %s`.
    ///
    /// Returns `None` if the stat command fails or the output cannot be parsed.
    fn query_file_size(adb: &dyn AdbShell, serial: &str, path: &str) -> Option<u64> {
        let cmd = format!("stat -c %s '{}'", path);
        adb.shell_command(serial, &cmd)
            .ok()
            .and_then(|output| output.trim().parse::<u64>().ok())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Mock ADB Shell
// ──────────────────────────────────────────────────────────────────────────────

/// A mock ADB shell implementation for testing.
///
/// Allows tests to pre-configure which files exist, which are readable,
/// and what shell commands return.
#[cfg(any(test, feature = "test-support"))]
pub struct MockAdbShell {
    /// Paths that exist on the "device".
    pub existing_paths: Vec<String>,
    /// Paths that are readable on the "device".
    pub readable_paths: Vec<String>,
    /// Canned shell command responses keyed by (serial, command) → output.
    pub command_responses: Vec<(String, String, String)>,
}

#[cfg(any(test, feature = "test-support"))]
impl MockAdbShell {
    /// Create a new mock with no files.
    pub fn new() -> Self {
        Self {
            existing_paths: Vec::new(),
            readable_paths: Vec::new(),
            command_responses: Vec::new(),
        }
    }

    /// Register a path as existing on the mock device.
    pub fn add_existing_path(&mut self, path: &str) {
        self.existing_paths.push(path.to_string());
    }

    /// Register a path as both existing and readable.
    pub fn add_readable_path(&mut self, path: &str) {
        if !self.existing_paths.contains(&path.to_string()) {
            self.existing_paths.push(path.to_string());
        }
        self.readable_paths.push(path.to_string());
    }

    /// Register a canned response for a shell command.
    pub fn add_command_response(&mut self, serial: &str, cmd: &str, output: &str) {
        self.command_responses.push((
            serial.to_string(),
            cmd.to_string(),
            output.to_string(),
        ));
    }
}

#[cfg(any(test, feature = "test-support"))]
impl AdbShell for MockAdbShell {
    fn shell_command(&self, serial: &str, cmd: &str) -> OracleResult<String> {
        for (s, c, output) in &self.command_responses {
            if s == serial && c == cmd {
                return Ok(output.clone());
            }
        }
        Err(OracleError::AdbCommandFailed {
            serial: serial.to_string(),
            command: cmd.to_string(),
            reason: "No mock response configured".to_string(),
        })
    }

    fn check_file_exists(&self, _serial: &str, path: &str) -> OracleResult<bool> {
        Ok(self.existing_paths.contains(&path.to_string()))
    }

    fn check_file_readable(&self, _serial: &str, path: &str) -> OracleResult<bool> {
        Ok(self.readable_paths.contains(&path.to_string()))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PathRegistry;

    const TEST_SERIAL: &str = "MOCK123456";

    /// Scan with no files present should return empty found and inaccessible.
    #[test]
    fn test_scan_empty_device() {
        let adb = MockAdbShell::new();
        let registry = PathRegistry::default();

        let result = ArtifactScanner::scan_device(&adb, TEST_SERIAL, &registry)
            .expect("scan should not fail on empty device");

        assert!(result.found.is_empty());
        assert!(result.inaccessible.is_empty());
    }

    /// Files that exist and are readable appear in `found`.
    #[test]
    fn test_scan_finds_readable_artifacts() {
        let mut adb = MockAdbShell::new();

        // Make WPA supplicant readable
        adb.add_readable_path("/data/misc/wifi/wpa_supplicant.conf");
        adb.add_command_response(
            TEST_SERIAL,
            "stat -c %s '/data/misc/wifi/wpa_supplicant.conf'",
            "4096\n",
        );

        // Make build.prop readable
        adb.add_readable_path("/system/build.prop");
        adb.add_command_response(
            TEST_SERIAL,
            "stat -c %s '/system/build.prop'",
            "2048\n",
        );

        let registry = PathRegistry::default();
        let result = ArtifactScanner::scan_device(&adb, TEST_SERIAL, &registry)
            .expect("scan should succeed");

        assert_eq!(result.found.len(), 2);
        assert!(result.found.iter().any(|a| a.artifact_class == ArtifactClass::WpaSupplicant));
        assert!(result.found.iter().any(|a| a.artifact_class == ArtifactClass::BuildProp));

        // Verify file sizes were captured.
        let wpa = result
            .found
            .iter()
            .find(|a| a.artifact_class == ArtifactClass::WpaSupplicant)
            .expect("WPA artifact should exist");
        assert_eq!(wpa.file_size, Some(4096));
    }

    /// Files that exist but are NOT readable appear in `inaccessible`.
    #[test]
    fn test_scan_inaccessible_paths() {
        let mut adb = MockAdbShell::new();

        // File exists but is NOT readable (only in existing_paths).
        adb.add_existing_path("/data/misc/wifi/WifiConfigStore.xml");

        let registry = PathRegistry::default();
        let result = ArtifactScanner::scan_device(&adb, TEST_SERIAL, &registry)
            .expect("scan should succeed");

        assert!(result.found.is_empty());
        assert_eq!(result.inaccessible.len(), 1);
        assert_eq!(
            result.inaccessible[0].artifact_class,
            ArtifactClass::WifiConfigStore
        );
        assert!(result.inaccessible[0].reason.contains("not readable"));
    }

    /// Mixed scenario: some found, some inaccessible, some missing.
    #[test]
    fn test_scan_mixed_results() {
        let mut adb = MockAdbShell::new();

        // Readable
        adb.add_readable_path("/system/build.prop");
        adb.add_readable_path("/vendor/build.prop");

        // Exists but not readable
        adb.add_existing_path("/data/system/netpolicy.xml");

        // Everything else is missing.

        let registry = PathRegistry::default();
        let result = ArtifactScanner::scan_device(&adb, TEST_SERIAL, &registry)
            .expect("scan should succeed");

        assert_eq!(result.found.len(), 2);
        assert_eq!(result.inaccessible.len(), 1);
        assert!(result.found.iter().all(|a| a.artifact_class == ArtifactClass::BuildProp));
        assert_eq!(
            result.inaccessible[0].artifact_class,
            ArtifactClass::NetworkPolicy
        );
    }
}
