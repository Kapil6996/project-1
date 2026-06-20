//! # Capability Detection Engine
//!
//! The core detection engine that probes a connected Android device via ADB
//! to build a comprehensive [`CapabilityProfile`]. This profile drives all
//! downstream acquisition and parsing decisions, ensuring ORACLE only
//! attempts operations confirmed to be feasible.
//!
//! ## Detection Sequence
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │              CapabilityDetector::detect()            │
//! │                                                     │
//! │  1. verify_device_authorized()                      │
//! │  2. detect_device_identity()    → DeviceIdentity    │
//! │  3. detect_root_method()        → RootMethod        │
//! │  4. detect_selinux_mode()       → SelinuxMode       │
//! │  5. detect_bootloader_state()   → BootloaderState   │
//! │  6. detect_encryption_state()   → EncryptionState   │
//! │  7. determine_acquisition_methods()                 │
//! │  8. determine_accessible_artifacts()                │
//! │                                                     │
//! │  └──→ CapabilityProfile                             │
//! └─────────────────────────────────────────────────────┘
//! ```

use chrono::Utc;
use tracing::{debug, info, warn};

use oracle_core::error::{OracleError, OracleResult};
use oracle_core::types::{
    AccessibleArtifactClass, AcquisitionMethod, ArtifactClass, BootloaderState,
    CapabilityProfile, DeviceIdentity, EncryptionState, InaccessibleArtifactClass,
    RootMethod, SelinuxMode,
};

use crate::adb::{AdbDeviceState, AdbInterface};

// ──────────────────────────────────────────────────────────────────────────────
// Known Artifact Paths
// ──────────────────────────────────────────────────────────────────────────────

/// Maps each [`ArtifactClass`] to its known filesystem paths on Android.
///
/// These paths are probed during capability detection to determine which
/// artifact classes are accessible on the target device.
const ARTIFACT_PATHS: &[(ArtifactClass, &[&str])] = &[
    (
        ArtifactClass::WpaSupplicant,
        &[
            "/data/misc/wifi/wpa_supplicant.conf",
            "/data/misc/wifi/WifiConfigStore.xml",
        ],
    ),
    (
        ArtifactClass::WifiConfigStore,
        &[
            "/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml",
            "/data/misc/wifi/WifiConfigStore.xml",
        ],
    ),
    (
        ArtifactClass::DhcpLeases,
        &["/data/misc/dhcp/", "/data/misc/ethernet/"],
    ),
    (
        ArtifactClass::BatteryStats,
        &[
            "/data/system/batterystats.bin",
            "/data/system/batterystats-daily.xml",
        ],
    ),
    (
        ArtifactClass::ConnectivityLogs,
        &["/data/misc/logd/", "/data/system/connectivity/"],
    ),
    (
        ArtifactClass::KernelLogs,
        &["/proc/kmsg", "/dev/kmsg"],
    ),
    (
        ArtifactClass::HostapdLogs,
        &[
            "/data/misc/wifi/hostapd.conf",
            "/data/vendor/wifi/hostapd/",
        ],
    ),
    (
        ArtifactClass::DnsCache,
        &["/data/misc/net/"],
    ),
    (
        ArtifactClass::NetworkPolicy,
        &["/data/system/netpolicy.xml", "/data/system/netstats/"],
    ),
    (
        ArtifactClass::BuildProp,
        &["/system/build.prop", "/vendor/build.prop"],
    ),
];

// ──────────────────────────────────────────────────────────────────────────────
// Detector
// ──────────────────────────────────────────────────────────────────────────────

/// The main Capability Detection Engine.
///
/// Probes a connected Android device via ADB to determine its forensic
/// capabilities, building a complete [`CapabilityProfile`] that guides
/// all downstream acquisition and parsing decisions.
///
/// The detector is stateless — all state is captured in the returned profile.
///
/// # Usage
///
/// ```no_run
/// use oracle_capability::detector::CapabilityDetector;
/// use oracle_capability::adb::LiveAdbInterface;
///
/// let detector = CapabilityDetector::new();
/// let adb = LiveAdbInterface::new();
/// let profile = detector.detect(&adb, "RFXXXXXXXX").unwrap();
/// println!("Root method: {:?}", profile.root_method);
/// ```
pub struct CapabilityDetector;

impl CapabilityDetector {
    /// Creates a new `CapabilityDetector`.
    pub fn new() -> Self {
        Self
    }

    /// Runs the full capability detection sequence on the target device.
    ///
    /// This is the main entry point. It executes all detection steps in order:
    ///
    /// 1. Verify the device is connected and authorized
    /// 2. Detect device identity (manufacturer, model, OS version, etc.)
    /// 3. Detect root access method (Magisk, KernelSU, su, adb root)
    /// 4. Detect SELinux enforcement mode
    /// 5. Detect bootloader lock state
    /// 6. Detect encryption state (FBE/FDE, BFU/AFU)
    /// 7. Determine available acquisition methods
    /// 8. Probe filesystem to determine accessible artifact classes
    ///
    /// # Errors
    ///
    /// - [`OracleError::NoDeviceDetected`] if the device is not found.
    /// - [`OracleError::DeviceUnauthorized`] if ADB access is not authorized.
    /// - [`OracleError::AdbCommandFailed`] if critical ADB commands fail.
    pub fn detect(
        &self,
        adb: &dyn AdbInterface,
        serial: &str,
    ) -> OracleResult<CapabilityProfile> {
        info!(serial = %serial, "Starting capability detection");

        // Step 0: Verify device is connected and authorized.
        self.verify_device_authorized(adb, serial)?;

        // Step 1: Device identity.
        let device = self.detect_device_identity(adb, serial)?;
        info!(
            manufacturer = %device.manufacturer,
            model = %device.model,
            android_version = %device.android_version,
            "Device identity detected"
        );

        // Step 2: Root method.
        let root_method = self.detect_root_method(adb, serial)?;
        info!(root_method = ?root_method, "Root method detected");

        // Step 3: SELinux mode.
        let selinux_mode = self.detect_selinux_mode(adb, serial)?;
        info!(selinux_mode = ?selinux_mode, "SELinux mode detected");

        // Step 4: Bootloader state.
        let bootloader_state = self.detect_bootloader_state(adb, serial)?;
        info!(bootloader_state = ?bootloader_state, "Bootloader state detected");

        // Step 5: Encryption state.
        let encryption_state = self.detect_encryption_state(adb, serial)?;
        info!(encryption_state = ?encryption_state, "Encryption state detected");

        // Step 6: Available acquisition methods.
        let available_methods =
            Self::determine_acquisition_methods(root_method, selinux_mode, encryption_state);
        info!(methods = ?available_methods, "Acquisition methods determined");

        // Step 7: Accessible artifacts.
        let (accessible, inaccessible) = self.determine_accessible_artifacts(
            adb,
            serial,
            root_method,
            selinux_mode,
            &available_methods,
        )?;
        info!(
            accessible_count = accessible.len(),
            inaccessible_count = inaccessible.len(),
            "Artifact accessibility determined"
        );

        let profile = CapabilityProfile {
            device,
            usb_debugging_enabled: true,
            adb_authorized: true,
            root_method,
            selinux_mode,
            bootloader_state,
            encryption_state,
            available_methods,
            accessible_artifact_classes: accessible,
            inaccessible_artifact_classes: inaccessible,
            detected_at: Utc::now(),
            acknowledged: false,
        };

        info!(serial = %serial, "Capability detection completed");
        Ok(profile)
    }

    /// Verifies that the target device is connected and authorized for ADB access.
    ///
    /// # Errors
    ///
    /// - [`OracleError::NoDeviceDetected`] if no device with the given serial is found.
    /// - [`OracleError::DeviceUnauthorized`] if the device has not accepted the RSA key.
    /// - [`OracleError::DeviceOffline`] if the device is in an offline state.
    fn verify_device_authorized(
        &self,
        adb: &dyn AdbInterface,
        serial: &str,
    ) -> OracleResult<()> {
        let devices = adb.list_devices()?;

        let device = devices
            .iter()
            .find(|d| d.serial == serial)
            .ok_or(OracleError::NoDeviceDetected)?;

        match &device.state {
            AdbDeviceState::Device => Ok(()),
            AdbDeviceState::Unauthorized => Err(OracleError::DeviceUnauthorized {
                serial: serial.to_string(),
            }),
            AdbDeviceState::Offline => Err(OracleError::DeviceOffline {
                serial: serial.to_string(),
                state: "offline".to_string(),
            }),
            AdbDeviceState::Unknown(state) => Err(OracleError::DeviceOffline {
                serial: serial.to_string(),
                state: state.clone(),
            }),
        }
    }

    /// Detects the device identity by reading system properties via `getprop`.
    ///
    /// Populates all fields of [`DeviceIdentity`] including OEM skin detection
    /// for Samsung (One UI) and Xiaomi (HyperOS/MIUI) devices.
    fn detect_device_identity(
        &self,
        adb: &dyn AdbInterface,
        serial: &str,
    ) -> OracleResult<DeviceIdentity> {
        debug!(serial = %serial, "Detecting device identity");

        let device_serial = {
            let prop_serial = adb.get_prop(serial, "ro.serialno")?;
            if prop_serial.is_empty() {
                serial.to_string()
            } else {
                prop_serial
            }
        };

        let manufacturer = adb.get_prop(serial, "ro.product.manufacturer")?;
        let model = adb.get_prop(serial, "ro.product.model")?;
        let android_version = adb.get_prop(serial, "ro.build.version.release")?;

        let api_level_str = adb.get_prop(serial, "ro.build.version.sdk")?;
        let api_level = api_level_str.trim().parse::<u32>().unwrap_or(0);

        let security_patch_level = adb.get_prop(serial, "ro.build.version.security_patch")?;
        let build_fingerprint = adb.get_prop(serial, "ro.build.fingerprint")?;

        // OEM skin detection
        let (oem_skin, oem_skin_version) =
            self.detect_oem_skin(adb, serial, &manufacturer)?;

        Ok(DeviceIdentity {
            serial: device_serial,
            manufacturer,
            model,
            android_version,
            api_level,
            security_patch_level,
            build_fingerprint,
            oem_skin,
            oem_skin_version,
        })
    }

    /// Detects OEM skin name and version based on manufacturer.
    ///
    /// Currently supports:
    /// - Samsung → One UI (version from `ro.build.PDA`)
    /// - Xiaomi → HyperOS or MIUI (version from `ro.miui.ui.version.name`)
    fn detect_oem_skin(
        &self,
        adb: &dyn AdbInterface,
        serial: &str,
        manufacturer: &str,
    ) -> OracleResult<(Option<String>, Option<String>)> {
        let mfg_lower = manufacturer.to_lowercase();

        if mfg_lower.contains("samsung") {
            let pda = adb.get_prop(serial, "ro.build.PDA")?;
            let version = if pda.is_empty() { None } else { Some(pda) };
            Ok((Some("One UI".to_string()), version))
        } else if mfg_lower.contains("xiaomi") || mfg_lower.contains("redmi") || mfg_lower.contains("poco") {
            let miui_version = adb.get_prop(serial, "ro.miui.ui.version.name")?;
            if miui_version.is_empty() {
                Ok((None, None))
            } else {
                // HyperOS versions typically start with "OS1." prefix
                let skin_name = if miui_version.starts_with("OS") {
                    "HyperOS"
                } else {
                    "MIUI"
                };
                Ok((
                    Some(skin_name.to_string()),
                    Some(miui_version),
                ))
            }
        } else {
            Ok((None, None))
        }
    }

    /// Detects the root access method available on the device.
    ///
    /// Checks in priority order:
    /// 1. **Magisk** — systemless root via `which magisk`
    /// 2. **KernelSU** — kernel-level root via `/data/adb/ksu` directory
    /// 3. **SystemRoot** — traditional su binary via `which su`
    /// 4. **AdbRoot** — ADB daemon running as root (uid=0)
    /// 5. **None** — no root access detected
    fn detect_root_method(
        &self,
        adb: &dyn AdbInterface,
        serial: &str,
    ) -> OracleResult<RootMethod> {
        debug!(serial = %serial, "Detecting root method");

        // Check for Magisk
        let magisk_path = adb.shell_command(serial, "which magisk").unwrap_or_default();
        if !magisk_path.trim().is_empty() && !magisk_path.contains("not found") {
            debug!("Magisk detected at: {}", magisk_path.trim());
            return Ok(RootMethod::Magisk);
        }

        // Check for KernelSU
        let ksu_exists = adb.check_file_exists(serial, "/data/adb/ksu").unwrap_or_default();
        if ksu_exists {
            debug!("KernelSU detected via /data/adb/ksu");
            return Ok(RootMethod::KernelSU);
        }

        // Check for system su binary
        let su_path = adb.shell_command(serial, "which su").unwrap_or_default();
        if !su_path.trim().is_empty() && !su_path.contains("not found") {
            debug!("System su binary detected at: {}", su_path.trim());
            return Ok(RootMethod::SystemRoot);
        }

        // Check for ADB root (uid=0)
        let id_output = adb.shell_command(serial, "id").unwrap_or_default();
        if id_output.contains("uid=0") {
            debug!("ADB root detected (uid=0)");
            return Ok(RootMethod::AdbRoot);
        }

        debug!("No root method detected");
        Ok(RootMethod::None)
    }

    /// Detects the SELinux enforcement mode on the device.
    ///
    /// Tries `getenforce` first, falls back to reading
    /// `/sys/fs/selinux/enforce`. Returns [`SelinuxMode::Unknown`] if
    /// neither method succeeds.
    fn detect_selinux_mode(
        &self,
        adb: &dyn AdbInterface,
        serial: &str,
    ) -> OracleResult<SelinuxMode> {
        debug!(serial = %serial, "Detecting SELinux mode");

        // Primary: getenforce command
        let getenforce = adb.shell_command(serial, "getenforce").unwrap_or_default();
        let getenforce_trimmed = getenforce.trim().to_lowercase();

        if getenforce_trimmed.contains("enforcing") {
            return Ok(SelinuxMode::Enforcing);
        }
        if getenforce_trimmed.contains("permissive") {
            return Ok(SelinuxMode::Permissive);
        }
        if getenforce_trimmed.contains("disabled") {
            return Ok(SelinuxMode::Disabled);
        }

        // Fallback: read the selinux enforce node
        let enforce_node =
            adb.shell_command(serial, "cat /sys/fs/selinux/enforce").unwrap_or_default();
        let enforce_trimmed = enforce_node.trim();

        match enforce_trimmed {
            "1" => Ok(SelinuxMode::Enforcing),
            "0" => Ok(SelinuxMode::Permissive),
            _ => {
                warn!(
                    serial = %serial,
                    getenforce = %getenforce,
                    enforce_node = %enforce_node,
                    "Could not determine SELinux mode"
                );
                Ok(SelinuxMode::Unknown)
            }
        }
    }

    /// Detects the bootloader lock state via `ro.boot.verifiedbootstate`.
    ///
    /// Mapping:
    /// - `"green"` → Locked (verified boot intact)
    /// - `"orange"` → Unlocked (bootloader unlocked)
    /// - `"yellow"` or `"red"` → Tampered (custom key or verification failure)
    fn detect_bootloader_state(
        &self,
        adb: &dyn AdbInterface,
        serial: &str,
    ) -> OracleResult<BootloaderState> {
        debug!(serial = %serial, "Detecting bootloader state");

        let vb_state = adb.get_prop(serial, "ro.boot.verifiedbootstate")?;
        let state = match vb_state.trim().to_lowercase().as_str() {
            "green" => BootloaderState::Locked,
            "orange" => BootloaderState::Unlocked,
            "yellow" | "red" => BootloaderState::Tampered,
            other => {
                if !other.is_empty() {
                    warn!(
                        serial = %serial,
                        verified_boot_state = %other,
                        "Unrecognized verified boot state"
                    );
                }
                BootloaderState::Unknown
            }
        };

        Ok(state)
    }

    /// Detects the encryption state of the device.
    ///
    /// Reads `ro.crypto.state` to determine the encryption mode, then
    /// further checks `ro.crypto.type` for FBE vs FDE, and probes
    /// `/data/data/` to distinguish BFU from AFU.
    fn detect_encryption_state(
        &self,
        adb: &dyn AdbInterface,
        serial: &str,
    ) -> OracleResult<EncryptionState> {
        debug!(serial = %serial, "Detecting encryption state");

        let crypto_state = adb.get_prop(serial, "ro.crypto.state")?;
        let crypto_state_trimmed = crypto_state.trim().to_lowercase();

        match crypto_state_trimmed.as_str() {
            "encrypted" => {
                let crypto_type = adb.get_prop(serial, "ro.crypto.type")?;
                let crypto_type_trimmed = crypto_type.trim().to_lowercase();

                if crypto_type_trimmed == "block" {
                    return Ok(EncryptionState::FullDiskEncryption);
                }

                // File-based encryption — determine BFU vs AFU
                // If /data/data/ is accessible and non-empty, CE keys are loaded (AFU)
                let data_listing =
                    adb.shell_command(serial, "ls /data/data/ 2>/dev/null").unwrap_or_default();

                if data_listing.trim().is_empty() {
                    Ok(EncryptionState::BeforeFirstUnlock)
                } else {
                    Ok(EncryptionState::AfterFirstUnlock)
                }
            }
            "unencrypted" => {
                // No encryption barrier — equivalent to AFU
                Ok(EncryptionState::AfterFirstUnlock)
            }
            _ => {
                warn!(
                    serial = %serial,
                    crypto_state = %crypto_state,
                    "Could not determine encryption state"
                );
                Ok(EncryptionState::Unknown)
            }
        }
    }

    /// Determines which acquisition methods are available based on
    /// the device's root status, SELinux mode, and encryption state.
    ///
    /// The returned list is sorted by preference (most capable first).
    pub fn determine_acquisition_methods(
        root_method: RootMethod,
        _selinux_mode: SelinuxMode,
        _encryption_state: EncryptionState,
    ) -> Vec<AcquisitionMethod> {
        let mut methods = Vec::new();

        if root_method != RootMethod::None {
            // Rooted device — privileged access is available
            methods.push(AcquisitionMethod::PrivilegedLogical);
        }

        // Content provider queries are always available when ADB is authorized
        methods.push(AcquisitionMethod::ContentProvider);

        if root_method == RootMethod::None {
            // Unrooted — limited methods only
            methods.push(AcquisitionMethod::UnprivilegedLogical);
            methods.push(AcquisitionMethod::AdbBackup);
        }

        methods
    }

    /// Probes the device filesystem to determine which artifact classes
    /// are accessible and which are not.
    ///
    /// For each known artifact class and its associated paths, checks
    /// file readability. Produces both an accessible list (with acquisition
    /// method and confidence) and an inaccessible list (with forensic
    /// justification for inaccessibility).
    fn determine_accessible_artifacts(
        &self,
        adb: &dyn AdbInterface,
        serial: &str,
        root_method: RootMethod,
        selinux_mode: SelinuxMode,
        available_methods: &[AcquisitionMethod],
    ) -> OracleResult<(Vec<AccessibleArtifactClass>, Vec<InaccessibleArtifactClass>)> {
        let mut accessible = Vec::new();
        let mut inaccessible = Vec::new();

        for (artifact_class, paths) in ARTIFACT_PATHS {
            let mut found_readable = false;

            for path in *paths {
                match adb.check_file_readable(serial, path) {
                    Ok(true) => {
                        found_readable = true;

                        // Select the best acquisition method for this artifact
                        let method = if available_methods
                            .contains(&AcquisitionMethod::PrivilegedLogical)
                        {
                            AcquisitionMethod::PrivilegedLogical
                        } else {
                            AcquisitionMethod::UnprivilegedLogical
                        };

                        accessible.push(AccessibleArtifactClass {
                            artifact_class: *artifact_class,
                            acquisition_method: method,
                            confidence: artifact_class.baseline_reliability(),
                        });

                        break; // One readable path is sufficient
                    }
                    Ok(false) => continue,
                    Err(e) => {
                        debug!(
                            artifact = ?artifact_class,
                            path = %path,
                            error = %e,
                            "Error checking file readability, skipping path"
                        );
                        continue;
                    }
                }
            }

            if !found_readable {
                let reason = Self::determine_inaccessibility_reason(
                    root_method,
                    selinux_mode,
                    artifact_class,
                );
                inaccessible.push(InaccessibleArtifactClass {
                    artifact_class: *artifact_class,
                    reason,
                });
            }
        }

        Ok((accessible, inaccessible))
    }

    /// Produces a forensic justification for why an artifact class is
    /// inaccessible on this device.
    fn determine_inaccessibility_reason(
        root_method: RootMethod,
        selinux_mode: SelinuxMode,
        _artifact_class: &ArtifactClass,
    ) -> String {
        if root_method == RootMethod::None {
            "Requires root access — file resides in privileged partition".to_string()
        } else if selinux_mode == SelinuxMode::Enforcing {
            "SELinux enforcing — MAC policy blocks access even with root".to_string()
        } else {
            "File not found on device".to_string()
        }
    }
}

impl Default for CapabilityDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adb::{AdbDeviceState, MockAdbInterface};

    /// Helper: creates a mock ADB interface simulating a basic connected device.
    fn base_mock(serial: &str) -> MockAdbInterface {
        MockAdbInterface::new()
            .with_device(serial, AdbDeviceState::Device)
            .with_prop(serial, "ro.serialno", serial)
            .with_prop(serial, "ro.product.manufacturer", "Google")
            .with_prop(serial, "ro.product.model", "Pixel 8 Pro")
            .with_prop(serial, "ro.build.version.release", "14")
            .with_prop(serial, "ro.build.version.sdk", "34")
            .with_prop(serial, "ro.build.version.security_patch", "2024-12-01")
            .with_prop(serial, "ro.build.fingerprint", "google/husky/husky:14/AP2A.240905.003/12231197:userdebug/dev-keys")
            .with_shell_response(serial, "which magisk", "")
            .with_shell_response(serial, "which su", "")
            .with_shell_response(serial, "id", "uid=2000(shell)")
            .with_shell_response(serial, "getenforce", "Enforcing")
            .with_prop(serial, "ro.boot.verifiedbootstate", "green")
            .with_prop(serial, "ro.crypto.state", "encrypted")
            .with_prop(serial, "ro.crypto.type", "file")
            .with_shell_response(serial, "ls /data/data/ 2>/dev/null", "com.android.settings\ncom.google.android.gms")
            .with_file_exists(serial, "/data/adb/ksu", false)
    }

    // ── Device Identity Tests ───────────────────────────────────────────

    #[test]
    fn test_detect_device_identity() {
        let serial = "PIXEL8PRO";
        let mock = base_mock(serial);
        let detector = CapabilityDetector::new();

        let identity = detector.detect_device_identity(&mock, serial).unwrap();

        assert_eq!(identity.serial, serial);
        assert_eq!(identity.manufacturer, "Google");
        assert_eq!(identity.model, "Pixel 8 Pro");
        assert_eq!(identity.android_version, "14");
        assert_eq!(identity.api_level, 34);
        assert_eq!(identity.security_patch_level, "2024-12-01");
        assert!(identity.build_fingerprint.contains("google/husky"));
        // Google devices don't have a known OEM skin
        assert!(identity.oem_skin.is_none());
    }

    #[test]
    fn test_detect_device_identity_samsung() {
        let serial = "RF8N123456";
        let mock = MockAdbInterface::new()
            .with_device(serial, AdbDeviceState::Device)
            .with_prop(serial, "ro.serialno", serial)
            .with_prop(serial, "ro.product.manufacturer", "samsung")
            .with_prop(serial, "ro.product.model", "SM-S928B")
            .with_prop(serial, "ro.build.version.release", "14")
            .with_prop(serial, "ro.build.version.sdk", "34")
            .with_prop(serial, "ro.build.version.security_patch", "2024-11-01")
            .with_prop(serial, "ro.build.fingerprint", "samsung/e3qxxx/e3q:14/UP1A.231005.007/S928BXXU1AXLA:user/release-keys")
            .with_prop(serial, "ro.build.PDA", "S928BXXU1AXLA");

        let detector = CapabilityDetector::new();
        let identity = detector.detect_device_identity(&mock, serial).unwrap();

        assert_eq!(identity.manufacturer, "samsung");
        assert_eq!(identity.model, "SM-S928B");
        assert_eq!(identity.oem_skin.as_deref(), Some("One UI"));
        assert_eq!(identity.oem_skin_version.as_deref(), Some("S928BXXU1AXLA"));
    }

    // ── Root Detection Tests ────────────────────────────────────────────

    #[test]
    fn test_detect_root_magisk() {
        let serial = "DEV1";
        let mock = MockAdbInterface::new()
            .with_shell_response(serial, "which magisk", "/sbin/magisk")
            .with_file_exists(serial, "/data/adb/ksu", false);

        let detector = CapabilityDetector::new();
        let root = detector.detect_root_method(&mock, serial).unwrap();
        assert_eq!(root, RootMethod::Magisk);
    }

    #[test]
    fn test_detect_root_kernelsu() {
        let serial = "DEV1";
        let mock = MockAdbInterface::new()
            .with_shell_response(serial, "which magisk", "")
            .with_file_exists(serial, "/data/adb/ksu", true);

        let detector = CapabilityDetector::new();
        let root = detector.detect_root_method(&mock, serial).unwrap();
        assert_eq!(root, RootMethod::KernelSU);
    }

    #[test]
    fn test_detect_root_system_su() {
        let serial = "DEV1";
        let mock = MockAdbInterface::new()
            .with_shell_response(serial, "which magisk", "")
            .with_file_exists(serial, "/data/adb/ksu", false)
            .with_shell_response(serial, "which su", "/system/bin/su")
            .with_shell_response(serial, "id", "uid=2000(shell)");

        let detector = CapabilityDetector::new();
        let root = detector.detect_root_method(&mock, serial).unwrap();
        assert_eq!(root, RootMethod::SystemRoot);
    }

    #[test]
    fn test_detect_root_adb_root() {
        let serial = "DEV1";
        let mock = MockAdbInterface::new()
            .with_shell_response(serial, "which magisk", "")
            .with_file_exists(serial, "/data/adb/ksu", false)
            .with_shell_response(serial, "which su", "")
            .with_shell_response(serial, "id", "uid=0(root) gid=0(root)");

        let detector = CapabilityDetector::new();
        let root = detector.detect_root_method(&mock, serial).unwrap();
        assert_eq!(root, RootMethod::AdbRoot);
    }

    #[test]
    fn test_detect_root_none() {
        let serial = "DEV1";
        let mock = MockAdbInterface::new()
            .with_shell_response(serial, "which magisk", "")
            .with_file_exists(serial, "/data/adb/ksu", false)
            .with_shell_response(serial, "which su", "")
            .with_shell_response(serial, "id", "uid=2000(shell) gid=2000(shell)");

        let detector = CapabilityDetector::new();
        let root = detector.detect_root_method(&mock, serial).unwrap();
        assert_eq!(root, RootMethod::None);
    }

    // ── SELinux Detection Tests ─────────────────────────────────────────

    #[test]
    fn test_detect_selinux_enforcing() {
        let serial = "DEV1";
        let mock = MockAdbInterface::new()
            .with_shell_response(serial, "getenforce", "Enforcing");

        let detector = CapabilityDetector::new();
        let mode = detector.detect_selinux_mode(&mock, serial).unwrap();
        assert_eq!(mode, SelinuxMode::Enforcing);
    }

    #[test]
    fn test_detect_selinux_permissive() {
        let serial = "DEV1";
        let mock = MockAdbInterface::new()
            .with_shell_response(serial, "getenforce", "Permissive");

        let detector = CapabilityDetector::new();
        let mode = detector.detect_selinux_mode(&mock, serial).unwrap();
        assert_eq!(mode, SelinuxMode::Permissive);
    }

    #[test]
    fn test_detect_selinux_disabled() {
        let serial = "DEV1";
        let mock = MockAdbInterface::new()
            .with_shell_response(serial, "getenforce", "Disabled");

        let detector = CapabilityDetector::new();
        let mode = detector.detect_selinux_mode(&mock, serial).unwrap();
        assert_eq!(mode, SelinuxMode::Disabled);
    }

    #[test]
    fn test_detect_selinux_fallback_to_enforce_node() {
        let serial = "DEV1";
        let mock = MockAdbInterface::new()
            .with_shell_response(serial, "getenforce", "")
            .with_shell_response(serial, "cat /sys/fs/selinux/enforce", "0");

        let detector = CapabilityDetector::new();
        let mode = detector.detect_selinux_mode(&mock, serial).unwrap();
        assert_eq!(mode, SelinuxMode::Permissive);
    }

    #[test]
    fn test_detect_selinux_unknown() {
        let serial = "DEV1";
        let mock = MockAdbInterface::new()
            .with_shell_response(serial, "getenforce", "")
            .with_shell_response(serial, "cat /sys/fs/selinux/enforce", "");

        let detector = CapabilityDetector::new();
        let mode = detector.detect_selinux_mode(&mock, serial).unwrap();
        assert_eq!(mode, SelinuxMode::Unknown);
    }

    // ── Authorization Tests ─────────────────────────────────────────────

    #[test]
    fn test_unauthorized_device_returns_error() {
        let serial = "UNAUTH_DEV";
        let mock = MockAdbInterface::new()
            .with_device(serial, AdbDeviceState::Unauthorized);

        let detector = CapabilityDetector::new();
        let result = detector.detect(&mock, serial);

        assert!(result.is_err());
        match result.unwrap_err() {
            OracleError::DeviceUnauthorized { serial: s } => {
                assert_eq!(s, serial);
            }
            other => panic!("Expected DeviceUnauthorized, got: {:?}", other),
        }
    }

    #[test]
    fn test_no_device_detected() {
        let mock = MockAdbInterface::new();
        let detector = CapabilityDetector::new();

        let result = detector.detect(&mock, "NONEXISTENT");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OracleError::NoDeviceDetected));
    }

    // ── Acquisition Method Tests ────────────────────────────────────────

    #[test]
    fn test_acquisition_methods_rooted_permissive() {
        let methods = CapabilityDetector::determine_acquisition_methods(
            RootMethod::Magisk,
            SelinuxMode::Permissive,
            EncryptionState::AfterFirstUnlock,
        );

        assert!(methods.contains(&AcquisitionMethod::PrivilegedLogical));
        assert!(methods.contains(&AcquisitionMethod::ContentProvider));
        // Should NOT include unprivileged-only methods
        assert!(!methods.contains(&AcquisitionMethod::UnprivilegedLogical));
        assert!(!methods.contains(&AcquisitionMethod::AdbBackup));
    }

    #[test]
    fn test_acquisition_methods_rooted_enforcing() {
        let methods = CapabilityDetector::determine_acquisition_methods(
            RootMethod::Magisk,
            SelinuxMode::Enforcing,
            EncryptionState::AfterFirstUnlock,
        );

        // Privileged logical should still be available with root, even if SELinux is enforcing
        assert!(methods.contains(&AcquisitionMethod::PrivilegedLogical));
        assert!(methods.contains(&AcquisitionMethod::ContentProvider));
    }

    #[test]
    fn test_acquisition_methods_unrooted_afu() {
        let methods = CapabilityDetector::determine_acquisition_methods(
            RootMethod::None,
            SelinuxMode::Enforcing,
            EncryptionState::AfterFirstUnlock,
        );

        assert!(!methods.contains(&AcquisitionMethod::PrivilegedLogical));
        assert!(methods.contains(&AcquisitionMethod::ContentProvider));
        assert!(methods.contains(&AcquisitionMethod::UnprivilegedLogical));
        assert!(methods.contains(&AcquisitionMethod::AdbBackup));
    }

    #[test]
    fn test_acquisition_methods_unrooted_bfu() {
        let methods = CapabilityDetector::determine_acquisition_methods(
            RootMethod::None,
            SelinuxMode::Enforcing,
            EncryptionState::BeforeFirstUnlock,
        );

        // Same methods available — BFU affects what data is decrypted, not method availability
        assert!(!methods.contains(&AcquisitionMethod::PrivilegedLogical));
        assert!(methods.contains(&AcquisitionMethod::ContentProvider));
        assert!(methods.contains(&AcquisitionMethod::UnprivilegedLogical));
        assert!(methods.contains(&AcquisitionMethod::AdbBackup));
    }

    // ── Bootloader Detection Tests ──────────────────────────────────────

    #[test]
    fn test_detect_bootloader_locked() {
        let serial = "DEV1";
        let mock = MockAdbInterface::new()
            .with_prop(serial, "ro.boot.verifiedbootstate", "green");

        let detector = CapabilityDetector::new();
        let state = detector.detect_bootloader_state(&mock, serial).unwrap();
        assert_eq!(state, BootloaderState::Locked);
    }

    #[test]
    fn test_detect_bootloader_unlocked() {
        let serial = "DEV1";
        let mock = MockAdbInterface::new()
            .with_prop(serial, "ro.boot.verifiedbootstate", "orange");

        let detector = CapabilityDetector::new();
        let state = detector.detect_bootloader_state(&mock, serial).unwrap();
        assert_eq!(state, BootloaderState::Unlocked);
    }

    #[test]
    fn test_detect_bootloader_tampered() {
        let serial = "DEV1";
        let mock = MockAdbInterface::new()
            .with_prop(serial, "ro.boot.verifiedbootstate", "yellow");

        let detector = CapabilityDetector::new();
        let state = detector.detect_bootloader_state(&mock, serial).unwrap();
        assert_eq!(state, BootloaderState::Tampered);
    }

    // ── Encryption Detection Tests ──────────────────────────────────────

    #[test]
    fn test_detect_encryption_fbe_afu() {
        let serial = "DEV1";
        let mock = MockAdbInterface::new()
            .with_prop(serial, "ro.crypto.state", "encrypted")
            .with_prop(serial, "ro.crypto.type", "file")
            .with_shell_response(serial, "ls /data/data/ 2>/dev/null", "com.android.settings");

        let detector = CapabilityDetector::new();
        let state = detector.detect_encryption_state(&mock, serial).unwrap();
        assert_eq!(state, EncryptionState::AfterFirstUnlock);
    }

    #[test]
    fn test_detect_encryption_fbe_bfu() {
        let serial = "DEV1";
        let mock = MockAdbInterface::new()
            .with_prop(serial, "ro.crypto.state", "encrypted")
            .with_prop(serial, "ro.crypto.type", "file")
            .with_shell_response(serial, "ls /data/data/ 2>/dev/null", "");

        let detector = CapabilityDetector::new();
        let state = detector.detect_encryption_state(&mock, serial).unwrap();
        assert_eq!(state, EncryptionState::BeforeFirstUnlock);
    }

    #[test]
    fn test_detect_encryption_fde() {
        let serial = "DEV1";
        let mock = MockAdbInterface::new()
            .with_prop(serial, "ro.crypto.state", "encrypted")
            .with_prop(serial, "ro.crypto.type", "block");

        let detector = CapabilityDetector::new();
        let state = detector.detect_encryption_state(&mock, serial).unwrap();
        assert_eq!(state, EncryptionState::FullDiskEncryption);
    }

    #[test]
    fn test_detect_encryption_unencrypted() {
        let serial = "DEV1";
        let mock = MockAdbInterface::new()
            .with_prop(serial, "ro.crypto.state", "unencrypted");

        let detector = CapabilityDetector::new();
        let state = detector.detect_encryption_state(&mock, serial).unwrap();
        assert_eq!(state, EncryptionState::AfterFirstUnlock);
    }

    // ── Full Detection Flow ─────────────────────────────────────────────

    #[test]
    fn test_full_detection_flow() {
        let serial = "FULL_TEST";
        let mock = base_mock(serial)
            .with_shell_response(serial, "which magisk", "/sbin/magisk")
            .with_shell_response(serial, "getenforce", "Permissive")
            .with_prop(serial, "ro.boot.verifiedbootstate", "orange")
            .with_file_readable(serial, "/system/build.prop", true)
            .with_file_readable(serial, "/data/misc/wifi/WifiConfigStore.xml", true)
            .with_file_readable(serial, "/proc/kmsg", true);

        let detector = CapabilityDetector::new();
        let profile = detector.detect(&mock, serial).unwrap();

        // Verify device identity
        assert_eq!(profile.device.manufacturer, "Google");
        assert_eq!(profile.device.model, "Pixel 8 Pro");
        assert_eq!(profile.device.api_level, 34);

        // Verify capabilities
        assert_eq!(profile.root_method, RootMethod::Magisk);
        assert_eq!(profile.selinux_mode, SelinuxMode::Permissive);
        assert_eq!(profile.bootloader_state, BootloaderState::Unlocked);
        assert_eq!(profile.encryption_state, EncryptionState::AfterFirstUnlock);

        // Verify acquisition methods
        assert!(profile.available_methods.contains(&AcquisitionMethod::PrivilegedLogical));
        assert!(profile.available_methods.contains(&AcquisitionMethod::ContentProvider));

        // Verify some artifacts are accessible
        assert!(!profile.accessible_artifact_classes.is_empty());

        // Verify profile metadata
        assert!(profile.usb_debugging_enabled);
        assert!(profile.adb_authorized);
        assert!(!profile.acknowledged);
    }
}
