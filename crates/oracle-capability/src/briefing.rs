//! # Investigator Briefing Generator
//!
//! Produces a human-readable briefing from a [`CapabilityProfile`],
//! summarizing what artifacts are accessible, what is inaccessible (and why),
//! the recommended acquisition method, and any warnings about limitations.
//!
//! The briefing is presented to the forensic examiner before acquisition
//! begins, ensuring informed consent and documented awareness of the
//! investigation's forensic scope.

use serde::{Deserialize, Serialize};

use oracle_core::types::{
    AcquisitionMethod, CapabilityProfile, EncryptionState, RootMethod, SelinuxMode,
};

// ──────────────────────────────────────────────────────────────────────────────
// Briefing Structure
// ──────────────────────────────────────────────────────────────────────────────

/// A human-readable briefing summarizing the forensic capabilities
/// detected on the target device.
///
/// This briefing is presented to the investigator before acquisition
/// begins, ensuring they understand what evidence is and is not
/// recoverable from the device given its current state.
///
/// # Fields
///
/// - `accessible_summary` — One line per accessible artifact class,
///   including acquisition method and confidence percentage.
/// - `inaccessible_summary` — One line per inaccessible artifact class,
///   with forensic justification for inaccessibility.
/// - `warnings` — Critical alerts about limitations (e.g., no root, BFU state).
/// - `recommended_method` — The optimal acquisition method for this device.
/// - `full_text` — Complete formatted briefing text for display or printing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigatorBriefing {
    /// Summary of accessible artifact classes and their acquisition methods.
    pub accessible_summary: Vec<String>,
    /// Summary of inaccessible artifact classes with forensic reasons.
    pub inaccessible_summary: Vec<String>,
    /// Warnings about limitations, data that cannot be recovered, etc.
    pub warnings: Vec<String>,
    /// The recommended acquisition method for this device state.
    pub recommended_method: Option<AcquisitionMethod>,
    /// Human-readable formatted text of the full briefing.
    pub full_text: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Generator
// ──────────────────────────────────────────────────────────────────────────────

/// Generates an investigator briefing from a capability profile.
///
/// The briefing provides a comprehensive, human-readable summary of:
/// - What artifacts are accessible and via which acquisition method
/// - What artifacts are inaccessible and why
/// - The recommended acquisition method given the device state
/// - Warnings about evidence that cannot be recovered
///
/// This briefing must be reviewed and acknowledged by the examiner
/// before any acquisition proceeds.
///
/// # Examples
///
/// ```
/// use oracle_capability::briefing::generate_briefing;
/// // let profile = detector.detect(&adb, serial).unwrap();
/// // let briefing = generate_briefing(&profile);
/// // println!("{}", briefing.full_text);
/// ```
pub fn generate_briefing(profile: &CapabilityProfile) -> InvestigatorBriefing {
    // Build accessible artifact summary
    let accessible_summary: Vec<String> = profile
        .accessible_artifact_classes
        .iter()
        .map(|a| {
            format!(
                "{:?} — accessible via {:?} (confidence: {:.0}%)",
                a.artifact_class,
                a.acquisition_method,
                a.confidence * 100.0
            )
        })
        .collect();

    // Build inaccessible artifact summary
    let inaccessible_summary: Vec<String> = profile
        .inaccessible_artifact_classes
        .iter()
        .map(|i| {
            format!(
                "{:?} — INACCESSIBLE: {}",
                i.artifact_class, i.reason
            )
        })
        .collect();

    // Build warnings
    let warnings = generate_warnings(profile);

    // Determine recommended method
    let recommended_method = determine_recommended_method(profile);

    // Build full text
    let full_text = format_full_text(
        profile,
        &accessible_summary,
        &inaccessible_summary,
        &warnings,
        recommended_method,
    );

    InvestigatorBriefing {
        accessible_summary,
        inaccessible_summary,
        warnings,
        recommended_method,
        full_text,
    }
}

/// Generates warning messages based on the device's capability profile.
///
/// Warnings alert the examiner to significant limitations that may affect
/// the scope and completeness of the forensic investigation.
fn generate_warnings(profile: &CapabilityProfile) -> Vec<String> {
    let mut warnings = Vec::new();

    // No root access warning
    if profile.root_method == RootMethod::None {
        warnings.push(
            "Device is NOT rooted. Only unprivileged extraction methods are available. \
             Many system-level artifacts will be inaccessible."
                .to_string(),
        );
    }

    // SELinux enforcing with root
    if profile.selinux_mode == SelinuxMode::Enforcing
        && profile.root_method != RootMethod::None
    {
        warnings.push(
            "SELinux is ENFORCING. Even with root access, some artifacts may be \
             blocked by Mandatory Access Control policies."
                .to_string(),
        );
    }

    // Encryption state warnings
    match profile.encryption_state {
        EncryptionState::BeforeFirstUnlock => {
            warnings.push(
                "Device is in Before First Unlock (BFU) state. Credential-encrypted (CE) \
                 storage is NOT accessible. Only device-encrypted (DE) artifacts can be \
                 recovered."
                    .to_string(),
            );
        }
        EncryptionState::FullDiskEncryption => {
            warnings.push(
                "Device uses legacy Full Disk Encryption. Access depends on whether \
                 the device has been unlocked."
                    .to_string(),
            );
        }
        EncryptionState::Unknown => {
            warnings.push(
                "Encryption state could not be determined. Proceed with caution — \
                 some artifacts may be encrypted and inaccessible."
                    .to_string(),
            );
        }
        EncryptionState::AfterFirstUnlock => {}
    }

    // Inaccessible artifacts count
    if !profile.inaccessible_artifact_classes.is_empty() {
        warnings.push(format!(
            "{} artifact class(es) are INACCESSIBLE. Evidence from these sources \
             cannot be recovered with current device state.",
            profile.inaccessible_artifact_classes.len()
        ));
    }

    warnings
}

/// Determines the recommended acquisition method based on device capabilities.
///
/// Priority order:
/// 1. `PrivilegedLogical` — fullest coverage with root
/// 2. `ContentProvider` — good coverage via Android APIs
/// 3. `UnprivilegedLogical` — limited but non-invasive
/// 4. `AdbBackup` — legacy fallback
/// 5. First available method as last resort
fn determine_recommended_method(
    profile: &CapabilityProfile,
) -> Option<AcquisitionMethod> {
    let priority = [
        AcquisitionMethod::PrivilegedLogical,
        AcquisitionMethod::ContentProvider,
        AcquisitionMethod::UnprivilegedLogical,
        AcquisitionMethod::AdbBackup,
        AcquisitionMethod::OfflineImage,
    ];

    for method in &priority {
        if profile.available_methods.contains(method) {
            return Some(*method);
        }
    }

    profile.available_methods.first().copied()
}

/// Formats the full briefing text for display or printing.
fn format_full_text(
    profile: &CapabilityProfile,
    accessible_summary: &[String],
    inaccessible_summary: &[String],
    warnings: &[String],
    recommended_method: Option<AcquisitionMethod>,
) -> String {
    let mut text = String::with_capacity(2048);

    // Header
    text.push_str("═══════════════════════════════════════════════════════════════\n");
    text.push_str("                  INVESTIGATOR BRIEFING\n");
    text.push_str("═══════════════════════════════════════════════════════════════\n\n");

    // Device summary
    text.push_str(&format!(
        "Device: {} {} (Android {})\n",
        profile.device.manufacturer, profile.device.model, profile.device.android_version
    ));
    text.push_str(&format!("Serial: {}\n", profile.device.serial));
    text.push_str(&format!(
        "Build:  {}\n",
        profile.device.build_fingerprint
    ));
    text.push_str(&format!(
        "Patch:  {}\n",
        profile.device.security_patch_level
    ));

    if let Some(skin) = &profile.device.oem_skin {
        text.push_str(&format!("Skin:   {}", skin));
        if let Some(ver) = &profile.device.oem_skin_version {
            text.push_str(&format!(" ({})", ver));
        }
        text.push('\n');
    }

    text.push('\n');

    // Device state
    text.push_str(&format!("Root:       {:?}\n", profile.root_method));
    text.push_str(&format!("SELinux:    {:?}\n", profile.selinux_mode));
    text.push_str(&format!("Encryption: {:?}\n", profile.encryption_state));
    text.push_str(&format!("Bootloader: {:?}\n\n", profile.bootloader_state));

    // Recommended method
    if let Some(method) = recommended_method {
        text.push_str(&format!("RECOMMENDED METHOD: {:?}\n\n", method));
    }

    // Accessible artifacts
    text.push_str("── ACCESSIBLE ARTIFACTS ──\n");
    if accessible_summary.is_empty() {
        text.push_str("  (none)\n");
    } else {
        for s in accessible_summary {
            text.push_str(&format!("  ✓ {}\n", s));
        }
    }
    text.push('\n');

    // Inaccessible artifacts
    text.push_str("── INACCESSIBLE ARTIFACTS ──\n");
    if inaccessible_summary.is_empty() {
        text.push_str("  (none)\n");
    } else {
        for s in inaccessible_summary {
            text.push_str(&format!("  ✗ {}\n", s));
        }
    }
    text.push('\n');

    // Warnings
    if !warnings.is_empty() {
        text.push_str("── WARNINGS ──\n");
        for w in warnings {
            text.push_str(&format!("  ⚠ {}\n", w));
        }
        text.push('\n');
    }

    text.push_str("═══════════════════════════════════════════════════════════════\n");

    text
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use oracle_core::types::*;

    /// Creates a test profile with the given capability parameters.
    fn make_test_profile(
        root: RootMethod,
        selinux: SelinuxMode,
        encryption: EncryptionState,
        accessible: Vec<AccessibleArtifactClass>,
        inaccessible: Vec<InaccessibleArtifactClass>,
        methods: Vec<AcquisitionMethod>,
    ) -> CapabilityProfile {
        CapabilityProfile {
            device: DeviceIdentity {
                serial: "TEST_SERIAL".into(),
                manufacturer: "Samsung".into(),
                model: "SM-S928B".into(),
                android_version: "14".into(),
                api_level: 34,
                security_patch_level: "2024-12-01".into(),
                build_fingerprint: "samsung/e3qxxx/e3q:14/test".into(),
                oem_skin: Some("One UI".into()),
                oem_skin_version: Some("6.1".into()),
            },
            usb_debugging_enabled: true,
            adb_authorized: true,
            root_method: root,
            selinux_mode: selinux,
            bootloader_state: BootloaderState::Locked,
            encryption_state: encryption,
            available_methods: methods,
            accessible_artifact_classes: accessible,
            inaccessible_artifact_classes: inaccessible,
            detected_at: Utc::now(),
            acknowledged: false,
        }
    }

    #[test]
    fn test_briefing_accessible_artifacts() {
        let accessible = vec![
            AccessibleArtifactClass {
                artifact_class: ArtifactClass::BuildProp,
                acquisition_method: AcquisitionMethod::PrivilegedLogical,
                confidence: 0.99,
            },
            AccessibleArtifactClass {
                artifact_class: ArtifactClass::WifiConfigStore,
                acquisition_method: AcquisitionMethod::PrivilegedLogical,
                confidence: 0.95,
            },
        ];

        let profile = make_test_profile(
            RootMethod::Magisk,
            SelinuxMode::Permissive,
            EncryptionState::AfterFirstUnlock,
            accessible,
            vec![],
            vec![AcquisitionMethod::PrivilegedLogical, AcquisitionMethod::ContentProvider],
        );

        let briefing = generate_briefing(&profile);

        assert_eq!(briefing.accessible_summary.len(), 2);
        assert!(briefing.accessible_summary[0].contains("BuildProp"));
        assert!(briefing.accessible_summary[0].contains("99%"));
        assert!(briefing.accessible_summary[1].contains("WifiConfigStore"));
        assert!(briefing.inaccessible_summary.is_empty());
    }

    #[test]
    fn test_briefing_inaccessible_artifacts() {
        let inaccessible = vec![
            InaccessibleArtifactClass {
                artifact_class: ArtifactClass::KernelLogs,
                reason: "Requires root access — file resides in privileged partition".into(),
            },
            InaccessibleArtifactClass {
                artifact_class: ArtifactClass::WpaSupplicant,
                reason: "Requires root access — file resides in privileged partition".into(),
            },
        ];

        let profile = make_test_profile(
            RootMethod::None,
            SelinuxMode::Enforcing,
            EncryptionState::AfterFirstUnlock,
            vec![],
            inaccessible,
            vec![AcquisitionMethod::UnprivilegedLogical, AcquisitionMethod::AdbBackup],
        );

        let briefing = generate_briefing(&profile);

        assert_eq!(briefing.inaccessible_summary.len(), 2);
        assert!(briefing.inaccessible_summary[0].contains("KernelLogs"));
        assert!(briefing.inaccessible_summary[0].contains("INACCESSIBLE"));
        assert!(briefing.inaccessible_summary[1].contains("WpaSupplicant"));
    }

    #[test]
    fn test_briefing_bfu_warning() {
        let profile = make_test_profile(
            RootMethod::Magisk,
            SelinuxMode::Permissive,
            EncryptionState::BeforeFirstUnlock,
            vec![],
            vec![],
            vec![AcquisitionMethod::PrivilegedLogical],
        );

        let briefing = generate_briefing(&profile);

        let has_bfu_warning = briefing
            .warnings
            .iter()
            .any(|w| w.contains("Before First Unlock"));
        assert!(
            has_bfu_warning,
            "Expected BFU warning, got: {:?}",
            briefing.warnings
        );
    }

    #[test]
    fn test_briefing_no_root_warning() {
        let profile = make_test_profile(
            RootMethod::None,
            SelinuxMode::Enforcing,
            EncryptionState::AfterFirstUnlock,
            vec![],
            vec![],
            vec![AcquisitionMethod::UnprivilegedLogical],
        );

        let briefing = generate_briefing(&profile);

        let has_no_root_warning = briefing
            .warnings
            .iter()
            .any(|w| w.contains("NOT rooted"));
        assert!(
            has_no_root_warning,
            "Expected no-root warning, got: {:?}",
            briefing.warnings
        );
    }

    #[test]
    fn test_briefing_selinux_enforcing_with_root_warning() {
        let profile = make_test_profile(
            RootMethod::Magisk,
            SelinuxMode::Enforcing,
            EncryptionState::AfterFirstUnlock,
            vec![],
            vec![],
            vec![AcquisitionMethod::PrivilegedLogical],
        );

        let briefing = generate_briefing(&profile);

        let has_selinux_warning = briefing
            .warnings
            .iter()
            .any(|w| w.contains("SELinux is ENFORCING"));
        assert!(
            has_selinux_warning,
            "Expected SELinux enforcing warning with root, got: {:?}",
            briefing.warnings
        );
    }

    #[test]
    fn test_briefing_recommended_method_privileged() {
        let profile = make_test_profile(
            RootMethod::Magisk,
            SelinuxMode::Permissive,
            EncryptionState::AfterFirstUnlock,
            vec![],
            vec![],
            vec![
                AcquisitionMethod::PrivilegedLogical,
                AcquisitionMethod::ContentProvider,
            ],
        );

        let briefing = generate_briefing(&profile);
        assert_eq!(
            briefing.recommended_method,
            Some(AcquisitionMethod::PrivilegedLogical)
        );
    }

    #[test]
    fn test_briefing_recommended_method_unprivileged() {
        let profile = make_test_profile(
            RootMethod::None,
            SelinuxMode::Enforcing,
            EncryptionState::AfterFirstUnlock,
            vec![],
            vec![],
            vec![
                AcquisitionMethod::UnprivilegedLogical,
                AcquisitionMethod::AdbBackup,
            ],
        );

        let briefing = generate_briefing(&profile);
        assert_eq!(
            briefing.recommended_method,
            Some(AcquisitionMethod::UnprivilegedLogical)
        );
    }

    #[test]
    fn test_briefing_recommended_method_content_provider() {
        let profile = make_test_profile(
            RootMethod::None,
            SelinuxMode::Enforcing,
            EncryptionState::AfterFirstUnlock,
            vec![],
            vec![],
            vec![
                AcquisitionMethod::ContentProvider,
                AcquisitionMethod::AdbBackup,
            ],
        );

        let briefing = generate_briefing(&profile);
        assert_eq!(
            briefing.recommended_method,
            Some(AcquisitionMethod::ContentProvider)
        );
    }

    #[test]
    fn test_briefing_no_methods_available() {
        let profile = make_test_profile(
            RootMethod::None,
            SelinuxMode::Enforcing,
            EncryptionState::AfterFirstUnlock,
            vec![],
            vec![],
            vec![],
        );

        let briefing = generate_briefing(&profile);
        assert_eq!(briefing.recommended_method, None);
    }

    #[test]
    fn test_briefing_full_text_contains_device_info() {
        let profile = make_test_profile(
            RootMethod::Magisk,
            SelinuxMode::Permissive,
            EncryptionState::AfterFirstUnlock,
            vec![],
            vec![],
            vec![AcquisitionMethod::PrivilegedLogical],
        );

        let briefing = generate_briefing(&profile);

        assert!(briefing.full_text.contains("Samsung"));
        assert!(briefing.full_text.contains("SM-S928B"));
        assert!(briefing.full_text.contains("Android 14"));
        assert!(briefing.full_text.contains("TEST_SERIAL"));
        assert!(briefing.full_text.contains("INVESTIGATOR BRIEFING"));
        assert!(briefing.full_text.contains("One UI"));
    }

    #[test]
    fn test_briefing_full_text_shows_accessible_artifacts() {
        let accessible = vec![AccessibleArtifactClass {
            artifact_class: ArtifactClass::BuildProp,
            acquisition_method: AcquisitionMethod::PrivilegedLogical,
            confidence: 0.99,
        }];

        let profile = make_test_profile(
            RootMethod::Magisk,
            SelinuxMode::Permissive,
            EncryptionState::AfterFirstUnlock,
            accessible,
            vec![],
            vec![AcquisitionMethod::PrivilegedLogical],
        );

        let briefing = generate_briefing(&profile);
        assert!(briefing.full_text.contains("✓"));
        assert!(briefing.full_text.contains("BuildProp"));
    }

    #[test]
    fn test_briefing_full_text_shows_inaccessible_artifacts() {
        let inaccessible = vec![InaccessibleArtifactClass {
            artifact_class: ArtifactClass::KernelLogs,
            reason: "Requires root access".into(),
        }];

        let profile = make_test_profile(
            RootMethod::None,
            SelinuxMode::Enforcing,
            EncryptionState::AfterFirstUnlock,
            vec![],
            inaccessible,
            vec![AcquisitionMethod::UnprivilegedLogical],
        );

        let briefing = generate_briefing(&profile);
        assert!(briefing.full_text.contains("✗"));
        assert!(briefing.full_text.contains("KernelLogs"));
    }

    #[test]
    fn test_briefing_full_text_shows_warnings() {
        let profile = make_test_profile(
            RootMethod::None,
            SelinuxMode::Enforcing,
            EncryptionState::BeforeFirstUnlock,
            vec![],
            vec![InaccessibleArtifactClass {
                artifact_class: ArtifactClass::WpaSupplicant,
                reason: "No root".into(),
            }],
            vec![AcquisitionMethod::UnprivilegedLogical],
        );

        let briefing = generate_briefing(&profile);
        assert!(briefing.full_text.contains("⚠"));
        assert!(briefing.full_text.contains("WARNINGS"));
    }
}
