//! # Capability Profile Management
//!
//! Stores and retrieves [`CapabilityProfile`]s for forensic investigations,
//! and manages the examiner acknowledgment flow.
//!
//! Before any acquisition proceeds, the examiner must acknowledge the
//! capability profile, confirming they understand which artifacts are
//! accessible and which are not (and why).

use std::collections::HashMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::info;

use oracle_core::error::{OracleError, OracleResult};
use oracle_core::types::{CapabilityProfile, ExaminerIdentity, InvestigationId};

// ──────────────────────────────────────────────────────────────────────────────
// Stored Profile
// ──────────────────────────────────────────────────────────────────────────────

/// A stored capability profile with acknowledgment metadata.
///
/// Wraps the raw [`CapabilityProfile`] with investigation linkage and
/// examiner acknowledgment tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProfile {
    /// The capability profile produced by the detection engine.
    pub profile: CapabilityProfile,
    /// The investigation this profile belongs to.
    pub investigation_id: InvestigationId,
    /// The examiner who acknowledged the profile, if any.
    pub acknowledged_by: Option<ExaminerIdentity>,
    /// Timestamp when the profile was acknowledged.
    pub acknowledged_at: Option<chrono::DateTime<chrono::Utc>>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Profile Store
// ──────────────────────────────────────────────────────────────────────────────

/// Stores and manages capability profiles for forensic investigations.
///
/// Each investigation has at most one capability profile, representing
/// the device state at the time of capability detection. The store
/// enforces the following invariants:
///
/// - A profile can only be stored once per investigation.
/// - A profile can only be acknowledged once.
/// - An unacknowledged profile blocks downstream acquisition.
///
/// # Examples
///
/// ```
/// use oracle_capability::profiles::CapabilityProfileStore;
/// use oracle_core::types::InvestigationId;
///
/// let mut store = CapabilityProfileStore::new();
/// // Store and retrieve profiles by investigation ID.
/// ```
pub struct CapabilityProfileStore {
    /// In-memory map of investigation ID → stored profile.
    profiles: HashMap<String, StoredProfile>,
}

impl CapabilityProfileStore {
    /// Creates a new empty profile store.
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
        }
    }

    /// Stores a capability profile for an investigation.
    ///
    /// # Errors
    ///
    /// Returns [`OracleError::ConfigurationError`] if a profile already
    /// exists for this investigation (profiles are immutable once stored).
    pub fn store_profile(
        &mut self,
        investigation_id: InvestigationId,
        profile: CapabilityProfile,
    ) -> OracleResult<()> {
        let key = investigation_id.to_string();
        if self.profiles.contains_key(&key) {
            return Err(OracleError::ConfigurationError {
                reason: format!(
                    "Profile already exists for investigation {}",
                    investigation_id
                ),
            });
        }

        self.profiles.insert(
            key,
            StoredProfile {
                profile,
                investigation_id,
                acknowledged_by: None,
                acknowledged_at: None,
            },
        );

        info!(%investigation_id, "Capability profile stored");
        Ok(())
    }

    /// Retrieves the capability profile for an investigation.
    ///
    /// # Errors
    ///
    /// Returns [`OracleError::ConfigurationError`] if no profile exists
    /// for this investigation.
    pub fn get_profile(
        &self,
        investigation_id: &InvestigationId,
    ) -> OracleResult<&StoredProfile> {
        let key = investigation_id.to_string();
        self.profiles.get(&key).ok_or_else(|| {
            OracleError::ConfigurationError {
                reason: format!(
                    "No profile found for investigation {}",
                    investigation_id
                ),
            }
        })
    }

    /// Records an examiner's acknowledgment of the capability profile.
    ///
    /// The examiner acknowledges that they have reviewed the profile and
    /// understand which artifacts are accessible and which are not, and
    /// the forensic justification for each inaccessible artifact.
    ///
    /// # Errors
    ///
    /// - Returns [`OracleError::ConfigurationError`] if no profile exists.
    /// - Returns [`OracleError::ConfigurationError`] if the profile has
    ///   already been acknowledged.
    pub fn acknowledge_profile(
        &mut self,
        investigation_id: &InvestigationId,
        examiner: ExaminerIdentity,
    ) -> OracleResult<()> {
        let key = investigation_id.to_string();
        let stored =
            self.profiles.get_mut(&key).ok_or_else(|| {
                OracleError::ConfigurationError {
                    reason: format!(
                        "No profile found for investigation {}",
                        investigation_id
                    ),
                }
            })?;

        if stored.acknowledged_by.is_some() {
            return Err(OracleError::ConfigurationError {
                reason: format!(
                    "Profile for investigation {} is already acknowledged",
                    investigation_id
                ),
            });
        }

        stored.profile.acknowledged = true;
        stored.acknowledged_at = Some(Utc::now());
        stored.acknowledged_by = Some(examiner.clone());

        info!(
            %investigation_id,
            examiner = %examiner.name,
            "Capability profile acknowledged"
        );

        Ok(())
    }

    /// Returns whether the profile for an investigation has been acknowledged.
    ///
    /// Returns `false` if no profile exists for the investigation.
    pub fn is_acknowledged(&self, investigation_id: &InvestigationId) -> bool {
        self.profiles
            .get(&investigation_id.to_string())
            .map(|p| p.acknowledged_by.is_some())
            .unwrap_or(false)
    }

    /// Returns the total number of stored profiles.
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }
}

impl Default for CapabilityProfileStore {
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
    use chrono::Utc;
    use oracle_core::types::*;

    /// Creates a minimal test capability profile.
    fn make_test_profile() -> CapabilityProfile {
        CapabilityProfile {
            device: DeviceIdentity {
                serial: "TEST123".into(),
                manufacturer: "TestMfg".into(),
                model: "TestModel".into(),
                android_version: "14".into(),
                api_level: 34,
                security_patch_level: "2024-01-01".into(),
                build_fingerprint: "test/fingerprint".into(),
                oem_skin: None,
                oem_skin_version: None,
            },
            usb_debugging_enabled: true,
            adb_authorized: true,
            root_method: RootMethod::None,
            selinux_mode: SelinuxMode::Enforcing,
            bootloader_state: BootloaderState::Locked,
            encryption_state: EncryptionState::AfterFirstUnlock,
            available_methods: vec![AcquisitionMethod::UnprivilegedLogical],
            accessible_artifact_classes: vec![],
            inaccessible_artifact_classes: vec![],
            detected_at: Utc::now(),
            acknowledged: false,
        }
    }

    /// Creates a test examiner identity.
    fn make_test_examiner() -> ExaminerIdentity {
        ExaminerIdentity {
            name: "Jane Doe".to_string(),
            badge_id: "EX-001".to_string(),
            organization: "Digital Forensics Lab".to_string(),
        }
    }

    #[test]
    fn test_store_and_retrieve_profile() {
        let mut store = CapabilityProfileStore::new();
        let inv_id = InvestigationId::new();
        let profile = make_test_profile();

        store.store_profile(inv_id, profile.clone()).unwrap();

        let stored = store.get_profile(&inv_id).unwrap();
        assert_eq!(stored.investigation_id, inv_id);
        assert_eq!(stored.profile.device.serial, "TEST123");
        assert_eq!(stored.profile.device.manufacturer, "TestMfg");
        assert!(stored.acknowledged_by.is_none());
        assert!(stored.acknowledged_at.is_none());
    }

    #[test]
    fn test_store_duplicate_profile_errors() {
        let mut store = CapabilityProfileStore::new();
        let inv_id = InvestigationId::new();

        store
            .store_profile(inv_id, make_test_profile())
            .unwrap();

        let result = store.store_profile(inv_id, make_test_profile());
        assert!(result.is_err());
    }

    #[test]
    fn test_get_nonexistent_profile_errors() {
        let store = CapabilityProfileStore::new();
        let inv_id = InvestigationId::new();

        let result = store.get_profile(&inv_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_acknowledge_profile() {
        let mut store = CapabilityProfileStore::new();
        let inv_id = InvestigationId::new();
        let examiner = make_test_examiner();

        store
            .store_profile(inv_id, make_test_profile())
            .unwrap();

        store.acknowledge_profile(&inv_id, examiner.clone()).unwrap();

        let stored = store.get_profile(&inv_id).unwrap();
        assert!(stored.profile.acknowledged);
        assert!(stored.acknowledged_at.is_some());
        assert_eq!(
            stored.acknowledged_by.as_ref().map(|e| e.name.as_str()),
            Some("Jane Doe")
        );
    }

    #[test]
    fn test_acknowledge_already_acknowledged_errors() {
        let mut store = CapabilityProfileStore::new();
        let inv_id = InvestigationId::new();

        store
            .store_profile(inv_id, make_test_profile())
            .unwrap();

        store
            .acknowledge_profile(&inv_id, make_test_examiner())
            .unwrap();

        let result = store.acknowledge_profile(&inv_id, make_test_examiner());
        assert!(result.is_err());
    }

    #[test]
    fn test_acknowledge_nonexistent_profile_errors() {
        let mut store = CapabilityProfileStore::new();
        let inv_id = InvestigationId::new();

        let result = store.acknowledge_profile(&inv_id, make_test_examiner());
        assert!(result.is_err());
    }

    #[test]
    fn test_is_acknowledged() {
        let mut store = CapabilityProfileStore::new();
        let inv_id = InvestigationId::new();

        assert!(!store.is_acknowledged(&inv_id));

        store
            .store_profile(inv_id, make_test_profile())
            .unwrap();

        assert!(!store.is_acknowledged(&inv_id));

        store
            .acknowledge_profile(&inv_id, make_test_examiner())
            .unwrap();

        assert!(store.is_acknowledged(&inv_id));
    }

    #[test]
    fn test_profile_count() {
        let mut store = CapabilityProfileStore::new();
        assert_eq!(store.profile_count(), 0);

        store
            .store_profile(InvestigationId::new(), make_test_profile())
            .unwrap();
        assert_eq!(store.profile_count(), 1);

        store
            .store_profile(InvestigationId::new(), make_test_profile())
            .unwrap();
        assert_eq!(store.profile_count(), 2);
    }
}
