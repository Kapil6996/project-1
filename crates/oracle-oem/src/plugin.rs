//! # OEM Plugin Trait & Registry
//!
//! Defines the [`OemPlugin`] trait that all manufacturer-specific plugins must
//! implement, along with the [`OemPluginRegistry`] that manages plugin discovery
//! and dispatch based on device identity.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐     ┌─────────────────────┐     ┌───────────────┐
//! │ DeviceIdentity│────▶│ OemPluginRegistry    │────▶│ OemPlugin     │
//! │               │     │  (find_plugin_for_   │     │  (Samsung,    │
//! │               │     │   device)            │     │   Xiaomi, ..) │
//! └──────────────┘     └─────────────────────┘     └───────────────┘
//! ```
//!
//! The registry iterates registered plugins and returns the first plugin
//! whose [`OemPlugin::matches_device`] method returns `true` for the
//! given [`DeviceIdentity`].

use oracle_core::{ArtifactClass, DeviceIdentity};
use oracle_parser::ArtifactParser;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::samsung::SamsungPlugin;

// ──────────────────────────────────────────────────────────────────────────────
// Artifact Path Override
// ──────────────────────────────────────────────────────────────────────────────

/// Describes an OEM-specific override for a standard artifact path.
///
/// Samsung, Xiaomi, and other OEMs often store forensic artifacts in
/// non-standard filesystem locations or use proprietary formats at standard
/// paths. This struct captures the mapping from the platform's expected path
/// to the OEM-specific path, along with a forensic justification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactPathOverride {
    /// The artifact class this override applies to.
    pub artifact_class: ArtifactClass,
    /// The standard Android path the core platform expects.
    pub original_path: String,
    /// The OEM-specific path where the artifact is actually located.
    pub override_path: String,
    /// Forensic justification for why this override exists.
    ///
    /// This reason is recorded in audit logs and included in court reports
    /// to explain why a non-standard path was accessed.
    pub reason: String,
}

impl fmt::Display for ArtifactPathOverride {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}: {} → {} ({})",
            self.artifact_class, self.original_path, self.override_path, self.reason
        )
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// OEM Plugin Trait
// ──────────────────────────────────────────────────────────────────────────────

/// Trait that all OEM-specific forensic plugins must implement.
///
/// Each plugin encapsulates manufacturer-specific knowledge:
/// - Which devices it supports (via model patterns and manufacturer matching).
/// - Where OEM-specific artifacts are stored on the filesystem.
/// - Custom parsers for proprietary artifact formats.
///
/// # Implementor Contract
///
/// - [`oem_id`](OemPlugin::oem_id) must return a unique, lowercase identifier
///   (e.g., `"samsung"`, `"xiaomi"`).
/// - [`matches_device`](OemPlugin::matches_device) must perform case-insensitive
///   manufacturer matching and must not panic on any input.
/// - [`custom_parsers`](OemPlugin::custom_parsers) must return parsers that
///   conform to the [`ArtifactParser`] contract (no panics, confidence in `[0, 1]`).
pub trait OemPlugin: Send + Sync + fmt::Debug {
    /// Returns the unique identifier for this OEM plugin (e.g., `"samsung"`).
    fn oem_id(&self) -> &str;

    /// Returns the human-readable OEM name (e.g., `"Samsung Electronics"`).
    fn oem_name(&self) -> &str;

    /// Returns a list of supported model patterns.
    ///
    /// These are human-readable patterns describing which device models
    /// this plugin supports (e.g., `"Galaxy S series (SM-S*)"`,
    /// `"Galaxy A series (SM-A*)"`, etc.).
    fn supported_models(&self) -> Vec<String>;

    /// Returns `true` if this plugin can handle artifacts from the given device.
    ///
    /// The matching logic should be case-insensitive on the manufacturer field
    /// and may optionally inspect model patterns.
    fn matches_device(&self, device: &DeviceIdentity) -> bool;

    /// Returns OEM-specific artifact path overrides.
    ///
    /// These overrides tell the acquisition engine where to look for artifacts
    /// when the OEM stores them at non-standard paths or uses proprietary formats
    /// at standard paths.
    fn override_artifact_paths(&self) -> Vec<ArtifactPathOverride>;

    /// Returns custom parsers for OEM-specific artifact formats.
    ///
    /// These parsers are registered alongside the core parsers and are
    /// dispatched when the OEM plugin is active for the current device.
    fn custom_parsers(&self) -> Vec<Box<dyn ArtifactParser>>;
}

// ──────────────────────────────────────────────────────────────────────────────
// OEM Plugin Registry
// ──────────────────────────────────────────────────────────────────────────────

/// Registry that manages all loaded OEM plugins and dispatches to the
/// correct plugin based on device identity.
///
/// The registry is populated at startup (via [`default_registry`](OemPluginRegistry::default_registry))
/// with all built-in plugins. Additional plugins can be registered at runtime
/// via [`register`](OemPluginRegistry::register).
///
/// # Thread Safety
///
/// The registry is `Send + Sync` and can be shared across threads. However,
/// mutation (via `register`) requires `&mut self`.
pub struct OemPluginRegistry {
    /// Registered plugins, in order of registration.
    plugins: Vec<Box<dyn OemPlugin>>,
}

impl fmt::Debug for OemPluginRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OemPluginRegistry")
            .field("plugin_count", &self.plugins.len())
            .field(
                "plugin_ids",
                &self
                    .plugins
                    .iter()
                    .map(|p| p.oem_id().to_string())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl OemPluginRegistry {
    /// Creates a new, empty plugin registry.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Creates the default registry pre-populated with all built-in OEM plugins.
    ///
    /// Currently registered plugins:
    /// - [`SamsungPlugin`](crate::samsung::SamsungPlugin) — Samsung OneUI devices
    pub fn default_registry() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(SamsungPlugin::new()));
        registry
    }

    /// Registers a new OEM plugin with the registry.
    ///
    /// Plugins are queried in registration order. If two plugins match the
    /// same device, the first registered plugin wins.
    pub fn register(&mut self, plugin: Box<dyn OemPlugin>) {
        tracing::info!(
            oem_id = plugin.oem_id(),
            oem_name = plugin.oem_name(),
            "Registered OEM plugin"
        );
        self.plugins.push(plugin);
    }

    /// Finds the first plugin that matches the given device identity.
    ///
    /// Returns `None` if no registered plugin matches the device.
    pub fn find_plugin_for_device(&self, device: &DeviceIdentity) -> Option<&dyn OemPlugin> {
        self.plugins
            .iter()
            .find(|p| p.matches_device(device))
            .map(|p| p.as_ref())
    }

    /// Returns an iterator over all registered plugins.
    pub fn list_plugins(&self) -> &[Box<dyn OemPlugin>] {
        &self.plugins
    }

    /// Returns the number of registered plugins.
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }
}

impl Default for OemPluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a Samsung device identity for testing.
    fn samsung_device() -> DeviceIdentity {
        DeviceIdentity {
            serial: "R5CR30ABCDE".to_string(),
            manufacturer: "samsung".to_string(),
            model: "SM-S928B".to_string(),
            android_version: "14".to_string(),
            api_level: 34,
            security_patch_level: "2024-12-01".to_string(),
            build_fingerprint: "samsung/dm3q/dm3q:14/UP1A.231005.007/S928BXXS3AXL1:user/release-keys".to_string(),
            oem_skin: Some("One UI".to_string()),
            oem_skin_version: Some("6.1".to_string()),
        }
    }

    /// Helper to create a Google Pixel device identity for testing.
    fn pixel_device() -> DeviceIdentity {
        DeviceIdentity {
            serial: "ABC123XYZ".to_string(),
            manufacturer: "Google".to_string(),
            model: "Pixel 8 Pro".to_string(),
            android_version: "14".to_string(),
            api_level: 34,
            security_patch_level: "2024-12-05".to_string(),
            build_fingerprint: "google/husky/husky:14/AP2A.240805.005/12025142:user/release-keys".to_string(),
            oem_skin: None,
            oem_skin_version: None,
        }
    }

    #[test]
    fn test_registry_find_samsung_plugin() {
        let registry = OemPluginRegistry::default_registry();
        let device = samsung_device();
        let plugin = registry.find_plugin_for_device(&device);
        assert!(plugin.is_some(), "Should find Samsung plugin for Samsung device");
        assert_eq!(plugin.map(|p| p.oem_id()), Some("samsung"));
    }

    #[test]
    fn test_registry_no_match_for_pixel() {
        let registry = OemPluginRegistry::default_registry();
        let device = pixel_device();
        let plugin = registry.find_plugin_for_device(&device);
        assert!(plugin.is_none(), "Should not match any plugin for Pixel device");
    }

    #[test]
    fn test_registry_list_plugins() {
        let registry = OemPluginRegistry::default_registry();
        let plugins = registry.list_plugins();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].oem_id(), "samsung");
    }

    #[test]
    fn test_registry_register_custom_plugin() {
        let mut registry = OemPluginRegistry::new();
        assert_eq!(registry.plugin_count(), 0);
        registry.register(Box::new(SamsungPlugin::new()));
        assert_eq!(registry.plugin_count(), 1);
    }

    #[test]
    fn test_empty_registry_returns_none() {
        let registry = OemPluginRegistry::new();
        let device = samsung_device();
        assert!(registry.find_plugin_for_device(&device).is_none());
    }
}
