//! # Plugin Validation
//!
//! Validates OEM plugins before they are registered with the platform.
//!
//! Every plugin must pass validation before it can be loaded into the
//! [`OemPluginRegistry`](crate::plugin::OemPluginRegistry). Validation ensures:
//!
//! - Plugin metadata is complete and well-formed.
//! - Model patterns are non-empty and syntactically valid.
//! - Custom parsers conform to the [`ArtifactParser`](oracle_parser::ArtifactParser) contract.
//! - Path overrides have forensic justifications.
//!
//! Validation failures are recorded in the audit log as
//! [`PluginValidationFailed`](oracle_core::OracleError::PluginValidationFailed) events.

use oracle_core::{OracleError, OracleResult};
use serde::{Deserialize, Serialize};

use crate::plugin::OemPlugin;

// ──────────────────────────────────────────────────────────────────────────────
// Validation Report
// ──────────────────────────────────────────────────────────────────────────────

/// A single validation issue found during plugin validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationIssue {
    /// The severity of this issue.
    pub severity: ValidationSeverity,
    /// The validation rule that was violated.
    pub rule: String,
    /// A human-readable description of the issue.
    pub message: String,
}

/// Severity levels for plugin validation issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationSeverity {
    /// A critical issue that prevents the plugin from being loaded.
    Error,
    /// A non-critical issue that should be addressed but does not prevent loading.
    Warning,
    /// An informational note about the plugin configuration.
    Info,
}

impl std::fmt::Display for ValidationSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationSeverity::Error => write!(f, "ERROR"),
            ValidationSeverity::Warning => write!(f, "WARNING"),
            ValidationSeverity::Info => write!(f, "INFO"),
        }
    }
}

/// The complete result of validating an OEM plugin.
///
/// Contains all issues found during validation, categorized by severity.
/// A plugin passes validation if and only if there are zero `Error`-severity issues.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginValidationReport {
    /// The OEM ID of the validated plugin.
    pub oem_id: String,
    /// The OEM name of the validated plugin.
    pub oem_name: String,
    /// All validation issues found.
    pub issues: Vec<ValidationIssue>,
    /// Whether the plugin passed validation (no `Error`-severity issues).
    pub passed: bool,
}

impl PluginValidationReport {
    /// Returns all error-severity issues.
    pub fn errors(&self) -> Vec<&ValidationIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == ValidationSeverity::Error)
            .collect()
    }

    /// Returns all warning-severity issues.
    pub fn warnings(&self) -> Vec<&ValidationIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == ValidationSeverity::Warning)
            .collect()
    }

    /// Returns all info-severity issues.
    pub fn info_issues(&self) -> Vec<&ValidationIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == ValidationSeverity::Info)
            .collect()
    }
}

impl std::fmt::Display for PluginValidationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Plugin Validation Report: {} ({})",
            self.oem_name, self.oem_id
        )?;
        writeln!(
            f,
            "Result: {}",
            if self.passed { "PASSED" } else { "FAILED" }
        )?;

        if self.issues.is_empty() {
            writeln!(f, "  No issues found.")?;
        } else {
            for issue in &self.issues {
                writeln!(
                    f,
                    "  [{}] {}: {}",
                    issue.severity, issue.rule, issue.message
                )?;
            }
        }

        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Validation Logic
// ──────────────────────────────────────────────────────────────────────────────

/// Validates an OEM plugin's metadata, model patterns, parsers, and path overrides.
///
/// Returns `Ok(())` if the plugin passes all validation checks (no `Error`-severity issues).
/// Returns `Err(OracleError::PluginValidationFailed)` with a detailed reason if any
/// critical validation rule is violated.
///
/// # Validation Rules
///
/// 1. **`oem_id_non_empty`** — `oem_id()` must return a non-empty, lowercase string.
/// 2. **`oem_name_non_empty`** — `oem_name()` must return a non-empty string.
/// 3. **`models_non_empty`** — `supported_models()` must return at least one model pattern.
/// 4. **`model_pattern_non_empty`** — Each model pattern must be a non-empty string.
/// 5. **`parser_ids_unique`** — All custom parsers must have unique `parser_id` values.
/// 6. **`parser_has_supported_classes`** — Each parser must support at least one artifact class.
/// 7. **`override_has_reason`** — Each path override must have a non-empty `reason`.
/// 8. **`override_has_paths`** — Each path override must have non-empty paths.
///
/// # Examples
///
/// ```rust,no_run
/// use oracle_oem::samsung::SamsungPlugin;
/// use oracle_oem::validation::validate_plugin;
///
/// let plugin = SamsungPlugin::new();
/// let result = validate_plugin(&plugin);
/// assert!(result.is_ok());
/// ```
pub fn validate_plugin(plugin: &dyn OemPlugin) -> OracleResult<()> {
    let report = generate_validation_report(plugin);

    if report.passed {
        tracing::info!(
            oem_id = report.oem_id,
            warnings = report.warnings().len(),
            "Plugin validation passed"
        );
        Ok(())
    } else {
        let error_messages: Vec<String> = report
            .errors()
            .iter()
            .map(|e| format!("[{}] {}", e.rule, e.message))
            .collect();
        let reason = error_messages.join("; ");

        tracing::error!(
            oem_id = report.oem_id,
            error_count = report.errors().len(),
            "Plugin validation failed"
        );

        Err(OracleError::PluginValidationFailed {
            plugin_id: report.oem_id,
            reason,
        })
    }
}

/// Generates a detailed validation report for an OEM plugin.
///
/// Unlike [`validate_plugin`], this function always returns a report (never an error).
/// Use this when you want to inspect individual validation issues without
/// short-circuiting on the first failure.
pub fn generate_validation_report(plugin: &dyn OemPlugin) -> PluginValidationReport {
    let mut issues = Vec::new();

    // Rule 1: oem_id must be non-empty and lowercase.
    validate_oem_id(plugin, &mut issues);

    // Rule 2: oem_name must be non-empty.
    validate_oem_name(plugin, &mut issues);

    // Rule 3 & 4: supported_models must be non-empty, each pattern must be non-empty.
    validate_supported_models(plugin, &mut issues);

    // Rule 5 & 6: custom parser validation.
    validate_custom_parsers(plugin, &mut issues);

    // Rule 7 & 8: path override validation.
    validate_path_overrides(plugin, &mut issues);

    let has_errors = issues.iter().any(|i| i.severity == ValidationSeverity::Error);

    PluginValidationReport {
        oem_id: plugin.oem_id().to_string(),
        oem_name: plugin.oem_name().to_string(),
        issues,
        passed: !has_errors,
    }
}

/// Validates the OEM ID: must be non-empty and lowercase.
fn validate_oem_id(plugin: &dyn OemPlugin, issues: &mut Vec<ValidationIssue>) {
    let oem_id = plugin.oem_id();

    if oem_id.is_empty() {
        issues.push(ValidationIssue {
            severity: ValidationSeverity::Error,
            rule: "oem_id_non_empty".to_string(),
            message: "oem_id() returned an empty string".to_string(),
        });
        return;
    }

    if oem_id != oem_id.to_lowercase() {
        issues.push(ValidationIssue {
            severity: ValidationSeverity::Warning,
            rule: "oem_id_lowercase".to_string(),
            message: format!(
                "oem_id() should be lowercase (got '{}', expected '{}')",
                oem_id,
                oem_id.to_lowercase()
            ),
        });
    }

    if oem_id.contains(' ') {
        issues.push(ValidationIssue {
            severity: ValidationSeverity::Warning,
            rule: "oem_id_no_spaces".to_string(),
            message: format!("oem_id() should not contain spaces (got '{}')", oem_id),
        });
    }
}

/// Validates the OEM name: must be non-empty.
fn validate_oem_name(plugin: &dyn OemPlugin, issues: &mut Vec<ValidationIssue>) {
    let oem_name = plugin.oem_name();

    if oem_name.is_empty() {
        issues.push(ValidationIssue {
            severity: ValidationSeverity::Error,
            rule: "oem_name_non_empty".to_string(),
            message: "oem_name() returned an empty string".to_string(),
        });
    }
}

/// Validates supported models: at least one model, each non-empty.
fn validate_supported_models(plugin: &dyn OemPlugin, issues: &mut Vec<ValidationIssue>) {
    let models = plugin.supported_models();

    if models.is_empty() {
        issues.push(ValidationIssue {
            severity: ValidationSeverity::Error,
            rule: "models_non_empty".to_string(),
            message: "supported_models() returned an empty list".to_string(),
        });
        return;
    }

    for (i, model) in models.iter().enumerate() {
        if model.trim().is_empty() {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Error,
                rule: "model_pattern_non_empty".to_string(),
                message: format!("Model pattern at index {} is empty or whitespace-only", i),
            });
        }
    }
}

/// Validates custom parsers: unique IDs and at least one supported class each.
fn validate_custom_parsers(plugin: &dyn OemPlugin, issues: &mut Vec<ValidationIssue>) {
    let parsers = plugin.custom_parsers();

    if parsers.is_empty() {
        issues.push(ValidationIssue {
            severity: ValidationSeverity::Info,
            rule: "parsers_present".to_string(),
            message: "Plugin provides no custom parsers".to_string(),
        });
        return;
    }

    let mut seen_ids = std::collections::HashSet::new();

    for parser in &parsers {
        let info = parser.info();

        // Rule 5: parser IDs must be unique.
        if !seen_ids.insert(info.parser_id.clone()) {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Error,
                rule: "parser_ids_unique".to_string(),
                message: format!("Duplicate parser ID: '{}'", info.parser_id),
            });
        }

        // Rule 6: each parser must support at least one artifact class.
        if info.supported_classes.is_empty() {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Error,
                rule: "parser_has_supported_classes".to_string(),
                message: format!(
                    "Parser '{}' declares no supported artifact classes",
                    info.parser_id
                ),
            });
        }

        // Informational: parser version should follow semver.
        if info.parser_version.is_empty() {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Warning,
                rule: "parser_has_version".to_string(),
                message: format!("Parser '{}' has an empty version string", info.parser_id),
            });
        }
    }
}

/// Validates path overrides: each must have non-empty paths and a reason.
fn validate_path_overrides(plugin: &dyn OemPlugin, issues: &mut Vec<ValidationIssue>) {
    let overrides = plugin.override_artifact_paths();

    for (i, path_override) in overrides.iter().enumerate() {
        // Rule 7: override must have a reason.
        if path_override.reason.trim().is_empty() {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Error,
                rule: "override_has_reason".to_string(),
                message: format!(
                    "Path override at index {} for {:?} has no forensic justification",
                    i, path_override.artifact_class
                ),
            });
        }

        // Rule 8: override must have non-empty paths.
        if path_override.original_path.trim().is_empty() {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Error,
                rule: "override_has_paths".to_string(),
                message: format!(
                    "Path override at index {} for {:?} has an empty original_path",
                    i, path_override.artifact_class
                ),
            });
        }

        if path_override.override_path.trim().is_empty() {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Error,
                rule: "override_has_paths".to_string(),
                message: format!(
                    "Path override at index {} for {:?} has an empty override_path",
                    i, path_override.artifact_class
                ),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::samsung::SamsungPlugin;

    #[test]
    fn test_validate_samsung_plugin_passes() {
        let plugin = SamsungPlugin::new();
        let result = validate_plugin(&plugin);
        assert!(result.is_ok(), "Samsung plugin should pass validation");
    }

    #[test]
    fn test_samsung_validation_report_no_errors() {
        let plugin = SamsungPlugin::new();
        let report = generate_validation_report(&plugin);
        assert!(report.passed);
        assert!(report.errors().is_empty());
    }

    #[test]
    fn test_samsung_validation_report_metadata() {
        let plugin = SamsungPlugin::new();
        let report = generate_validation_report(&plugin);
        assert_eq!(report.oem_id, "samsung");
        assert_eq!(report.oem_name, "Samsung Electronics");
    }

    /// A deliberately broken plugin for negative testing.
    #[derive(Debug)]
    struct BrokenPlugin;

    impl OemPlugin for BrokenPlugin {
        fn oem_id(&self) -> &str {
            ""
        }

        fn oem_name(&self) -> &str {
            ""
        }

        fn supported_models(&self) -> Vec<String> {
            vec![]
        }

        fn matches_device(&self, _device: &oracle_core::DeviceIdentity) -> bool {
            false
        }

        fn override_artifact_paths(&self) -> Vec<crate::plugin::ArtifactPathOverride> {
            vec![crate::plugin::ArtifactPathOverride {
                artifact_class: oracle_core::ArtifactClass::Unknown,
                original_path: String::new(),
                override_path: String::new(),
                reason: String::new(),
            }]
        }

        fn custom_parsers(&self) -> Vec<Box<dyn oracle_parser::ArtifactParser>> {
            vec![]
        }
    }

    #[test]
    fn test_broken_plugin_fails_validation() {
        let plugin = BrokenPlugin;
        let result = validate_plugin(&plugin);
        assert!(result.is_err(), "Broken plugin should fail validation");
    }

    #[test]
    fn test_broken_plugin_report_has_errors() {
        let plugin = BrokenPlugin;
        let report = generate_validation_report(&plugin);
        assert!(!report.passed);
        let errors = report.errors();
        assert!(!errors.is_empty());

        // Should have errors for empty oem_id, empty oem_name, empty models, and empty paths
        let error_rules: Vec<&str> = errors.iter().map(|e| e.rule.as_str()).collect();
        assert!(
            error_rules.contains(&"oem_id_non_empty"),
            "Should flag empty oem_id"
        );
        assert!(
            error_rules.contains(&"oem_name_non_empty"),
            "Should flag empty oem_name"
        );
        assert!(
            error_rules.contains(&"models_non_empty"),
            "Should flag empty models"
        );
        assert!(
            error_rules.contains(&"override_has_reason"),
            "Should flag missing override reason"
        );
        assert!(
            error_rules.contains(&"override_has_paths"),
            "Should flag empty override paths"
        );
    }

    #[test]
    fn test_validation_report_display() {
        let plugin = SamsungPlugin::new();
        let report = generate_validation_report(&plugin);
        let display = format!("{}", report);
        assert!(display.contains("Samsung Electronics"));
        assert!(display.contains("PASSED"));
    }

    #[test]
    fn test_broken_plugin_report_display() {
        let plugin = BrokenPlugin;
        let report = generate_validation_report(&plugin);
        let display = format!("{}", report);
        assert!(display.contains("FAILED"));
        assert!(display.contains("ERROR"));
    }

    #[test]
    fn test_validation_severity_display() {
        assert_eq!(format!("{}", ValidationSeverity::Error), "ERROR");
        assert_eq!(format!("{}", ValidationSeverity::Warning), "WARNING");
        assert_eq!(format!("{}", ValidationSeverity::Info), "INFO");
    }

    #[test]
    fn test_report_filter_methods() {
        let plugin = BrokenPlugin;
        let report = generate_validation_report(&plugin);

        // Should have errors
        assert!(!report.errors().is_empty());

        // Info issues should include the "no custom parsers" note
        let info = report.info_issues();
        assert!(
            info.iter().any(|i| i.rule == "parsers_present"),
            "Should have info about no custom parsers"
        );
    }
}
