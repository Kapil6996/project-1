//! # Parser Registry
//!
//! Central registry for discovering and dispatching artifact parsers.
//! The registry holds all registered parser implementations and provides
//! lookup by [`ArtifactClass`].
//!
//! ## Usage
//!
//! ```no_run
//! use oracle_parser::registry::ParserRegistry;
//! use oracle_core::ArtifactClass;
//!
//! let registry = ParserRegistry::default_registry();
//! if let Some(parser) = registry.get_parser_for_class(ArtifactClass::WifiConfigStore) {
//!     println!("Found parser: {}", parser.info().parser_id);
//! }
//! ```

use oracle_core::ArtifactClass;

use crate::traits::{ArtifactParser, ParserInfo};

/// Central registry holding all available artifact parsers.
///
/// The registry is the single dispatch point for the ingestion pipeline.
/// Parsers are registered at startup and looked up by artifact class
/// when an artifact needs to be parsed.
///
/// When multiple parsers support the same artifact class, the first
/// registered parser takes priority (first-match-wins semantics).
pub struct ParserRegistry {
    /// All registered parsers, in registration order.
    parsers: Vec<Box<dyn ArtifactParser>>,
}

impl ParserRegistry {
    /// Create an empty parser registry.
    pub fn new() -> Self {
        Self {
            parsers: Vec::new(),
        }
    }

    /// Register a parser with the registry.
    ///
    /// Parsers are stored in registration order. When multiple parsers
    /// support the same artifact class, the first registered parser
    /// takes priority.
    pub fn register(&mut self, parser: Box<dyn ArtifactParser>) {
        tracing::info!(
            parser_id = %parser.info().parser_id,
            version = %parser.info().parser_version,
            "Registered parser: {}",
            parser.info().description
        );
        self.parsers.push(parser);
    }

    /// Find the first parser that can handle the given artifact class.
    ///
    /// Returns `None` if no registered parser supports the class.
    pub fn get_parser_for_class(&self, class: ArtifactClass) -> Option<&dyn ArtifactParser> {
        self.parsers
            .iter()
            .find(|p| p.can_parse(class))
            .map(|p| p.as_ref())
    }

    /// List metadata for all registered parsers.
    pub fn list_parsers(&self) -> Vec<ParserInfo> {
        self.parsers.iter().map(|p| p.info()).collect()
    }

    /// Create a registry pre-populated with all core parsers.
    ///
    /// This is the standard entry point for the ORACLE platform.
    /// All built-in parsers are registered in forensic priority order:
    /// 1. WifiConfigStore (highest reliability)
    /// 2. WPA Supplicant
    /// 3. DHCP Leases
    /// 4. Connectivity Logs
    pub fn default_registry() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(crate::wifi_config::WifiConfigStoreParser));
        registry.register(Box::new(crate::wpa_supplicant::WpaSupplicantParser));
        registry.register(Box::new(crate::dhcp::DhcpLeaseParser));
        registry.register(Box::new(crate::connectivity::ConnectivityLogParser));
        registry
    }
}

impl Default for ParserRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_core::{ArtifactId, OracleError};

    #[test]
    fn test_register_and_lookup() {
        let registry = ParserRegistry::default_registry();
        let parsers = registry.list_parsers();
        assert!(parsers.len() >= 4, "Expected at least 4 core parsers, got {}", parsers.len());

        // WifiConfigStore should be found
        let parser = registry.get_parser_for_class(ArtifactClass::WifiConfigStore);
        assert!(parser.is_some(), "Expected a parser for WifiConfigStore");
        assert!(
            parser.map(|p| p.info().parser_id.contains("wifi_config")).unwrap_or(false),
            "WifiConfigStore parser should have 'wifi_config' in parser_id"
        );

        // WpaSupplicant should be found
        let parser = registry.get_parser_for_class(ArtifactClass::WpaSupplicant);
        assert!(parser.is_some(), "Expected a parser for WpaSupplicant");

        // DhcpLeases should be found
        let parser = registry.get_parser_for_class(ArtifactClass::DhcpLeases);
        assert!(parser.is_some(), "Expected a parser for DhcpLeases");

        // ConnectivityLogs should be found
        let parser = registry.get_parser_for_class(ArtifactClass::ConnectivityLogs);
        assert!(parser.is_some(), "Expected a parser for ConnectivityLogs");
    }

    #[test]
    fn test_no_parser_for_unknown_class() {
        let registry = ParserRegistry::default_registry();
        let parser = registry.get_parser_for_class(ArtifactClass::Unknown);
        assert!(parser.is_none(), "No parser should handle Unknown class");
    }

    #[test]
    fn test_no_parser_for_unregistered_class() {
        let registry = ParserRegistry::default_registry();
        // BatteryStats has no parser registered
        let parser = registry.get_parser_for_class(ArtifactClass::BatteryStats);
        assert!(parser.is_none(), "No parser should handle BatteryStats");
    }

    #[test]
    fn test_parser_does_not_panic_on_garbage() {
        let registry = ParserRegistry::default_registry();
        let parser = registry
            .get_parser_for_class(ArtifactClass::WifiConfigStore)
            .expect("WifiConfigStore parser must exist");
        let artifact_id = ArtifactId::new();
        // Passing garbage bytes should not panic — it may return Ok([]) or Err
        let result = parser.parse(artifact_id, "deadbeef", b"not xml at all");
        let _ = result;
    }

    #[test]
    fn test_parser_incompatible_on_wrong_class() {
        // Get the WifiConfigStore parser and try to parse WpaSupplicant data
        // The parser itself won't check class (it just parses bytes), but
        // we verify that the registry correctly filters by class.
        let registry = ParserRegistry::default_registry();
        let wifi_parser = registry
            .get_parser_for_class(ArtifactClass::WifiConfigStore)
            .expect("WifiConfigStore parser must exist");

        // The wifi parser should NOT claim to handle WpaSupplicant
        assert!(
            !wifi_parser.can_parse(ArtifactClass::WpaSupplicant),
            "WifiConfigStore parser must not accept WpaSupplicant class"
        );
    }

    #[test]
    fn test_list_parsers_metadata() {
        let registry = ParserRegistry::default_registry();
        let parsers = registry.list_parsers();
        for info in &parsers {
            assert!(!info.parser_id.is_empty(), "parser_id must not be empty");
            assert!(!info.parser_version.is_empty(), "parser_version must not be empty");
            assert!(!info.supported_classes.is_empty(), "supported_classes must not be empty");
            assert!(!info.description.is_empty(), "description must not be empty");
        }
    }

    #[test]
    fn test_empty_registry() {
        let registry = ParserRegistry::new();
        assert!(registry.list_parsers().is_empty());
        assert!(registry.get_parser_for_class(ArtifactClass::WifiConfigStore).is_none());
    }
}
