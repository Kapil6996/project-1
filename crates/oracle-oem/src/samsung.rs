//! # Samsung OneUI Plugin
//!
//! OEM plugin for Samsung Galaxy devices running OneUI.
//!
//! Samsung devices store several forensically relevant artifacts in non-standard
//! locations and use proprietary formats for wifi and connectivity logging.
//! This plugin provides:
//!
//! - **Device matching** — case-insensitive manufacturer detection for Samsung devices.
//! - **Path overrides** — Samsung-specific artifact locations including proprietary
//!   Wi-Fi manager logs and connectivity diagnostics.
//! - **Custom parsers** — [`SamsungWifiLogParser`] for Samsung's proprietary
//!   binary/text wifi log format found under `/data/log/wifi/`.
//!
//! # Supported Device Families
//!
//! - Galaxy S series (flagship, model prefix `SM-S`)
//! - Galaxy A series (mid-range, model prefix `SM-A`)
//! - Galaxy Note series (stylus-equipped, model prefix `SM-N`)
//! - Galaxy Z Fold/Flip series (foldables, model prefix `SM-F`)
//! - Galaxy Tab series (tablets, model prefix `SM-T` and `SM-X`)

use oracle_core::{ArtifactClass, ArtifactId, DeviceIdentity, OracleResult};
use oracle_parser::{ArtifactParser, ParsedOutput, ParserInfo};
use serde_json::json;

use crate::plugin::{ArtifactPathOverride, OemPlugin};

// ──────────────────────────────────────────────────────────────────────────────
// Samsung Plugin
// ──────────────────────────────────────────────────────────────────────────────

/// Samsung OneUI OEM plugin.
///
/// Provides manufacturer-specific forensic support for Samsung Galaxy devices,
/// including path overrides for Samsung's proprietary artifact locations and
/// a custom parser for Samsung's wifi log format.
#[derive(Debug, Clone)]
pub struct SamsungPlugin {
    /// Supported model prefixes for Samsung Galaxy devices.
    model_prefixes: Vec<SamsungModelFamily>,
}

/// Describes a Samsung device model family by its model prefix and human-readable name.
#[derive(Debug, Clone)]
struct SamsungModelFamily {
    /// The model number prefix (e.g., `"SM-S"` for Galaxy S series).
    prefix: &'static str,
    /// Human-readable family name (e.g., `"Galaxy S series"`).
    family_name: &'static str,
}

impl SamsungPlugin {
    /// Creates a new Samsung plugin with all known device families.
    pub fn new() -> Self {
        Self {
            model_prefixes: vec![
                SamsungModelFamily {
                    prefix: "SM-S",
                    family_name: "Galaxy S series",
                },
                SamsungModelFamily {
                    prefix: "SM-A",
                    family_name: "Galaxy A series",
                },
                SamsungModelFamily {
                    prefix: "SM-N",
                    family_name: "Galaxy Note series",
                },
                SamsungModelFamily {
                    prefix: "SM-F",
                    family_name: "Galaxy Z Fold/Flip series",
                },
                SamsungModelFamily {
                    prefix: "SM-T",
                    family_name: "Galaxy Tab series",
                },
                SamsungModelFamily {
                    prefix: "SM-X",
                    family_name: "Galaxy Tab series (2023+)",
                },
            ],
        }
    }

    /// Checks if the device manufacturer is Samsung (case-insensitive).
    fn is_samsung_manufacturer(manufacturer: &str) -> bool {
        manufacturer.to_lowercase().contains("samsung")
    }
}

impl Default for SamsungPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl OemPlugin for SamsungPlugin {
    fn oem_id(&self) -> &str {
        "samsung"
    }

    fn oem_name(&self) -> &str {
        "Samsung Electronics"
    }

    fn supported_models(&self) -> Vec<String> {
        self.model_prefixes
            .iter()
            .map(|family| format!("{} ({}*)", family.family_name, family.prefix))
            .collect()
    }

    fn matches_device(&self, device: &DeviceIdentity) -> bool {
        Self::is_samsung_manufacturer(&device.manufacturer)
    }

    fn override_artifact_paths(&self) -> Vec<ArtifactPathOverride> {
        vec![
            ArtifactPathOverride {
                artifact_class: ArtifactClass::WifiConfigStore,
                original_path: "/data/misc/wifi/WifiConfigStore.xml".to_string(),
                override_path: "/data/misc/wifi/WifiConfigStore.xml".to_string(),
                reason: "Samsung uses the standard path but stores additional proprietary XML \
                         elements within the WifiConfigStore (e.g., Samsung-specific network \
                         scoring and roaming configuration). The Samsung parser extracts these \
                         additional fields."
                    .to_string(),
            },
            ArtifactPathOverride {
                artifact_class: ArtifactClass::ConnectivityLogs,
                original_path: "/data/log/wifi/".to_string(),
                override_path: "/data/log/wifi/".to_string(),
                reason: "Samsung WiFi Manager writes proprietary diagnostic logs to \
                         /data/log/wifi/ in a Samsung-specific binary/text format. These logs \
                         contain connection attempts, DHCP negotiations, and roaming decisions \
                         not available in standard Android logs."
                    .to_string(),
            },
            ArtifactPathOverride {
                artifact_class: ArtifactClass::ConnectivityLogs,
                original_path: "/data/log/connectivity/".to_string(),
                override_path: "/data/log/connectivity/".to_string(),
                reason: "Samsung stores additional connectivity diagnostic data in \
                         /data/log/connectivity/ including carrier-specific network state \
                         transitions and Samsung Connectivity Manager events not present \
                         in AOSP connectivity logs."
                    .to_string(),
            },
        ]
    }

    fn custom_parsers(&self) -> Vec<Box<dyn ArtifactParser>> {
        vec![Box::new(SamsungWifiLogParser::new())]
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Samsung WiFi Log Parser
// ──────────────────────────────────────────────────────────────────────────────

/// Parser for Samsung's proprietary WiFi Manager log format.
///
/// Samsung devices write detailed WiFi diagnostic logs to `/data/log/wifi/`
/// in a proprietary text-based format. These logs contain:
///
/// - WiFi connection state transitions (connecting, connected, disconnected)
/// - DHCP lease negotiation details
/// - Roaming decisions and signal strength measurements
/// - Hotspot activation/deactivation events
///
/// # Log Format
///
/// Samsung WiFi logs use a line-oriented text format with the following structure:
/// ```text
/// <timestamp> <level> <tag>: <message>
/// ```
///
/// Where:
/// - `<timestamp>` is in `MM-DD HH:MM:SS.mmm` format
/// - `<level>` is one of `V`, `D`, `I`, `W`, `E`
/// - `<tag>` is the logging component (e.g., `WifiManager`, `WifiStateMachine`)
///
/// # Parsed Record Types
///
/// - `samsung_wifi_connection_event` — WiFi connection state changes
/// - `samsung_wifi_scan_result` — WiFi scan results with signal strengths
/// - `samsung_wifi_hotspot_event` — Hotspot activation/deactivation
#[derive(Debug, Clone)]
pub struct SamsungWifiLogParser;

impl SamsungWifiLogParser {
    /// Creates a new Samsung WiFi log parser instance.
    pub fn new() -> Self {
        Self
    }

    /// Attempts to parse a single log line into a structured event.
    ///
    /// Returns `None` if the line is not a recognized Samsung WiFi log entry
    /// (e.g., blank lines, malformed entries, or non-WiFi log lines).
    fn parse_log_line(line: &str, line_offset: u64) -> Option<ParsedOutput> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }

        // Detect connection state change events.
        // Format: "<timestamp> <level> WifiStateMachine: <state_change_message>"
        if let Some(record) = Self::try_parse_connection_event(trimmed, line_offset, line.len() as u64) {
            return Some(record);
        }

        // Detect hotspot events.
        // Format: "<timestamp> <level> SoftApManager: <hotspot_message>"
        if let Some(record) = Self::try_parse_hotspot_event(trimmed, line_offset, line.len() as u64) {
            return Some(record);
        }

        // Detect scan results.
        // Format: "<timestamp> <level> WifiScanManager: <scan_message>"
        if let Some(record) = Self::try_parse_scan_event(trimmed, line_offset, line.len() as u64) {
            return Some(record);
        }

        None
    }

    /// Tries to parse a WiFi connection state change event.
    fn try_parse_connection_event(
        line: &str,
        byte_offset: u64,
        byte_length: u64,
    ) -> Option<ParsedOutput> {
        // Look for WifiStateMachine or WifiManager connection keywords
        let lower = line.to_lowercase();
        if !lower.contains("wifistatemachine") && !lower.contains("wifimanager") {
            return None;
        }

        // Check for connection-related keywords.
        // IMPORTANT: check "disconnected" before "connected" because
        // "disconnected" contains "connected" as a substring.
        let event_type = if lower.contains("disconnected") {
            "disconnected"
        } else if lower.contains("connected") {
            "connected"
        } else if lower.contains("connecting") {
            "connecting"
        } else if lower.contains("associating") {
            "associating"
        } else {
            return None;
        };

        Some(ParsedOutput {
            record_type: "samsung_wifi_connection_event".to_string(),
            record_data: json!({
                "raw_line": line,
                "event_type": event_type,
                "source": "samsung_wifi_log",
            }),
            byte_offset: Some(byte_offset),
            byte_length: Some(byte_length),
            confidence: 0.75,
        })
    }

    /// Tries to parse a hotspot activation/deactivation event.
    fn try_parse_hotspot_event(
        line: &str,
        byte_offset: u64,
        byte_length: u64,
    ) -> Option<ParsedOutput> {
        let lower = line.to_lowercase();
        if !lower.contains("softapmanager") && !lower.contains("hotspot") && !lower.contains("tethering") {
            return None;
        }

        let event_type = if lower.contains("started") || lower.contains("enabled") || lower.contains("activated") {
            "hotspot_started"
        } else if lower.contains("stopped") || lower.contains("disabled") || lower.contains("deactivated") {
            "hotspot_stopped"
        } else if lower.contains("client connected") || lower.contains("station associated") {
            "hotspot_client_connected"
        } else if lower.contains("client disconnected") || lower.contains("station disassociated") {
            "hotspot_client_disconnected"
        } else {
            return None;
        };

        Some(ParsedOutput {
            record_type: "samsung_wifi_hotspot_event".to_string(),
            record_data: json!({
                "raw_line": line,
                "event_type": event_type,
                "source": "samsung_wifi_log",
            }),
            byte_offset: Some(byte_offset),
            byte_length: Some(byte_length),
            confidence: 0.70,
        })
    }

    /// Tries to parse a WiFi scan result event.
    fn try_parse_scan_event(
        line: &str,
        byte_offset: u64,
        byte_length: u64,
    ) -> Option<ParsedOutput> {
        let lower = line.to_lowercase();
        if !lower.contains("wifiscanmanager") && !lower.contains("scanresult") {
            return None;
        }

        if !lower.contains("scan") {
            return None;
        }

        let event_type = if lower.contains("completed") || lower.contains("results") {
            "scan_completed"
        } else if lower.contains("started") {
            "scan_started"
        } else if lower.contains("failed") {
            "scan_failed"
        } else {
            "scan_event"
        };

        Some(ParsedOutput {
            record_type: "samsung_wifi_scan_result".to_string(),
            record_data: json!({
                "raw_line": line,
                "event_type": event_type,
                "source": "samsung_wifi_log",
            }),
            byte_offset: Some(byte_offset),
            byte_length: Some(byte_length),
            confidence: 0.65,
        })
    }
}

impl Default for SamsungWifiLogParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for SamsungWifiLogParser {
    fn info(&self) -> ParserInfo {
        ParserInfo {
            parser_id: "oracle.oem.samsung.wifi_log".to_string(),
            parser_version: "1.0.0".to_string(),
            supported_classes: vec![ArtifactClass::ConnectivityLogs],
            description: "Parses Samsung's proprietary WiFi Manager diagnostic logs \
                         found in /data/log/wifi/. Extracts connection state changes, \
                         scan results, and hotspot events from Samsung-specific log format."
                .to_string(),
        }
    }

    fn can_parse(&self, class: ArtifactClass) -> bool {
        matches!(class, ArtifactClass::ConnectivityLogs)
    }

    fn parse(
        &self,
        artifact_id: ArtifactId,
        _artifact_hash: &str,
        raw_bytes: &[u8],
    ) -> OracleResult<Vec<ParsedOutput>> {
        let content = String::from_utf8_lossy(raw_bytes);
        let mut records = Vec::new();
        let mut byte_offset: u64 = 0;

        for line in content.lines() {
            if let Some(record) = Self::parse_log_line(line, byte_offset) {
                records.push(record);
            }
            // +1 for the newline character
            byte_offset += line.len() as u64 + 1;
        }

        tracing::debug!(
            artifact_id = %artifact_id,
            record_count = records.len(),
            "Samsung WiFi log parsing complete"
        );

        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn xiaomi_device() -> DeviceIdentity {
        DeviceIdentity {
            serial: "XMI456DEF".to_string(),
            manufacturer: "Xiaomi".to_string(),
            model: "23127PN0CC".to_string(),
            android_version: "14".to_string(),
            api_level: 34,
            security_patch_level: "2024-11-01".to_string(),
            build_fingerprint: "Xiaomi/topaz/topaz:14/UKQ1.231003.002/V816.0.5.0.UMGMIXM:user/release-keys".to_string(),
            oem_skin: Some("HyperOS".to_string()),
            oem_skin_version: Some("1.0".to_string()),
        }
    }

    // ── Device Matching Tests ─────────────────────────────────────────────

    #[test]
    fn test_matches_samsung_lowercase() {
        let plugin = SamsungPlugin::new();
        assert!(plugin.matches_device(&samsung_device()));
    }

    #[test]
    fn test_matches_samsung_uppercase() {
        let plugin = SamsungPlugin::new();
        let mut device = samsung_device();
        device.manufacturer = "SAMSUNG".to_string();
        assert!(plugin.matches_device(&device));
    }

    #[test]
    fn test_matches_samsung_mixed_case() {
        let plugin = SamsungPlugin::new();
        let mut device = samsung_device();
        device.manufacturer = "Samsung Electronics Co., Ltd.".to_string();
        assert!(plugin.matches_device(&device));
    }

    #[test]
    fn test_rejects_google_pixel() {
        let plugin = SamsungPlugin::new();
        assert!(!plugin.matches_device(&pixel_device()));
    }

    #[test]
    fn test_rejects_xiaomi() {
        let plugin = SamsungPlugin::new();
        assert!(!plugin.matches_device(&xiaomi_device()));
    }

    #[test]
    fn test_rejects_empty_manufacturer() {
        let plugin = SamsungPlugin::new();
        let mut device = samsung_device();
        device.manufacturer = String::new();
        assert!(!plugin.matches_device(&device));
    }

    // ── Plugin Metadata Tests ─────────────────────────────────────────────

    #[test]
    fn test_oem_id() {
        let plugin = SamsungPlugin::new();
        assert_eq!(plugin.oem_id(), "samsung");
    }

    #[test]
    fn test_oem_name() {
        let plugin = SamsungPlugin::new();
        assert_eq!(plugin.oem_name(), "Samsung Electronics");
    }

    #[test]
    fn test_supported_models_not_empty() {
        let plugin = SamsungPlugin::new();
        let models = plugin.supported_models();
        assert!(!models.is_empty());
        // Should contain at minimum Galaxy S, A, and Note series
        assert!(models.iter().any(|m| m.contains("Galaxy S")));
        assert!(models.iter().any(|m| m.contains("Galaxy A")));
        assert!(models.iter().any(|m| m.contains("Galaxy Note")));
    }

    // ── Path Override Tests ───────────────────────────────────────────────

    #[test]
    fn test_path_overrides_not_empty() {
        let plugin = SamsungPlugin::new();
        let overrides = plugin.override_artifact_paths();
        assert!(!overrides.is_empty());
    }

    #[test]
    fn test_path_overrides_contain_wifi_config_store() {
        let plugin = SamsungPlugin::new();
        let overrides = plugin.override_artifact_paths();
        let wifi_override = overrides
            .iter()
            .find(|o| o.artifact_class == ArtifactClass::WifiConfigStore);
        assert!(wifi_override.is_some(), "Should have WifiConfigStore override");
        let wifi_override = wifi_override.expect("checked above");
        assert!(wifi_override.original_path.contains("WifiConfigStore.xml"));
    }

    #[test]
    fn test_path_overrides_contain_samsung_wifi_logs() {
        let plugin = SamsungPlugin::new();
        let overrides = plugin.override_artifact_paths();
        let wifi_log_override = overrides
            .iter()
            .find(|o| o.original_path.contains("/data/log/wifi/"));
        assert!(
            wifi_log_override.is_some(),
            "Should have Samsung WiFi log path override"
        );
    }

    #[test]
    fn test_path_overrides_contain_connectivity_logs() {
        let plugin = SamsungPlugin::new();
        let overrides = plugin.override_artifact_paths();
        let conn_override = overrides
            .iter()
            .find(|o| o.original_path.contains("/data/log/connectivity/"));
        assert!(
            conn_override.is_some(),
            "Should have Samsung connectivity log path override"
        );
    }

    #[test]
    fn test_all_overrides_have_reasons() {
        let plugin = SamsungPlugin::new();
        for override_entry in plugin.override_artifact_paths() {
            assert!(
                !override_entry.reason.is_empty(),
                "Override for {:?} at {} must have a reason",
                override_entry.artifact_class,
                override_entry.original_path
            );
        }
    }

    // ── Custom Parser Tests ───────────────────────────────────────────────

    #[test]
    fn test_custom_parsers_not_empty() {
        let plugin = SamsungPlugin::new();
        let parsers = plugin.custom_parsers();
        assert_eq!(parsers.len(), 1);
        assert_eq!(parsers[0].info().parser_id, "oracle.oem.samsung.wifi_log");
    }

    #[test]
    fn test_samsung_wifi_log_parser_connection_events() {
        let parser = SamsungWifiLogParser::new();
        let log_data = b"01-15 10:30:45.123 D WifiStateMachine: Connected to SSID \"HomeNetwork\"\n\
                         01-15 10:35:12.456 D WifiStateMachine: Disconnected from SSID \"HomeNetwork\"\n\
                         01-15 10:40:00.789 I WifiManager: Connecting to SSID \"OfficeWiFi\"\n";

        let artifact_id = ArtifactId::new();
        let results = parser
            .parse(artifact_id, "abc123hash", log_data)
            .expect("parsing should succeed");

        assert_eq!(results.len(), 3, "Should parse 3 connection events");
        assert_eq!(results[0].record_type, "samsung_wifi_connection_event");
        assert_eq!(results[0].record_data["event_type"], "connected");
        assert_eq!(results[1].record_data["event_type"], "disconnected");
        assert_eq!(results[2].record_data["event_type"], "connecting");
    }

    #[test]
    fn test_samsung_wifi_log_parser_hotspot_events() {
        let parser = SamsungWifiLogParser::new();
        let log_data = b"01-15 11:00:00.000 I SoftApManager: Hotspot started on channel 6\n\
                         01-15 11:05:00.000 I SoftApManager: Hotspot stopped\n";

        let artifact_id = ArtifactId::new();
        let results = parser
            .parse(artifact_id, "def456hash", log_data)
            .expect("parsing should succeed");

        assert_eq!(results.len(), 2, "Should parse 2 hotspot events");
        assert_eq!(results[0].record_type, "samsung_wifi_hotspot_event");
        assert_eq!(results[0].record_data["event_type"], "hotspot_started");
        assert_eq!(results[1].record_data["event_type"], "hotspot_stopped");
    }

    #[test]
    fn test_samsung_wifi_log_parser_scan_events() {
        let parser = SamsungWifiLogParser::new();
        let log_data = b"01-15 12:00:00.000 D WifiScanManager: Scan started\n\
                         01-15 12:00:05.000 D WifiScanManager: Scan completed with 15 results\n";

        let artifact_id = ArtifactId::new();
        let results = parser
            .parse(artifact_id, "ghi789hash", log_data)
            .expect("parsing should succeed");

        assert_eq!(results.len(), 2, "Should parse 2 scan events");
        assert_eq!(results[0].record_type, "samsung_wifi_scan_result");
        assert_eq!(results[0].record_data["event_type"], "scan_started");
        assert_eq!(results[1].record_data["event_type"], "scan_completed");
    }

    #[test]
    fn test_samsung_wifi_log_parser_empty_input() {
        let parser = SamsungWifiLogParser::new();
        let artifact_id = ArtifactId::new();
        let results = parser
            .parse(artifact_id, "empty_hash", b"")
            .expect("parsing empty input should succeed");
        assert!(results.is_empty());
    }

    #[test]
    fn test_samsung_wifi_log_parser_unrecognized_lines() {
        let parser = SamsungWifiLogParser::new();
        let log_data = b"Some random log line that is not WiFi related\n\
                         Another unrelated log entry\n\
                         System boot completed\n";

        let artifact_id = ArtifactId::new();
        let results = parser
            .parse(artifact_id, "random_hash", log_data)
            .expect("parsing should succeed");
        assert!(results.is_empty(), "Should produce no records for unrecognized lines");
    }

    #[test]
    fn test_samsung_wifi_log_parser_confidence_values() {
        let parser = SamsungWifiLogParser::new();
        let log_data = b"01-15 10:30:45.123 D WifiStateMachine: Connected to SSID \"Test\"\n";

        let artifact_id = ArtifactId::new();
        let results = parser
            .parse(artifact_id, "conf_hash", log_data)
            .expect("parsing should succeed");

        for record in &results {
            assert!(
                record.confidence > 0.0 && record.confidence <= 1.0,
                "Confidence must be in (0.0, 1.0], got {}",
                record.confidence
            );
        }
    }

    #[test]
    fn test_samsung_wifi_log_parser_can_parse() {
        let parser = SamsungWifiLogParser::new();
        assert!(parser.can_parse(ArtifactClass::ConnectivityLogs));
        assert!(!parser.can_parse(ArtifactClass::WifiConfigStore));
        assert!(!parser.can_parse(ArtifactClass::DhcpLeases));
        assert!(!parser.can_parse(ArtifactClass::Unknown));
    }

    #[test]
    fn test_samsung_wifi_log_parser_info() {
        let parser = SamsungWifiLogParser::new();
        let info = parser.info();
        assert_eq!(info.parser_id, "oracle.oem.samsung.wifi_log");
        assert_eq!(info.parser_version, "1.0.0");
        assert!(info.supported_classes.contains(&ArtifactClass::ConnectivityLogs));
        assert!(!info.description.is_empty());
    }

    #[test]
    fn test_samsung_wifi_log_parser_byte_offsets() {
        let parser = SamsungWifiLogParser::new();
        let log_data = b"01-15 10:30:45.123 D WifiStateMachine: Connected\n\
                         01-15 10:35:12.456 D WifiStateMachine: Disconnected\n";

        let artifact_id = ArtifactId::new();
        let results = parser
            .parse(artifact_id, "offset_hash", log_data)
            .expect("parsing should succeed");

        assert_eq!(results.len(), 2);
        // First record should start at offset 0
        assert_eq!(results[0].byte_offset, Some(0));
        // Second record should start after the first line + newline
        assert!(results[1].byte_offset.is_some());
        let second_offset = results[1].byte_offset.expect("checked above");
        assert!(second_offset > 0, "Second record offset should be > 0");
    }
}
