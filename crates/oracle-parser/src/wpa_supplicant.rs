//! # WPA Supplicant Configuration Parser
//!
//! Parses the legacy `wpa_supplicant.conf` file format used by Android
//! devices (primarily pre-Android 8, but still present on many devices).
//!
//! The parser extracts `network={...}` blocks using regex and maps
//! `key_mgmt` values to [`SecurityProtocol`] variants.

use oracle_core::{ArtifactClass, ArtifactId, OracleError, OracleResult, SecurityProtocol};
use regex::Regex;
use serde_json::json;
use tracing::warn;

use crate::traits::{ArtifactParser, ParsedOutput, ParserInfo};

/// Parser for `wpa_supplicant.conf` artifacts.
///
/// This configuration file contains known Wi-Fi networks with SSIDs,
/// optional BSSIDs, key management settings, and priority values.
/// Each `network={...}` block represents a single saved network.
pub struct WpaSupplicantParser;

/// Map a `key_mgmt` string value to [`SecurityProtocol`].
fn map_key_mgmt(value: &str) -> SecurityProtocol {
    let upper = value.trim().to_uppercase();
    match upper.as_str() {
        "NONE" => SecurityProtocol::Open,
        "WPA-PSK" => SecurityProtocol::WpaPsk,
        "WPA2-PSK" | "RSN-PSK" => SecurityProtocol::Wpa2Psk,
        "SAE" => SecurityProtocol::Wpa3Sae,
        "WPA-EAP" | "IEEE8021X" => SecurityProtocol::EapPeap,
        _ => {
            if upper.contains("WEP") {
                SecurityProtocol::Wep
            } else {
                SecurityProtocol::Unknown
            }
        }
    }
}

/// Extract a field value from a `network={...}` block body.
///
/// Searches for lines matching `key=value` or `key="value"` patterns
/// and returns the unquoted value, or `None` if not found.
fn extract_field<'a>(block: &'a str, field_name: &str) -> Option<&'a str> {
    for line in block.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(field_name) {
            if let Some(value) = rest.strip_prefix('=') {
                let value = value.trim();
                // Strip surrounding quotes if present
                let unquoted = value
                    .strip_prefix('"')
                    .and_then(|v| v.strip_suffix('"'))
                    .unwrap_or(value);
                return Some(unquoted);
            }
        }
    }
    None
}

impl ArtifactParser for WpaSupplicantParser {
    fn info(&self) -> ParserInfo {
        ParserInfo {
            parser_id: "oracle.wpa_supplicant".to_string(),
            parser_version: "1.0.0".to_string(),
            supported_classes: vec![ArtifactClass::WpaSupplicant],
            description:
                "WPA supplicant configuration parser — extracts known Wi-Fi networks".to_string(),
        }
    }

    fn can_parse(&self, class: ArtifactClass) -> bool {
        class == ArtifactClass::WpaSupplicant
    }

    fn parse(
        &self,
        artifact_id: ArtifactId,
        _artifact_hash: &str,
        raw_bytes: &[u8],
    ) -> OracleResult<Vec<ParsedOutput>> {
        let text = std::str::from_utf8(raw_bytes).map_err(|e| OracleError::ArtifactCorrupted {
            artifact_id: artifact_id.0,
            reason: format!("Invalid UTF-8: {e}"),
        })?;

        // Match network={...} blocks. The (?s) flag enables dotall mode so
        // the `.` metacharacter also matches newlines within the block.
        let network_re = Regex::new(r"(?s)network\s*=\s*\{([^}]*)\}").map_err(|e| {
            OracleError::ArtifactCorrupted {
                artifact_id: artifact_id.0,
                reason: format!("Internal regex compilation error: {e}"),
            }
        })?;

        let mut results = Vec::new();

        for cap in network_re.captures_iter(text) {
            let full_match = cap.get(0);
            let block_body = match cap.get(1) {
                Some(m) => m.as_str(),
                None => continue,
            };

            let ssid = match extract_field(block_body, "ssid") {
                Some(s) => s.to_string(),
                None => {
                    warn!(
                        artifact_id = %artifact_id,
                        "Skipping network block with no ssid field"
                    );
                    continue;
                }
            };

            let bssid = extract_field(block_body, "bssid").map(|s| s.to_string());
            let key_mgmt_raw = extract_field(block_body, "key_mgmt").unwrap_or("NONE");
            let security = map_key_mgmt(key_mgmt_raw);
            let priority: Option<i64> = extract_field(block_body, "priority")
                .and_then(|s| s.parse().ok());

            let (byte_offset, byte_length) = match full_match {
                Some(m) => (Some(m.start() as u64), Some(m.len() as u64)),
                None => (None, None),
            };

            let record_data = json!({
                "ssid": ssid,
                "bssid": bssid,
                "security_protocol": format!("{security}"),
                "key_mgmt": key_mgmt_raw,
                "priority": priority,
            });

            results.push(ParsedOutput {
                record_type: "wifi_known_network".to_string(),
                record_data,
                byte_offset,
                byte_length,
                confidence: 0.90,
            });
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_core::ArtifactId;

    const SAMPLE_CONF: &str = r#"ctrl_interface=/data/misc/wifi/sockets
update_config=1

network={
    ssid="HomeWiFi"
    psk="password123"
    key_mgmt=WPA-PSK
    priority=1
}

network={
    ssid="OpenCafe"
    key_mgmt=NONE
    priority=0
}
"#;

    #[test]
    fn test_parse_two_networks() {
        let parser = WpaSupplicantParser;
        let id = ArtifactId::new();
        let results = parser
            .parse(id, "hash123", SAMPLE_CONF.as_bytes())
            .expect("parse failed");
        assert_eq!(results.len(), 2);

        assert_eq!(results[0].record_type, "wifi_known_network");
        assert_eq!(results[0].record_data["ssid"], "HomeWiFi");
        assert_eq!(results[0].record_data["security_protocol"], "WPA-PSK");
        assert_eq!(results[0].record_data["priority"], 1);
        assert!((results[0].confidence - 0.90).abs() < f64::EPSILON);
        assert!(results[0].byte_offset.is_some());
        assert!(results[0].byte_length.is_some());

        assert_eq!(results[1].record_data["ssid"], "OpenCafe");
        assert_eq!(results[1].record_data["security_protocol"], "OPEN");
        assert_eq!(results[1].record_data["priority"], 0);
    }

    #[test]
    fn test_can_parse() {
        let parser = WpaSupplicantParser;
        assert!(parser.can_parse(ArtifactClass::WpaSupplicant));
        assert!(!parser.can_parse(ArtifactClass::WifiConfigStore));
        assert!(!parser.can_parse(ArtifactClass::DhcpLeases));
    }

    #[test]
    fn test_empty_input() {
        let parser = WpaSupplicantParser;
        let id = ArtifactId::new();
        let results = parser
            .parse(id, "hash", b"")
            .expect("should not fail on empty");
        assert!(results.is_empty());
    }

    #[test]
    fn test_network_with_bssid() {
        let input = r#"
network={
    ssid="Locked"
    bssid=aa:bb:cc:dd:ee:ff
    key_mgmt=WPA-PSK
}
"#;
        let parser = WpaSupplicantParser;
        let id = ArtifactId::new();
        let results = parser.parse(id, "h", input.as_bytes()).expect("parse failed");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].record_data["bssid"], "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_key_mgmt_mapping() {
        assert_eq!(map_key_mgmt("NONE"), SecurityProtocol::Open);
        assert_eq!(map_key_mgmt("WPA-PSK"), SecurityProtocol::WpaPsk);
        assert_eq!(map_key_mgmt("RSN-PSK"), SecurityProtocol::Wpa2Psk);
        assert_eq!(map_key_mgmt("SAE"), SecurityProtocol::Wpa3Sae);
        assert_eq!(map_key_mgmt("WPA-EAP"), SecurityProtocol::EapPeap);
        assert_eq!(map_key_mgmt("SOMETHING"), SecurityProtocol::Unknown);
    }
}
