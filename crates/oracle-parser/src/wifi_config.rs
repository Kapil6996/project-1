//! # WifiConfigStore XML Parser
//!
//! Parses Android's `WifiConfigStore.xml` artifact to extract saved Wi-Fi
//! network configurations including SSIDs, BSSIDs, and security protocols.
//!
//! This parser handles format variations across Android versions:
//! - String-based security types (e.g., `"WPA-PSK"`)
//! - Integer-based security types (e.g., `value="2"`)
//! - XML-entity-quoted SSIDs (`&quot;MyNetwork&quot;`)
//! - Missing or `"any"` BSSID values

use oracle_core::{ArtifactClass, ArtifactId, OracleError, OracleResult, SecurityProtocol};
use quick_xml::events::Event;
use quick_xml::Reader;
use serde_json::json;
use tracing::warn;

use crate::traits::{ArtifactParser, ParsedOutput, ParserInfo};

/// Parser for Android `WifiConfigStore.xml` artifacts.
///
/// This file is the primary source of saved Wi-Fi network configurations
/// on Android 8+ devices. It contains network SSIDs, BSSIDs, security
/// settings, and other configuration parameters in XML format.
pub struct WifiConfigStoreParser;

/// Map a string security type value to [`SecurityProtocol`].
///
/// Handles both string representations (e.g., `"WPA-PSK"`) and provides
/// case-insensitive matching for common variations across OEM ROMs.
fn map_security_string(value: &str) -> SecurityProtocol {
    let upper = value.to_uppercase();
    if upper == "OPEN" || upper == "NONE" {
        SecurityProtocol::Open
    } else if upper.contains("WPA3") || upper.contains("SAE") {
        SecurityProtocol::Wpa3Sae
    } else if upper.contains("WPA2") {
        SecurityProtocol::Wpa2Psk
    } else if upper.contains("WPA") && upper.contains("PSK") {
        SecurityProtocol::WpaPsk
    } else if upper.contains("WEP") {
        SecurityProtocol::Wep
    } else if upper.contains("OWE") {
        SecurityProtocol::Owe
    } else if upper.contains("EAP-TLS") {
        SecurityProtocol::EapTls
    } else if upper.contains("EAP") {
        SecurityProtocol::EapPeap
    } else {
        SecurityProtocol::Unknown
    }
}

/// Map an integer security type value to [`SecurityProtocol`].
///
/// Android internally uses integer codes for security types:
/// - 0 = Open
/// - 1 = WEP
/// - 2 = WPA-PSK
/// - 3 = WPA2-PSK (IEEE 802.11i)
/// - 4 = WPA3-SAE
/// - 5 = WPA-EAP
/// - 6 = OWE
fn map_security_int(value: u32) -> SecurityProtocol {
    match value {
        0 => SecurityProtocol::Open,
        1 => SecurityProtocol::Wep,
        2 => SecurityProtocol::WpaPsk,
        3 => SecurityProtocol::Wpa2Psk,
        4 => SecurityProtocol::Wpa3Sae,
        5 => SecurityProtocol::EapPeap,
        6 => SecurityProtocol::Owe,
        _ => SecurityProtocol::Unknown,
    }
}

/// Strip surrounding quote characters and XML `&quot;` entities from SSID values.
///
/// Android XML stores SSIDs as `&quot;MyNetwork&quot;` which quick-xml
/// decodes to `"MyNetwork"`. This function strips the outer quotes.
fn strip_ssid_quotes(raw: &str) -> String {
    let trimmed = raw.trim();
    // Strip XML-decoded quote characters
    let stripped = trimmed
        .strip_prefix('"')
        .unwrap_or(trimmed);
    let stripped = stripped
        .strip_suffix('"')
        .unwrap_or(stripped);
    stripped.to_string()
}

/// Intermediate state for tracking which XML element we are reading.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReadingField {
    Ssid,
    Bssid,
    SecurityTypeString,
    Other,
}

/// Accumulated data for a single network block being parsed.
#[derive(Debug, Default)]
struct NetworkData {
    ssid: Option<String>,
    bssid: Option<String>,
    security_protocol: Option<SecurityProtocol>,
    raw_security_value: Option<String>,
}

impl ArtifactParser for WifiConfigStoreParser {
    fn info(&self) -> ParserInfo {
        ParserInfo {
            parser_id: "oracle.wifi_config_store".to_string(),
            parser_version: "1.0.0".to_string(),
            supported_classes: vec![ArtifactClass::WifiConfigStore],
            description:
                "Android WifiConfigStore.xml parser — extracts saved Wi-Fi network configurations"
                    .to_string(),
        }
    }

    fn can_parse(&self, class: ArtifactClass) -> bool {
        class == ArtifactClass::WifiConfigStore
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

        let mut reader = Reader::from_str(text);

        let mut results: Vec<ParsedOutput> = Vec::new();
        let mut in_wifi_config = false;
        let mut current_network: Option<NetworkData> = None;
        let mut reading_field = ReadingField::Other;
        // Buffer for accumulating text content inside XML elements.
        let mut text_buf = String::new();

        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) => {
                    let local_name = e.local_name();
                    let tag = std::str::from_utf8(local_name.as_ref()).unwrap_or("");

                    match tag {
                        "Network" => {
                            current_network = Some(NetworkData::default());
                        }
                        "WifiConfiguration" => {
                            in_wifi_config = true;
                        }
                        "string" if in_wifi_config => {
                            // Check the "name" attribute to know which field we're reading
                            reading_field = ReadingField::Other;
                            text_buf.clear();
                            for attr_result in e.attributes() {
                                if let Ok(attr) = attr_result {
                                    let key =
                                        std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                                    if key == "name" {
                                        let val = attr
                                            .unescape_value()
                                            .unwrap_or_default();
                                        match val.as_ref() {
                                            "SSID" => reading_field = ReadingField::Ssid,
                                            "BSSID" => reading_field = ReadingField::Bssid,
                                            "SecurityType" => {
                                                reading_field = ReadingField::SecurityTypeString
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }

                    // Handle <int name="SecurityType" value="N" /> via Start event
                    // (some XML serializers emit it as <int ...>...</int>)
                    if tag == "int" && in_wifi_config {
                        Self::try_parse_int_security(e, &mut current_network);
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    let local_name = e.local_name();
                    let tag = std::str::from_utf8(local_name.as_ref()).unwrap_or("");

                    // Handle self-closing <int name="SecurityType" value="N" />
                    if tag == "int" && in_wifi_config {
                        Self::try_parse_int_security(e, &mut current_network);
                    }
                }
                Ok(Event::Text(ref e)) => {
                    if reading_field != ReadingField::Other {
                        if let Ok(decoded) = e.unescape() {
                            text_buf.push_str(&decoded);
                        }
                    }
                }
                Ok(Event::End(ref e)) => {
                    let local_name = e.local_name();
                    let tag = std::str::from_utf8(local_name.as_ref()).unwrap_or("");

                    match tag {
                        "string" if in_wifi_config => {
                            if let Some(ref mut network) = current_network {
                                match reading_field {
                                    ReadingField::Ssid => {
                                        network.ssid = Some(strip_ssid_quotes(&text_buf));
                                    }
                                    ReadingField::Bssid => {
                                        let bssid = text_buf.trim().to_string();
                                        if !bssid.is_empty()
                                            && bssid.to_lowercase() != "any"
                                        {
                                            network.bssid = Some(bssid);
                                        }
                                    }
                                    ReadingField::SecurityTypeString => {
                                        let raw = text_buf.trim().to_string();
                                        network.security_protocol =
                                            Some(map_security_string(&raw));
                                        network.raw_security_value = Some(raw);
                                    }
                                    ReadingField::Other => {}
                                }
                            }
                            reading_field = ReadingField::Other;
                            text_buf.clear();
                        }
                        "WifiConfiguration" => {
                            in_wifi_config = false;
                        }
                        "Network" => {
                            // Emit the completed network record
                            if let Some(network) = current_network.take() {
                                if let Some(ref ssid) = network.ssid {
                                    let security = network
                                        .security_protocol
                                        .unwrap_or(SecurityProtocol::Unknown);
                                    let record_data = json!({
                                        "ssid": ssid,
                                        "bssid": network.bssid,
                                        "security_protocol": format!("{security}"),
                                        "raw_security_value": network.raw_security_value,
                                    });
                                    results.push(ParsedOutput {
                                        record_type: "wifi_configured_network".to_string(),
                                        record_data,
                                        byte_offset: None,
                                        byte_length: None,
                                        confidence: 0.95,
                                    });
                                } else {
                                    warn!(
                                        artifact_id = %artifact_id,
                                        "Skipping network block with no SSID"
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    warn!(
                        artifact_id = %artifact_id,
                        error = %e,
                        "XML parse error in WifiConfigStore — returning partial results"
                    );
                    break;
                }
                _ => {}
            }
        }

        Ok(results)
    }
}

impl WifiConfigStoreParser {
    /// Attempt to extract `SecurityType` from an `<int>` element's attributes.
    ///
    /// Checks for `name="SecurityType"` and reads `value="N"` to map to a
    /// [`SecurityProtocol`] via [`map_security_int`].
    fn try_parse_int_security(
        e: &quick_xml::events::BytesStart<'_>,
        current_network: &mut Option<NetworkData>,
    ) {
        let mut is_security = false;
        let mut int_value: Option<u32> = None;

        for attr_result in e.attributes() {
            if let Ok(attr) = attr_result {
                let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                let val = attr.unescape_value().unwrap_or_default();
                if key == "name" && val.as_ref() == "SecurityType" {
                    is_security = true;
                } else if key == "value" {
                    int_value = val.parse::<u32>().ok();
                }
            }
        }

        if is_security {
            if let (Some(ref mut network), Some(val)) = (current_network, int_value) {
                network.security_protocol = Some(map_security_int(val));
                network.raw_security_value = Some(val.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_core::ArtifactId;

    const SAMPLE_XML: &str = r#"<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<WifiConfigStoreData>
<NetworkList>
<Network>
<WifiConfiguration>
<string name="ConfigKey">&quot;HomeWiFi&quot;WPA_PSK</string>
<string name="SSID">&quot;HomeWiFi&quot;</string>
<string name="BSSID">aa:bb:cc:dd:ee:ff</string>
<string name="SecurityType">WPA-PSK</string>
</WifiConfiguration>
</Network>
<Network>
<WifiConfiguration>
<string name="SSID">&quot;CoffeeShop&quot;</string>
<string name="BSSID">11:22:33:44:55:66</string>
<int name="SecurityType" value="0" />
</WifiConfiguration>
</Network>
<Network>
<WifiConfiguration>
<string name="SSID">&quot;Office5G&quot;</string>
<string name="BSSID">any</string>
<string name="SecurityType">WPA2-PSK</string>
</WifiConfiguration>
</Network>
</NetworkList>
</WifiConfigStoreData>"#;

    #[test]
    fn test_parse_three_networks() {
        let parser = WifiConfigStoreParser;
        let id = ArtifactId::new();
        let results = parser
            .parse(id, "abc123", SAMPLE_XML.as_bytes())
            .expect("parse failed");
        assert_eq!(results.len(), 3);

        // First network
        assert_eq!(results[0].record_type, "wifi_configured_network");
        assert_eq!(results[0].record_data["ssid"], "HomeWiFi");
        assert_eq!(results[0].record_data["bssid"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(results[0].record_data["security_protocol"], "WPA-PSK");
        assert!((results[0].confidence - 0.95).abs() < f64::EPSILON);

        // Second network — open, using int SecurityType
        assert_eq!(results[1].record_data["ssid"], "CoffeeShop");
        assert_eq!(results[1].record_data["security_protocol"], "OPEN");

        // Third network — BSSID is "any" → null
        assert_eq!(results[2].record_data["ssid"], "Office5G");
        assert_eq!(results[2].record_data["bssid"], serde_json::Value::Null);
        assert_eq!(results[2].record_data["security_protocol"], "WPA2-PSK");
    }

    #[test]
    fn test_invalid_xml() {
        let parser = WifiConfigStoreParser;
        let id = ArtifactId::new();
        let result = parser.parse(id, "abc123", b"<<<not valid xml");
        // Should return Ok with 0 records or an error, but must not panic
        match result {
            Ok(records) => assert!(records.is_empty()),
            Err(_) => {} // ArtifactCorrupted is acceptable
        }
    }

    #[test]
    fn test_can_parse() {
        let parser = WifiConfigStoreParser;
        assert!(parser.can_parse(ArtifactClass::WifiConfigStore));
        assert!(!parser.can_parse(ArtifactClass::WpaSupplicant));
        assert!(!parser.can_parse(ArtifactClass::DhcpLeases));
    }

    #[test]
    fn test_empty_xml() {
        let parser = WifiConfigStoreParser;
        let id = ArtifactId::new();
        let results = parser
            .parse(id, "hash", b"<?xml version='1.0'?><WifiConfigStoreData></WifiConfigStoreData>")
            .expect("should not fail on empty config");
        assert!(results.is_empty());
    }

    #[test]
    fn test_ssid_quote_stripping() {
        assert_eq!(strip_ssid_quotes(r#""MyNet""#), "MyNet");
        assert_eq!(strip_ssid_quotes("PlainSSID"), "PlainSSID");
        assert_eq!(strip_ssid_quotes(r#"  "SpacedSSID"  "#), "SpacedSSID");
    }

    #[test]
    fn test_security_string_mapping() {
        assert_eq!(map_security_string("OPEN"), SecurityProtocol::Open);
        assert_eq!(map_security_string("None"), SecurityProtocol::Open);
        assert_eq!(map_security_string("WPA-PSK"), SecurityProtocol::WpaPsk);
        assert_eq!(map_security_string("WPA2-PSK"), SecurityProtocol::Wpa2Psk);
        assert_eq!(map_security_string("WPA3-SAE"), SecurityProtocol::Wpa3Sae);
        assert_eq!(map_security_string("SAE"), SecurityProtocol::Wpa3Sae);
        assert_eq!(map_security_string("WEP"), SecurityProtocol::Wep);
        assert_eq!(map_security_string("OWE"), SecurityProtocol::Owe);
        assert_eq!(map_security_string("EAP"), SecurityProtocol::EapPeap);
        assert_eq!(map_security_string("EAP-TLS"), SecurityProtocol::EapTls);
        assert_eq!(map_security_string("MAGIC"), SecurityProtocol::Unknown);
    }

    #[test]
    fn test_security_int_mapping() {
        assert_eq!(map_security_int(0), SecurityProtocol::Open);
        assert_eq!(map_security_int(1), SecurityProtocol::Wep);
        assert_eq!(map_security_int(2), SecurityProtocol::WpaPsk);
        assert_eq!(map_security_int(3), SecurityProtocol::Wpa2Psk);
        assert_eq!(map_security_int(4), SecurityProtocol::Wpa3Sae);
        assert_eq!(map_security_int(5), SecurityProtocol::EapPeap);
        assert_eq!(map_security_int(6), SecurityProtocol::Owe);
        assert_eq!(map_security_int(99), SecurityProtocol::Unknown);
    }
}
