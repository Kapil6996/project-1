//! # DHCP Lease File Parser
//!
//! Parses Android's dnsmasq-format DHCP lease files to extract device
//! lease assignments including timestamps, MAC addresses, IP addresses,
//! and hostnames.
//!
//! ## Lease File Format
//!
//! Each line follows the format:
//! ```text
//! <unix_timestamp> <mac_address> <ip_address> <hostname> <client_id|*>
//! ```
//!
//! Lines starting with `#` are comments. Empty lines are skipped.

use oracle_core::{ArtifactClass, ArtifactId, OracleError, OracleResult};
use serde_json::json;
use tracing::warn;

use crate::traits::{ArtifactParser, ParsedOutput, ParserInfo};

/// Parser for DHCP lease file artifacts.
///
/// DHCP lease files record which devices were assigned IP addresses
/// by the device's DHCP server (e.g., when acting as a mobile hotspot).
/// Each entry provides a MAC address, IP, hostname, and timestamp.
pub struct DhcpLeaseParser;

impl ArtifactParser for DhcpLeaseParser {
    fn info(&self) -> ParserInfo {
        ParserInfo {
            parser_id: "oracle.dhcp_lease".to_string(),
            parser_version: "1.0.0".to_string(),
            supported_classes: vec![ArtifactClass::DhcpLeases],
            description: "DHCP lease file parser — extracts device lease assignments".to_string(),
        }
    }

    fn can_parse(&self, class: ArtifactClass) -> bool {
        class == ArtifactClass::DhcpLeases
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

        let mut results = Vec::new();
        let mut byte_pos: u64 = 0;

        for line in text.lines() {
            let line_bytes = line.len() as u64;
            let trimmed = line.trim();

            // Skip empty lines and comments.
            if trimmed.is_empty() || trimmed.starts_with('#') {
                // +1 for the newline character consumed by lines()
                byte_pos += line_bytes + 1;
                continue;
            }

            let fields: Vec<&str> = trimmed.split_whitespace().collect();
            if fields.len() < 4 {
                warn!(
                    artifact_id = %artifact_id,
                    line = trimmed,
                    "Skipping malformed DHCP lease line: expected at least 4 fields, got {}",
                    fields.len()
                );
                byte_pos += line_bytes + 1;
                continue;
            }

            let timestamp: Option<u64> = fields[0].parse().ok();
            if timestamp.is_none() {
                warn!(
                    artifact_id = %artifact_id,
                    raw_value = fields[0],
                    "Skipping DHCP lease line with unparseable timestamp"
                );
                byte_pos += line_bytes + 1;
                continue;
            }

            let mac_address = fields[1];
            let ip_address = fields[2];
            let hostname_raw = fields[3];
            let hostname: serde_json::Value = if hostname_raw == "*" {
                serde_json::Value::Null
            } else {
                json!(hostname_raw)
            };

            let client_id: serde_json::Value = if fields.len() >= 5 && fields[4] != "*" {
                json!(fields[4])
            } else {
                serde_json::Value::Null
            };

            let record_data = json!({
                "timestamp": timestamp,
                "mac_address": mac_address,
                "ip_address": ip_address,
                "hostname": hostname,
                "client_id": client_id,
            });

            results.push(ParsedOutput {
                record_type: "dhcp_lease".to_string(),
                record_data,
                byte_offset: Some(byte_pos),
                byte_length: Some(line_bytes),
                confidence: 0.92,
            });

            byte_pos += line_bytes + 1;
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_core::ArtifactId;

    const SAMPLE_LEASES: &str =
        "# DHCP leases\n1609459200 aa:bb:cc:dd:ee:ff 192.168.1.100 android-abc123 *\n1609459300 11:22:33:44:55:66 192.168.1.101 Galaxy-S21 01:11:22:33:44:55:66\n";

    #[test]
    fn test_parse_leases() {
        let parser = DhcpLeaseParser;
        let id = ArtifactId::new();
        let results = parser
            .parse(id, "hash", SAMPLE_LEASES.as_bytes())
            .expect("parse failed");
        assert_eq!(results.len(), 2);

        assert_eq!(results[0].record_type, "dhcp_lease");
        assert_eq!(results[0].record_data["mac_address"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(results[0].record_data["ip_address"], "192.168.1.100");
        assert_eq!(results[0].record_data["hostname"], "android-abc123");
        assert_eq!(results[0].record_data["timestamp"], 1_609_459_200u64);
        assert!((results[0].confidence - 0.92).abs() < f64::EPSILON);
        assert!(results[0].byte_offset.is_some());

        assert_eq!(results[1].record_data["hostname"], "Galaxy-S21");
        assert_eq!(
            results[1].record_data["client_id"],
            "01:11:22:33:44:55:66"
        );
    }

    #[test]
    fn test_can_parse() {
        let parser = DhcpLeaseParser;
        assert!(parser.can_parse(ArtifactClass::DhcpLeases));
        assert!(!parser.can_parse(ArtifactClass::WifiConfigStore));
        assert!(!parser.can_parse(ArtifactClass::WpaSupplicant));
    }

    #[test]
    fn test_empty_input() {
        let parser = DhcpLeaseParser;
        let id = ArtifactId::new();
        let results = parser
            .parse(id, "hash", b"")
            .expect("should not fail on empty");
        assert!(results.is_empty());
    }

    #[test]
    fn test_comments_and_blank_lines() {
        let input = "# comment\n\n# another comment\n";
        let parser = DhcpLeaseParser;
        let id = ArtifactId::new();
        let results = parser
            .parse(id, "hash", input.as_bytes())
            .expect("should not fail");
        assert!(results.is_empty());
    }

    #[test]
    fn test_wildcard_hostname() {
        let input = "1609459200 aa:bb:cc:dd:ee:ff 192.168.1.50 * *\n";
        let parser = DhcpLeaseParser;
        let id = ArtifactId::new();
        let results = parser
            .parse(id, "hash", input.as_bytes())
            .expect("parse failed");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].record_data["hostname"], serde_json::Value::Null);
        assert_eq!(
            results[0].record_data["client_id"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn test_malformed_line_skipped() {
        let input = "not_a_timestamp foo bar\n1609459200 aa:bb:cc:dd:ee:ff 192.168.1.1 host *\n";
        let parser = DhcpLeaseParser;
        let id = ArtifactId::new();
        let results = parser
            .parse(id, "hash", input.as_bytes())
            .expect("should not fail");
        // Only the valid line should be parsed
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].record_data["ip_address"], "192.168.1.1");
    }
}
