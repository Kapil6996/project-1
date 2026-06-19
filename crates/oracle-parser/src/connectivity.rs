//! # Connectivity Log Parser
//!
//! Parses Android connectivity service and netstats log output to extract
//! network state changes (WIFI/MOBILE connected/disconnected) and
//! individual connection events (TCP/UDP connections with addresses and ports).
//!
//! ## Recognized Log Patterns
//!
//! 1. **State changes** — `ConnectivityService:` lines with `state=CONNECTED`
//!    or `state=DISCONNECTED` and a network type in brackets (`[WIFI ...]`).
//! 2. **Connection events** — `NetdEventListenerService:` lines with
//!    `type=`, `addr=`, and `port=` fields.

use oracle_core::{ArtifactClass, ArtifactId, OracleError, OracleResult};
use regex::Regex;
use serde_json::json;
use tracing::warn;

use crate::traits::{ArtifactParser, ParsedOutput, ParserInfo};

/// Parser for Android connectivity and netstats log artifacts.
///
/// These logs record network type transitions (Wi-Fi ↔ mobile data) and
/// individual socket connection events, providing a timeline of the
/// device's network activity.
pub struct ConnectivityLogParser;

impl ArtifactParser for ConnectivityLogParser {
    fn info(&self) -> ParserInfo {
        ParserInfo {
            parser_id: "oracle.connectivity_log".to_string(),
            parser_version: "1.0.0".to_string(),
            supported_classes: vec![ArtifactClass::ConnectivityLogs],
            description: "Android connectivity log parser — extracts network state changes and connection events".to_string(),
        }
    }

    fn can_parse(&self, class: ArtifactClass) -> bool {
        class == ArtifactClass::ConnectivityLogs
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

        // Regex for connectivity state change lines:
        // 01-15 10:30:45.123 ... ConnectivityService: ... [WIFI ...] ... state=CONNECTED...
        let state_re = Regex::new(
            r"(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}).*ConnectivityService:.*\[(\w+)\s.*state=(\w+)",
        )
        .map_err(|e| OracleError::ArtifactCorrupted {
            artifact_id: artifact_id.0,
            reason: format!("Internal regex error: {e}"),
        })?;

        // Regex for connection event lines:
        // 01-15 10:32:15.789 ... NetdEventListenerService: type=CONNECT addr=192.168.1.1 port=443 ...
        let conn_re = Regex::new(
            r"(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}).*NetdEventListenerService:.*type=(\w+).*addr=([\d\.]+).*port=(\d+)",
        )
        .map_err(|e| OracleError::ArtifactCorrupted {
            artifact_id: artifact_id.0,
            reason: format!("Internal regex error: {e}"),
        })?;

        let mut results = Vec::new();
        let mut byte_pos: u64 = 0;

        for line in text.lines() {
            let line_bytes = line.len() as u64;

            // Try matching a connectivity state change
            if let Some(caps) = state_re.captures(line) {
                let timestamp_raw = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let network_type = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                let state = caps.get(3).map(|m| m.as_str()).unwrap_or("");

                let record_data = json!({
                    "timestamp_raw": timestamp_raw,
                    "network_type": network_type,
                    "state": state,
                    "event_kind": "state_change",
                });

                results.push(ParsedOutput {
                    record_type: "connectivity_event".to_string(),
                    record_data,
                    byte_offset: Some(byte_pos),
                    byte_length: Some(line_bytes),
                    confidence: 0.85,
                });
            }
            // Try matching a connection event
            else if let Some(caps) = conn_re.captures(line) {
                let timestamp_raw = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let event_type = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                let address = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                let port_str = caps.get(4).map(|m| m.as_str()).unwrap_or("0");
                let port: u16 = port_str.parse().unwrap_or(0);

                let record_data = json!({
                    "timestamp_raw": timestamp_raw,
                    "event_type": event_type,
                    "address": address,
                    "port": port,
                    "event_kind": "connection",
                });

                results.push(ParsedOutput {
                    record_type: "connectivity_event".to_string(),
                    record_data,
                    byte_offset: Some(byte_pos),
                    byte_length: Some(line_bytes),
                    confidence: 0.85,
                });
            }

            byte_pos += line_bytes + 1;
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_core::ArtifactId;

    const SAMPLE_LOG: &str = r#"01-15 10:30:45.123 1234 5678 D ConnectivityService: NetworkAgentInfo [WIFI () - 100] EVENT_NETWORK_INFO_CHANGED: state=CONNECTED/CONNECTED
01-15 10:31:00.456 1234 5678 D ConnectivityService: NetworkAgentInfo [MOBILE (LTE) - 101] EVENT_NETWORK_INFO_CHANGED: state=DISCONNECTED/DISCONNECTED
01-15 10:32:15.789 1234 5678 I NetdEventListenerService: type=CONNECT addr=192.168.1.1 port=443 uid=10042
Some random log line that should be ignored
"#;

    #[test]
    fn test_parse_connectivity_events() {
        let parser = ConnectivityLogParser;
        let id = ArtifactId::new();
        let results = parser
            .parse(id, "hash", SAMPLE_LOG.as_bytes())
            .expect("parse failed");
        assert_eq!(results.len(), 3);

        // First: WIFI CONNECTED
        assert_eq!(results[0].record_type, "connectivity_event");
        assert_eq!(results[0].record_data["network_type"], "WIFI");
        assert_eq!(results[0].record_data["state"], "CONNECTED");
        assert_eq!(results[0].record_data["event_kind"], "state_change");
        assert!((results[0].confidence - 0.85).abs() < f64::EPSILON);

        // Second: MOBILE DISCONNECTED
        assert_eq!(results[1].record_data["network_type"], "MOBILE");
        assert_eq!(results[1].record_data["state"], "DISCONNECTED");

        // Third: connection event
        assert_eq!(results[2].record_data["event_kind"], "connection");
        assert_eq!(results[2].record_data["address"], "192.168.1.1");
        assert_eq!(results[2].record_data["port"], 443);
        assert_eq!(results[2].record_data["event_type"], "CONNECT");
    }

    #[test]
    fn test_can_parse() {
        let parser = ConnectivityLogParser;
        assert!(parser.can_parse(ArtifactClass::ConnectivityLogs));
        assert!(!parser.can_parse(ArtifactClass::WpaSupplicant));
        assert!(!parser.can_parse(ArtifactClass::WifiConfigStore));
    }

    #[test]
    fn test_empty_input() {
        let parser = ConnectivityLogParser;
        let id = ArtifactId::new();
        let results = parser
            .parse(id, "hash", b"")
            .expect("should not fail on empty");
        assert!(results.is_empty());
    }

    #[test]
    fn test_unrecognized_lines_ignored() {
        let input = "random garbage\nanother line\nnot a log\n";
        let parser = ConnectivityLogParser;
        let id = ArtifactId::new();
        let results = parser
            .parse(id, "hash", input.as_bytes())
            .expect("should not fail");
        assert!(results.is_empty());
    }

    #[test]
    fn test_byte_offsets_present() {
        let parser = ConnectivityLogParser;
        let id = ArtifactId::new();
        let results = parser
            .parse(id, "hash", SAMPLE_LOG.as_bytes())
            .expect("parse failed");
        for result in &results {
            assert!(result.byte_offset.is_some());
            assert!(result.byte_length.is_some());
        }
    }
}
