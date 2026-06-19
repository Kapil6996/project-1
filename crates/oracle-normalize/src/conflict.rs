//! # Conflict Detector
//!
//! Identifies contradictions when multiple forensic artifact sources provide
//! conflicting claims about the same evidential fact. This is critical for
//! forensic integrity — courts require disclosure of contradictions.
//!
//! # Detection Categories
//!
//! - **SSID Conflicts:** Same BSSID associated with different SSIDs across sources.
//! - **BSSID Conflicts:** Same SSID associated with different BSSIDs (may be legitimate).
//! - **Security Protocol Conflicts:** Same network reported with different security protocols.
//! - **Timestamp Conflicts:** Same event reported with incompatible timestamps.
//! - **Network Role Conflicts:** Sources disagree on whether device was client or hotspot.
//!
//! # Forensic Significance
//!
//! Conflicts don't necessarily indicate evidence tampering — they often arise from:
//! - OEM-specific artifact format differences
//! - Log rotation and partial data
//! - MAC address randomization (Android 10+)
//! - Access point configuration changes over time
//!
//! However, every conflict MUST be documented and disclosed in the forensic report.

use chrono::{DateTime, Utc};
use oracle_core::types::{ArtifactId, RecordId, SecurityProtocol};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ──────────────────────────────────────────────────────────────────────────────
// Conflict Types
// ──────────────────────────────────────────────────────────────────────────────

/// Unique identifier for a detected conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConflictId(pub Uuid);

impl ConflictId {
    pub fn new() -> Self {
        ConflictId(Uuid::new_v4())
    }
}

impl Default for ConflictId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ConflictId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The severity of a conflict for forensic reporting purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConflictSeverity {
    /// Informational — likely explained by normal system behavior.
    /// Example: Different SSIDs for the same BSSID across time (AP renamed).
    Info,
    /// Warning — requires examiner review but has plausible explanations.
    /// Example: Security protocol mismatch between wpa_supplicant and WifiConfigStore.
    Warning,
    /// Critical — may affect finding reliability or indicate evidence issues.
    /// Example: Same event with incompatible timestamps across sources.
    Critical,
}

impl std::fmt::Display for ConflictSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConflictSeverity::Info => write!(f, "INFO"),
            ConflictSeverity::Warning => write!(f, "WARNING"),
            ConflictSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// The specific category of contradiction detected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConflictCategory {
    /// Same BSSID mapped to different SSIDs.
    SsidMismatch {
        bssid: String,
        ssid_a: String,
        ssid_b: String,
    },
    /// Same SSID mapped to different BSSIDs (may be legitimate — multi-AP networks).
    BssidMismatch {
        ssid: String,
        bssid_a: String,
        bssid_b: String,
    },
    /// Same network reported with different security protocols.
    SecurityProtocolMismatch {
        network_identifier: String,
        protocol_a: SecurityProtocol,
        protocol_b: SecurityProtocol,
    },
    /// Same event reported with incompatible timestamps (delta exceeds threshold).
    TimestampMismatch {
        event_description: String,
        timestamp_a: DateTime<Utc>,
        timestamp_b: DateTime<Utc>,
        delta_seconds: f64,
    },
    /// Sources disagree on whether the device was a client or hotspot.
    NetworkRoleMismatch {
        network_identifier: String,
        role_a: String,
        role_b: String,
    },
    /// Generic conflict for future extensibility.
    Other {
        description: String,
    },
}

/// A detected conflict between two or more evidence sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conflict {
    /// Unique identifier for this conflict.
    pub id: ConflictId,
    /// The category and details of the contradiction.
    pub category: ConflictCategory,
    /// The severity level for forensic reporting.
    pub severity: ConflictSeverity,
    /// The record from Source A that participates in this conflict.
    pub source_a: ConflictSource,
    /// The record from Source B that participates in this conflict.
    pub source_b: ConflictSource,
    /// Human-readable explanation of the conflict.
    pub explanation: String,
    /// Whether this conflict has been reviewed by an examiner.
    pub examiner_reviewed: bool,
    /// Optional examiner note explaining the resolution.
    pub examiner_note: Option<String>,
    /// When this conflict was detected.
    pub detected_at: DateTime<Utc>,
}

/// Identifies one side of a conflict — the artifact and record that provided the claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictSource {
    /// The artifact from which the conflicting claim originates.
    pub artifact_id: ArtifactId,
    /// The specific record within the artifact.
    pub record_id: RecordId,
    /// Human-readable source description (e.g., "wpa_supplicant.conf", "WifiConfigStore.xml").
    pub source_description: String,
    /// The raw value that was claimed.
    pub claimed_value: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Conflict Report
// ──────────────────────────────────────────────────────────────────────────────

/// A complete conflict analysis report for an investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictReport {
    /// All detected conflicts.
    pub conflicts: Vec<Conflict>,
    /// Summary statistics.
    pub summary: ConflictSummary,
    /// When this report was generated.
    pub generated_at: DateTime<Utc>,
}

/// Summary statistics for a conflict report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictSummary {
    pub total_conflicts: usize,
    pub critical_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub unreviewed_count: usize,
}

// ──────────────────────────────────────────────────────────────────────────────
// Conflict Detector
// ──────────────────────────────────────────────────────────────────────────────

/// Threshold in seconds: timestamp deltas below this are not flagged as conflicts.
const TIMESTAMP_CONFLICT_THRESHOLD_SECS: f64 = 120.0; // 2 minutes

/// Detects contradictions across normalized forensic evidence claims.
///
/// The detector operates on claim pairs — it receives two assertions about
/// the same forensic fact from different sources and determines whether
/// they are consistent, complementary, or contradictory.
pub struct ConflictDetector {
    conflicts: Vec<Conflict>,
}

impl ConflictDetector {
    /// Create a new empty conflict detector.
    pub fn new() -> Self {
        ConflictDetector {
            conflicts: Vec::new(),
        }
    }

    /// Check two SSID claims for the same BSSID.
    ///
    /// If both sources report a different SSID for the same BSSID, a conflict
    /// is recorded. This can happen legitimately when an access point is renamed.
    pub fn check_ssid_for_bssid(
        &mut self,
        bssid: &str,
        ssid_a: &str,
        source_a: ConflictSource,
        ssid_b: &str,
        source_b: ConflictSource,
    ) {
        if ssid_a == ssid_b {
            return;
        }

        let conflict = Conflict {
            id: ConflictId::new(),
            category: ConflictCategory::SsidMismatch {
                bssid: bssid.to_string(),
                ssid_a: ssid_a.to_string(),
                ssid_b: ssid_b.to_string(),
            },
            severity: ConflictSeverity::Warning,
            source_a,
            source_b,
            explanation: format!(
                "BSSID {} is associated with SSID \"{}\" in one source and \"{}\" in another. \
                 This may indicate AP renaming, MAC randomization, or data inconsistency.",
                bssid, ssid_a, ssid_b
            ),
            examiner_reviewed: false,
            examiner_note: None,
            detected_at: Utc::now(),
        };

        self.conflicts.push(conflict);
    }

    /// Check two BSSID claims for the same SSID.
    ///
    /// Multiple BSSIDs for the same SSID are common in enterprise networks
    /// (multi-AP deployments), so this is flagged as Info severity.
    pub fn check_bssid_for_ssid(
        &mut self,
        ssid: &str,
        bssid_a: &str,
        source_a: ConflictSource,
        bssid_b: &str,
        source_b: ConflictSource,
    ) {
        if bssid_a == bssid_b {
            return;
        }

        let conflict = Conflict {
            id: ConflictId::new(),
            category: ConflictCategory::BssidMismatch {
                ssid: ssid.to_string(),
                bssid_a: bssid_a.to_string(),
                bssid_b: bssid_b.to_string(),
            },
            severity: ConflictSeverity::Info,
            source_a,
            source_b,
            explanation: format!(
                "SSID \"{}\" is associated with BSSID {} in one source and {} in another. \
                 This is common in multi-AP enterprise deployments and may not indicate a conflict.",
                ssid, bssid_a, bssid_b
            ),
            examiner_reviewed: false,
            examiner_note: None,
            detected_at: Utc::now(),
        };

        self.conflicts.push(conflict);
    }

    /// Check two security protocol claims for the same network.
    ///
    /// Different sources may report different security protocols due to
    /// format differences (e.g., `wpa_supplicant.conf` vs `WifiConfigStore.xml`).
    pub fn check_security_protocol(
        &mut self,
        network_id: &str,
        proto_a: SecurityProtocol,
        source_a: ConflictSource,
        proto_b: SecurityProtocol,
        source_b: ConflictSource,
    ) {
        if proto_a == proto_b {
            return;
        }

        // Determine severity based on how different the protocols are
        let severity = Self::security_conflict_severity(proto_a, proto_b);

        let conflict = Conflict {
            id: ConflictId::new(),
            category: ConflictCategory::SecurityProtocolMismatch {
                network_identifier: network_id.to_string(),
                protocol_a: proto_a,
                protocol_b: proto_b,
            },
            severity,
            source_a,
            source_b,
            explanation: format!(
                "Network \"{}\" is reported with security protocol {} in one source \
                 and {} in another. {}",
                network_id,
                proto_a,
                proto_b,
                Self::security_conflict_rationale(proto_a, proto_b)
            ),
            examiner_reviewed: false,
            examiner_note: None,
            detected_at: Utc::now(),
        };

        self.conflicts.push(conflict);
    }

    /// Check two timestamp claims for the same event.
    ///
    /// If the timestamps differ by more than `TIMESTAMP_CONFLICT_THRESHOLD_SECS`,
    /// a conflict is flagged. Small deltas are expected due to log buffer timing.
    pub fn check_timestamp(
        &mut self,
        event_desc: &str,
        ts_a: DateTime<Utc>,
        source_a: ConflictSource,
        ts_b: DateTime<Utc>,
        source_b: ConflictSource,
    ) {
        let delta = (ts_a - ts_b).num_milliseconds() as f64 / 1000.0;
        let abs_delta = delta.abs();

        if abs_delta <= TIMESTAMP_CONFLICT_THRESHOLD_SECS {
            return;
        }

        let severity = if abs_delta > 3600.0 {
            ConflictSeverity::Critical
        } else if abs_delta > 300.0 {
            ConflictSeverity::Warning
        } else {
            ConflictSeverity::Info
        };

        let conflict = Conflict {
            id: ConflictId::new(),
            category: ConflictCategory::TimestampMismatch {
                event_description: event_desc.to_string(),
                timestamp_a: ts_a,
                timestamp_b: ts_b,
                delta_seconds: delta,
            },
            severity,
            source_a,
            source_b,
            explanation: format!(
                "Event \"{}\" is timestamped at {} in one source and {} in another \
                 (delta: {:.1}s). {}",
                event_desc,
                ts_a.format("%Y-%m-%dT%H:%M:%SZ"),
                ts_b.format("%Y-%m-%dT%H:%M:%SZ"),
                delta,
                if abs_delta > 3600.0 {
                    "This large discrepancy may indicate clock tampering or a corrupt artifact."
                } else {
                    "This may be due to clock skew or different log buffer flush timing."
                }
            ),
            examiner_reviewed: false,
            examiner_note: None,
            detected_at: Utc::now(),
        };

        self.conflicts.push(conflict);
    }

    /// Check network role claims (client vs hotspot) for the same event window.
    pub fn check_network_role(
        &mut self,
        network_id: &str,
        role_a: &str,
        source_a: ConflictSource,
        role_b: &str,
        source_b: ConflictSource,
    ) {
        if role_a == role_b {
            return;
        }

        let conflict = Conflict {
            id: ConflictId::new(),
            category: ConflictCategory::NetworkRoleMismatch {
                network_identifier: network_id.to_string(),
                role_a: role_a.to_string(),
                role_b: role_b.to_string(),
            },
            severity: ConflictSeverity::Critical,
            source_a,
            source_b,
            explanation: format!(
                "Sources disagree on the device's network role for \"{}\": \
                 one source claims \"{}\" while another claims \"{}\". \
                 This is a critical distinction for forensic findings.",
                network_id, role_a, role_b
            ),
            examiner_reviewed: false,
            examiner_note: None,
            detected_at: Utc::now(),
        };

        self.conflicts.push(conflict);
    }

    /// Generate the final conflict report.
    pub fn generate_report(self) -> ConflictReport {
        let total = self.conflicts.len();
        let critical = self.conflicts.iter()
            .filter(|c| c.severity == ConflictSeverity::Critical)
            .count();
        let warning = self.conflicts.iter()
            .filter(|c| c.severity == ConflictSeverity::Warning)
            .count();
        let info = self.conflicts.iter()
            .filter(|c| c.severity == ConflictSeverity::Info)
            .count();
        let unreviewed = self.conflicts.iter()
            .filter(|c| !c.examiner_reviewed)
            .count();

        ConflictReport {
            conflicts: self.conflicts,
            summary: ConflictSummary {
                total_conflicts: total,
                critical_count: critical,
                warning_count: warning,
                info_count: info,
                unreviewed_count: unreviewed,
            },
            generated_at: Utc::now(),
        }
    }

    /// Return a reference to all currently detected conflicts.
    pub fn conflicts(&self) -> &[Conflict] {
        &self.conflicts
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    /// Determine conflict severity for security protocol mismatches.
    ///
    /// Some mismatches are expected (e.g., WPA-PSK vs WPA2-PSK during transition)
    /// while others indicate real data inconsistency.
    fn security_conflict_severity(a: SecurityProtocol, b: SecurityProtocol) -> ConflictSeverity {
        use SecurityProtocol::*;

        match (a, b) {
            // WPA/WPA2 confusion is very common across different Android versions
            (WpaPsk, Wpa2Psk) | (Wpa2Psk, WpaPsk) => ConflictSeverity::Info,
            // WPA2/WPA3 transition mode is common on modern APs
            (Wpa2Psk, Wpa3Sae) | (Wpa3Sae, Wpa2Psk) => ConflictSeverity::Info,
            // Unknown to anything else is just a normalization gap
            (Unknown, _) | (_, Unknown) => ConflictSeverity::Info,
            // Open vs encrypted is a significant conflict
            (Open, _) | (_, Open) => ConflictSeverity::Critical,
            // Everything else is a warning
            _ => ConflictSeverity::Warning,
        }
    }

    /// Provide a forensic rationale for a security protocol mismatch.
    fn security_conflict_rationale(a: SecurityProtocol, b: SecurityProtocol) -> &'static str {
        use SecurityProtocol::*;

        match (a, b) {
            (WpaPsk, Wpa2Psk) | (Wpa2Psk, WpaPsk) =>
                "WPA/WPA2 confusion is common — older Android versions may report WPA \
                 for networks that also support WPA2.",
            (Wpa2Psk, Wpa3Sae) | (Wpa3Sae, Wpa2Psk) =>
                "WPA2/WPA3 transition mode is common on modern access points that \
                 support both protocols simultaneously.",
            (Open, _) | (_, Open) =>
                "A mismatch between Open and encrypted is forensically significant \
                 and requires examiner review.",
            _ =>
                "This mismatch requires examiner review to determine the cause.",
        }
    }
}

impl Default for ConflictDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_core::types::{ArtifactId, RecordId};

    fn make_source(desc: &str, value: &str) -> ConflictSource {
        ConflictSource {
            artifact_id: ArtifactId::new(),
            record_id: RecordId::new(),
            source_description: desc.to_string(),
            claimed_value: value.to_string(),
        }
    }

    // ── SSID Conflict Tests ─────────────────────────────────────────────

    #[test]
    fn test_ssid_conflict_detected() {
        let mut detector = ConflictDetector::new();
        detector.check_ssid_for_bssid(
            "AA:BB:CC:DD:EE:FF",
            "HomeNetwork",
            make_source("wpa_supplicant.conf", "HomeNetwork"),
            "Home_Network_5G",
            make_source("WifiConfigStore.xml", "Home_Network_5G"),
        );
        assert_eq!(detector.conflicts().len(), 1);
        assert_eq!(detector.conflicts()[0].severity, ConflictSeverity::Warning);
    }

    #[test]
    fn test_ssid_no_conflict_when_same() {
        let mut detector = ConflictDetector::new();
        detector.check_ssid_for_bssid(
            "AA:BB:CC:DD:EE:FF",
            "HomeNetwork",
            make_source("wpa_supplicant.conf", "HomeNetwork"),
            "HomeNetwork",
            make_source("WifiConfigStore.xml", "HomeNetwork"),
        );
        assert!(detector.conflicts().is_empty());
    }

    // ── BSSID Conflict Tests ────────────────────────────────────────────

    #[test]
    fn test_bssid_conflict_info_severity() {
        let mut detector = ConflictDetector::new();
        detector.check_bssid_for_ssid(
            "CorporateWifi",
            "AA:BB:CC:DD:EE:F0",
            make_source("wpa_supplicant.conf", "AA:BB:CC:DD:EE:F0"),
            "AA:BB:CC:DD:EE:F1",
            make_source("WifiConfigStore.xml", "AA:BB:CC:DD:EE:F1"),
        );
        assert_eq!(detector.conflicts().len(), 1);
        // Multi-AP is common; should be Info, not Warning
        assert_eq!(detector.conflicts()[0].severity, ConflictSeverity::Info);
    }

    // ── Security Protocol Conflict Tests ────────────────────────────────

    #[test]
    fn test_security_wpa_wpa2_is_info() {
        let mut detector = ConflictDetector::new();
        detector.check_security_protocol(
            "TestNetwork",
            SecurityProtocol::WpaPsk,
            make_source("wpa_supplicant.conf", "WPA-PSK"),
            SecurityProtocol::Wpa2Psk,
            make_source("WifiConfigStore.xml", "WPA2-PSK"),
        );
        assert_eq!(detector.conflicts().len(), 1);
        assert_eq!(detector.conflicts()[0].severity, ConflictSeverity::Info);
    }

    #[test]
    fn test_security_open_vs_encrypted_is_critical() {
        let mut detector = ConflictDetector::new();
        detector.check_security_protocol(
            "SuspiciousNetwork",
            SecurityProtocol::Open,
            make_source("wpa_supplicant.conf", "NONE"),
            SecurityProtocol::Wpa2Psk,
            make_source("WifiConfigStore.xml", "WPA2-PSK"),
        );
        assert_eq!(detector.conflicts().len(), 1);
        assert_eq!(detector.conflicts()[0].severity, ConflictSeverity::Critical);
    }

    #[test]
    fn test_security_no_conflict_when_same() {
        let mut detector = ConflictDetector::new();
        detector.check_security_protocol(
            "TestNetwork",
            SecurityProtocol::Wpa2Psk,
            make_source("source_a", "WPA2-PSK"),
            SecurityProtocol::Wpa2Psk,
            make_source("source_b", "WPA2-PSK"),
        );
        assert!(detector.conflicts().is_empty());
    }

    // ── Timestamp Conflict Tests ────────────────────────────────────────

    #[test]
    fn test_timestamp_small_delta_no_conflict() {
        let mut detector = ConflictDetector::new();
        let ts_a = Utc::now();
        let ts_b = ts_a + chrono::Duration::seconds(60); // 60s < 120s threshold
        detector.check_timestamp(
            "wifi_connect",
            ts_a,
            make_source("logcat", &ts_a.to_string()),
            ts_b,
            make_source("connectivity_log", &ts_b.to_string()),
        );
        assert!(detector.conflicts().is_empty());
    }

    #[test]
    fn test_timestamp_large_delta_is_critical() {
        let mut detector = ConflictDetector::new();
        let ts_a = Utc::now();
        let ts_b = ts_a + chrono::Duration::hours(2); // 7200s > 3600s critical threshold
        detector.check_timestamp(
            "wifi_connect",
            ts_a,
            make_source("logcat", &ts_a.to_string()),
            ts_b,
            make_source("connectivity_log", &ts_b.to_string()),
        );
        assert_eq!(detector.conflicts().len(), 1);
        assert_eq!(detector.conflicts()[0].severity, ConflictSeverity::Critical);
    }

    #[test]
    fn test_timestamp_medium_delta_is_warning() {
        let mut detector = ConflictDetector::new();
        let ts_a = Utc::now();
        let ts_b = ts_a + chrono::Duration::seconds(600); // 10 minutes, > 300s threshold
        detector.check_timestamp(
            "wifi_connect",
            ts_a,
            make_source("logcat", &ts_a.to_string()),
            ts_b,
            make_source("connectivity_log", &ts_b.to_string()),
        );
        assert_eq!(detector.conflicts().len(), 1);
        assert_eq!(detector.conflicts()[0].severity, ConflictSeverity::Warning);
    }

    // ── Network Role Conflict Tests ─────────────────────────────────────

    #[test]
    fn test_network_role_conflict_is_critical() {
        let mut detector = ConflictDetector::new();
        detector.check_network_role(
            "TestNetwork",
            "client",
            make_source("wpa_supplicant.conf", "client"),
            "hotspot",
            make_source("hostapd.conf", "hotspot"),
        );
        assert_eq!(detector.conflicts().len(), 1);
        assert_eq!(detector.conflicts()[0].severity, ConflictSeverity::Critical);
    }

    // ── Report Generation Tests ─────────────────────────────────────────

    #[test]
    fn test_empty_report() {
        let detector = ConflictDetector::new();
        let report = detector.generate_report();
        assert_eq!(report.summary.total_conflicts, 0);
        assert_eq!(report.summary.critical_count, 0);
        assert_eq!(report.summary.warning_count, 0);
        assert_eq!(report.summary.info_count, 0);
    }

    #[test]
    fn test_report_summary_counts() {
        let mut detector = ConflictDetector::new();

        // Add one of each severity
        detector.check_security_protocol(
            "Net1",
            SecurityProtocol::Open,
            make_source("a", "Open"),
            SecurityProtocol::Wpa2Psk,
            make_source("b", "WPA2"),
        ); // Critical

        detector.check_ssid_for_bssid(
            "AA:BB:CC:DD:EE:FF",
            "SSID_A",
            make_source("a", "SSID_A"),
            "SSID_B",
            make_source("b", "SSID_B"),
        ); // Warning

        detector.check_bssid_for_ssid(
            "CorpNet",
            "11:22:33:44:55:66",
            make_source("a", "11:22:33:44:55:66"),
            "11:22:33:44:55:67",
            make_source("b", "11:22:33:44:55:67"),
        ); // Info

        let report = detector.generate_report();
        assert_eq!(report.summary.total_conflicts, 3);
        assert_eq!(report.summary.critical_count, 1);
        assert_eq!(report.summary.warning_count, 1);
        assert_eq!(report.summary.info_count, 1);
        assert_eq!(report.summary.unreviewed_count, 3);
    }
}
