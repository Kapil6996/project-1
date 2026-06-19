//! # Core Types
//!
//! Canonical data structures shared across all ORACLE subsystems.
//!
//! These types form the forensic ontology of the platform. Every subsystem
//! that stores, transmits, or processes evidence records must use these
//! exact types to ensure provenance traceability and cross-module consistency.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ──────────────────────────────────────────────────────────────────────────────
// Investigation Identity
// ──────────────────────────────────────────────────────────────────────────────

/// A unique investigation identifier generated at case creation time.
/// Every artifact, record, and audit entry references its parent investigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InvestigationId(pub Uuid);

impl InvestigationId {
    /// Generate a new unique investigation identifier.
    pub fn new() -> Self {
        InvestigationId(Uuid::new_v4())
    }
}

impl Default for InvestigationId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for InvestigationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A unique artifact identifier assigned when an artifact is ingested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactId(pub Uuid);

impl ArtifactId {
    pub fn new() -> Self {
        ArtifactId(Uuid::new_v4())
    }
}

impl Default for ArtifactId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A unique record identifier for any evidence record (parsed, normalized, or correlated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecordId(pub Uuid);

impl RecordId {
    pub fn new() -> Self {
        RecordId(Uuid::new_v4())
    }
}

impl Default for RecordId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RecordId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Examiner Identity
// ──────────────────────────────────────────────────────────────────────────────

/// Identifies the forensic examiner operating the platform.
/// Recorded in every audit log entry and chain of custody record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExaminerIdentity {
    /// Full legal name of the examiner.
    pub name: String,
    /// Badge number or employee identifier within the forensic lab.
    pub badge_id: String,
    /// The forensic laboratory or agency name.
    pub organization: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Device Identity
// ──────────────────────────────────────────────────────────────────────────────

/// Complete identity profile of the target Android device.
/// Populated by the Capability Detection Engine before any acquisition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// Device serial number (from `ro.serialno` or ADB).
    pub serial: String,
    /// OEM manufacturer (e.g., "samsung", "Google", "Xiaomi").
    pub manufacturer: String,
    /// Device model (e.g., "SM-S928B", "Pixel 8 Pro").
    pub model: String,
    /// Android version string (e.g., "14").
    pub android_version: String,
    /// API level (e.g., 34).
    pub api_level: u32,
    /// Security patch level (e.g., "2024-12-01").
    pub security_patch_level: String,
    /// Build fingerprint — uniquely identifies the exact firmware build.
    pub build_fingerprint: String,
    /// OEM skin name if detectable (e.g., "One UI", "HyperOS").
    pub oem_skin: Option<String>,
    /// OEM skin version if detectable.
    pub oem_skin_version: Option<String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Capability Profile
// ──────────────────────────────────────────────────────────────────────────────

/// The root access method detected on the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RootMethod {
    /// No root access available.
    None,
    /// Magisk systemless root detected.
    Magisk,
    /// Traditional system-level su binary detected.
    SystemRoot,
    /// ADB daemon running as root (engineering build or `adb root` success).
    AdbRoot,
    /// KernelSU detected.
    KernelSU,
}

/// SELinux enforcement mode on the target device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelinuxMode {
    Enforcing,
    Permissive,
    Disabled,
    Unknown,
}

/// Bootloader lock state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootloaderState {
    Locked,
    Unlocked,
    Tampered,
    Unknown,
}

/// File-Based Encryption (FBE) device state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionState {
    /// Before First Unlock — CE keys are evicted. Only DE storage is accessible.
    BeforeFirstUnlock,
    /// After First Unlock — CE keys are loaded. Full access if privileged.
    AfterFirstUnlock,
    /// Legacy Full Disk Encryption (pre-Android 10).
    FullDiskEncryption,
    /// Encryption state could not be determined.
    Unknown,
}

/// The acquisition method available for the device given its current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AcquisitionMethod {
    /// Full filesystem extraction via rooted ADB shell.
    PrivilegedLogical,
    /// ADB backup-based extraction (limited scope).
    AdbBackup,
    /// Shell-user level extraction via `run-as` or accessible paths.
    UnprivilegedLogical,
    /// Content provider queries via instrumentation.
    ContentProvider,
    /// Static/offline image analysis (no live device required).
    OfflineImage,
}

/// The complete capability profile generated by the Capability Detection Engine.
///
/// Every downstream subsystem receives this profile and adapts its behavior
/// to only request operations that the profile confirms are possible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityProfile {
    /// The device identity.
    pub device: DeviceIdentity,
    /// Whether USB debugging is enabled.
    pub usb_debugging_enabled: bool,
    /// Whether ADB is authorized.
    pub adb_authorized: bool,
    /// Root availability and method.
    pub root_method: RootMethod,
    /// SELinux mode.
    pub selinux_mode: SelinuxMode,
    /// Bootloader lock state.
    pub bootloader_state: BootloaderState,
    /// FBE encryption state.
    pub encryption_state: EncryptionState,
    /// Acquisition methods available given the detected state.
    pub available_methods: Vec<AcquisitionMethod>,
    /// Artifact classes accessible under each method.
    pub accessible_artifact_classes: Vec<AccessibleArtifactClass>,
    /// Artifact classes that are inaccessible and the reason why.
    pub inaccessible_artifact_classes: Vec<InaccessibleArtifactClass>,
    /// Timestamp of capability detection.
    pub detected_at: DateTime<Utc>,
    /// Whether the investigator has acknowledged this profile.
    pub acknowledged: bool,
}

/// An artifact class that is accessible under a given acquisition method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessibleArtifactClass {
    pub artifact_class: ArtifactClass,
    pub acquisition_method: AcquisitionMethod,
    pub confidence: f64,
}

/// An artifact class that is inaccessible, with forensic justification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InaccessibleArtifactClass {
    pub artifact_class: ArtifactClass,
    pub reason: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Artifact Classification
// ──────────────────────────────────────────────────────────────────────────────

/// Classification of forensic artifact types recognized by the platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactClass {
    /// WPA supplicant configuration (known networks).
    WpaSupplicant,
    /// WifiConfigStore XML (Android 8+).
    WifiConfigStore,
    /// DHCP lease records.
    DhcpLeases,
    /// Battery statistics with network correlation.
    BatteryStats,
    /// System connectivity logs.
    ConnectivityLogs,
    /// Kernel dmesg network events.
    KernelLogs,
    /// Hostapd (hotspot) configuration and logs.
    HostapdLogs,
    /// DNS resolver cache.
    DnsCache,
    /// Network policy data.
    NetworkPolicy,
    /// Build properties (device identity).
    BuildProp,
    /// Unknown or unclassified artifact.
    Unknown,
}

impl ArtifactClass {
    /// Returns the baseline reliability score for this artifact class.
    ///
    /// These values are constants defined by the Confidence Model v1.0
    /// and are documented in the forensic methodology disclosure.
    pub fn baseline_reliability(&self) -> f64 {
        match self {
            ArtifactClass::KernelLogs => 0.99,
            ArtifactClass::WifiConfigStore => 0.95,
            ArtifactClass::WpaSupplicant => 0.90,
            ArtifactClass::DhcpLeases => 0.92,
            ArtifactClass::ConnectivityLogs => 0.85,
            ArtifactClass::BatteryStats => 0.80,
            ArtifactClass::HostapdLogs => 0.88,
            ArtifactClass::DnsCache => 0.70,
            ArtifactClass::NetworkPolicy => 0.85,
            ArtifactClass::BuildProp => 0.99,
            ArtifactClass::Unknown => 0.30,
        }
    }
}

/// The volatility classification of an artifact.
/// Volatile artifacts are cleared on reboot or under memory pressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VolatilityClass {
    /// Persistent — survives reboot (e.g., configuration files).
    Persistent,
    /// Semi-volatile — survives reboot but may be rotated (e.g., log files).
    SemiVolatile,
    /// Volatile — lost on reboot (e.g., kernel ring buffer, RAM caches).
    Volatile,
}

// ──────────────────────────────────────────────────────────────────────────────
// Evidence Records
// ──────────────────────────────────────────────────────────────────────────────

/// The provenance of a piece of evidence, linking it back to its
/// exact source bytes in the original artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceReference {
    /// The artifact from which this record was extracted.
    pub artifact_id: ArtifactId,
    /// The SHA-256 hash of the source artifact at time of parsing.
    pub artifact_hash: String,
    /// The parser that produced this record.
    pub parser_id: String,
    /// The exact version of the parser.
    pub parser_version: String,
    /// Byte offset within the artifact where this record's source data begins.
    pub byte_offset: Option<u64>,
    /// Byte length of the source data for this record.
    pub byte_length: Option<u64>,
    /// Database row ID if the artifact is a SQLite database.
    pub db_row_id: Option<i64>,
    /// Timestamp when this parsing occurred.
    pub parsed_at: DateTime<Utc>,
}

/// Wi-Fi security protocol taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityProtocol {
    Open,
    Wep,
    WpaPsk,
    Wpa2Psk,
    Wpa3Sae,
    Owe,
    EapPeap,
    EapTls,
    Unknown,
}

impl std::fmt::Display for SecurityProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityProtocol::Open => write!(f, "OPEN"),
            SecurityProtocol::Wep => write!(f, "WEP"),
            SecurityProtocol::WpaPsk => write!(f, "WPA-PSK"),
            SecurityProtocol::Wpa2Psk => write!(f, "WPA2-PSK"),
            SecurityProtocol::Wpa3Sae => write!(f, "WPA3-SAE"),
            SecurityProtocol::Owe => write!(f, "OWE"),
            SecurityProtocol::EapPeap => write!(f, "EAP-PEAP"),
            SecurityProtocol::EapTls => write!(f, "EAP-TLS"),
            SecurityProtocol::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Anomaly flags for timestamps that require forensic attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimestampAnomaly {
    /// No anomaly detected.
    None,
    /// Timestamp is in the future relative to acquisition time.
    Future,
    /// Timestamp is Unix epoch zero (1970-01-01T00:00:00Z).
    EpochDefault,
    /// Timestamp predates the Android OS (before 2008).
    PreAndroidEra,
    /// Timestamp matches a known OEM default date.
    OemDefault,
    /// Clock skew detected between device time and acquisition time.
    ClockSkewDetected,
    /// Timestamp format could not be reliably determined.
    FormatAmbiguous,
}

/// A forensic timestamp carrying both the raw and normalized values
/// along with provenance and anomaly metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForensicTimestamp {
    /// The raw timestamp value exactly as extracted from the artifact.
    pub raw_value: String,
    /// The format of the raw timestamp (e.g., "unix_epoch_ms", "iso8601").
    pub source_format: String,
    /// The normalized UTC timestamp.
    pub normalized_utc: DateTime<Utc>,
    /// Any detected clock skew compensation applied (in seconds).
    pub clock_skew_compensation_secs: Option<f64>,
    /// Anomaly classification for this timestamp.
    pub anomaly: TimestampAnomaly,
    /// Confidence in this timestamp's accuracy (0.0 to 1.0).
    pub confidence: f64,
}

/// The evidence layer classification, tracking the processing stage of each record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceLayer {
    /// Layer 0: Raw bytes, exactly as acquired.
    Raw,
    /// Layer 1: Parsed records, untransformed structured data.
    Parsed,
    /// Layer 2: Normalized records, cleaned and unified.
    Normalized,
    /// Layer 3: Correlated records, derived conclusions.
    Correlated,
}

/// Whether the device was acting as a Wi-Fi client or a hotspot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkRole {
    /// Device connected to an external Wi-Fi network.
    DeviceAsClient,
    /// Device operating as a mobile hotspot / access point.
    DeviceAsHotspot,
    /// Insufficient evidence to classify.
    Ambiguous,
}

/// Confidence classification for court presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConfidenceClassification {
    /// Score ≥ 0.95 — supported by multiple independent sources with no contradictions.
    Definitive,
    /// Score 0.80–0.94 — strong evidence with minor gaps.
    High,
    /// Score 0.50–0.79 — moderate evidence, some uncertainty.
    Moderate,
    /// Score < 0.50 — weak evidence, significant gaps or contradictions.
    Low,
    /// Active contradictions exist for this finding.
    Contradicted,
}

impl ConfidenceClassification {
    /// Derive the classification from a numeric score.
    pub fn from_score(score: f64) -> Self {
        if score >= 0.95 {
            ConfidenceClassification::Definitive
        } else if score >= 0.80 {
            ConfidenceClassification::High
        } else if score >= 0.50 {
            ConfidenceClassification::Moderate
        } else {
            ConfidenceClassification::Low
        }
    }
}

impl std::fmt::Display for ConfidenceClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfidenceClassification::Definitive => write!(f, "DEFINITIVE"),
            ConfidenceClassification::High => write!(f, "HIGH"),
            ConfidenceClassification::Moderate => write!(f, "MODERATE"),
            ConfidenceClassification::Low => write!(f, "LOW"),
            ConfidenceClassification::Contradicted => write!(f, "CONTRADICTED"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Audit Types
// ──────────────────────────────────────────────────────────────────────────────

/// Classification of operations recorded in the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOperationType {
    // ── Investigation Lifecycle ──
    InvestigationCreated,
    InvestigationOpened,
    InvestigationClosed,

    // ── Device Operations ──
    DeviceConnected,
    DeviceDisconnected,
    CapabilityDetectionStarted,
    CapabilityDetectionCompleted,
    CapabilityProfileAcknowledged,

    // ── Acquisition ──
    ArtifactAcquisitionStarted,
    ArtifactAcquisitionCompleted,
    ArtifactAcquisitionFailed,

    // ── Parsing ──
    ParserExecutionStarted,
    ParserExecutionCompleted,
    ParserExecutionFailed,

    // ── Normalization ──
    NormalizationStarted,
    NormalizationCompleted,

    // ── Correlation ──
    CorrelationStarted,
    CorrelationCompleted,

    // ── Confidence ──
    ConfidenceScoreComputed,

    // ── Examiner Actions ──
    ExaminerOverrideApplied,
    ExaminerNoteAdded,

    // ── Report ──
    ReportGenerationStarted,
    ReportGenerationCompleted,
    ReportExported,

    // ── Evidence Store ──
    EvidenceStoreCreated,
    EvidenceStoreVerified,
    EvidenceIntegrityViolation,

    // ── Plugin ──
    PluginLoaded,
    PluginValidationFailed,

    // ── System Events ──
    SystemStartup,
    SystemShutdown,
    SystemCrashRecovery,
    AuditChainVerified,

    // ── Catch-all for extensibility ──
    Custom(String),
}

/// The result status of an audited operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditResult {
    /// The operation completed successfully.
    Success,
    /// The operation failed with an error.
    Failure(String),
    /// The operation was started but not yet completed (intent log).
    Pending,
    /// The operation was skipped (e.g., artifact already exists).
    Skipped(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_classification_boundaries() {
        assert_eq!(ConfidenceClassification::from_score(1.0), ConfidenceClassification::Definitive);
        assert_eq!(ConfidenceClassification::from_score(0.95), ConfidenceClassification::Definitive);
        assert_eq!(ConfidenceClassification::from_score(0.94), ConfidenceClassification::High);
        assert_eq!(ConfidenceClassification::from_score(0.80), ConfidenceClassification::High);
        assert_eq!(ConfidenceClassification::from_score(0.79), ConfidenceClassification::Moderate);
        assert_eq!(ConfidenceClassification::from_score(0.50), ConfidenceClassification::Moderate);
        assert_eq!(ConfidenceClassification::from_score(0.49), ConfidenceClassification::Low);
        assert_eq!(ConfidenceClassification::from_score(0.0), ConfidenceClassification::Low);
    }

    #[test]
    fn test_artifact_class_baseline_reliability() {
        assert_eq!(ArtifactClass::KernelLogs.baseline_reliability(), 0.99);
        assert_eq!(ArtifactClass::Unknown.baseline_reliability(), 0.30);
        // Ensure all classes return a value in [0, 1]
        let all_classes = [
            ArtifactClass::WpaSupplicant, ArtifactClass::WifiConfigStore,
            ArtifactClass::DhcpLeases, ArtifactClass::BatteryStats,
            ArtifactClass::ConnectivityLogs, ArtifactClass::KernelLogs,
            ArtifactClass::HostapdLogs, ArtifactClass::DnsCache,
            ArtifactClass::NetworkPolicy, ArtifactClass::BuildProp,
            ArtifactClass::Unknown,
        ];
        for class in &all_classes {
            let score = class.baseline_reliability();
            assert!(score >= 0.0 && score <= 1.0, "{:?} has invalid baseline: {}", class, score);
        }
    }

    #[test]
    fn test_investigation_id_uniqueness() {
        let id1 = InvestigationId::new();
        let id2 = InvestigationId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_security_protocol_display() {
        assert_eq!(format!("{}", SecurityProtocol::Wpa2Psk), "WPA2-PSK");
        assert_eq!(format!("{}", SecurityProtocol::Open), "OPEN");
    }
}
