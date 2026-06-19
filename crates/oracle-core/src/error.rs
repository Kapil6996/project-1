//! # Core Error Types
//!
//! Defines the canonical error hierarchy for the ORACLE platform.
//! Every subsystem propagates errors through these types to ensure
//! consistent error handling and audit logging across the platform.

use thiserror::Error;
use std::path::PathBuf;
use uuid::Uuid;

/// The result type used throughout the ORACLE platform.
pub type OracleResult<T> = Result<T, OracleError>;

/// Top-level error type for the ORACLE forensic platform.
///
/// Every error variant carries sufficient context to produce a meaningful
/// audit log entry and a forensically defensible error report.
#[derive(Error, Debug)]
pub enum OracleError {
    // ── Audit and Chain of Custody Errors ──────────────────────────────

    /// The cryptographic chain in the audit log is broken.
    /// This indicates tampering or corruption and is a forensic integrity violation.
    #[error("Audit chain integrity violation at entry {entry_index}: expected hash {expected}, found {found}")]
    AuditChainBroken {
        entry_index: u64,
        expected: String,
        found: String,
    },

    /// An audit log write failed. The operation it was meant to record
    /// must NOT proceed — write-before-execute semantics are mandatory.
    #[error("Audit log write failed: {reason}")]
    AuditWriteFailed { reason: String },

    /// An incomplete audit entry was detected on startup, indicating
    /// a process crash between intent logging and result logging.
    #[error("Incomplete audit entry detected at index {entry_index}: {description}")]
    AuditEntryIncomplete {
        entry_index: u64,
        description: String,
    },

    // ── Evidence Store Errors ──────────────────────────────────────────

    /// Attempted to modify an existing evidence record.
    /// The evidence store is strictly append-only.
    #[error("Forensic integrity violation: attempted to modify existing record {record_id}")]
    EvidenceModificationAttempt { record_id: Uuid },

    /// An artifact's hash at retrieval does not match its hash at storage.
    /// This indicates corruption or tampering of stored evidence.
    #[error("Evidence integrity violation: artifact {artifact_id} hash mismatch — stored: {stored_hash}, computed: {computed_hash}")]
    EvidenceHashMismatch {
        artifact_id: Uuid,
        stored_hash: String,
        computed_hash: String,
    },

    /// The evidence store is in an inconsistent state and cannot be used.
    #[error("Evidence store integrity check failed: {reason}")]
    EvidenceStoreCorrupted { reason: String },

    /// The provenance chain for a record is broken or incomplete.
    #[error("Provenance chain broken for record {record_id}: {reason}")]
    ProvenanceChainBroken { record_id: Uuid, reason: String },

    // ── Device and Capability Errors ───────────────────────────────────

    /// No Android device is connected or detectable.
    #[error("No Android device detected on any transport")]
    NoDeviceDetected,

    /// Multiple devices are connected and no target was specified.
    #[error("Multiple devices detected ({count}). Specify target device serial.")]
    MultipleDevicesDetected { count: usize },

    /// The connected device has not authorized this host for ADB access.
    #[error("Device {serial} is not authorized for ADB. Accept the RSA key prompt on the device.")]
    DeviceUnauthorized { serial: String },

    /// The device is connected but offline (e.g., in sideload mode or recovery).
    #[error("Device {serial} is in offline state: {state}")]
    DeviceOffline { serial: String, state: String },

    /// An ADB command failed during capability detection or acquisition.
    #[error("ADB command failed on device {serial}: {command} — {reason}")]
    AdbCommandFailed {
        serial: String,
        command: String,
        reason: String,
    },

    /// A capability was assumed by a downstream module but was not confirmed
    /// by the Capability Detection Engine.
    #[error("Capability not confirmed: {capability}. The CDE profile does not grant this access.")]
    CapabilityNotConfirmed { capability: String },

    // ── Parser Errors ──────────────────────────────────────────────────

    /// A parser encountered an artifact format it cannot handle.
    #[error("Parser {parser_id} cannot parse artifact {artifact_id}: {reason}")]
    ParserIncompatible {
        parser_id: String,
        artifact_id: Uuid,
        reason: String,
    },

    /// A parser produced output that failed schema validation.
    #[error("Parser {parser_id} produced invalid output for artifact {artifact_id}: {reason}")]
    ParserOutputInvalid {
        parser_id: String,
        artifact_id: Uuid,
        reason: String,
    },

    /// An artifact file is corrupted or truncated beyond recovery.
    #[error("Artifact {artifact_id} is corrupted: {reason}")]
    ArtifactCorrupted { artifact_id: Uuid, reason: String },

    // ── Plugin Errors ──────────────────────────────────────────────────

    /// A plugin failed validation and cannot be loaded.
    #[error("Plugin {plugin_id} failed validation: {reason}")]
    PluginValidationFailed { plugin_id: String, reason: String },

    /// A required plugin is missing.
    #[error("Required plugin {plugin_id} version {required_version} is not installed")]
    PluginMissing {
        plugin_id: String,
        required_version: String,
    },

    // ── Configuration Errors ───────────────────────────────────────────

    /// The configuration file is missing or unreadable.
    #[error("Configuration error: {reason}")]
    ConfigurationError { reason: String },

    // ── I/O and Infrastructure Errors ──────────────────────────────────

    /// A filesystem operation failed.
    #[error("Filesystem I/O error at path {}: {source}", path.display())]
    IoError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// A database operation failed.
    #[error("Database error: {reason}")]
    DatabaseError { reason: String },

    /// A serialization or deserialization operation failed.
    #[error("Serialization error: {reason}")]
    SerializationError { reason: String },
}

impl From<std::io::Error> for OracleError {
    fn from(err: std::io::Error) -> Self {
        OracleError::IoError {
            path: PathBuf::from("<unknown>"),
            source: err,
        }
    }
}

impl From<serde_json::Error> for OracleError {
    fn from(err: serde_json::Error) -> Self {
        OracleError::SerializationError {
            reason: err.to_string(),
        }
    }
}

impl From<rusqlite::Error> for OracleError {
    fn from(err: rusqlite::Error) -> Self {
        OracleError::DatabaseError {
            reason: err.to_string(),
        }
    }
}
