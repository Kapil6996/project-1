//! # Parser Trait Definitions
//!
//! Core trait and data structures for ORACLE artifact parsers.
//! All parsers — built-in and plugin — must implement [`ArtifactParser`].
//!
//! The parser subsystem is designed around three principles:
//! 1. **Stateless transformation** — parsers receive raw bytes and produce structured records.
//! 2. **Provenance preservation** — every output carries byte offsets back to source data.
//! 3. **Confidence annotation** — every record carries a parser-assigned confidence score.

use oracle_core::{ArtifactClass, ArtifactId, OracleResult};
use serde::{Deserialize, Serialize};

/// Metadata describing a parser's identity and capabilities.
///
/// Every registered parser exposes a `ParserInfo` via [`ArtifactParser::info`].
/// The registry uses this metadata for dispatch and audit logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParserInfo {
    /// Unique identifier for this parser (e.g., `"oracle.wifi_config_store"`).
    pub parser_id: String,
    /// Semantic version of the parser implementation (e.g., `"1.0.0"`).
    pub parser_version: String,
    /// The set of [`ArtifactClass`] variants this parser can handle.
    pub supported_classes: Vec<ArtifactClass>,
    /// Human-readable description of what this parser does.
    pub description: String,
}

/// A single parsed output record produced by a parser.
///
/// Each `ParsedOutput` represents one logical record extracted from
/// a raw artifact. The `record_data` field carries the structured
/// payload as a JSON value, allowing flexible schema evolution
/// without breaking downstream consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedOutput {
    /// The type of record (e.g., `"wifi_configured_network"`, `"dhcp_lease"`).
    pub record_type: String,
    /// Structured record payload as a JSON value.
    pub record_data: serde_json::Value,
    /// Byte offset within the source artifact where this record's source data begins.
    pub byte_offset: Option<u64>,
    /// Byte length of the source data for this record within the artifact.
    pub byte_length: Option<u64>,
    /// Parser confidence in this record's accuracy (0.0 to 1.0).
    ///
    /// This value is typically set to the artifact class's baseline reliability
    /// but may be adjusted downward if the parser encounters ambiguity.
    pub confidence: f64,
}

/// The core parser trait that all ORACLE artifact parsers must implement.
///
/// Parsers are stateless transformation functions: given raw bytes and
/// an artifact identity, they produce a vector of structured records.
/// The registry dispatches to parsers based on [`ArtifactClass`].
///
/// # Implementor Contract
///
/// - Parsers **must not panic** on malformed input. Return an appropriate
///   [`OracleError`](oracle_core::OracleError) variant instead.
/// - Parsers **must not** use `unwrap()` or `expect()` on fallible operations.
/// - Every output record **must** have `confidence` in the range `[0.0, 1.0]`.
/// - Byte offsets, when provided, **must** reference valid ranges in `raw_bytes`.
pub trait ArtifactParser: Send + Sync {
    /// Returns metadata about this parser.
    fn info(&self) -> ParserInfo;

    /// Returns `true` if this parser can handle the given artifact class.
    fn can_parse(&self, class: ArtifactClass) -> bool;

    /// Parse the raw artifact bytes and produce structured output records.
    ///
    /// # Arguments
    ///
    /// * `artifact_id` — The unique identifier assigned to this artifact.
    /// * `artifact_hash` — The SHA-256 hash of the raw bytes at ingestion time.
    /// * `raw_bytes` — The raw artifact content to parse.
    ///
    /// # Errors
    ///
    /// * [`OracleError::ParserIncompatible`](oracle_core::OracleError::ParserIncompatible)
    ///   if the artifact class is not supported by this parser.
    /// * [`OracleError::ArtifactCorrupted`](oracle_core::OracleError::ArtifactCorrupted)
    ///   if the data is malformed beyond recovery.
    fn parse(
        &self,
        artifact_id: ArtifactId,
        artifact_hash: &str,
        raw_bytes: &[u8],
    ) -> OracleResult<Vec<ParsedOutput>>;
}
