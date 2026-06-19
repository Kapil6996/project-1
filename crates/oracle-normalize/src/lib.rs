//! # ORACLE Evidence Normalization Layer
//!
//! Standardizes forensic artifacts from heterogeneous sources into canonical
//! formats for downstream correlation and reporting.
//!
//! Different Android versions, OEMs, and artifact types represent the same
//! forensic concepts (timestamps, network identifiers, location data) in
//! wildly different formats. The normalization layer transforms all parsed
//! artifacts into ORACLE's canonical types to enable cross-source correlation.
//!
//! # Modules
//!
//! - [`ssid`] — SSID normalization (quoted, hex-encoded, Unicode escapes).
//! - [`bssid`] — BSSID/MAC address normalization and validation.
//! - [`timestamp`] — Timestamp normalization across formats and timezones.
//! - [`security`] — Wi-Fi security protocol normalization.
//! - [`conflict`] — Cross-source conflict detection and reporting.
//! - [`provenance`] — Provenance chain validation for evidence integrity.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────┐  ┌────────────┐  ┌──────────────┐  ┌────────────────┐
//! │   SSID     │  │   BSSID    │  │  Timestamp   │  │   Security     │
//! │ Normalizer │  │ Normalizer │  │  Normalizer  │  │  Normalizer    │
//! └─────┬──────┘  └─────┬──────┘  └──────┬───────┘  └───────┬────────┘
//!       │               │                │                   │
//!       └───────────────┴────────┬───────┴───────────────────┘
//!                                │
//!                     ┌──────────▼──────────┐
//!                     │  Conflict Detector  │
//!                     └──────────┬──────────┘
//!                                │
//!                     ┌──────────▼──────────┐
//!                     │ Provenance Validator │
//!                     └─────────────────────┘
//! ```

pub mod ssid;
pub mod bssid;
pub mod timestamp;
pub mod security;
pub mod conflict;
pub mod provenance;

// Re-export primary types for ergonomic downstream usage.
pub use ssid::{NormalizedSsid, SsidEncoding, SsidNormalizer};
pub use bssid::{BssidNormalizer, NormalizedBssid};
pub use timestamp::TimestampNormalizer;
pub use security::SecurityNormalizer;
pub use conflict::{
    Conflict, ConflictCategory, ConflictDetector, ConflictId, ConflictReport,
    ConflictSeverity, ConflictSource, ConflictSummary,
};
pub use provenance::{
    ProvenanceLink, ProvenanceReport, ProvenanceSummary, ProvenanceValidator,
    ValidationFinding, ValidationId, ValidationResult,
};
