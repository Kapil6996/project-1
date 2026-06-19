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
//! # Key Normalizations
//!
//! - **Timestamps:** All timestamps converted to UTC nanosecond epochs
//! - **MAC Addresses:** Normalized to uppercase colon-separated format
//! - **SSIDs:** Unicode-normalized and whitespace-trimmed
//! - **GPS Coordinates:** Standardized to WGS84 decimal degrees
//!
//! # Modules (planned)
//!
//! - `normalizer` — Core normalization pipeline
//! - `timestamp` — Timestamp normalization across formats and timezones
//! - `network` — MAC address and SSID normalization
//! - `location` — GPS coordinate normalization

// TODO: Uncomment as modules are implemented
// pub mod normalizer;
// pub mod timestamp;
// pub mod network;
// pub mod location;
