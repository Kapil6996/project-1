//! # ORACLE Parser Registry & Core Parsers
//!
//! Extensible parser registry for Android forensic artifact formats,
//! with built-in parsers for common artifact types.
//!
//! The parser subsystem transforms raw binary and text artifacts into
//! structured, queryable forensic records. Parsers are registered by
//! artifact type and invoked by the ingestion pipeline. Each parser
//! emits typed events that feed into the normalization and correlation layers.
//!
//! # Built-in Parsers
//!
//! | Parser | Artifact | Record Type |
//! |--------|----------|-------------|
//! | [`wifi_config::WifiConfigStoreParser`] | `WifiConfigStore.xml` | `wifi_configured_network` |
//! | [`wpa_supplicant::WpaSupplicantParser`] | `wpa_supplicant.conf` | `wifi_known_network` |
//! | [`dhcp::DhcpLeaseParser`] | DHCP lease files | `dhcp_lease` |
//! | [`connectivity::ConnectivityLogParser`] | Connectivity logs | `connectivity_event` |
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐     ┌──────────────┐     ┌────────────┐
//! │  Raw Bytes   │────▶│ ParserRegistry│────▶│ ParsedOutput│
//! │  (artifact)  │     │  (dispatch)   │     │  (records)  │
//! └─────────────┘     └──────────────┘     └────────────┘
//! ```
//!
//! All parsers implement the [`traits::ArtifactParser`] trait. The
//! [`registry::ParserRegistry`] dispatches to the correct parser based
//! on [`ArtifactClass`](oracle_core::ArtifactClass).

pub mod connectivity;
pub mod dhcp;
pub mod registry;
pub mod traits;
pub mod wpa_supplicant;
pub mod wifi_config;

// Re-export primary types for ergonomic imports.
pub use registry::ParserRegistry;
pub use traits::{ArtifactParser, ParsedOutput, ParserInfo};
