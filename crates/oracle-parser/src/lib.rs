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
//! # Built-in Parsers (planned)
//!
//! - `WifiConfigStore.xml` — Saved Wi-Fi networks with BSSIDs and SSIDs
//! - `wpa_supplicant.conf` — Legacy Wi-Fi network configurations
//! - `dumpsys wifi` — Runtime Wi-Fi state and scan results
//! - `logcat` — Android system log entries with timestamps
//!
//! # Modules (planned)
//!
//! - `registry` — Parser registration and dispatch
//! - `traits` — Parser trait definitions
//! - `wifi` — Wi-Fi artifact parsers
//! - `logcat` — Logcat log parser
//! - `location` — Location-related artifact parsers

// TODO: Uncomment as modules are implemented
// pub mod registry;
// pub mod traits;
// pub mod wifi;
// pub mod logcat;
// pub mod location;
