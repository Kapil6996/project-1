//! # ORACLE Artifact Discovery Engine
//!
//! Locates, catalogs, and extracts forensic artifacts from Android devices
//! and filesystem images for the ORACLE forensic platform.
//!
//! The discovery engine walks known Android filesystem paths, applies pattern
//! matching rules, and streams discovered artifacts into the evidence store.
//! Every file access is audited to maintain a complete chain of custody.
//!
//! # Modules (planned)
//!
//! - `scanner` — Filesystem scanner with configurable path rules
//! - `rules` — Artifact discovery rule definitions
//! - `extractor` — Raw artifact extraction and streaming into evidence store
//! - `manifest` — Discovery manifest builder for investigation records

// TODO: Uncomment as modules are implemented
// pub mod scanner;
// pub mod rules;
// pub mod extractor;
// pub mod manifest;
