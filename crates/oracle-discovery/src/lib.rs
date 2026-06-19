//! # ORACLE Artifact Discovery Engine
//!
//! Locates, catalogs, and extracts forensic artifacts from Android devices
//! and filesystem images for the ORACLE forensic platform.
//!
//! The discovery engine walks known Android filesystem paths, applies pattern
//! matching rules, and streams discovered artifacts into the evidence store.
//! Every file access is audited to maintain a complete chain of custody.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐     ┌───────────┐     ┌────────────┐     ┌──────────────┐
//! │ PathRegistry │──▶──│  Scanner  │──▶──│  Manifest  │──▶──│ Acquisition  │
//! └─────────────┘     └───────────┘     └────────────┘     └──────────────┘
//! ```
//!
//! 1. **Registry** — Enumerates all known device-side paths per artifact class.
//! 2. **Scanner** — Probes the device via ADB to discover which paths exist.
//! 3. **Manifest** — Builds a structured manifest of discovered artifacts.
//! 4. **Acquisition** — Pulls artifacts byte-for-byte with integrity hashing.
//!
//! # Modules
//!
//! - [`registry`] — Known Android artifact path registry.
//! - [`scanner`] — Device filesystem scanner with ADB abstraction.
//! - [`manifest`] — Artifact manifest builder for investigation records.
//! - [`acquisition`] — Acquisition coordinator for pulling device artifacts.

pub mod acquisition;
pub mod manifest;
pub mod registry;
pub mod scanner;

// ── Re-exports for ergonomic access ─────────────────────────────────────────

pub use acquisition::{AcquiredArtifact, AcquisitionCoordinator, AcquisitionReport, FailedArtifact};
pub use manifest::{ArtifactManifest, ManifestBuilder};
pub use registry::{ArtifactPathEntry, PathRegistry};
pub use scanner::{
    AdbShell, ArtifactScanner, DiscoveredArtifact, InaccessiblePath, ScanResult,
};
