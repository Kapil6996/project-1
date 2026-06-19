//! # ORACLE Evidence Store
//!
//! Append-only evidence storage with content-addressable blob management and
//! cryptographic integrity verification for the ORACLE forensic platform.
//!
//! This crate implements the core evidence management subsystem:
//!
//! - **Content-Addressable Storage (CAS):** Raw forensic artifacts are stored by
//!   their SHA-256 hash, ensuring deduplication and tamper detection.
//! - **Append-Only Semantics:** Once ingested, evidence cannot be modified or
//!   deleted. Any mutation attempt is rejected with a forensic integrity error.
//! - **Integrity Verification:** On-demand and on-read hash verification ensures
//!   that stored evidence has not been altered since ingestion.
//! - **Provenance Tracking:** Every parsed and normalized record carries a full
//!   source reference back to the exact bytes in the original artifact.
//! - **SQLite Metadata Index:** Artifact metadata and record storage use SQLite
//!   (WAL mode) for efficient querying while raw blobs live on the filesystem.
//!
//! # Modules
//!
//! - [`store`] — Primary evidence store API (initialize, open, manage).
//! - [`cas`] — Content-addressable blob storage with deduplication.
//! - [`records`] — Parsed and normalized evidence record storage.
//! - [`integrity`] — Hash verification and provenance chain validation.
//!
//! # Architecture
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────┐
//! │                      EvidenceStore                         │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │
//! │  │     CAS      │  │  RecordStore │  │ IntegrityVerifier │ │
//! │  │  (filesystem │  │  (SQLite     │  │  (SHA-256         │ │
//! │  │   blobs)     │  │   records)   │  │   verification)   │ │
//! │  └──────┬───────┘  └──────┬───────┘  └──────────┬───────┘ │
//! │         │                 │                      │         │
//! │         └─────────────────┼──────────────────────┘         │
//! │                           │                                │
//! │                  SQLite Metadata DB                        │
//! └───────────────────────────────────────────────────────────┘
//! ```

pub mod store;
pub mod cas;
pub mod records;
pub mod integrity;

// Re-export primary types for ergonomic downstream usage.
pub use store::EvidenceStore;
pub use cas::ContentAddressableStore;
pub use records::{ParsedRecord, NormalizedRecord, RecordStore};
pub use integrity::{IntegrityVerifier, IntegrityReport, IntegrityFailure};
