//! # ORACLE Audit and Chain of Custody Logger
//!
//! Cryptographically chained, append-only audit log for the ORACLE Android
//! Network Forensics Platform.
//!
//! This crate is the **first** module built because every other subsystem
//! depends on it. No forensic operation may proceed without a successful
//! audit log write (write-before-execute semantics).
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │                  AuditLogWriter                   │
//! │  ┌─────────┐  ┌─────────┐  ┌─────────┐          │
//! │  │ Entry 0 │──│ Entry 1 │──│ Entry 2 │── ...     │
//! │  │ (hash₀) │  │ (hash₁) │  │ (hash₂) │          │
//! │  └─────────┘  └─────────┘  └─────────┘          │
//! │       ↑ previous_hash = GENESIS                  │
//! └──────────────────────────────────────────────────┘
//!          │                          │
//!          ▼                          ▼
//!   AuditLogVerifier          ChainOfCustodyBuilder
//!   (read-only chain          (court-ready timeline
//!    integrity check)          from audit entries)
//!          │
//!          ▼
//!   export_audit_log()
//!   (self-verifying JSON)
//! ```
//!
//! ## Modules
//!
//! - [`entry`] — The [`AuditEntry`] data structure and hash computation.
//! - [`writer`] — SQLite-backed append-only writer with crash recovery.
//! - [`verifier`] — Read-only chain integrity verifier.
//! - [`custody`] — Chain of custody record builder.
//! - [`export`] — Full audit log export to self-verifying JSON.

pub mod entry;
pub mod writer;
pub mod verifier;
pub mod custody;
pub mod export;

// Re-export primary types for ergonomic downstream usage.
pub use entry::AuditEntry;
pub use writer::AuditLogWriter;
pub use verifier::{AuditLogVerifier, ChainStatus, VerificationReport};
pub use custody::{ChainOfCustodyBuilder, ChainOfCustodyRecord, CustodyEvent, CustodyEventCategory};
pub use export::{export_audit_log, verify_export_hash, AuditLogExport};
