//! # ORACLE Report Generator
//!
//! Produces court-ready forensic reports from correlated evidence with
//! full chain-of-custody documentation.
//!
//! The report generator transforms investigation results into presentable
//! documents suitable for law enforcement, legal proceedings, and internal
//! analysis. Reports include:
//!
//! - **Executive Summary:** High-level findings with confidence scores
//! - **Detailed Timeline:** Chronological evidence with source citations
//! - **Evidence Appendix:** Hash-verified artifact inventory
//! - **Chain of Custody:** Complete audit trail from the audit logger
//! - **Methodology Disclosure:** Configuration and tool versions used
//!
//! # Output Formats
//!
//! - PDF — Court-ready formatted document via [`pdf::render_pdf`]
//! - JSON — Machine-readable structured output via [`generator::JsonRenderer`]
//!
//! # Modules
//!
//! - [`types`] — Core report data structures.
//! - [`generator`] — Report generation orchestrator and JSON renderer.
//! - [`appendix`] — Evidence appendix builder with cross-referencing.
//! - [`custody_report`] — Chain of custody document generator.
//! - [`signing`] — Report signing and tamper-evidence verification.
//! - [`pdf`] — PDF output renderer using printpdf.

pub mod types;
pub mod generator;
pub mod appendix;
pub mod custody_report;
pub mod signing;
pub mod pdf;

// Re-export primary types for ergonomic downstream usage.
pub use types::{
    EvidenceEntry, ForensicReport, InvestigationSummary, ReportFinding, ReportId, ReportMetadata,
    ReportType,
};
pub use generator::{JsonRenderer, ReportGenerator};
pub use appendix::{
    EvidenceAppendix, EvidenceAppendixBuilder, EvidenceEntryInput, render_appendix_text,
};
pub use custody_report::{CustodyDocument, CustodyDocumentBuilder};
pub use signing::{sign_report, verify_report, SignedReport, VerificationResult};
pub use pdf::{render_pdf, PdfError};
