//! # ORACLE Confidence Scoring Engine
//!
//! Quantitative assessment of forensic evidence quality, reliability,
//! and probative value for the ORACLE platform.
//!
//! Every forensic conclusion must be accompanied by a confidence score
//! that communicates to investigators and courts how much weight to assign
//! to the finding. The scoring engine evaluates evidence based on four
//! weighted factors defined in the Confidence Model v1.0.
//!
//! # Modules
//!
//! - [`model`] — Confidence Model v1.0 formal documentation and constants.
//! - [`scorer`] — Deterministic score computation engine with examiner overrides.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────┐     ┌───────────────┐     ┌──────────────────┐
//! │  ScoringInput    │──▶──│ ScoringEngine │──▶──│ ConfidenceScore  │
//! │  (factors)       │     │ (deterministic)│     │ (versioned)      │
//! └──────────────────┘     └───────────────┘     └──────────────────┘
//!                                │                        │
//!                                ▼                        ▼
//!                        ┌───────────────┐        ┌──────────────┐
//!                        │ ExaminerOverride│       │ ScoreHistory │
//!                        └───────────────┘        └──────────────┘
//! ```

pub mod model;
pub mod scorer;

// Re-export primary types.
pub use model::{ModelDocumentation, MODEL_VERSION};
pub use scorer::{
    ConfidenceScore, ExaminerOverride, FactorBreakdown, ScoreHistory, ScoreId, ScoringEngine,
    ScoringInput,
};
