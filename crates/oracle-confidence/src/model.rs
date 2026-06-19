//! # Confidence Model v1.0 Documentation
//!
//! Formal definition of the ORACLE Confidence Scoring Model. This module
//! serves as both executable documentation and the authoritative source
//! of truth for all scoring parameters.
//!
//! # Model Overview
//!
//! The confidence score quantifies how much weight a forensic examiner or
//! court should assign to a particular finding. It is a deterministic value
//! in the range `[0.0, 1.0]` computed from four weighted factors.
//!
//! # Scoring Factors
//!
//! | Factor                | Weight | Range   | Description                               |
//! |-----------------------|--------|---------|-------------------------------------------|
//! | Source Reliability     | 0.30   | 0.0–1.0 | Baseline reliability of the artifact type |
//! | Temporal Consistency   | 0.25   | 0.0–1.0 | Cross-source timestamp agreement          |
//! | Corroboration          | 0.30   | 0.0–1.0 | Number of independent confirming sources  |
//! | Artifact Freshness     | 0.15   | 0.0–1.0 | Proximity to the relevant time window     |
//!
//! # Determinism Guarantee
//!
//! Given identical inputs, the scoring engine MUST produce bit-identical
//! output. No randomness, no floating-point non-determinism (all operations
//! use ordered comparisons), no external state.

use serde::{Deserialize, Serialize};

/// The current model version string. Embedded in every score output.
pub const MODEL_VERSION: &str = "1.0.0";

/// Factor weights — MUST sum to exactly 1.0.
pub const WEIGHT_SOURCE_RELIABILITY: f64 = 0.30;
pub const WEIGHT_TEMPORAL_CONSISTENCY: f64 = 0.25;
pub const WEIGHT_CORROBORATION: f64 = 0.30;
pub const WEIGHT_FRESHNESS: f64 = 0.15;

/// Penalty applied when active contradictions exist for a finding.
pub const CONTRADICTION_PENALTY: f64 = 0.40;

/// Maximum confidence when a contradiction is present (hard cap).
pub const CONTRADICTION_MAX_CONFIDENCE: f64 = 0.50;

/// Formal model documentation for inclusion in forensic reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDocumentation {
    pub version: String,
    pub factor_weights: Vec<FactorWeight>,
    pub contradiction_penalty: f64,
    pub contradiction_max_confidence: f64,
    pub methodology_summary: String,
}

/// A single factor weight entry for documentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactorWeight {
    pub factor_name: String,
    pub weight: f64,
    pub description: String,
}

impl ModelDocumentation {
    /// Generate the v1.0 model documentation.
    pub fn v1() -> Self {
        ModelDocumentation {
            version: MODEL_VERSION.to_string(),
            factor_weights: vec![
                FactorWeight {
                    factor_name: "Source Reliability".to_string(),
                    weight: WEIGHT_SOURCE_RELIABILITY,
                    description: "Baseline reliability of the artifact type, derived from \
                        the artifact class taxonomy (e.g., kernel logs = 0.99, DNS cache = 0.70)."
                        .to_string(),
                },
                FactorWeight {
                    factor_name: "Temporal Consistency".to_string(),
                    weight: WEIGHT_TEMPORAL_CONSISTENCY,
                    description: "Degree to which timestamps from different sources agree. \
                        Computed as 1.0 minus the normalized standard deviation of timestamps."
                        .to_string(),
                },
                FactorWeight {
                    factor_name: "Corroboration".to_string(),
                    weight: WEIGHT_CORROBORATION,
                    description: "Number of independent artifact sources that confirm the \
                        finding. Scored on a logarithmic curve: 1 source = 0.40, 2 = 0.65, \
                        3 = 0.80, 4 = 0.90, 5+ = 0.95."
                        .to_string(),
                },
                FactorWeight {
                    factor_name: "Artifact Freshness".to_string(),
                    weight: WEIGHT_FRESHNESS,
                    description: "How recently the artifact was created or modified relative \
                        to the investigation's time window of interest. Decays exponentially \
                        with age."
                        .to_string(),
                },
            ],
            contradiction_penalty: CONTRADICTION_PENALTY,
            contradiction_max_confidence: CONTRADICTION_MAX_CONFIDENCE,
            methodology_summary: "The ORACLE Confidence Model v1.0 computes a weighted sum \
                of four factors: Source Reliability (30%), Temporal Consistency (25%), \
                Corroboration (30%), and Artifact Freshness (15%). When active contradictions \
                exist, a 40% penalty is applied and the score is capped at 0.50. The model \
                is fully deterministic — identical inputs always produce identical scores. \
                All factor baselines are documented in the ArtifactClass taxonomy."
                .to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weights_sum_to_one() {
        let sum = WEIGHT_SOURCE_RELIABILITY
            + WEIGHT_TEMPORAL_CONSISTENCY
            + WEIGHT_CORROBORATION
            + WEIGHT_FRESHNESS;
        assert!(
            (sum - 1.0).abs() < 1e-10,
            "Factor weights must sum to 1.0, got {}",
            sum
        );
    }

    #[test]
    fn test_model_version() {
        assert_eq!(MODEL_VERSION, "1.0.0");
    }

    #[test]
    fn test_documentation_generation() {
        let doc = ModelDocumentation::v1();
        assert_eq!(doc.version, "1.0.0");
        assert_eq!(doc.factor_weights.len(), 4);
        assert!(!doc.methodology_summary.is_empty());
    }

    #[test]
    fn test_contradiction_penalty_range() {
        assert!(CONTRADICTION_PENALTY > 0.0 && CONTRADICTION_PENALTY < 1.0);
        assert!(CONTRADICTION_MAX_CONFIDENCE > 0.0 && CONTRADICTION_MAX_CONFIDENCE < 1.0);
    }
}
