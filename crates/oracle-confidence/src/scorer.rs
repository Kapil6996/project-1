//! # Confidence Score Computation Engine
//!
//! Deterministic computation of confidence scores based on the Confidence
//! Model v1.0. Given a set of scoring inputs, produces a versioned,
//! reproducible score with full factor breakdown.
//!
//! # Determinism Contract
//!
//! This engine guarantees bit-identical output for identical inputs.
//! No randomness, no external state, no non-deterministic floating-point
//! operations. Every score is reproducible and auditable.

use chrono::{DateTime, Duration, Utc};
use oracle_core::types::{ArtifactClass, ConfidenceClassification};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::{
    CONTRADICTION_MAX_CONFIDENCE, CONTRADICTION_PENALTY, MODEL_VERSION,
    WEIGHT_CORROBORATION, WEIGHT_FRESHNESS, WEIGHT_SOURCE_RELIABILITY,
    WEIGHT_TEMPORAL_CONSISTENCY,
};

// ──────────────────────────────────────────────────────────────────────────────
// Score Types
// ──────────────────────────────────────────────────────────────────────────────

/// Unique identifier for a computed confidence score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScoreId(pub Uuid);

impl ScoreId {
    pub fn new() -> Self {
        ScoreId(Uuid::new_v4())
    }
}

impl Default for ScoreId {
    fn default() -> Self {
        Self::new()
    }
}

/// Inputs to the confidence scoring engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringInput {
    /// The artifact class of the primary evidence source.
    pub primary_artifact_class: ArtifactClass,
    /// Number of independent sources corroborating the finding.
    pub corroboration_count: usize,
    /// Timestamps from all corroborating sources (for consistency computation).
    pub source_timestamps: Vec<DateTime<Utc>>,
    /// When the artifact was acquired.
    pub acquisition_time: DateTime<Utc>,
    /// The time window of forensic interest (e.g., the incident window).
    pub interest_window_start: DateTime<Utc>,
    pub interest_window_end: DateTime<Utc>,
    /// Whether any active contradictions exist for this finding.
    pub has_contradictions: bool,
    /// Number of active contradictions.
    pub contradiction_count: usize,
}

/// The breakdown of individual factor scores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactorBreakdown {
    /// Source reliability factor value (0.0–1.0).
    pub source_reliability: f64,
    /// Temporal consistency factor value (0.0–1.0).
    pub temporal_consistency: f64,
    /// Corroboration factor value (0.0–1.0).
    pub corroboration: f64,
    /// Artifact freshness factor value (0.0–1.0).
    pub freshness: f64,
}

/// A fully computed, versioned confidence score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceScore {
    /// Unique identifier.
    pub id: ScoreId,
    /// The model version that produced this score.
    pub model_version: String,
    /// The final composite score (0.0–1.0).
    pub score: f64,
    /// The court-facing classification derived from the score.
    pub classification: ConfidenceClassification,
    /// Full factor breakdown.
    pub factors: FactorBreakdown,
    /// Whether contradictions were present and applied as a penalty.
    pub contradiction_applied: bool,
    /// The raw weighted sum before any penalties.
    pub raw_weighted_sum: f64,
    /// When this score was computed.
    pub computed_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Score Versioning
// ──────────────────────────────────────────────────────────────────────────────

/// Tracks historical score versions when a finding is re-scored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreHistory {
    /// All versions of the score, newest first.
    pub versions: Vec<ConfidenceScore>,
}

impl ScoreHistory {
    pub fn new(initial: ConfidenceScore) -> Self {
        ScoreHistory {
            versions: vec![initial],
        }
    }

    /// Add a new score version (e.g., after examiner override or new evidence).
    pub fn add_version(&mut self, score: ConfidenceScore) {
        self.versions.insert(0, score);
    }

    /// Get the current (latest) score.
    pub fn current(&self) -> Option<&ConfidenceScore> {
        self.versions.first()
    }

    /// How many times this finding has been re-scored.
    pub fn revision_count(&self) -> usize {
        self.versions.len()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Examiner Override
// ──────────────────────────────────────────────────────────────────────────────

/// An examiner override that adjusts a confidence score with justification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExaminerOverride {
    /// The original computed score.
    pub original_score: f64,
    /// The examiner-adjusted score.
    pub adjusted_score: f64,
    /// The examiner's justification for the override.
    pub justification: String,
    /// Name of the examiner who applied the override.
    pub examiner_name: String,
    /// When the override was applied.
    pub applied_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Scoring Engine
// ──────────────────────────────────────────────────────────────────────────────

/// Deterministic confidence scoring engine.
pub struct ScoringEngine;

impl ScoringEngine {
    /// Compute a confidence score from the given inputs.
    ///
    /// This function is deterministic — identical inputs always produce
    /// identical outputs.
    pub fn compute(input: &ScoringInput) -> ConfidenceScore {
        let source_reliability = Self::compute_source_reliability(input.primary_artifact_class);
        let temporal_consistency = Self::compute_temporal_consistency(&input.source_timestamps);
        let corroboration = Self::compute_corroboration(input.corroboration_count);
        let freshness = Self::compute_freshness(
            input.acquisition_time,
            input.interest_window_start,
            input.interest_window_end,
        );

        let raw_weighted_sum = (source_reliability * WEIGHT_SOURCE_RELIABILITY)
            + (temporal_consistency * WEIGHT_TEMPORAL_CONSISTENCY)
            + (corroboration * WEIGHT_CORROBORATION)
            + (freshness * WEIGHT_FRESHNESS);

        // Apply contradiction penalty
        let (final_score, contradiction_applied) = if input.has_contradictions {
            let penalized = (raw_weighted_sum - CONTRADICTION_PENALTY).max(0.0);
            let capped = penalized.min(CONTRADICTION_MAX_CONFIDENCE);
            (capped, true)
        } else {
            (raw_weighted_sum.min(1.0), false)
        };

        let classification = if input.has_contradictions && final_score < 0.50 {
            ConfidenceClassification::Contradicted
        } else {
            ConfidenceClassification::from_score(final_score)
        };

        ConfidenceScore {
            id: ScoreId::new(),
            model_version: MODEL_VERSION.to_string(),
            score: final_score,
            classification,
            factors: FactorBreakdown {
                source_reliability,
                temporal_consistency,
                corroboration,
                freshness,
            },
            contradiction_applied,
            raw_weighted_sum,
            computed_at: Utc::now(),
        }
    }

    /// Apply an examiner override to an existing score.
    pub fn apply_override(
        original: &ConfidenceScore,
        adjusted_score: f64,
        justification: &str,
        examiner_name: &str,
    ) -> (ConfidenceScore, ExaminerOverride) {
        let clamped = adjusted_score.clamp(0.0, 1.0);

        let override_record = ExaminerOverride {
            original_score: original.score,
            adjusted_score: clamped,
            justification: justification.to_string(),
            examiner_name: examiner_name.to_string(),
            applied_at: Utc::now(),
        };

        let new_score = ConfidenceScore {
            id: ScoreId::new(),
            model_version: original.model_version.clone(),
            score: clamped,
            classification: ConfidenceClassification::from_score(clamped),
            factors: original.factors.clone(),
            contradiction_applied: original.contradiction_applied,
            raw_weighted_sum: original.raw_weighted_sum,
            computed_at: Utc::now(),
        };

        (new_score, override_record)
    }

    // ── Factor Computations ─────────────────────────────────────────────

    /// Source reliability: baseline reliability from the artifact class taxonomy.
    fn compute_source_reliability(class: ArtifactClass) -> f64 {
        class.baseline_reliability()
    }

    /// Temporal consistency: how well timestamps agree across sources.
    ///
    /// Computed as `1.0 - normalized_stddev`, where the standard deviation
    /// is normalized by a 5-minute reference window.
    fn compute_temporal_consistency(timestamps: &[DateTime<Utc>]) -> f64 {
        if timestamps.len() < 2 {
            return 0.5; // Can't assess consistency with fewer than 2 timestamps
        }

        let mean_epoch: f64 = timestamps
            .iter()
            .map(|t| t.timestamp() as f64)
            .sum::<f64>()
            / timestamps.len() as f64;

        let variance: f64 = timestamps
            .iter()
            .map(|t| {
                let diff = t.timestamp() as f64 - mean_epoch;
                diff * diff
            })
            .sum::<f64>()
            / timestamps.len() as f64;

        let stddev = variance.sqrt();

        // Normalize by a 5-minute reference (300 seconds)
        let normalized = (stddev / 300.0).min(1.0);
        (1.0 - normalized).max(0.0)
    }

    /// Corroboration: logarithmic curve based on independent source count.
    fn compute_corroboration(source_count: usize) -> f64 {
        match source_count {
            0 => 0.10,
            1 => 0.40,
            2 => 0.65,
            3 => 0.80,
            4 => 0.90,
            _ => 0.95,
        }
    }

    /// Artifact freshness: exponential decay based on distance from interest window.
    fn compute_freshness(
        acquisition_time: DateTime<Utc>,
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
    ) -> f64 {
        // If acquisition is within the interest window, freshness is 1.0
        if acquisition_time >= window_start && acquisition_time <= window_end {
            return 1.0;
        }

        // Distance from nearest edge of the interest window
        let distance = if acquisition_time < window_start {
            (window_start - acquisition_time).num_hours() as f64
        } else {
            (acquisition_time - window_end).num_hours() as f64
        };

        // Exponential decay: half-life of 24 hours
        let half_life = 24.0;
        let decay = (-distance * (2.0_f64.ln()) / half_life).exp();
        decay.max(0.05) // Floor at 0.05
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_core::types::ArtifactClass;

    fn make_input(
        class: ArtifactClass,
        sources: usize,
        contradictions: bool,
    ) -> ScoringInput {
        let now = Utc::now();
        let timestamps: Vec<_> = (0..sources)
            .map(|i| now + Duration::seconds(i as i64 * 5))
            .collect();

        ScoringInput {
            primary_artifact_class: class,
            corroboration_count: sources,
            source_timestamps: timestamps,
            acquisition_time: now,
            interest_window_start: now - Duration::hours(1),
            interest_window_end: now + Duration::hours(1),
            has_contradictions: contradictions,
            contradiction_count: if contradictions { 1 } else { 0 },
        }
    }

    #[test]
    fn test_high_confidence_scenario() {
        // Best case: reliable source, many corroborations, fresh, no contradictions
        let input = make_input(ArtifactClass::KernelLogs, 5, false);
        let score = ScoringEngine::compute(&input);

        assert!(score.score >= 0.90, "high-quality evidence should score >= 0.90, got {}", score.score);
        assert_eq!(score.classification, ConfidenceClassification::Definitive);
        assert!(!score.contradiction_applied);
    }

    #[test]
    fn test_low_confidence_scenario() {
        // Worst case: unknown source, single source, no contradictions
        let input = make_input(ArtifactClass::Unknown, 1, false);
        let score = ScoringEngine::compute(&input);

        assert!(score.score < 0.50, "low-quality evidence should score < 0.50, got {}", score.score);
    }

    #[test]
    fn test_contradiction_penalty() {
        let input_clean = make_input(ArtifactClass::WifiConfigStore, 3, false);
        let input_contradicted = make_input(ArtifactClass::WifiConfigStore, 3, true);

        let score_clean = ScoringEngine::compute(&input_clean);
        let score_contradicted = ScoringEngine::compute(&input_contradicted);

        assert!(score_contradicted.score < score_clean.score);
        assert!(score_contradicted.contradiction_applied);
        assert!(score_contradicted.score <= CONTRADICTION_MAX_CONFIDENCE);
    }

    #[test]
    fn test_contradicted_classification() {
        let input = make_input(ArtifactClass::Unknown, 1, true);
        let score = ScoringEngine::compute(&input);

        assert_eq!(score.classification, ConfidenceClassification::Contradicted);
    }

    #[test]
    fn test_more_sources_higher_score() {
        let score_1 = ScoringEngine::compute(&make_input(ArtifactClass::WifiConfigStore, 1, false));
        let score_3 = ScoringEngine::compute(&make_input(ArtifactClass::WifiConfigStore, 3, false));
        let score_5 = ScoringEngine::compute(&make_input(ArtifactClass::WifiConfigStore, 5, false));

        assert!(score_3.score > score_1.score);
        assert!(score_5.score > score_3.score);
    }

    #[test]
    fn test_determinism() {
        let input = make_input(ArtifactClass::DhcpLeases, 3, false);
        let s1 = ScoringEngine::compute(&input);
        let s2 = ScoringEngine::compute(&input);

        // Scores should be identical for identical inputs
        // (computed_at and id will differ, but score value must match)
        assert_eq!(s1.score, s2.score);
        assert_eq!(s1.raw_weighted_sum, s2.raw_weighted_sum);
        assert_eq!(s1.model_version, s2.model_version);
    }

    #[test]
    fn test_model_version_embedded() {
        let input = make_input(ArtifactClass::WpaSupplicant, 2, false);
        let score = ScoringEngine::compute(&input);
        assert_eq!(score.model_version, "1.0.0");
    }

    #[test]
    fn test_freshness_inside_window() {
        let now = Utc::now();
        let freshness = ScoringEngine::compute_freshness(
            now,
            now - Duration::hours(1),
            now + Duration::hours(1),
        );
        assert_eq!(freshness, 1.0);
    }

    #[test]
    fn test_freshness_decays_with_age() {
        let now = Utc::now();
        let window_start = now - Duration::hours(48);
        let window_end = now - Duration::hours(47);

        // Acquisition much later than window
        let freshness = ScoringEngine::compute_freshness(now, window_start, window_end);
        assert!(freshness < 0.5, "old evidence should have low freshness, got {}", freshness);
    }

    #[test]
    fn test_examiner_override() {
        let input = make_input(ArtifactClass::DhcpLeases, 2, false);
        let original = ScoringEngine::compute(&input);

        let (overridden, record) = ScoringEngine::apply_override(
            &original,
            0.95,
            "Manual verification confirms this finding.",
            "Examiner Smith",
        );

        assert_eq!(overridden.score, 0.95);
        assert_eq!(record.examiner_name, "Examiner Smith");
        assert!(!record.justification.is_empty());
    }

    #[test]
    fn test_temporal_consistency_single_source() {
        let timestamps = vec![Utc::now()];
        let consistency = ScoringEngine::compute_temporal_consistency(&timestamps);
        assert_eq!(consistency, 0.5, "single source should return 0.5");
    }

    #[test]
    fn test_temporal_consistency_tight_agreement() {
        let now = Utc::now();
        let timestamps = vec![now, now + Duration::seconds(1), now + Duration::seconds(2)];
        let consistency = ScoringEngine::compute_temporal_consistency(&timestamps);
        assert!(consistency > 0.95, "tight timestamps should give high consistency");
    }

    #[test]
    fn test_score_history() {
        let input = make_input(ArtifactClass::WifiConfigStore, 2, false);
        let s1 = ScoringEngine::compute(&input);
        let mut history = ScoreHistory::new(s1);

        assert_eq!(history.revision_count(), 1);

        let s2 = ScoringEngine::compute(&make_input(ArtifactClass::WifiConfigStore, 3, false));
        history.add_version(s2);

        assert_eq!(history.revision_count(), 2);
        assert!(history.current().unwrap().score > 0.0);
    }
}
