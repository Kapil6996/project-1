//! # Report Signing and Tamper Evidence
//!
//! Provides cryptographic signing and verification for forensic reports.
//! Every generated report receives a SHA-256 integrity seal computed over
//! a deterministic canonicalization of the report content. The seal can be
//! verified independently to detect any post-generation tampering.
//!
//! ## Design Rationale
//!
//! We use SHA-256 hashing rather than asymmetric signatures because:
//! 1. The hash is computed at generation time and stored alongside the report.
//! 2. The original report JSON can be re-hashed to verify integrity.
//! 3. No key management infrastructure is required.
//! 4. SHA-256 is NIST-approved and court-accepted for integrity verification.
//!
//! For deployments requiring non-repudiation (proving *who* generated the
//! report), wrap the hash in an external signing ceremony using the
//! organization's PKI infrastructure.

use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::types::ForensicReport;

/// A signed report with integrity verification capabilities.
#[derive(Debug, Clone)]
pub struct SignedReport {
    /// The original report.
    pub report: ForensicReport,
    /// The canonical JSON representation used for hashing.
    pub canonical_json: String,
    /// SHA-256 hash of the canonical JSON (the "seal").
    pub integrity_seal: String,
}

/// The result of verifying a report's integrity seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// The report has not been modified since signing.
    Intact,
    /// The report has been modified — the computed hash does not match the seal.
    Tampered {
        expected: String,
        computed: String,
    },
    /// The report has no integrity seal.
    Unsigned,
}

impl std::fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationResult::Intact => write!(f, "INTACT — Report integrity verified"),
            VerificationResult::Tampered { expected, computed } => {
                write!(
                    f,
                    "TAMPERED — Expected hash {} but computed {}",
                    expected, computed
                )
            }
            VerificationResult::Unsigned => write!(f, "UNSIGNED — No integrity seal present"),
        }
    }
}

/// Sign a forensic report by computing its canonical JSON and SHA-256 seal.
///
/// The signing process:
/// 1. Serializes the report to canonical (deterministic) JSON.
/// 2. Strips the existing `report_hash` field to avoid circular hashing.
/// 3. Computes SHA-256 over the canonical JSON bytes.
/// 4. Stores the seal back into the report's `report_hash` field.
///
/// # Returns
///
/// A [`SignedReport`] containing the sealed report, canonical JSON, and
/// integrity seal hash.
pub fn sign_report(mut report: ForensicReport) -> Result<SignedReport, serde_json::Error> {
    // Clear any existing hash to produce a clean canonical form.
    report.report_hash = None;

    // Serialize to canonical JSON (serde_json produces deterministic output
    // for structs with named fields in declaration order).
    let canonical_json = serde_json::to_string_pretty(&report)?;

    // Compute the integrity seal.
    let integrity_seal = compute_sha256(&canonical_json);

    info!(
        case = %report.metadata.case_number,
        report_id = %report.metadata.report_id,
        seal = %integrity_seal,
        "Report signed with integrity seal"
    );

    // Store the seal in the report.
    report.report_hash = Some(integrity_seal.clone());

    Ok(SignedReport {
        report,
        canonical_json,
        integrity_seal,
    })
}

/// Verify the integrity seal of a forensic report.
///
/// Re-computes the SHA-256 hash of the report's canonical JSON (with the
/// `report_hash` field cleared) and compares it to the stored seal.
///
/// # Returns
///
/// - [`VerificationResult::Intact`] if the seal matches.
/// - [`VerificationResult::Tampered`] if the seal does not match.
/// - [`VerificationResult::Unsigned`] if no seal is present.
pub fn verify_report(report: &ForensicReport) -> Result<VerificationResult, serde_json::Error> {
    let stored_seal = match &report.report_hash {
        Some(seal) => seal.clone(),
        None => {
            warn!(
                case = %report.metadata.case_number,
                "Report has no integrity seal"
            );
            return Ok(VerificationResult::Unsigned);
        }
    };

    // Re-serialize with the hash cleared.
    let mut report_clone = report.clone();
    report_clone.report_hash = None;
    let canonical_json = serde_json::to_string_pretty(&report_clone)?;

    let computed_seal = compute_sha256(&canonical_json);

    if computed_seal == stored_seal {
        info!(
            case = %report.metadata.case_number,
            "Report integrity verified — seal intact"
        );
        Ok(VerificationResult::Intact)
    } else {
        warn!(
            case = %report.metadata.case_number,
            expected = %stored_seal,
            computed = %computed_seal,
            "Report integrity FAILED — possible tampering detected"
        );
        Ok(VerificationResult::Tampered {
            expected: stored_seal,
            computed: computed_seal,
        })
    }
}

/// Compute SHA-256 of a string.
fn compute_sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use chrono::Utc;
    use oracle_confidence::MODEL_VERSION;
    use oracle_core::types::{ConfidenceClassification, ExaminerIdentity, InvestigationId};

    fn sample_report() -> ForensicReport {
        ForensicReport {
            metadata: ReportMetadata {
                report_id: ReportId::new(),
                investigation_id: InvestigationId::new(),
                report_type: ReportType::Complete,
                case_number: "CASE-SIGN-001".to_string(),
                examiner: ExaminerIdentity {
                    name: "Signing Examiner".to_string(),
                    badge_id: "B-SIGN".to_string(),
                    organization: "Crypto Lab".to_string(),
                },
                generated_at: Utc::now(),
                platform_version: "1.0.0-alpha.1".to_string(),
                model_version: MODEL_VERSION.to_string(),
            },
            summary: InvestigationSummary {
                case_number: "CASE-SIGN-001".to_string(),
                purpose: "Test signing".to_string(),
                device_description: "Test Device".to_string(),
                investigation_window: "2024-01-01 to 2024-01-02".to_string(),
                total_artifacts: 5,
                total_findings: 2,
                high_confidence_findings: 1,
                contradicted_findings: 0,
                anomalies_detected: 0,
                key_findings: vec!["F-001: Network connection".to_string()],
            },
            findings: vec![ReportFinding {
                finding_number: "F-001".to_string(),
                title: "Test Finding".to_string(),
                description: "A test finding for signing.".to_string(),
                network_ssid: Some("TestSSID".to_string()),
                network_bssid: None,
                security_protocol: None,
                event_time: Some(Utc::now()),
                confidence_score: 0.92,
                confidence_classification: ConfidenceClassification::High,
                corroboration_count: 2,
                corroborating_sources: vec!["source1".to_string()],
                contradictions: Vec::new(),
                examiner_override: false,
            }],
            evidence_entries: Vec::new(),
            methodology_disclosure: "Test methodology".to_string(),
            report_hash: None,
        }
    }

    #[test]
    fn test_sign_report_produces_valid_seal() {
        let report = sample_report();
        let signed = sign_report(report).unwrap();

        assert_eq!(signed.integrity_seal.len(), 64);
        assert!(signed.integrity_seal.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(signed.report.report_hash, Some(signed.integrity_seal.clone()));
    }

    #[test]
    fn test_verify_intact_report() {
        let report = sample_report();
        let signed = sign_report(report).unwrap();

        let result = verify_report(&signed.report).unwrap();
        assert_eq!(result, VerificationResult::Intact);
    }

    #[test]
    fn test_verify_tampered_report() {
        let report = sample_report();
        let signed = sign_report(report).unwrap();

        // Tamper with the report.
        let mut tampered = signed.report;
        tampered.metadata.case_number = "TAMPERED-CASE".to_string();

        let result = verify_report(&tampered).unwrap();
        assert!(matches!(result, VerificationResult::Tampered { .. }));
    }

    #[test]
    fn test_verify_unsigned_report() {
        let report = sample_report();
        let result = verify_report(&report).unwrap();
        assert_eq!(result, VerificationResult::Unsigned);
    }

    #[test]
    fn test_sign_then_verify_round_trip() {
        let report = sample_report();
        let signed = sign_report(report).unwrap();

        // Verify immediately.
        let result = verify_report(&signed.report).unwrap();
        assert_eq!(result, VerificationResult::Intact);

        // Serialize, deserialize, verify again.
        let json = serde_json::to_string_pretty(&signed.report).unwrap();
        let deserialized: ForensicReport = serde_json::from_str(&json).unwrap();
        let result2 = verify_report(&deserialized).unwrap();
        assert_eq!(result2, VerificationResult::Intact);
    }
}
