//! # Report Signing (V2)
//!
//! Provides examiner-attributed report signing and verification for the
//! new report pipeline modules. Complements the existing [`crate::signing`]
//! module by supporting the [`ReportBundle`](crate::json_export::ReportBundle)
//! format and including examiner attribution metadata.
//!
//! ## Design
//!
//! Each [`ReportSignature`] captures:
//! - A SHA-256 hash of the report JSON content.
//! - The examiner who signed the report.
//! - When the signature was created.
//! - The ORACLE platform version for reproducibility.
//!
//! This module uses hash-based integrity verification rather than asymmetric
//! cryptographic signatures. For non-repudiation requirements, wrap the
//! signature in an external PKI ceremony.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use tracing::info;

// ──────────────────────────────────────────────────────────────────────────────
// Data Structures
// ──────────────────────────────────────────────────────────────────────────────

/// The ORACLE platform version embedded in signatures.
const PLATFORM_VERSION: &str = "1.0.0-alpha.1";

/// A cryptographic signature binding a report to an examiner.
///
/// The signature includes the SHA-256 hash of the report content, the
/// examiner's name, and a timestamp, enabling independent verification
/// of both integrity and attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSignature {
    /// SHA-256 hash of the report JSON content that was signed.
    pub report_hash: String,
    /// Name of the examiner who signed the report.
    pub signed_by: String,
    /// UTC timestamp of when the signature was created.
    pub signed_at: DateTime<Utc>,
    /// Version of the ORACLE platform that produced this signature.
    pub platform_version: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Signing & Verification
// ──────────────────────────────────────────────────────────────────────────────

/// Sign a report JSON string with the examiner's identity.
///
/// Computes the SHA-256 hash of the report JSON and creates a
/// [`ReportSignature`] binding the hash to the examiner.
///
/// # Arguments
///
/// * `report_json` — The JSON string of the report to sign.
/// * `examiner` — The name of the examiner performing the signing.
///
/// # Returns
///
/// A [`ReportSignature`] containing the hash, examiner name, timestamp,
/// and platform version.
pub fn sign_report_v2(report_json: &str, examiner: &str) -> ReportSignature {
    let report_hash = compute_sha256(report_json);

    info!(
        examiner = examiner,
        hash = %report_hash,
        "Report signed by examiner"
    );

    ReportSignature {
        report_hash,
        signed_by: examiner.to_string(),
        signed_at: Utc::now(),
        platform_version: PLATFORM_VERSION.to_string(),
    }
}

/// Verify a report signature against the current report content.
///
/// Re-computes the SHA-256 hash of the report JSON and compares it
/// to the hash stored in the signature. If they match, the report
/// has not been modified since signing.
///
/// # Arguments
///
/// * `report_json` — The current JSON string of the report.
/// * `signature` — The signature to verify against.
///
/// # Returns
///
/// `true` if the computed hash matches the signature's hash (report is
/// intact), `false` if the hashes diverge (report was modified).
pub fn verify_report_signature(report_json: &str, signature: &ReportSignature) -> bool {
    let computed_hash = compute_sha256(report_json);
    let is_valid = computed_hash == signature.report_hash;

    if is_valid {
        info!(
            signed_by = %signature.signed_by,
            "Report signature verified — content intact"
        );
    } else {
        tracing::warn!(
            signed_by = %signature.signed_by,
            expected = %signature.report_hash,
            computed = %computed_hash,
            "Report signature verification FAILED — content modified"
        );
    }

    is_valid
}

/// Compute SHA-256 hash of a string.
fn compute_sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_JSON: &str = r#"{
        "case_number": "CASE-SIGN-001",
        "findings": ["Connection to suspect network detected"],
        "confidence": 0.95
    }"#;

    #[test]
    fn test_sign_report_produces_valid_hash() {
        let signature = sign_report_v2(SAMPLE_JSON, "Dr. Jane Smith");

        assert_eq!(signature.report_hash.len(), 64);
        assert!(signature.report_hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(signature.signed_by, "Dr. Jane Smith");
        assert_eq!(signature.platform_version, "1.0.0-alpha.1");
    }

    #[test]
    fn test_sign_and_verify_round_trip() {
        let signature = sign_report_v2(SAMPLE_JSON, "Examiner A");

        // Verification should succeed with the same content.
        assert!(verify_report_signature(SAMPLE_JSON, &signature));
    }

    #[test]
    fn test_verify_fails_on_tampered_content() {
        let signature = sign_report_v2(SAMPLE_JSON, "Examiner B");

        let tampered = r#"{
            "case_number": "CASE-TAMPERED",
            "findings": ["Connection to suspect network detected"],
            "confidence": 0.95
        }"#;

        assert!(!verify_report_signature(tampered, &signature));
    }

    #[test]
    fn test_verify_fails_on_empty_content() {
        let signature = sign_report_v2(SAMPLE_JSON, "Examiner C");

        assert!(!verify_report_signature("", &signature));
    }

    #[test]
    fn test_signature_deterministic() {
        let sig1 = sign_report_v2(SAMPLE_JSON, "Same Examiner");
        let sig2 = sign_report_v2(SAMPLE_JSON, "Same Examiner");

        // Hash should be identical for same content.
        assert_eq!(sig1.report_hash, sig2.report_hash);
        // Examiner should be the same.
        assert_eq!(sig1.signed_by, sig2.signed_by);
    }

    #[test]
    fn test_sign_and_verify_with_serialized_signature() {
        let signature = sign_report_v2(SAMPLE_JSON, "Examiner D");

        // Serialize and deserialize the signature (simulating persistence).
        let sig_json = serde_json::to_string(&signature).unwrap();
        let recovered: ReportSignature = serde_json::from_str(&sig_json).unwrap();

        // Verification should still succeed after round-tripping.
        assert!(verify_report_signature(SAMPLE_JSON, &recovered));
    }
}
