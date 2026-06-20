//! # JSON Report Export
//!
//! Serializes all report types into a self-verifying JSON file. The exported
//! bundle includes a SHA-256 content hash that enables independent verification
//! of the file's integrity without access to the ORACLE platform.
//!
//! The JSON export is designed as the primary machine-readable interchange
//! format for sharing investigation results with other forensic tools,
//! case management systems, and defense counsel.

use std::path::Path;

use chrono::{DateTime, Utc};
use oracle_core::error::{OracleError, OracleResult};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::custody::CustodyDocumentV2;
use crate::executive::ExecutiveReport;
use crate::summary::InvestigationSummaryV2;
use crate::technical::TechnicalReport;

// ──────────────────────────────────────────────────────────────────────────────
// Data Structures
// ──────────────────────────────────────────────────────────────────────────────

/// A complete bundle of all report types for JSON serialization.
///
/// Wraps the investigation summary, executive report, technical report,
/// and chain of custody document into a single exportable structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportBundle {
    /// Schema version for forward compatibility.
    pub schema_version: String,
    /// Investigation summary with aggregate statistics.
    pub summary: InvestigationSummaryV2,
    /// Executive-level report for non-technical audiences.
    pub executive: ExecutiveReport,
    /// Detailed technical findings report.
    pub technical: TechnicalReport,
    /// Chain of custody documentation.
    pub custody: CustodyDocumentV2,
    /// UTC timestamp of when this bundle was generated.
    pub exported_at: DateTime<Utc>,
    /// SHA-256 hash of the serialized content (computed over all fields above).
    /// This field is `None` during serialization for hash computation, then
    /// populated after the hash is computed.
    pub content_hash: Option<String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Export Functions
// ──────────────────────────────────────────────────────────────────────────────

/// Export all investigation reports to a self-verifying JSON file.
///
/// The function:
/// 1. Bundles all report types into a single [`ReportBundle`].
/// 2. Serializes the bundle to JSON with `content_hash` set to `None`.
/// 3. Computes the SHA-256 hash of the JSON bytes.
/// 4. Re-serializes the bundle with the computed hash embedded.
/// 5. Writes the final JSON to the specified output path.
///
/// # Arguments
///
/// * `summary` — Investigation summary.
/// * `executive` — Executive report.
/// * `technical` — Technical findings report.
/// * `custody` — Chain of custody document.
/// * `output_path` — Filesystem path where the JSON file will be written.
///
/// # Errors
///
/// Returns [`OracleError::IoError`] if the file cannot be written, or
/// [`OracleError::SerializationError`] if JSON serialization fails.
pub fn export_investigation_json(
    summary: InvestigationSummaryV2,
    executive: ExecutiveReport,
    technical: TechnicalReport,
    custody: CustodyDocumentV2,
    output_path: &Path,
) -> OracleResult<ReportBundle> {
    info!(
        output = %output_path.display(),
        "Exporting investigation reports to JSON"
    );

    let mut bundle = ReportBundle {
        schema_version: "1.0.0".to_string(),
        summary,
        executive,
        technical,
        custody,
        exported_at: Utc::now(),
        content_hash: None,
    };

    // Serialize without the hash to compute the hash.
    let json_for_hash = serde_json::to_string_pretty(&bundle)?;
    let content_hash = compute_sha256(&json_for_hash);

    // Embed the hash.
    bundle.content_hash = Some(content_hash);

    // Serialize the final version with the embedded hash.
    let final_json = serde_json::to_string_pretty(&bundle)?;

    // Write to disk.
    std::fs::write(output_path, final_json.as_bytes()).map_err(|e| OracleError::IoError {
        path: output_path.to_path_buf(),
        source: e,
    })?;

    info!(
        output = %output_path.display(),
        hash = bundle.content_hash.as_deref().unwrap_or("none"),
        "Investigation JSON export completed"
    );

    Ok(bundle)
}

/// Verify the content hash of a previously exported [`ReportBundle`].
///
/// Re-computes the SHA-256 hash over the bundle with `content_hash` set to
/// `None` and compares it to the stored hash.
///
/// # Returns
///
/// `true` if the computed hash matches the stored hash, `false` otherwise.
/// Returns `false` if no hash is present.
pub fn verify_bundle_hash(bundle: &ReportBundle) -> OracleResult<bool> {
    let stored_hash = match &bundle.content_hash {
        Some(h) => h.clone(),
        None => return Ok(false),
    };

    let mut hashable = bundle.clone();
    hashable.content_hash = None;

    let json = serde_json::to_string_pretty(&hashable)?;
    let computed = compute_sha256(&json);

    Ok(computed == stored_hash)
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
    use chrono::Utc;
    use oracle_core::types::{
        ArtifactId, ConfidenceClassification, InvestigationId, NetworkRole, SecurityProtocol,
    };
    use tempfile::TempDir;

    use crate::custody::{CustodyDocumentV2, CustodyEntry, DeviceInfo, IntegrityStatus};
    use crate::executive::{
        ExecutiveReport, NetworkSummary, Significance, TimelineHighlight,
    };
    use crate::summary::{CaseInfo, Finding, InvestigationSummaryV2};
    use crate::technical::{
        ArtifactDetail, ConfidenceDistribution, CorrelationSummary, NormalizationSummary,
        TechnicalReport,
    };
    use oracle_core::types::ArtifactClass;

    fn sample_summary() -> InvestigationSummaryV2 {
        InvestigationSummaryV2 {
            investigation_id: InvestigationId::new(),
            case_number: "CASE-JSON-001".to_string(),
            examiner_name: "Test Examiner".to_string(),
            device_summary: "Test Device".to_string(),
            total_artifacts: 5,
            total_networks_found: 2,
            total_connections: 10,
            key_findings: vec![Finding {
                description: "Test finding".to_string(),
                confidence: ConfidenceClassification::High,
                supporting_evidence_count: 3,
            }],
            generated_at: Utc::now(),
        }
    }

    fn sample_executive() -> ExecutiveReport {
        ExecutiveReport {
            summary: sample_summary(),
            network_overview: vec![NetworkSummary {
                ssid: "TestNet".to_string(),
                bssid: "AA:BB:CC:DD:EE:FF".to_string(),
                security: SecurityProtocol::Wpa2Psk,
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                role: NetworkRole::DeviceAsClient,
                confidence: ConfidenceClassification::High,
            }],
            timeline_highlights: vec![TimelineHighlight {
                timestamp: Utc::now(),
                description: "Connection to TestNet".to_string(),
                significance: Significance::High,
            }],
            methodology_statement: "Test methodology".to_string(),
        }
    }

    fn sample_technical() -> TechnicalReport {
        TechnicalReport {
            all_artifacts: vec![ArtifactDetail {
                artifact_id: ArtifactId::new(),
                class: ArtifactClass::WifiConfigStore,
                original_path: "/data/misc/wifi/WifiConfigStore.xml".to_string(),
                sha256: format!("{:064x}", 42),
                file_size: 4096,
                parser_used: "wifi_config_parser_v1".to_string(),
                records_extracted: 15,
            }],
            all_parsed_records_count: 15,
            normalization_summary: NormalizationSummary {
                total_parsed: 15,
                total_normalized: 14,
                records_dropped: 1,
                normalization_rate: 0.933,
            },
            correlation_findings: CorrelationSummary {
                total_events_reconstructed: 10,
                total_sessions: 3,
                gaps_detected: 1,
                overlaps_detected: 0,
            },
            anomalies: Vec::new(),
            confidence_distribution: ConfidenceDistribution {
                definitive: 1,
                high: 2,
                moderate: 1,
                low: 0,
                contradicted: 0,
            },
        }
    }

    fn sample_custody() -> CustodyDocumentV2 {
        CustodyDocumentV2 {
            investigation_id: InvestigationId::new(),
            examiner: "Test Examiner".to_string(),
            device_info: DeviceInfo {
                description: "Test Device".to_string(),
                serial: Some("SN123".to_string()),
            },
            evidence_timeline: vec![CustodyEntry {
                timestamp: Utc::now(),
                action: "DeviceConnected".to_string(),
                actor: "SYSTEM".to_string(),
                details: "Test device connected".to_string(),
                audit_entry_reference: "#0 (test-uuid)".to_string(),
            }],
            integrity_verification_status: IntegrityStatus::Verified,
            generated_at: Utc::now(),
            document_hash: format!("{:064x}", 99),
        }
    }

    #[test]
    fn test_json_export_produces_valid_json_with_hash() {
        let dir = TempDir::new().unwrap();
        let output = dir.path().join("test_export.json");

        let bundle = export_investigation_json(
            sample_summary(),
            sample_executive(),
            sample_technical(),
            sample_custody(),
            &output,
        )
        .unwrap();

        // File should exist and contain valid JSON.
        assert!(output.exists());
        let content = std::fs::read_to_string(&output).unwrap();
        let parsed: ReportBundle = serde_json::from_str(&content).unwrap();

        // Hash should be present and valid.
        assert!(parsed.content_hash.is_some());
        let hash = parsed.content_hash.as_ref().unwrap();
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Schema version should be set.
        assert_eq!(parsed.schema_version, "1.0.0");
    }

    #[test]
    fn test_json_export_hash_verification() {
        let dir = TempDir::new().unwrap();
        let output = dir.path().join("verify_export.json");

        let bundle = export_investigation_json(
            sample_summary(),
            sample_executive(),
            sample_technical(),
            sample_custody(),
            &output,
        )
        .unwrap();

        // The bundle should verify successfully.
        assert!(verify_bundle_hash(&bundle).unwrap());
    }

    #[test]
    fn test_json_export_tamper_detection() {
        let dir = TempDir::new().unwrap();
        let output = dir.path().join("tamper_export.json");

        let mut bundle = export_investigation_json(
            sample_summary(),
            sample_executive(),
            sample_technical(),
            sample_custody(),
            &output,
        )
        .unwrap();

        // Tamper with the bundle.
        bundle.summary.case_number = "TAMPERED".to_string();

        // Verification should fail.
        assert!(!verify_bundle_hash(&bundle).unwrap());
    }

    #[test]
    fn test_json_export_no_hash_returns_false() {
        let bundle = ReportBundle {
            schema_version: "1.0.0".to_string(),
            summary: sample_summary(),
            executive: sample_executive(),
            technical: sample_technical(),
            custody: sample_custody(),
            exported_at: Utc::now(),
            content_hash: None,
        };

        assert!(!verify_bundle_hash(&bundle).unwrap());
    }
}
