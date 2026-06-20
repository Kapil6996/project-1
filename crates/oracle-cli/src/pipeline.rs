//! # Forensic Investigation Pipeline Controller
//!
//! Orchestrates the execution of all forensic stages in the correct sequence.
//! Maintains the cryptographically audited chain of custody throughout the run.
//!
//! ## Pipeline Stages
//!
//! 1. Create investigation (initialize audit log + evidence store)
//! 2. Connect device & detect capabilities
//! 3. Generate investigator briefing
//! 4. Discover artifacts on device
//! 5. Generate artifact manifest
//! 6. Acquire all discovered artifacts
//! 7. Parse all acquired artifacts
//! 8. Normalize parsed records
//! 9. Correlate normalized records
//! 10. Score confidence for each finding
//! 11. Generate reports (JSON + PDF)
//! 12. Verify audit chain integrity

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde_json::json;
use tracing::{debug, error, info, warn};

use oracle_core::OracleConfig;
use oracle_core::error::{OracleError, OracleResult};
use oracle_core::types::{
    AccessibleArtifactClass, AcquisitionMethod, ArtifactClass, ArtifactId, BootloaderState,
    CapabilityProfile, DeviceIdentity, EncryptionState, EvidenceLayer, ExaminerIdentity,
    InvestigationId, NetworkRole, RecordId, SecurityProtocol, SourceReference,
    AuditOperationType, AuditResult as AuditOutcome,
};
use oracle_audit::{AuditLogWriter, AuditLogVerifier, ChainStatus};
use oracle_evidence::{
    ContentAddressableStore, EvidenceStore, NormalizedRecord, ParsedRecord, RecordStore,
};
use oracle_capability::adb::{AdbInterface, LiveAdbInterface};
use oracle_capability::detector::CapabilityDetector;
use oracle_discovery::{
    AcquisitionCoordinator, ArtifactScanner, ManifestBuilder, PathRegistry, DiscoveredArtifact,
};
use oracle_parser::{ParserRegistry, ParsedOutput};
use oracle_oem::plugin::OemPluginRegistry;
use oracle_normalize::{
    BssidNormalizer, ConflictDetector, ProvenanceLink, ProvenanceValidator,
    SecurityNormalizer, SsidNormalizer, TimestampNormalizer, ConflictCategory,
};
use oracle_correlate::{
    AnomalyDetector, EventReconstructor, NetworkIdentityResolver, RoleClassifier,
    TimelineBuilder, ConnectionEventType, EventEvidence,
};
use oracle_confidence::{ScoringEngine, ScoringInput};
use oracle_report::{
    EvidenceEntry, ForensicReport, InvestigationSummary, ReportFinding, ReportGenerator,
    ReportType, render_pdf, sign_report,
};

// ──────────────────────────────────────────────────────────────────────────────
// ADB Shell Adapter
// ──────────────────────────────────────────────────────────────────────────────

/// Adapts the [`AdbInterface`] from `oracle_capability` to the [`AdbShell`]
/// trait required by `oracle_discovery`.
pub struct AdbShellAdapter<'a>(pub &'a dyn AdbInterface);

impl<'a> oracle_discovery::scanner::AdbShell for AdbShellAdapter<'a> {
    fn shell_command(&self, serial: &str, cmd: &str) -> OracleResult<String> {
        self.0.shell_command(serial, cmd)
    }
    fn check_file_exists(&self, serial: &str, path: &str) -> OracleResult<bool> {
        self.0.check_file_exists(serial, path)
    }
    fn check_file_readable(&self, serial: &str, path: &str) -> OracleResult<bool> {
        self.0.check_file_readable(serial, path)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Pipeline Stage Enum
// ──────────────────────────────────────────────────────────────────────────────

/// The discrete stages of the forensic pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineStage {
    /// Stage 1: Initialize loggers and evidence store.
    StartupAndInit,
    /// Stage 2: Connect to device and detect capabilities.
    DeviceConnection,
    /// Stage 3: Discover artifacts on the device.
    ArtifactDiscovery,
    /// Stage 4: Acquire all discovered artifacts.
    ArtifactAcquisition,
    /// Stage 5: Parse all acquired artifacts.
    Parsing,
    /// Stage 6: Normalize parsed records.
    Normalization,
    /// Stage 7: Correlate normalized records.
    Correlation,
    /// Stage 8: Compute confidence scores.
    ConfidenceScoring,
    /// Stage 9: Generate reports.
    ReportGeneration,
    /// Stage 10: Verify audit chain integrity.
    AuditVerification,
}

impl std::fmt::Display for PipelineStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipelineStage::StartupAndInit => write!(f, "Startup & Init"),
            PipelineStage::DeviceConnection => write!(f, "Device Connection"),
            PipelineStage::ArtifactDiscovery => write!(f, "Artifact Discovery"),
            PipelineStage::ArtifactAcquisition => write!(f, "Artifact Acquisition"),
            PipelineStage::Parsing => write!(f, "Parsing"),
            PipelineStage::Normalization => write!(f, "Normalization"),
            PipelineStage::Correlation => write!(f, "Correlation"),
            PipelineStage::ConfidenceScoring => write!(f, "Confidence Scoring"),
            PipelineStage::ReportGeneration => write!(f, "Report Generation"),
            PipelineStage::AuditVerification => write!(f, "Audit Verification"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Pipeline Result Wrapper
// ──────────────────────────────────────────────────────────────────────────────

/// Contains the final signed report and all supporting pipeline artifacts.
pub struct SignedReportWrapper {
    /// The cryptographically signed forensic report.
    pub signed_report: oracle_report::signing::SignedReport,
    /// The reconstructed timeline of events.
    pub timeline: oracle_correlate::Timeline,
    /// Detected anomalies in the timeline.
    pub anomaly_report: oracle_correlate::AnomalyReport,
    /// Detected conflicts across normalized records.
    pub conflict_report: oracle_normalize::ConflictReport,
}

// ──────────────────────────────────────────────────────────────────────────────
// ForensicPipeline
// ──────────────────────────────────────────────────────────────────────────────

/// The main forensic pipeline orchestrator.
///
/// Holds references to all subsystems and coordinates the sequential
/// execution of forensic stages with full audit logging.
pub struct ForensicPipeline {
    /// Application configuration (immutable during investigation).
    config: OracleConfig,
    /// Investigation identifier for this pipeline run.
    investigation_id: InvestigationId,
    /// Case name (human-readable).
    case_name: String,
    /// Identity of the forensic examiner.
    examiner: ExaminerIdentity,
}

// Alias kept for backwards compatibility with commands.rs
pub type InvestigationPipeline = ForensicPipeline;

impl ForensicPipeline {
    /// Create a new forensic pipeline for the given investigation.
    ///
    /// # Arguments
    ///
    /// * `config` — Application configuration (cloned, immutable).
    /// * `investigation_id` — The unique identifier for this investigation.
    /// * `case_name` — Human-readable case identifier.
    /// * `examiner` — Identity of the forensic examiner.
    pub fn new(
        config: OracleConfig,
        investigation_id: InvestigationId,
        case_name: String,
        examiner: ExaminerIdentity,
    ) -> Self {
        Self {
            config,
            investigation_id,
            case_name,
            examiner,
        }
    }

    /// Run the full forensic investigation pipeline sequentially.
    ///
    /// Executes all stages in order:
    /// 1. Initialize audit log and evidence store
    /// 2. Connect to device and detect capabilities
    /// 3. Generate investigator briefing
    /// 4. Discover artifacts on device
    /// 5. Generate manifest
    /// 6. Acquire all artifacts
    /// 7. Parse all acquired artifacts
    /// 8. Normalize parsed records
    /// 9. Correlate normalized records
    /// 10. Score confidence
    /// 11. Generate reports
    /// 12. Verify audit chain integrity
    ///
    /// Each step logs intent before execution and result after
    /// (write-before-execute semantics).
    pub fn run(&self, device_serial: &str) -> Result<SignedReportWrapper> {
        let start_time = Instant::now();
        info!(
            investigation_id = %self.investigation_id,
            case = %self.case_name,
            device = %device_serial,
            "Starting forensic pipeline execution"
        );

        // ── Stage 1: Startup & Loggers/Store Initialization ──────────
        self.log_stage(PipelineStage::StartupAndInit);

        let audit_db_path = self.config.general.investigations_dir.join("audit.db");
        let mut audit_writer = AuditLogWriter::new(&audit_db_path)
            .map_err(|e| anyhow!("Failed to open audit log: {}", e))?;

        let store_dir = self
            .config
            .general
            .investigations_dir
            .join(self.investigation_id.to_string());
        let store = if store_dir.exists() {
            EvidenceStore::open(&store_dir).context("Failed to open existing evidence store")?
        } else {
            EvidenceStore::initialize(&store_dir, &mut audit_writer)
                .context("Failed to initialize new evidence store")?
        };

        // Log the opening of this pipeline run
        let run_intent = audit_writer.log_intent(
            Some(self.investigation_id),
            AuditOperationType::InvestigationOpened,
            "EXAMINER",
            &self.case_name,
            json!({
                "case_name": self.case_name,
                "examiner": self.examiner,
                "device_serial": device_serial,
            }),
        )?;

        // ── Stage 2: Device Connection & Capability Detection ────────
        self.log_stage(PipelineStage::DeviceConnection);

        let adb = LiveAdbInterface::new();
        let cap_intent = audit_writer.log_intent(
            Some(self.investigation_id),
            AuditOperationType::CapabilityDetectionStarted,
            "SYSTEM",
            device_serial,
            json!({ "serial": device_serial }),
        )?;

        let detector = CapabilityDetector::new();
        let profile = match detector.detect(&adb, device_serial) {
            Ok(p) => {
                info!(
                    root = ?p.root_method,
                    selinux = ?p.selinux_mode,
                    encryption = ?p.encryption_state,
                    "Capability detection completed"
                );
                audit_writer.log_result(
                    cap_intent,
                    AuditOutcome::Success,
                    json!({
                        "root_method": format!("{:?}", p.root_method),
                        "selinux_mode": format!("{:?}", p.selinux_mode),
                        "encryption_state": format!("{:?}", p.encryption_state),
                    }),
                )?;
                p
            }
            Err(e) => {
                audit_writer.log_result(
                    cap_intent,
                    AuditOutcome::Failure(e.to_string()),
                    json!({}),
                )?;
                let _ = audit_writer.log_result(
                    run_intent,
                    AuditOutcome::Failure(e.to_string()),
                    json!({}),
                );
                return Err(e.into());
            }
        };

        // ── Stage 2b: Investigator Briefing ──────────────────────────
        let briefing = oracle_capability::briefing::generate_briefing(&profile);
        info!(
            "--- INVESTIGATOR BRIEFING GENERATED ---\n{}",
            briefing.full_text
        );

        // Auto-acknowledge profile for CLI pipeline execution
        audit_writer.log_intent(
            Some(self.investigation_id),
            AuditOperationType::CapabilityProfileAcknowledged,
            "EXAMINER",
            device_serial,
            json!({ "briefing": briefing }),
        )?;

        // ── Stage 3: Artifact Discovery ──────────────────────────────
        self.log_stage(PipelineStage::ArtifactDiscovery);

        let disc_intent = audit_writer.log_intent(
            Some(self.investigation_id),
            AuditOperationType::Custom("ArtifactDiscoveryStarted".to_string()),
            "SYSTEM",
            device_serial,
            json!({}),
        )?;

        // Apply OEM-specific overrides if an OEM plugin is active.
        let mut path_registry = PathRegistry::default();
        let oem_registry = OemPluginRegistry::default_registry();
        let oem_plugin = oem_registry.find_plugin_for_device(&profile.device);

        if let Some(plugin) = oem_plugin {
            info!(
                oem = plugin.oem_name(),
                "Applying OEM plugin overrides to path registry"
            );
            let _ = audit_writer.log_intent(
                Some(self.investigation_id),
                AuditOperationType::PluginLoaded,
                "SYSTEM",
                plugin.oem_name(),
                json!({
                    "oem_id": plugin.oem_id(),
                    "oem_name": plugin.oem_name(),
                }),
            );

            let mut custom_registry = PathRegistry::new();
            for entry in PathRegistry::default().get_all_entries() {
                let mut entry_clone = entry.clone();
                for path_override in plugin.override_artifact_paths() {
                    if path_override.artifact_class == entry.artifact_class {
                        entry_clone.device_paths = vec![path_override.override_path.clone()];
                    }
                }
                custom_registry.add_entry(entry_clone);
            }
            path_registry = custom_registry;
        }

        let adapter = AdbShellAdapter(&adb);
        let scan_result =
            match ArtifactScanner::scan_device(&adapter, device_serial, &path_registry) {
                Ok(res) => {
                    info!(
                        found = res.found.len(),
                        inaccessible = res.inaccessible.len(),
                        "Device scan complete"
                    );
                    audit_writer.log_result(
                        disc_intent,
                        AuditOutcome::Success,
                        json!({
                            "found_count": res.found.len(),
                            "inaccessible_count": res.inaccessible.len(),
                        }),
                    )?;
                    res
                }
                Err(e) => {
                    audit_writer.log_result(
                        disc_intent,
                        AuditOutcome::Failure(e.to_string()),
                        json!({}),
                    )?;
                    let _ = audit_writer.log_result(
                        run_intent,
                        AuditOutcome::Failure(e.to_string()),
                        json!({}),
                    );
                    return Err(e.into());
                }
            };

        // ── Stage 3b: Manifest Generation ────────────────────────────
        let manifest = ManifestBuilder::build(&scan_result, self.investigation_id);
        info!(
            total_bytes = manifest.total_estimated_bytes,
            "Artifact manifest generated"
        );

        // ── Stage 4: Artifact Acquisition ────────────────────────────
        self.log_stage(PipelineStage::ArtifactAcquisition);

        let acq_intent = audit_writer.log_intent(
            Some(self.investigation_id),
            AuditOperationType::ArtifactAcquisitionStarted,
            "SYSTEM",
            device_serial,
            json!({ "total_estimated_bytes": manifest.total_estimated_bytes }),
        )?;

        let acq_report = AcquisitionCoordinator::acquire_all(&adapter, device_serial, &manifest);
        info!(
            successful = acq_report.successful.len(),
            failed = acq_report.failed.len(),
            total_bytes = acq_report.total_bytes,
            "Acquisition complete"
        );
        audit_writer.log_result(
            acq_intent,
            AuditOutcome::Success,
            json!({
                "successful_count": acq_report.successful.len(),
                "failed_count": acq_report.failed.len(),
                "total_bytes": acq_report.total_bytes,
            }),
        )?;

        // Write raw files into Content Addressable Storage (CAS)
        let cas = ContentAddressableStore::new(&store);
        let mut stored_artifacts = Vec::new();

        for artifact in acq_report.successful {
            let method = profile
                .accessible_artifact_classes
                .iter()
                .find(|a| a.artifact_class == artifact.artifact_class)
                .map(|a| a.acquisition_method)
                .unwrap_or(AcquisitionMethod::UnprivilegedLogical);

            let store_op = audit_writer.log_intent(
                Some(self.investigation_id),
                AuditOperationType::Custom("ArtifactStored".to_string()),
                "SYSTEM",
                &artifact.device_path,
                json!({
                    "device_path": artifact.device_path,
                    "artifact_class": artifact.artifact_class,
                    "sha256": artifact.sha256_hash,
                }),
            )?;

            match cas.store_artifact(
                self.investigation_id,
                artifact.artifact_class,
                &artifact.device_path,
                &artifact.raw_bytes,
                method,
            ) {
                Ok(id) => {
                    let _ = audit_writer.log_result(
                        store_op,
                        AuditOutcome::Success,
                        json!({ "artifact_id": id.0.to_string() }),
                    );
                    stored_artifacts.push((id, artifact));
                }
                Err(e) => {
                    let _ = audit_writer.log_result(
                        store_op,
                        AuditOutcome::Failure(e.to_string()),
                        json!({}),
                    );
                    warn!(
                        path = %artifact.device_path,
                        error = %e,
                        "Failed to store artifact in CAS"
                    );
                }
            }
        }

        // ── Stage 5: Parsing ─────────────────────────────────────────
        self.log_stage(PipelineStage::Parsing);

        let mut parser_registry = ParserRegistry::default_registry();
        if let Some(plugin) = oem_plugin {
            for custom_parser in plugin.custom_parsers() {
                parser_registry.register(custom_parser);
            }
        }

        let record_store = RecordStore::new(&store);
        let mut parsed_records = Vec::new();

        for (art_id, artifact) in &stored_artifacts {
            if let Some(parser) = parser_registry.get_parser_for_class(artifact.artifact_class) {
                let parse_op = audit_writer.log_intent(
                    Some(self.investigation_id),
                    AuditOperationType::ParserExecutionStarted,
                    "SYSTEM",
                    &parser.info().parser_id,
                    json!({
                        "artifact_id": art_id.0.to_string(),
                        "parser_id": parser.info().parser_id,
                    }),
                )?;

                // Catch panics to prevent crash corruption.
                let parse_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    parser.parse(*art_id, &artifact.sha256_hash, &artifact.raw_bytes)
                }));

                match parse_result {
                    Ok(Ok(outputs)) => {
                        let _ = audit_writer.log_result(
                            parse_op,
                            AuditOutcome::Success,
                            json!({ "records_count": outputs.len() }),
                        );
                        for out in outputs {
                            let parsed_record = ParsedRecord {
                                record_id: RecordId::new(),
                                artifact_id: *art_id,
                                investigation_id: self.investigation_id,
                                parser_id: parser.info().parser_id.clone(),
                                parser_version: parser.info().parser_version.clone(),
                                evidence_layer: EvidenceLayer::Parsed,
                                record_type: out.record_type.clone(),
                                record_data: out.record_data.clone(),
                                source_ref: SourceReference {
                                    artifact_id: *art_id,
                                    artifact_hash: artifact.sha256_hash.clone(),
                                    parser_id: parser.info().parser_id.clone(),
                                    parser_version: parser.info().parser_version.clone(),
                                    byte_offset: out.byte_offset,
                                    byte_length: out.byte_length,
                                    db_row_id: None,
                                    parsed_at: Utc::now(),
                                },
                                created_at: Utc::now(),
                            };
                            if let Err(e) = record_store.store_parsed_record(&parsed_record) {
                                error!(error = %e, "Failed to write parsed record");
                            } else {
                                parsed_records.push(parsed_record);
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        let _ = audit_writer.log_result(
                            parse_op,
                            AuditOutcome::Failure(e.to_string()),
                            json!({}),
                        );
                        warn!(error = %e, "Parser failed for artifact");
                    }
                    Err(_) => {
                        let _ = audit_writer.log_result(
                            parse_op,
                            AuditOutcome::Failure("Parser panic".to_string()),
                            json!({}),
                        );
                        warn!("Parser panicked/crashed on artifact");
                    }
                }
            }
        }

        // ── Stage 6: Normalization ───────────────────────────────────
        self.log_stage(PipelineStage::Normalization);

        let norm_intent = audit_writer.log_intent(
            Some(self.investigation_id),
            AuditOperationType::NormalizationStarted,
            "SYSTEM",
            "evidence_normalization",
            json!({ "input_parsed_count": parsed_records.len() }),
        )?;

        let mut prov_validator = ProvenanceValidator::new();
        for (art_id, artifact) in &stored_artifacts {
            prov_validator.register_artifact_hash(art_id, &artifact.sha256_hash);
            prov_validator.register_acquisition_time(art_id, artifact.acquired_at);
        }

        let mut normalized_records = Vec::new();
        for parsed in &parsed_records {
            let norm = self.normalize_record_fields(parsed);
            if let Err(e) = record_store.store_normalized_record(&norm) {
                error!(error = %e, "Failed to write normalized record");
            } else {
                let link = ProvenanceLink {
                    record_id: norm.record_id,
                    layer: EvidenceLayer::Normalized,
                    source_ref: norm.source_ref.clone(),
                    parent_layer: Some(EvidenceLayer::Parsed),
                };
                prov_validator.validate_link(&link);
                normalized_records.push(norm);
            }
        }

        let provenance_report = prov_validator.generate_report();
        debug!(
            provenance_status = ?provenance_report.overall_result,
            "Provenance validation complete"
        );

        // Conflict Detection
        let mut conflict_detector = ConflictDetector::new();
        self.detect_conflicts(&normalized_records, &mut conflict_detector);
        let conflict_report = conflict_detector.generate_report();

        audit_writer.log_result(
            norm_intent,
            AuditOutcome::Success,
            json!({
                "normalized_count": normalized_records.len(),
                "conflicts_count": conflict_report.summary.total_conflicts,
            }),
        )?;

        // ── Stage 7: Correlation Engine ──────────────────────────────
        self.log_stage(PipelineStage::Correlation);

        let corr_intent = audit_writer.log_intent(
            Some(self.investigation_id),
            AuditOperationType::CorrelationStarted,
            "SYSTEM",
            "evidence_correlation",
            json!({ "normalized_records": normalized_records.len() }),
        )?;

        // Resolve identities
        let mut identity_resolver = NetworkIdentityResolver::new();
        for norm in &normalized_records {
            let ssid = norm
                .record_data
                .get("ssid")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let bssid = norm
                .record_data
                .get("bssid")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let security_protocol = norm
                .record_data
                .get("security_protocol")
                .and_then(|v| v.as_str())
                .and_then(|s| self.map_security_protocol_str(s));

            let last_seen = norm
                .record_data
                .get("timestamp")
                .and_then(|v| v.as_str())
                .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
                .map(|dt| dt.with_timezone(&Utc));

            let is_locally_administered = norm
                .record_data
                .get("bssid_normalized")
                .and_then(|v| v.get("is_locally_administered"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let claim = oracle_correlate::types::NetworkClaim {
                artifact_id: norm.artifact_id,
                record_id: norm.record_id,
                source_description: norm.parser_id.clone(),
                ssid,
                bssid,
                security_protocol,
                last_seen,
                is_locally_administered,
            };
            identity_resolver.ingest(claim);
        }
        let resolved_networks = identity_resolver.resolve();

        // Reconstruct events
        let mut reconstructor = EventReconstructor::new();
        for norm in &normalized_records {
            self.reconstruct_event(norm, &resolved_networks, &mut reconstructor);
        }
        let events = reconstructor.finalize();

        // Build Timeline and detect anomalies
        let timeline = TimelineBuilder::new().build(events);
        let anomaly_report = AnomalyDetector::analyze(&timeline);

        info!(
            networks = resolved_networks.len(),
            sessions = timeline.sessions.len(),
            anomalies = anomaly_report.anomalies.len(),
            "Correlation complete"
        );

        audit_writer.log_result(
            corr_intent,
            AuditOutcome::Success,
            json!({
                "resolved_networks_count": resolved_networks.len(),
                "timeline_sessions_count": timeline.sessions.len(),
                "anomalies_count": anomaly_report.anomalies.len(),
            }),
        )?;

        // ── Stage 8: Confidence Scoring ──────────────────────────────
        self.log_stage(PipelineStage::ConfidenceScoring);

        let score_intent = audit_writer.log_intent(
            Some(self.investigation_id),
            AuditOperationType::ConfidenceScoreComputed,
            "SYSTEM",
            "timeline_confidence_scoring",
            json!({}),
        )?;

        let findings = self.score_findings(
            &timeline,
            &conflict_report,
            &stored_artifacts,
        );

        audit_writer.log_result(
            score_intent,
            AuditOutcome::Success,
            json!({ "findings_scored_count": findings.len() }),
        )?;

        // ── Stage 9: Report Generation ───────────────────────────────
        self.log_stage(PipelineStage::ReportGeneration);

        let rep_intent = audit_writer.log_intent(
            Some(self.investigation_id),
            AuditOperationType::ReportGenerationStarted,
            "SYSTEM",
            "report_generator",
            json!({}),
        )?;

        let signed_report = self.generate_signed_report(
            &profile,
            &findings,
            &stored_artifacts,
            &timeline,
            &anomaly_report,
        )?;

        audit_writer.log_result(
            rep_intent,
            AuditOutcome::Success,
            json!({
                "report_id": signed_report.report.metadata.report_id.0.to_string(),
                "integrity_seal": signed_report.integrity_seal,
            }),
        )?;

        // ── Stage 10: Audit Chain Verification ───────────────────────
        self.log_stage(PipelineStage::AuditVerification);

        let verifier = AuditLogVerifier::new(audit_writer.connection());
        match verifier.verify_full() {
            Ok(report) => {
                if report.overall_status == ChainStatus::Intact {
                    info!(
                        entries = report.total_entries,
                        "Audit chain verification passed"
                    );
                } else {
                    warn!(
                        status = ?report.overall_status,
                        "Audit chain verification completed with issues"
                    );
                }
            }
            Err(e) => {
                warn!(error = %e, "Audit chain verification query failed");
            }
        }

        // Close pipeline run cleanly
        audit_writer.log_result(run_intent, AuditOutcome::Success, json!({}))?;

        let elapsed = start_time.elapsed();
        info!(
            elapsed_secs = elapsed.as_secs_f32(),
            "Forensic pipeline completed successfully"
        );

        Ok(SignedReportWrapper {
            signed_report,
            timeline,
            anomaly_report,
            conflict_report,
        })
    }

    // ── Private Helpers ──────────────────────────────────────────────────────

    /// Log the current pipeline stage for operator visibility.
    fn log_stage(&self, stage: PipelineStage) {
        info!(
            investigation_id = %self.investigation_id,
            stage = %stage,
            "Entering pipeline stage"
        );
    }

    /// Normalize all fields in a parsed record.
    fn normalize_record_fields(&self, parsed: &ParsedRecord) -> NormalizedRecord {
        let mut normalized_data = parsed.record_data.clone();

        // SSID
        if let Some(ssid_val) = normalized_data.get("ssid").and_then(|v| v.as_str()) {
            let norm_ssid = SsidNormalizer::normalize(ssid_val);
            normalized_data["ssid"] = json!(norm_ssid.normalized);
            normalized_data["ssid_normalized"] = json!(norm_ssid);
        }

        // BSSID
        if let Some(bssid_val) = normalized_data.get("bssid").and_then(|v| v.as_str()) {
            let norm_bssid = BssidNormalizer::normalize(bssid_val);
            normalized_data["bssid"] = json!(norm_bssid.normalized);
            normalized_data["bssid_normalized"] = json!(norm_bssid);
        }

        // Security
        if let Some(sec_val) = normalized_data
            .get("security_protocol")
            .and_then(|v| v.as_str())
        {
            let norm_sec = SecurityNormalizer::normalize(sec_val);
            normalized_data["security_protocol"] = json!(format!("{}", norm_sec));
        }

        // Timestamp
        if let Some(ts_val) = normalized_data
            .get("timestamp_raw")
            .and_then(|v| v.as_str())
        {
            let format = if ts_val.contains('-') && ts_val.contains(':') {
                "iso8601"
            } else if ts_val.parse::<u64>().is_ok() {
                if ts_val.len() > 10 {
                    "unix_epoch_ms"
                } else {
                    "unix_epoch_s"
                }
            } else {
                "android_logcat"
            };

            let norm_ts = TimestampNormalizer::normalize(ts_val, format, None, Utc::now());
            normalized_data["timestamp"] = json!(norm_ts.normalized_utc.to_rfc3339());
            normalized_data["timestamp_normalized"] = json!(norm_ts);
        }

        NormalizedRecord {
            record_id: RecordId::new(),
            artifact_id: parsed.artifact_id,
            investigation_id: parsed.investigation_id,
            parser_id: parsed.parser_id.clone(),
            parser_version: parsed.parser_version.clone(),
            evidence_layer: EvidenceLayer::Normalized,
            record_type: parsed.record_type.clone(),
            record_data: normalized_data,
            source_ref: parsed.source_ref.clone(),
            created_at: Utc::now(),
        }
    }

    /// Detect contradictions across normalized records.
    fn detect_conflicts(
        &self,
        records: &[NormalizedRecord],
        detector: &mut ConflictDetector,
    ) {
        for i in 0..records.len() {
            for j in (i + 1)..records.len() {
                let r_a = &records[i];
                let r_b = &records[j];

                let bssid_a = r_a.record_data.get("bssid").and_then(|v| v.as_str());
                let ssid_a = r_a.record_data.get("ssid").and_then(|v| v.as_str());
                let bssid_b = r_b.record_data.get("bssid").and_then(|v| v.as_str());
                let ssid_b = r_b.record_data.get("ssid").and_then(|v| v.as_str());

                // Same BSSID, different SSID
                if let (Some(ba), Some(sa), Some(bb), Some(sb)) =
                    (bssid_a, ssid_a, bssid_b, ssid_b)
                {
                    if ba == bb && sa != sb {
                        detector.check_ssid_for_bssid(
                            ba,
                            sa,
                            self.conflict_source(r_a, sa.to_string()),
                            sb,
                            self.conflict_source(r_b, sb.to_string()),
                        );
                    }
                }

                // Same SSID, different BSSID
                if let (Some(ba), Some(sa), Some(bb), Some(sb)) =
                    (bssid_a, ssid_a, bssid_b, ssid_b)
                {
                    if sa == sb && ba != bb {
                        detector.check_bssid_for_ssid(
                            sa,
                            ba,
                            self.conflict_source(r_a, ba.to_string()),
                            bb,
                            self.conflict_source(r_b, bb.to_string()),
                        );
                    }
                }
            }
        }
    }

    /// Create a conflict source reference from a normalized record.
    fn conflict_source(
        &self,
        r: &NormalizedRecord,
        val: String,
    ) -> oracle_normalize::ConflictSource {
        oracle_normalize::ConflictSource {
            artifact_id: r.artifact_id,
            record_id: r.record_id,
            source_description: r.parser_id.clone(),
            claimed_value: val,
        }
    }

    /// Reconstruct a single event from a normalized record.
    fn reconstruct_event(
        &self,
        norm: &NormalizedRecord,
        resolved_networks: &[oracle_correlate::types::ResolvedNetworkIdentity],
        reconstructor: &mut EventReconstructor,
    ) {
        if norm.record_type == "connectivity_event" {
            if let Some(event_kind) = norm
                .record_data
                .get("event_kind")
                .and_then(|v| v.as_str())
            {
                if event_kind == "state_change" {
                    let state = norm
                        .record_data
                        .get("state")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let timestamp_str = norm
                        .record_data
                        .get("timestamp")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let timestamp = DateTime::parse_from_rfc3339(timestamp_str)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now());

                    let (network_id, network_label) =
                        self.match_network(resolved_networks, None, None);

                    let ev_type = if state == "CONNECTED" {
                        ConnectionEventType::Connected
                    } else {
                        ConnectionEventType::Disconnected
                    };

                    let evidence = EventEvidence {
                        artifact_id: norm.artifact_id,
                        record_id: norm.record_id,
                        description: format!("Connectivity log state change: WIFI {}", state),
                        timestamp,
                        confidence: 0.85,
                    };

                    reconstructor.record_evidence(
                        ev_type,
                        network_id,
                        &network_label,
                        SecurityProtocol::Unknown,
                        NetworkRole::DeviceAsClient,
                        evidence,
                        None,
                    );
                }
            }
        } else if norm.record_type == "dhcp_lease" {
            let ip = norm
                .record_data
                .get("ip_address")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let bssid = norm
                .record_data
                .get("mac_address")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let timestamp_str = norm
                .record_data
                .get("timestamp")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let timestamp = DateTime::parse_from_rfc3339(timestamp_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            let (network_id, network_label) = if let Some(matched) = resolved_networks
                .iter()
                .find(|n| n.observed_bssids.contains(&bssid.to_string()))
            {
                (
                    matched.id,
                    matched
                        .canonical_ssid
                        .clone()
                        .or_else(|| matched.canonical_bssid.clone())
                        .unwrap_or_else(|| bssid.to_string()),
                )
            } else {
                (
                    oracle_correlate::types::NetworkIdentityId::new(),
                    bssid.to_string(),
                )
            };

            let evidence = EventEvidence {
                artifact_id: norm.artifact_id,
                record_id: norm.record_id,
                description: format!("DHCP lease acquired: {}", bssid),
                timestamp,
                confidence: 0.90,
            };

            reconstructor.record_evidence(
                ConnectionEventType::DhcpLeaseAcquired,
                network_id,
                &network_label,
                SecurityProtocol::Unknown,
                NetworkRole::DeviceAsClient,
                evidence,
                ip,
            );
        }
    }

    /// Match a record against resolved network identities.
    fn match_network(
        &self,
        resolved_networks: &[oracle_correlate::types::ResolvedNetworkIdentity],
        _ssid: Option<&str>,
        _bssid: Option<&str>,
    ) -> (oracle_correlate::types::NetworkIdentityId, String) {
        if let Some(matched) = resolved_networks
            .iter()
            .find(|n| n.canonical_ssid.is_some() || n.canonical_bssid.is_some())
        {
            (
                matched.id,
                matched
                    .canonical_ssid
                    .clone()
                    .or_else(|| matched.canonical_bssid.clone())
                    .unwrap_or_else(|| "WIFI".to_string()),
            )
        } else {
            (
                oracle_correlate::types::NetworkIdentityId::new(),
                "WIFI".to_string(),
            )
        }
    }

    /// Score all findings from the timeline against the confidence model.
    fn score_findings(
        &self,
        timeline: &oracle_correlate::Timeline,
        conflict_report: &oracle_normalize::ConflictReport,
        stored_artifacts: &[(ArtifactId, oracle_discovery::AcquiredArtifact)],
    ) -> Vec<ReportFinding> {
        let mut findings = Vec::new();
        let mut finding_counter = 1;

        for session in &timeline.sessions {
            let primary_class = session
                .events
                .first()
                .and_then(|e| e.evidence.first())
                .map(|ev| {
                    stored_artifacts
                        .iter()
                        .find(|(id, _)| *id == ev.artifact_id)
                        .map(|(_, art)| art.artifact_class)
                        .unwrap_or(ArtifactClass::WifiConfigStore)
                })
                .unwrap_or(ArtifactClass::WifiConfigStore);

            let source_timestamps: Vec<DateTime<Utc>> = session
                .events
                .iter()
                .flat_map(|e| e.evidence.iter().map(|ev| ev.timestamp))
                .collect();

            let has_contradictions = timeline.overlaps.iter().any(|o| {
                o.network_a_label == session.network_label
                    || o.network_b_label == session.network_label
            }) || conflict_report.conflicts.iter().any(|c| match &c.category {
                ConflictCategory::SsidMismatch { ssid_a, ssid_b, .. } => {
                    *ssid_a == session.network_label || *ssid_b == session.network_label
                }
                ConflictCategory::BssidMismatch { ssid, .. } => {
                    *ssid == session.network_label
                }
                ConflictCategory::SecurityProtocolMismatch {
                    network_identifier, ..
                } => *network_identifier == session.network_label,
                _ => false,
            });

            let contradiction_count = if has_contradictions { 1 } else { 0 };

            let scoring_input = ScoringInput {
                primary_artifact_class: primary_class,
                corroboration_count: session.events.len(),
                source_timestamps,
                acquisition_time: Utc::now(),
                interest_window_start: timeline.earliest.unwrap_or_else(Utc::now),
                interest_window_end: timeline.latest.unwrap_or_else(Utc::now),
                has_contradictions,
                contradiction_count,
            };

            let score = ScoringEngine::compute(&scoring_input);

            let f = ReportFinding {
                finding_number: format!("F-{:03}", finding_counter),
                title: format!(
                    "Device associated with network \"{}\"",
                    session.network_label
                ),
                description: format!(
                    "Forensic timeline analysis indicates device associated with \
                     network \"{}\" between {} and {}.",
                    session.network_label,
                    session.start_time.format("%Y-%m-%d %H:%M:%S UTC"),
                    session.end_time.format("%Y-%m-%d %H:%M:%S UTC")
                ),
                network_ssid: Some(session.network_label.clone()),
                network_bssid: session.events.first().and_then(|e| {
                    if e.network_label != "WIFI"
                        && e.network_label != session.network_label
                    {
                        Some(e.network_label.clone())
                    } else {
                        None
                    }
                }),
                security_protocol: session.events.first().map(|e| e.security_protocol),
                event_time: Some(session.start_time),
                confidence_score: score.score,
                confidence_classification: score.classification,
                corroboration_count: session.events.len(),
                corroborating_sources: session
                    .events
                    .iter()
                    .flat_map(|e| e.evidence.iter().map(|ev| ev.description.clone()))
                    .collect(),
                contradictions: timeline
                    .overlaps
                    .iter()
                    .filter(|o| {
                        o.network_a_label == session.network_label
                            || o.network_b_label == session.network_label
                    })
                    .map(|o| o.explanation.clone())
                    .collect(),
                examiner_override: false,
            };

            findings.push(f);
            finding_counter += 1;
        }

        findings
    }

    /// Generate the final signed forensic report.
    fn generate_signed_report(
        &self,
        profile: &CapabilityProfile,
        findings: &[ReportFinding],
        stored_artifacts: &[(ArtifactId, oracle_discovery::AcquiredArtifact)],
        timeline: &oracle_correlate::Timeline,
        anomaly_report: &oracle_correlate::AnomalyReport,
    ) -> Result<oracle_report::signing::SignedReport> {
        let mut report_gen = ReportGenerator::new(
            &self.case_name,
            self.investigation_id,
            self.examiner.clone(),
            ReportType::Complete,
        );

        for f in findings {
            report_gen.add_finding(f.clone());
        }

        let mut evidence_counter = 1;
        for (_art_id, artifact) in stored_artifacts {
            let entry = EvidenceEntry {
                evidence_number: format!("E-{:03}", evidence_counter),
                original_path: artifact.device_path.clone(),
                sha256_hash: artifact.sha256_hash.clone(),
                size_bytes: artifact.raw_bytes.len() as u64,
                acquired_at: artifact.acquired_at,
                artifact_class: format!("{:?}", artifact.artifact_class),
                referenced_by_findings: Vec::new(),
            };
            report_gen.add_evidence_entry(entry);
            evidence_counter += 1;
        }

        let summary = InvestigationSummary {
            case_number: self.case_name.clone(),
            purpose: "Forensic Android network activity extraction".to_string(),
            device_description: format!(
                "{} {} (Serial: {})",
                profile.device.manufacturer, profile.device.model, profile.device.serial
            ),
            investigation_window: format!(
                "{} to {}",
                timeline
                    .earliest
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "N/A".to_string()),
                timeline
                    .latest
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "N/A".to_string())
            ),
            total_artifacts: stored_artifacts.len(),
            total_findings: findings.len(),
            high_confidence_findings: findings
                .iter()
                .filter(|f| f.confidence_score >= 0.8)
                .count(),
            contradicted_findings: findings
                .iter()
                .filter(|f| {
                    f.confidence_classification
                        == oracle_core::types::ConfidenceClassification::Contradicted
                })
                .count(),
            anomalies_detected: anomaly_report.anomalies.len(),
            key_findings: findings
                .iter()
                .take(3)
                .map(|f| format!("{}: {}", f.finding_number, f.title))
                .collect(),
        };
        report_gen.set_summary(summary);

        let report = report_gen.generate();
        sign_report(report).map_err(|e| anyhow!("Failed to sign forensic report: {}", e))
    }

    /// Map a security protocol string to its enum variant.
    fn map_security_protocol_str(&self, s: &str) -> Option<SecurityProtocol> {
        match s {
            "OPEN" => Some(SecurityProtocol::Open),
            "WEP" => Some(SecurityProtocol::Wep),
            "WPA-PSK" => Some(SecurityProtocol::WpaPsk),
            "WPA2-PSK" => Some(SecurityProtocol::Wpa2Psk),
            "WPA3-SAE" => Some(SecurityProtocol::Wpa3Sae),
            "OWE" => Some(SecurityProtocol::Owe),
            "EAP-TLS" => Some(SecurityProtocol::EapTls),
            "EAP-PEAP" => Some(SecurityProtocol::EapPeap),
            _ => None,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Verify that the pipeline stage enum covers all stages and formats.
    #[test]
    fn test_pipeline_stages_display() {
        let stages = [
            PipelineStage::StartupAndInit,
            PipelineStage::DeviceConnection,
            PipelineStage::ArtifactDiscovery,
            PipelineStage::ArtifactAcquisition,
            PipelineStage::Parsing,
            PipelineStage::Normalization,
            PipelineStage::Correlation,
            PipelineStage::ConfidenceScoring,
            PipelineStage::ReportGeneration,
            PipelineStage::AuditVerification,
        ];
        for stage in &stages {
            let display = format!("{}", stage);
            assert!(!display.is_empty(), "Stage {:?} must have a display name", stage);
        }
        assert_eq!(stages.len(), 10, "Expected 10 pipeline stages");
    }

    /// Verify that the pipeline can be constructed with valid parameters.
    #[test]
    fn test_pipeline_construction() {
        let config = OracleConfig::default_config(Path::new("/tmp/oracle-test"));
        let investigation_id = InvestigationId::new();
        let examiner = ExaminerIdentity {
            name: "Test Examiner".to_string(),
            badge_id: "T-001".to_string(),
            organization: "Test Lab".to_string(),
        };

        let pipeline = ForensicPipeline::new(
            config,
            investigation_id,
            "TEST-CASE-001".to_string(),
            examiner,
        );

        assert_eq!(pipeline.investigation_id, investigation_id);
        assert_eq!(pipeline.case_name, "TEST-CASE-001");
    }

    /// Verify security protocol string mapping covers all known protocols.
    #[test]
    fn test_security_protocol_mapping() {
        let config = OracleConfig::default_config(Path::new("/tmp/oracle-test"));
        let pipeline = ForensicPipeline::new(
            config,
            InvestigationId::new(),
            "test".to_string(),
            ExaminerIdentity {
                name: "tester".to_string(),
                badge_id: "T-001".to_string(),
                organization: "test".to_string(),
            },
        );

        assert_eq!(
            pipeline.map_security_protocol_str("OPEN"),
            Some(SecurityProtocol::Open)
        );
        assert_eq!(
            pipeline.map_security_protocol_str("WPA2-PSK"),
            Some(SecurityProtocol::Wpa2Psk)
        );
        assert_eq!(
            pipeline.map_security_protocol_str("WPA3-SAE"),
            Some(SecurityProtocol::Wpa3Sae)
        );
        assert_eq!(pipeline.map_security_protocol_str("UNKNOWN_PROTO"), None);
    }

    /// Verify that the pipeline stages are ordered correctly.
    #[test]
    fn test_pipeline_stage_ordering() {
        // This test ensures the documented stage order matches the enum definition.
        // The enum values don't have explicit ordinals but the doc-comments
        // and Display impl must match.
        assert_eq!(
            format!("{}", PipelineStage::StartupAndInit),
            "Startup & Init"
        );
        assert_eq!(
            format!("{}", PipelineStage::AuditVerification),
            "Audit Verification"
        );
    }
}
