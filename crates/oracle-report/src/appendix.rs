//! # Evidence Appendix Generator
//!
//! Constructs the evidence appendix section of a forensic report. The appendix
//! is a comprehensive inventory of every artifact acquired during the
//! investigation, including SHA-256 hashes, file sizes, acquisition timestamps,
//! and cross-references to findings that rely on each artifact.
//!
//! The appendix serves as the primary reference for defense counsel and
//! opposing experts to verify that evidence was properly handled and that
//! every finding traces back to a concrete, hash-verified artifact.

use chrono::Utc;
use tracing::info;

use crate::types::{EvidenceEntry, ReportFinding};

/// An assembled evidence appendix ready for inclusion in a report.
#[derive(Debug, Clone)]
pub struct EvidenceAppendix {
    /// All evidence entries, sorted by evidence number.
    pub entries: Vec<EvidenceEntry>,
    /// Total size of all artifacts in bytes.
    pub total_size_bytes: u64,
    /// Number of unique artifact classes represented.
    pub artifact_classes: Vec<String>,
    /// SHA-256 hash of the appendix itself for tamper evidence.
    pub appendix_hash: String,
    /// When the appendix was generated.
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

/// Builds an [`EvidenceAppendix`] from raw artifact metadata and findings.
///
/// The builder cross-references findings against evidence entries to populate
/// the `referenced_by_findings` field on each entry.
pub struct EvidenceAppendixBuilder {
    entries: Vec<EvidenceEntryInput>,
    findings: Vec<ReportFinding>,
}

/// Input data for a single evidence entry before cross-referencing.
#[derive(Debug, Clone)]
pub struct EvidenceEntryInput {
    /// Original path on the device.
    pub original_path: String,
    /// SHA-256 hash of the raw artifact.
    pub sha256_hash: String,
    /// Size of the artifact in bytes.
    pub size_bytes: u64,
    /// When the artifact was acquired (UTC).
    pub acquired_at: chrono::DateTime<chrono::Utc>,
    /// Classification of the artifact (e.g., "WPA Supplicant Config").
    pub artifact_class: String,
}

impl EvidenceAppendixBuilder {
    /// Create a new appendix builder.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            findings: Vec::new(),
        }
    }

    /// Add an evidence entry input to the appendix.
    pub fn add_entry(&mut self, entry: EvidenceEntryInput) {
        self.entries.push(entry);
    }

    /// Add all findings for cross-referencing.
    ///
    /// Findings are matched to evidence entries by comparing the artifact's
    /// original path against the finding's corroborating sources.
    pub fn set_findings(&mut self, findings: Vec<ReportFinding>) {
        self.findings = findings;
    }

    /// Build the evidence appendix.
    ///
    /// Assigns sequential evidence numbers (E-001, E-002, ...), calculates
    /// cross-references between findings and evidence entries, and computes
    /// a tamper-evident hash of the entire appendix.
    pub fn build(self) -> EvidenceAppendix {
        info!(
            entries = self.entries.len(),
            findings = self.findings.len(),
            "Building evidence appendix"
        );

        let mut evidence_entries: Vec<EvidenceEntry> = self
            .entries
            .into_iter()
            .enumerate()
            .map(|(idx, input)| {
                let evidence_number = format!("E-{:03}", idx + 1);

                // Cross-reference: which findings reference this artifact?
                let referenced_by: Vec<String> = self
                    .findings
                    .iter()
                    .filter(|f| {
                        f.corroborating_sources
                            .iter()
                            .any(|src| input.original_path.contains(src) || src.contains(&input.original_path))
                    })
                    .map(|f| f.finding_number.clone())
                    .collect();

                EvidenceEntry {
                    evidence_number,
                    original_path: input.original_path,
                    sha256_hash: input.sha256_hash,
                    size_bytes: input.size_bytes,
                    acquired_at: input.acquired_at,
                    artifact_class: input.artifact_class,
                    referenced_by_findings: referenced_by,
                }
            })
            .collect();

        // Sort by evidence number for deterministic ordering.
        evidence_entries.sort_by(|a, b| a.evidence_number.cmp(&b.evidence_number));

        let total_size_bytes: u64 = evidence_entries.iter().map(|e| e.size_bytes).sum();

        // Collect unique artifact classes.
        let mut artifact_classes: Vec<String> = evidence_entries
            .iter()
            .map(|e| e.artifact_class.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        artifact_classes.sort();

        // Compute appendix hash over all entry hashes for tamper evidence.
        let appendix_hash = Self::compute_appendix_hash(&evidence_entries);

        info!(
            total_entries = evidence_entries.len(),
            total_size_bytes = total_size_bytes,
            artifact_classes = artifact_classes.len(),
            "Evidence appendix built"
        );

        EvidenceAppendix {
            entries: evidence_entries,
            total_size_bytes,
            artifact_classes,
            appendix_hash,
            generated_at: Utc::now(),
        }
    }

    /// Compute a SHA-256 hash over all evidence entry hashes, chained together.
    ///
    /// This creates a single tamper-evident digest that covers every artifact
    /// in the appendix. If any hash is modified, this digest will change.
    fn compute_appendix_hash(entries: &[EvidenceEntry]) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        for entry in entries {
            hasher.update(entry.evidence_number.as_bytes());
            hasher.update(b"|");
            hasher.update(entry.sha256_hash.as_bytes());
            hasher.update(b"|");
            hasher.update(entry.size_bytes.to_le_bytes());
            hasher.update(b"|");
        }
        hex::encode(hasher.finalize())
    }
}

impl Default for EvidenceAppendixBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Render the evidence appendix as a formatted plain-text table suitable for
/// inclusion in text or PDF reports.
pub fn render_appendix_text(appendix: &EvidenceAppendix) -> String {
    let mut output = String::new();

    output.push_str("═══════════════════════════════════════════════════════════════════\n");
    output.push_str("                         EVIDENCE APPENDIX\n");
    output.push_str("═══════════════════════════════════════════════════════════════════\n\n");

    output.push_str(&format!(
        "Total Artifacts: {}    Total Size: {} bytes\n",
        appendix.entries.len(),
        appendix.total_size_bytes,
    ));
    output.push_str(&format!(
        "Artifact Classes: {}\n",
        appendix.artifact_classes.join(", ")
    ));
    output.push_str(&format!(
        "Appendix Hash: {}\n",
        appendix.appendix_hash
    ));
    output.push_str(&format!(
        "Generated: {}\n\n",
        appendix.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    output.push_str("───────────────────────────────────────────────────────────────────\n");

    for entry in &appendix.entries {
        output.push_str(&format!("  {} | {}\n", entry.evidence_number, entry.artifact_class));
        output.push_str(&format!("    Path:    {}\n", entry.original_path));
        output.push_str(&format!("    SHA-256: {}\n", entry.sha256_hash));
        output.push_str(&format!("    Size:    {} bytes\n", entry.size_bytes));
        output.push_str(&format!(
            "    Acquired: {}\n",
            entry.acquired_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        if !entry.referenced_by_findings.is_empty() {
            output.push_str(&format!(
                "    Referenced by: {}\n",
                entry.referenced_by_findings.join(", ")
            ));
        } else {
            output.push_str("    Referenced by: (none)\n");
        }
        output.push_str("───────────────────────────────────────────────────────────────────\n");
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_input(idx: usize) -> EvidenceEntryInput {
        EvidenceEntryInput {
            original_path: format!("/data/misc/wifi/file_{}.conf", idx),
            sha256_hash: format!("{:064x}", idx),
            size_bytes: 1024 * (idx as u64 + 1),
            acquired_at: Utc::now(),
            artifact_class: if idx % 2 == 0 {
                "WPA Supplicant Config".to_string()
            } else {
                "DHCP Leases".to_string()
            },
        }
    }

    #[test]
    fn test_appendix_builder_sequential_numbering() {
        let mut builder = EvidenceAppendixBuilder::new();
        builder.add_entry(sample_input(0));
        builder.add_entry(sample_input(1));
        builder.add_entry(sample_input(2));

        let appendix = builder.build();

        assert_eq!(appendix.entries.len(), 3);
        assert_eq!(appendix.entries[0].evidence_number, "E-001");
        assert_eq!(appendix.entries[1].evidence_number, "E-002");
        assert_eq!(appendix.entries[2].evidence_number, "E-003");
    }

    #[test]
    fn test_appendix_total_size() {
        let mut builder = EvidenceAppendixBuilder::new();
        builder.add_entry(sample_input(0));
        builder.add_entry(sample_input(1));

        let appendix = builder.build();
        // size_bytes = 1024 * 1 + 1024 * 2 = 3072
        assert_eq!(appendix.total_size_bytes, 3072);
    }

    #[test]
    fn test_appendix_artifact_classes() {
        let mut builder = EvidenceAppendixBuilder::new();
        builder.add_entry(sample_input(0));
        builder.add_entry(sample_input(1));
        builder.add_entry(sample_input(2));

        let appendix = builder.build();
        assert_eq!(appendix.artifact_classes.len(), 2);
        assert!(appendix.artifact_classes.contains(&"DHCP Leases".to_string()));
        assert!(appendix.artifact_classes.contains(&"WPA Supplicant Config".to_string()));
    }

    #[test]
    fn test_appendix_hash_is_sha256() {
        let mut builder = EvidenceAppendixBuilder::new();
        builder.add_entry(sample_input(0));

        let appendix = builder.build();
        assert_eq!(appendix.appendix_hash.len(), 64);
        assert!(appendix.appendix_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_appendix_text_rendering() {
        let mut builder = EvidenceAppendixBuilder::new();
        builder.add_entry(sample_input(0));

        let appendix = builder.build();
        let text = render_appendix_text(&appendix);

        assert!(text.contains("EVIDENCE APPENDIX"));
        assert!(text.contains("E-001"));
        assert!(text.contains("WPA Supplicant Config"));
    }
}
