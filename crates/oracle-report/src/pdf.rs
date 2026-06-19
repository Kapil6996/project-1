//! # PDF Report Renderer
//!
//! Renders a [`ForensicReport`] into a court-ready PDF document using the
//! `printpdf` crate. The PDF includes structured sections for executive
//! summaries, findings, evidence appendices, and methodology disclosures.
//!
//! ## Design Decisions
//!
//! - **No external fonts:** Uses the built-in PDF base fonts (Helvetica,
//!   Courier) to avoid font-file dependencies in forensic lab environments.
//! - **Fixed-width tables:** Evidence hashes and technical data are rendered
//!   in Courier for alignment and readability.
//! - **Deterministic layout:** Page layout is computed from content length,
//!   not from dynamic text measurement, ensuring reproducible output.

use std::io::BufWriter;
use std::path::Path;

use printpdf::*;
use tracing::{info, warn};

use crate::types::{
    EvidenceEntry, ForensicReport, InvestigationSummary, ReportFinding, ReportMetadata, ReportType,
};

/// Standard US Letter page dimensions in millimeters.
const PAGE_WIDTH_MM: f32 = 215.9;
const PAGE_HEIGHT_MM: f32 = 279.4;

/// Margins in millimeters.
const MARGIN_LEFT_MM: f32 = 25.0;
const MARGIN_RIGHT_MM: f32 = 25.0;
const MARGIN_TOP_MM: f32 = 25.0;
const MARGIN_BOTTOM_MM: f32 = 25.0;

/// Font sizes in points.
const FONT_SIZE_TITLE: f32 = 18.0;
const FONT_SIZE_SECTION: f32 = 14.0;
const FONT_SIZE_SUBSECTION: f32 = 11.0;
const FONT_SIZE_BODY: f32 = 10.0;
const FONT_SIZE_SMALL: f32 = 8.0;

/// Line height multiplier (relative to font size).
const LINE_HEIGHT_MULTIPLIER: f32 = 1.4;

/// Renders a [`ForensicReport`] to a PDF file on disk.
///
/// # Arguments
///
/// * `report` — The forensic report to render.
/// * `output_path` — The filesystem path where the PDF will be written.
///
/// # Errors
///
/// Returns an error if the PDF cannot be generated or written to disk.
pub fn render_pdf(report: &ForensicReport, output_path: &Path) -> Result<(), PdfError> {
    info!(
        case = %report.metadata.case_number,
        output = %output_path.display(),
        "Rendering forensic report to PDF"
    );

    let (doc, page_idx, layer_idx) = PdfDocument::new(
        &format!("ORACLE Forensic Report — {}", report.metadata.case_number),
        Mm(PAGE_WIDTH_MM),
        Mm(PAGE_HEIGHT_MM),
        "Layer 1",
    );

    let font_regular = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    let font_mono = doc.add_builtin_font(BuiltinFont::Courier)?;


    let mut renderer = PdfPageRenderer {
        doc: &doc,
        font_regular: &font_regular,
        font_bold: &font_bold,
        font_mono: &font_mono,
        current_page: page_idx,
        current_layer: layer_idx,
        y_position: PAGE_HEIGHT_MM - MARGIN_TOP_MM,
    };

    // ── Title Page ──
    renderer.render_title_page(&report.metadata);

    // ── Executive Summary ──
    renderer.new_page();
    renderer.render_section("EXECUTIVE SUMMARY");
    renderer.render_summary(&report.summary);

    // ── Findings ──
    if !report.findings.is_empty() {
        renderer.new_page();
        renderer.render_section("FINDINGS");
        for finding in &report.findings {
            renderer.render_finding(finding);
        }
    }

    // ── Evidence Appendix ──
    if !report.evidence_entries.is_empty() {
        renderer.new_page();
        renderer.render_section("EVIDENCE APPENDIX");
        for entry in &report.evidence_entries {
            renderer.render_evidence_entry(entry);
        }
    }

    // ── Methodology Disclosure ──
    renderer.new_page();
    renderer.render_section("METHODOLOGY DISCLOSURE");
    renderer.render_body_text(&report.methodology_disclosure);

    // ── Report Hash ──
    if let Some(hash) = &report.report_hash {
        renderer.render_spacer(10.0);
        renderer.render_mono_text(&format!("Report Integrity Seal: {}", hash));
    }

    // Save to disk.
    let file = std::fs::File::create(output_path).map_err(|e| {
        warn!(error = %e, path = %output_path.display(), "Failed to create PDF file");
        PdfError::Io(e)
    })?;
    let mut writer = BufWriter::new(file);
    doc.save(&mut writer).map_err(|e| {
        warn!(error = %e, "Failed to write PDF content");
        PdfError::Rendering(format!("Failed to save PDF: {}", e))
    })?;

    info!(
        output = %output_path.display(),
        "PDF report rendered successfully"
    );

    Ok(())
}

/// Errors that can occur during PDF rendering.
#[derive(Debug)]
pub enum PdfError {
    /// An I/O error occurred writing the file.
    Io(std::io::Error),
    /// A printpdf error occurred during rendering.
    Rendering(String),
}

impl std::fmt::Display for PdfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PdfError::Io(e) => write!(f, "PDF I/O error: {}", e),
            PdfError::Rendering(msg) => write!(f, "PDF rendering error: {}", msg),
        }
    }
}

impl std::error::Error for PdfError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PdfError::Io(e) => Some(e),
            PdfError::Rendering(_) => None,
        }
    }
}

impl From<printpdf::Error> for PdfError {
    fn from(e: printpdf::Error) -> Self {
        PdfError::Rendering(format!("{}", e))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal Page Renderer
// ──────────────────────────────────────────────────────────────────────────────

/// Internal helper that tracks page state while rendering.
struct PdfPageRenderer<'a> {
    doc: &'a PdfDocumentReference,
    font_regular: &'a IndirectFontRef,
    font_bold: &'a IndirectFontRef,
    font_mono: &'a IndirectFontRef,
    current_page: PdfPageIndex,
    current_layer: PdfLayerIndex,
    y_position: f32,
}

impl<'a> PdfPageRenderer<'a> {
    /// Start a new page and reset the Y cursor.
    fn new_page(&mut self) {
        let (page_idx, layer_idx) = self.doc.add_page(
            Mm(PAGE_WIDTH_MM),
            Mm(PAGE_HEIGHT_MM),
            "Layer 1",
        );
        self.current_page = page_idx;
        self.current_layer = layer_idx;
        self.y_position = PAGE_HEIGHT_MM - MARGIN_TOP_MM;
    }

    /// Check if we need a new page and create one if so.
    fn ensure_space(&mut self, needed_mm: f32) {
        if self.y_position - needed_mm < MARGIN_BOTTOM_MM {
            self.new_page();
        }
    }

    /// Get the current layer reference.
    fn layer(&self) -> PdfLayerReference {
        self.doc.get_page(self.current_page).get_layer(self.current_layer)
    }

    /// Add vertical spacing.
    fn render_spacer(&mut self, mm: f32) {
        self.y_position -= mm;
    }

    /// Render the title page with case metadata.
    fn render_title_page(&mut self, metadata: &ReportMetadata) {
        let layer = self.layer();

        // Title
        self.y_position -= 40.0;
        layer.use_text(
            "ORACLE FORENSIC REPORT",
            FONT_SIZE_TITLE,
            Mm(MARGIN_LEFT_MM),
            Mm(self.y_position),
            self.font_bold,
        );

        // Subtitle (report type)
        self.y_position -= 10.0;
        layer.use_text(
            &format!("{}", metadata.report_type),
            FONT_SIZE_SECTION,
            Mm(MARGIN_LEFT_MM),
            Mm(self.y_position),
            self.font_regular,
        );

        // Horizontal rule
        self.y_position -= 5.0;
        let line = Line {
            points: vec![
                (Point::new(Mm(MARGIN_LEFT_MM), Mm(self.y_position)), false),
                (
                    Point::new(Mm(PAGE_WIDTH_MM - MARGIN_RIGHT_MM), Mm(self.y_position)),
                    false,
                ),
            ],
            is_closed: false,
        };
        layer.add_line(line);

        // Metadata fields
        self.y_position -= 15.0;
        let fields = [
            ("Case Number:", &metadata.case_number),
            ("Report ID:", &metadata.report_id.to_string()),
            ("Investigation ID:", &metadata.investigation_id.to_string()),
            ("Examiner:", &metadata.examiner.name),
            ("Organization:", &metadata.examiner.organization),
            ("Badge ID:", &metadata.examiner.badge_id),
            (
                "Generated:",
                &metadata.generated_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            ),
            ("Platform Version:", &metadata.platform_version),
            ("Confidence Model:", &metadata.model_version),
        ];

        for (label, value) in &fields {
            layer.use_text(
                label,
                FONT_SIZE_BODY,
                Mm(MARGIN_LEFT_MM),
                Mm(self.y_position),
                self.font_bold,
            );
            layer.use_text(
                value,
                FONT_SIZE_BODY,
                Mm(MARGIN_LEFT_MM + 45.0),
                Mm(self.y_position),
                self.font_regular,
            );
            self.y_position -= FONT_SIZE_BODY * LINE_HEIGHT_MULTIPLIER * 0.3528; // pt to mm
        }

        // Footer notice
        self.y_position = MARGIN_BOTTOM_MM + 10.0;
        layer.use_text(
            "CONFIDENTIAL — LAW ENFORCEMENT SENSITIVE",
            FONT_SIZE_SMALL,
            Mm(MARGIN_LEFT_MM),
            Mm(self.y_position),
            self.font_bold,
        );
    }

    /// Render a section header.
    fn render_section(&mut self, title: &str) {
        self.ensure_space(15.0);
        let layer = self.layer();

        layer.use_text(
            title,
            FONT_SIZE_SECTION,
            Mm(MARGIN_LEFT_MM),
            Mm(self.y_position),
            self.font_bold,
        );

        self.y_position -= 3.0;
        let line = Line {
            points: vec![
                (Point::new(Mm(MARGIN_LEFT_MM), Mm(self.y_position)), false),
                (
                    Point::new(Mm(PAGE_WIDTH_MM - MARGIN_RIGHT_MM), Mm(self.y_position)),
                    false,
                ),
            ],
            is_closed: false,
        };
        layer.add_line(line);
        self.y_position -= 8.0;
    }

    /// Render the investigation summary.
    fn render_summary(&mut self, summary: &InvestigationSummary) {
        let lines = [
            format!("Case Number: {}", summary.case_number),
            format!("Purpose: {}", summary.purpose),
            format!("Device: {}", summary.device_description),
            format!("Investigation Window: {}", summary.investigation_window),
            format!("Total Artifacts: {}", summary.total_artifacts),
            format!("Total Findings: {}", summary.total_findings),
            format!("High Confidence Findings: {}", summary.high_confidence_findings),
            format!("Contradicted Findings: {}", summary.contradicted_findings),
            format!("Anomalies Detected: {}", summary.anomalies_detected),
        ];

        for line in &lines {
            self.render_body_line(line);
        }

        if !summary.key_findings.is_empty() {
            self.render_spacer(5.0);
            self.render_subsection("Key Findings:");
            for kf in &summary.key_findings {
                self.render_body_line(&format!("  • {}", kf));
            }
        }
    }

    /// Render a subsection header.
    fn render_subsection(&mut self, title: &str) {
        self.ensure_space(10.0);
        let layer = self.layer();

        layer.use_text(
            title,
            FONT_SIZE_SUBSECTION,
            Mm(MARGIN_LEFT_MM),
            Mm(self.y_position),
            self.font_bold,
        );
        self.y_position -= FONT_SIZE_SUBSECTION * LINE_HEIGHT_MULTIPLIER * 0.3528;
    }

    /// Render a single finding.
    fn render_finding(&mut self, finding: &ReportFinding) {
        self.ensure_space(30.0);

        self.render_subsection(&format!(
            "{} — {} [{}]",
            finding.finding_number, finding.title, finding.confidence_classification
        ));

        self.render_body_line(&finding.description);

        if let Some(ssid) = &finding.network_ssid {
            self.render_body_line(&format!("Network SSID: {}", ssid));
        }
        if let Some(bssid) = &finding.network_bssid {
            self.render_body_line(&format!("Network BSSID: {}", bssid));
        }
        if let Some(proto) = &finding.security_protocol {
            self.render_body_line(&format!("Security: {}", proto));
        }
        if let Some(time) = &finding.event_time {
            self.render_body_line(&format!(
                "Event Time: {}",
                time.format("%Y-%m-%d %H:%M:%S UTC")
            ));
        }

        self.render_body_line(&format!(
            "Confidence: {:.2} ({}) — {} corroborating source(s)",
            finding.confidence_score,
            finding.confidence_classification,
            finding.corroboration_count,
        ));

        if finding.examiner_override {
            self.render_body_line("⚠ EXAMINER OVERRIDE APPLIED");
        }

        if !finding.contradictions.is_empty() {
            self.render_body_line(&format!(
                "Contradictions: {}",
                finding.contradictions.join("; ")
            ));
        }

        self.render_spacer(5.0);
    }

    /// Render an evidence entry.
    fn render_evidence_entry(&mut self, entry: &EvidenceEntry) {
        self.ensure_space(25.0);

        self.render_subsection(&format!(
            "{} — {}",
            entry.evidence_number, entry.artifact_class
        ));
        self.render_body_line(&format!("Path: {}", entry.original_path));
        self.render_mono_text(&format!("SHA-256: {}", entry.sha256_hash));
        self.render_body_line(&format!("Size: {} bytes", entry.size_bytes));
        self.render_body_line(&format!(
            "Acquired: {}",
            entry.acquired_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        if !entry.referenced_by_findings.is_empty() {
            self.render_body_line(&format!(
                "Referenced by: {}",
                entry.referenced_by_findings.join(", ")
            ));
        }

        self.render_spacer(3.0);
    }

    /// Render a line of body text.
    fn render_body_line(&mut self, text: &str) {
        self.ensure_space(5.0);
        let layer = self.layer();

        // Simple word-wrap at ~80 chars per line.
        let max_chars = 80;
        let mut remaining = text;

        while !remaining.is_empty() {
            let (chunk, rest) = if remaining.len() <= max_chars {
                (remaining, "")
            } else {
                // Find the last space before the limit.
                match remaining[..max_chars].rfind(' ') {
                    Some(pos) => (&remaining[..pos], &remaining[pos + 1..]),
                    None => (&remaining[..max_chars], &remaining[max_chars..]),
                }
            };

            layer.use_text(
                chunk,
                FONT_SIZE_BODY,
                Mm(MARGIN_LEFT_MM),
                Mm(self.y_position),
                self.font_regular,
            );
            self.y_position -= FONT_SIZE_BODY * LINE_HEIGHT_MULTIPLIER * 0.3528;

            if self.y_position < MARGIN_BOTTOM_MM {
                self.new_page();
            }

            remaining = rest;
        }
    }

    /// Render a multi-line block of body text (splits on newlines).
    fn render_body_text(&mut self, text: &str) {
        for line in text.lines() {
            self.render_body_line(line);
        }
    }

    /// Render a line of monospaced text (for hashes, technical data).
    fn render_mono_text(&mut self, text: &str) {
        self.ensure_space(5.0);
        let layer = self.layer();

        layer.use_text(
            text,
            FONT_SIZE_SMALL,
            Mm(MARGIN_LEFT_MM),
            Mm(self.y_position),
            self.font_mono,
        );
        self.y_position -= FONT_SIZE_SMALL * LINE_HEIGHT_MULTIPLIER * 0.3528;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::ReportGenerator;
    use crate::types::{ReportFinding, ReportType};
    use chrono::Utc;
    use oracle_core::types::{ConfidenceClassification, ExaminerIdentity, InvestigationId};
    use tempfile::TempDir;

    fn test_examiner() -> ExaminerIdentity {
        ExaminerIdentity {
            name: "PDF Test Examiner".to_string(),
            badge_id: "B-PDF".to_string(),
            organization: "PDF Test Lab".to_string(),
        }
    }

    fn test_finding(num: usize, score: f64) -> ReportFinding {
        ReportFinding {
            finding_number: format!("F-{:03}", num),
            title: format!("Test Finding {}", num),
            description: "This is a test finding for PDF generation.".to_string(),
            network_ssid: Some("TestNetwork".to_string()),
            network_bssid: Some("AA:BB:CC:DD:EE:FF".to_string()),
            security_protocol: None,
            event_time: Some(Utc::now()),
            confidence_score: score,
            confidence_classification: ConfidenceClassification::from_score(score),
            corroboration_count: 3,
            corroborating_sources: vec!["wpa_supplicant.conf".to_string()],
            contradictions: Vec::new(),
            examiner_override: false,
        }
    }

    #[test]
    fn test_render_pdf_creates_file() {
        let dir = TempDir::new().unwrap();
        let output = dir.path().join("test_report.pdf");

        let mut gen = ReportGenerator::new(
            "CASE-PDF-001",
            InvestigationId::new(),
            test_examiner(),
            ReportType::Complete,
        );
        gen.add_finding(test_finding(1, 0.95));
        gen.add_finding(test_finding(2, 0.72));

        let report = gen.generate();
        render_pdf(&report, &output).unwrap();

        assert!(output.exists());
        let metadata = std::fs::metadata(&output).unwrap();
        assert!(metadata.len() > 0, "PDF file should not be empty");
    }

    #[test]
    fn test_render_pdf_empty_report() {
        let dir = TempDir::new().unwrap();
        let output = dir.path().join("empty_report.pdf");

        let gen = ReportGenerator::new(
            "CASE-PDF-EMPTY",
            InvestigationId::new(),
            test_examiner(),
            ReportType::Executive,
        );
        let report = gen.generate();
        render_pdf(&report, &output).unwrap();

        assert!(output.exists());
    }
}
