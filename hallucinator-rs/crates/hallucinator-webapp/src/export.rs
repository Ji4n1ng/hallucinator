//! Exports through upstream `hallucinator-reporting`, so every format (and
//! the JSON that `hallucinator-tui --load` reads back) matches the CLI/TUI.

use hallucinator_core::{CheckStats, ValidationResult};
use hallucinator_reporting::{
    ExportFormat, FpReason, PaperVerdict, ReportPaper, ReportRef, SkipInfo,
};

use crate::model::{StoredResult, export_check_stats};
use crate::store::{PaperRow, RefRow};

pub fn parse_format(s: &str) -> Option<ExportFormat> {
    match s {
        "json" => Some(ExportFormat::Json),
        "csv" => Some(ExportFormat::Csv),
        "markdown" | "md" => Some(ExportFormat::Markdown),
        "text" | "txt" => Some(ExportFormat::Text),
        "html" => Some(ExportFormat::Html),
        _ => None,
    }
}

pub fn content_type(f: ExportFormat) -> &'static str {
    match f {
        ExportFormat::Json => "application/json; charset=utf-8",
        ExportFormat::Csv => "text/csv; charset=utf-8",
        ExportFormat::Markdown => "text/markdown; charset=utf-8",
        ExportFormat::Text => "text/plain; charset=utf-8",
        ExportFormat::Html => "text/html; charset=utf-8",
    }
}

struct PaperData {
    filename: String,
    stats: CheckStats,
    results: Vec<Option<ValidationResult>>,
    verdict: Option<PaperVerdict>,
    refs: Vec<ReportRef>,
}

fn paper_data(p: &PaperRow, refs: &[RefRow]) -> PaperData {
    let results = refs
        .iter()
        .map(|r| {
            if r.skip_reason.is_some() {
                return None;
            }
            r.result_json
                .as_deref()
                .and_then(|s| serde_json::from_str::<StoredResult>(s).ok())
                .map(|s| s.to_core())
        })
        .collect();
    let report_refs = refs
        .iter()
        .map(|r| ReportRef {
            index: r.original_number.saturating_sub(1),
            title: r.title.clone().unwrap_or_default(),
            skip_info: r.skip_reason.as_ref().map(|reason| SkipInfo {
                reason: reason.clone(),
            }),
            fp_reason: r
                .fp_reason
                .as_deref()
                .and_then(|s| s.parse::<FpReason>().ok()),
        })
        .collect();
    let facts: Vec<_> = refs.iter().map(|r| r.facts()).collect();
    PaperData {
        filename: match &p.companion_filename {
            Some(c) => format!("{} (+ {c})", p.filename),
            None => p.filename.clone(),
        },
        stats: export_check_stats(&facts),
        results,
        verdict: match p.verdict.as_deref() {
            Some("safe") => Some(PaperVerdict::Safe),
            Some("questionable") => Some(PaperVerdict::Questionable),
            _ => None,
        },
        refs: report_refs,
    }
}

/// Render the given papers in `format`.
pub fn render(
    papers: &[(PaperRow, Vec<RefRow>)],
    format: ExportFormat,
    problematic_only: bool,
) -> anyhow::Result<Vec<u8>> {
    let data: Vec<PaperData> = papers.iter().map(|(p, r)| paper_data(p, r)).collect();
    let report_papers: Vec<ReportPaper<'_>> = data
        .iter()
        .map(|d| ReportPaper {
            filename: &d.filename,
            stats: &d.stats,
            results: &d.results,
            verdict: d.verdict,
        })
        .collect();
    let ref_slices: Vec<&[ReportRef]> = data.iter().map(|d| d.refs.as_slice()).collect();
    // Upstream exposes every format through `export_results(…, path)`.
    let tmp = tempfile::NamedTempFile::new()?;
    hallucinator_reporting::export_results(
        &report_papers,
        &ref_slices,
        format,
        tmp.path(),
        problematic_only,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    Ok(std::fs::read(tmp.path())?)
}

/// JSON report containing only marked-safe references, in the format
/// `hallucinator-cli import-corpus-reports` reads.
pub fn marked_safe_report(items: &[crate::store::MarkedSafe]) -> String {
    use std::collections::BTreeMap;
    let mut by_paper: BTreeMap<(String, usize), (String, Vec<&crate::store::MarkedSafe>)> =
        BTreeMap::new();
    for m in items {
        by_paper
            .entry((m.run_id.clone(), m.paper_idx))
            .or_insert_with(|| (m.filename.clone(), vec![]))
            .1
            .push(m);
    }
    let mut data = Vec::new();
    for (filename, ms) in by_paper.values() {
        let results: Vec<Option<ValidationResult>> = ms
            .iter()
            .map(|m| {
                let mut r = m
                    .result_json
                    .as_deref()
                    .and_then(|s| serde_json::from_str::<StoredResult>(s).ok())
                    .map(|s| s.to_core())
                    .unwrap_or_else(|| ValidationResult {
                        title: m.title.clone(),
                        raw_citation: m.raw_citation.clone(),
                        ref_authors: m.authors.clone(),
                        status: hallucinator_core::Status::NotFound,
                        source: None,
                        found_authors: vec![],
                        paper_url: None,
                        failed_dbs: vec![],
                        db_results: vec![],
                        doi_info: None,
                        arxiv_info: None,
                        retraction_info: None,
                        url_check_skipped: false,
                    });
                if r.title.trim().is_empty() {
                    r.title = m.title.clone();
                }
                Some(r)
            })
            .collect();
        let refs: Vec<ReportRef> = ms
            .iter()
            .map(|m| ReportRef {
                index: m.original_number.saturating_sub(1),
                title: m.title.clone(),
                skip_info: None,
                fp_reason: m.fp_reason.parse::<FpReason>().ok(),
            })
            .collect();
        data.push((filename.clone(), CheckStats::default(), results, refs));
    }
    let papers: Vec<ReportPaper<'_>> = data
        .iter()
        .map(|(f, s, r, _)| ReportPaper {
            filename: f,
            stats: s,
            results: r,
            verdict: None,
        })
        .collect();
    let slices: Vec<&[ReportRef]> = data.iter().map(|d| d.3.as_slice()).collect();
    hallucinator_reporting::export_json(&papers, &slices, false)
}
