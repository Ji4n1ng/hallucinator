//! Turning uploaded files into papers to check.
//!
//! * [`plan_papers`] pairs each PDF with a companion `.bib`/`.bbl`.
//! * [`merge_with_companion`] combines the two extractions: the PDF decides
//!   *which* references the paper cites (a `.bib` usually holds many more
//!   entries than are cited), the companion supplies clean structured fields
//!   (title, authors, DOI, arXiv id, URLs) that PDF text extraction often
//!   mangles — URLs broken across lines being the classic case.

use std::path::PathBuf;

use hallucinator_core::matching::normalize_title;
use hallucinator_core::{ExtractionResult, Reference, SkipStats};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InputKind {
    Pdf,
    Bib,
    Bbl,
    Xml,
}

impl InputKind {
    pub fn from_name(name: &str) -> Option<Self> {
        let lower = name.to_lowercase();
        if lower.ends_with(".pdf") {
            Some(Self::Pdf)
        } else if lower.ends_with(".bib") {
            Some(Self::Bib)
        } else if lower.ends_with(".bbl") {
            Some(Self::Bbl)
        } else if lower.ends_with(".xml") {
            Some(Self::Xml)
        } else {
            None
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pdf => "pdf",
            Self::Bib => "bib",
            Self::Bbl => "bbl",
            Self::Xml => "xml",
        }
    }

    fn is_bibliography(self) -> bool {
        matches!(self, Self::Bib | Self::Bbl)
    }
}

#[derive(Debug, Clone)]
pub struct InputFile {
    /// Name shown to the user (original upload name, or path inside an archive).
    pub display_name: String,
    pub path: PathBuf,
    pub kind: InputKind,
    pub sha256: Option<String>,
}

impl InputFile {
    fn stem(&self) -> String {
        let base = self
            .display_name
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&self.display_name);
        match base.rfind('.') {
            Some(i) if i > 0 => base[..i].to_lowercase(),
            _ => base.to_lowercase(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PlannedPaper {
    pub main: InputFile,
    pub companion: Option<InputFile>,
}

impl PlannedPaper {
    pub fn input_kind(&self) -> String {
        match &self.companion {
            Some(c) => format!("{}+{}", self.main.kind.as_str(), c.kind.as_str()),
            None => self.main.kind.as_str().to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BibMode {
    #[default]
    Merge,
    Separate,
}

/// Group uploaded files into papers. With [`BibMode::Merge`], a `.bib`/`.bbl`
/// is attached to the PDF with the same file stem (preferring `.bib`, whose
/// fields are richer); if the upload is exactly one PDF plus one
/// bibliography file, those two are paired regardless of names. Everything
/// left over is checked on its own, in upload order.
pub fn plan_papers(files: Vec<InputFile>, mode: BibMode) -> Vec<PlannedPaper> {
    let mut used = vec![false; files.len()];
    let mut companion_of: Vec<Option<usize>> = vec![None; files.len()];

    if mode == BibMode::Merge {
        for (i, f) in files.iter().enumerate() {
            if f.kind != InputKind::Pdf {
                continue;
            }
            let stem = f.stem();
            let pick = |want: InputKind, used: &[bool]| {
                files
                    .iter()
                    .enumerate()
                    .position(|(j, g)| !used[j] && g.kind == want && g.stem() == stem)
            };
            if let Some(j) = pick(InputKind::Bib, &used).or_else(|| pick(InputKind::Bbl, &used)) {
                used[j] = true;
                companion_of[i] = Some(j);
            }
        }
        let pdfs: Vec<usize> = (0..files.len())
            .filter(|&i| files[i].kind == InputKind::Pdf)
            .collect();
        let bibs: Vec<usize> = (0..files.len())
            .filter(|&i| files[i].kind.is_bibliography())
            .collect();
        if pdfs.len() == 1 && bibs.len() == 1 && companion_of[pdfs[0]].is_none() {
            used[bibs[0]] = true;
            companion_of[pdfs[0]] = Some(bibs[0]);
        }
    }

    let mut out = Vec::new();
    for i in 0..files.len() {
        if used[i] {
            continue;
        }
        out.push(PlannedPaper {
            main: files[i].clone(),
            companion: companion_of[i].map(|j| files[j].clone()),
        });
    }
    out
}

/// A reference plus where its fields came from.
#[derive(Debug, Clone)]
pub struct SourcedRef {
    pub reference: Reference,
    pub origin: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct MergeSummary {
    pub companion: String,
    pub companion_entries: usize,
    pub pdf_refs: usize,
    pub matched: usize,
    pub pdf_only: usize,
    /// Set when the PDF could not be used and the companion was checked
    /// on its own ("pdf_failed" or "pdf_empty").
    pub fallback: Option<String>,
}

/// Score how likely a companion entry describes a PDF reference.
fn match_score(pdf: &Reference, pdf_raw_norm: &str, bib_title_norm: &str) -> f64 {
    if bib_title_norm.len() < 8 {
        return 0.0;
    }
    // The PDF raw citation contains the title even when title extraction
    // failed; normalize_title strips spaces/punctuation, so hyphenation and
    // line-break damage don't defeat the containment test.
    if bib_title_norm.len() >= 16 && pdf_raw_norm.contains(bib_title_norm) {
        return 1.0;
    }
    match pdf.title.as_deref().map(normalize_title) {
        Some(t) if !t.is_empty() => rapidfuzz::fuzz::ratio(t.chars(), bib_title_norm.chars()),
        _ => 0.0,
    }
}

pub const MATCH_THRESHOLD: f64 = 0.90;

fn tag_all(refs: Vec<Reference>, origin: &'static str) -> Vec<SourcedRef> {
    refs.into_iter()
        .map(|reference| SourcedRef { reference, origin })
        .collect()
}

/// Use the companion alone (PDF unusable). Every entry is checked.
pub fn companion_only(
    companion: ExtractionResult,
    companion_name: &str,
    companion_origin: &'static str,
    pdf_refs: usize,
    reason: &str,
) -> (Vec<SourcedRef>, SkipStats, MergeSummary) {
    let n = companion.references.len();
    (
        tag_all(companion.references, companion_origin),
        companion.skip_stats,
        MergeSummary {
            companion: companion_name.to_string(),
            companion_entries: n,
            pdf_refs,
            matched: 0,
            pdf_only: 0,
            fallback: Some(reason.to_string()),
        },
    )
}

/// Merge a PDF extraction with its companion bibliography (see module docs).
pub fn merge_with_companion(
    pdf: ExtractionResult,
    companion: ExtractionResult,
    companion_name: &str,
    companion_origin: &'static str,
) -> (Vec<SourcedRef>, SkipStats, MergeSummary) {
    if pdf.references.is_empty() {
        return companion_only(companion, companion_name, companion_origin, 0, "pdf_empty");
    }

    let bib_norms: Vec<Option<String>> = companion
        .references
        .iter()
        .map(|b| {
            // Entries the companion parser itself skipped (no/short title)
            // are not trustworthy enough to override the PDF parse.
            if b.skip_reason.is_some() {
                None
            } else {
                b.title.as_deref().map(normalize_title)
            }
        })
        .collect();

    let mut candidates: Vec<(f64, usize, usize)> = Vec::new();
    for (i, p) in pdf.references.iter().enumerate() {
        let raw_norm = normalize_title(&p.raw_citation);
        for (j, bn) in bib_norms.iter().enumerate() {
            let Some(bn) = bn else { continue };
            let s = match_score(p, &raw_norm, bn);
            if s >= MATCH_THRESHOLD {
                candidates.push((s, i, j));
            }
        }
    }
    // Greedy one-to-one assignment, best scores first; ties keep PDF order.
    candidates.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.1.cmp(&b.1))
            .then(a.2.cmp(&b.2))
    });
    let mut pdf_match: Vec<Option<usize>> = vec![None; pdf.references.len()];
    let mut bib_used = vec![false; companion.references.len()];
    for (_, i, j) in candidates {
        if pdf_match[i].is_none() && !bib_used[j] {
            pdf_match[i] = Some(j);
            bib_used[j] = true;
        }
    }

    let mut stats = SkipStats {
        total_raw: pdf.skip_stats.total_raw.max(pdf.references.len()),
        ..Default::default()
    };
    let mut out = Vec::with_capacity(pdf.references.len());
    let mut matched = 0;
    for (i, p) in pdf.references.into_iter().enumerate() {
        let sourced = match pdf_match[i] {
            Some(j) => {
                matched += 1;
                let b = &companion.references[j];
                let mut urls = b.urls.clone();
                for u in &p.urls {
                    if !urls.contains(u) {
                        urls.push(u.clone());
                    }
                }
                SourcedRef {
                    reference: Reference {
                        raw_citation: if p.raw_citation.trim().is_empty() {
                            b.raw_citation.clone()
                        } else {
                            p.raw_citation
                        },
                        title: b.title.clone(),
                        authors: if b.authors.is_empty() {
                            p.authors
                        } else {
                            b.authors.clone()
                        },
                        doi: b.doi.clone().or(p.doi),
                        arxiv_id: b.arxiv_id.clone().or(p.arxiv_id),
                        urls,
                        original_number: p.original_number,
                        skip_reason: None,
                    },
                    origin: companion_origin,
                }
            }
            None => SourcedRef {
                reference: p,
                origin: "pdf",
            },
        };
        match sourced.reference.skip_reason.as_deref() {
            Some("url_only") => stats.url_only += 1,
            Some("short_title") => stats.short_title += 1,
            Some("no_title") => stats.no_title += 1,
            _ => {}
        }
        if sourced.reference.skip_reason.is_none() && sourced.reference.authors.is_empty() {
            stats.no_authors += 1;
        }
        out.push(sourced);
    }

    let pdf_refs = out.len();
    let summary = MergeSummary {
        companion: companion_name.to_string(),
        companion_entries: companion.references.len(),
        pdf_refs,
        matched,
        pdf_only: pdf_refs - matched,
        fallback: None,
    };
    (out, stats, summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str) -> InputFile {
        InputFile {
            display_name: name.to_string(),
            path: PathBuf::from(name),
            kind: InputKind::from_name(name).unwrap(),
            sha256: None,
        }
    }

    fn r(n: usize, title: Option<&str>, raw: &str) -> Reference {
        Reference {
            raw_citation: raw.to_string(),
            title: title.map(String::from),
            authors: vec!["Pdf Author".into()],
            doi: None,
            arxiv_id: None,
            urls: vec![],
            original_number: n,
            skip_reason: None,
        }
    }

    #[test]
    fn pairs_by_stem_and_single_pair() {
        let plan = plan_papers(
            vec![
                file("a.pdf"),
                file("b.pdf"),
                file("A.bib"),
                file("other.bbl"),
            ],
            BibMode::Merge,
        );
        assert_eq!(plan.len(), 3);
        assert_eq!(plan[0].input_kind(), "pdf+bib");
        assert_eq!(plan[1].input_kind(), "pdf");
        assert_eq!(plan[2].input_kind(), "bbl");

        let plan = plan_papers(vec![file("paper.pdf"), file("refs.bib")], BibMode::Merge);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].companion.as_ref().unwrap().display_name, "refs.bib");

        let plan = plan_papers(vec![file("paper.pdf"), file("refs.bib")], BibMode::Separate);
        assert_eq!(plan.len(), 2);
    }

    #[test]
    fn prefers_bib_over_bbl_for_same_stem() {
        let plan = plan_papers(
            vec![file("p.pdf"), file("p.bbl"), file("p.bib")],
            BibMode::Merge,
        );
        assert_eq!(plan[0].companion.as_ref().unwrap().kind, InputKind::Bib);
        assert_eq!(plan.len(), 2);
    }

    #[test]
    fn merge_uses_bib_fields_and_keeps_pdf_order() {
        let pdf = ExtractionResult {
            references: vec![
                r(
                    1,
                    Some("Deep Residual Learning for Image Recog-"),
                    "K. He. Deep residual learning for image recog- nition. CVPR 2016. https://exam ple.org/broken",
                ),
                r(
                    2,
                    Some("A Paper Only In The PDF Text"),
                    "X. A paper only in the PDF text.",
                ),
                r(
                    3,
                    None,
                    "Garbled [3] A. Vaswani Attention is all you need NeurIPS",
                ),
            ],
            skip_stats: SkipStats {
                total_raw: 3,
                ..Default::default()
            },
        };
        let mut bib1 = r(1, Some("Deep Residual Learning for Image Recognition"), "");
        bib1.authors = vec!["Kaiming He".into(), "Xiangyu Zhang".into()];
        bib1.urls = vec!["https://example.org/resnet".into()];
        bib1.doi = Some("10.1109/CVPR.2016.90".into());
        let bib2 = r(2, Some("Attention Is All You Need"), "");
        let bib3 = r(3, Some("Some Uncited Entry With A Long Title"), "");
        let companion = ExtractionResult {
            references: vec![bib3, bib2, bib1],
            skip_stats: SkipStats::default(),
        };
        let (refs, _stats, summary) = merge_with_companion(pdf, companion, "refs.bib", "bib");
        assert_eq!(refs.len(), 3);
        assert_eq!(summary.matched, 2);
        assert_eq!(summary.pdf_only, 1);
        assert_eq!(summary.companion_entries, 3);
        assert_eq!(refs[0].origin, "bib");
        assert_eq!(
            refs[0].reference.title.as_deref(),
            Some("Deep Residual Learning for Image Recognition")
        );
        assert_eq!(
            refs[0].reference.urls,
            vec!["https://example.org/resnet".to_string()]
        );
        assert_eq!(refs[0].reference.authors.len(), 2);
        assert_eq!(refs[0].reference.original_number, 1);
        assert!(refs[0].reference.raw_citation.starts_with("K. He."));
        assert_eq!(refs[1].origin, "pdf");
        // Title extraction failed in the PDF, but the raw text contains it.
        assert_eq!(refs[2].origin, "bib");
        assert_eq!(
            refs[2].reference.title.as_deref(),
            Some("Attention Is All You Need")
        );
    }

    #[test]
    fn empty_pdf_falls_back_to_companion() {
        let pdf = ExtractionResult {
            references: vec![],
            skip_stats: SkipStats::default(),
        };
        let companion = ExtractionResult {
            references: vec![r(1, Some("Attention Is All You Need"), "")],
            skip_stats: SkipStats::default(),
        };
        let (refs, _, summary) = merge_with_companion(pdf, companion, "x.bib", "bib");
        assert_eq!(refs.len(), 1);
        assert_eq!(summary.fallback.as_deref(), Some("pdf_empty"));
    }
}
