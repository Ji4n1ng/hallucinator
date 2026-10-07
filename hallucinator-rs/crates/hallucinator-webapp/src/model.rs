//! Serializable mirrors of upstream domain types.
//!
//! `hallucinator_core::ValidationResult` is not `Serialize`, and upstream's
//! report JSON is a presentation format. `StoredResult` is a lossless,
//! round-trippable mirror used both for the history database and the HTTP
//! API, so exports can rebuild the exact upstream type via
//! [`StoredResult::to_core`].

use std::time::Duration;

use hallucinator_core::{
    ArxivInfo, CheckStats, DbResult, DbStatus, DoiInfo, MismatchKind, RetractionInfo, Status,
    ValidationResult,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredResult {
    pub title: String,
    pub raw_citation: String,
    pub ref_authors: Vec<String>,
    /// "verified" | "not_found" | "mismatch"
    pub status: String,
    /// Subset of "author", "doi", "arxiv_id" (only for `status == "mismatch"`).
    #[serde(default)]
    pub mismatch: Vec<String>,
    pub source: Option<String>,
    #[serde(default)]
    pub found_authors: Vec<String>,
    pub paper_url: Option<String>,
    #[serde(default)]
    pub failed_dbs: Vec<String>,
    #[serde(default)]
    pub db_results: Vec<StoredDbResult>,
    pub doi_info: Option<StoredDoiInfo>,
    pub arxiv_info: Option<StoredArxivInfo>,
    pub retraction_info: Option<StoredRetractionInfo>,
    #[serde(default)]
    pub url_check_skipped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredDbResult {
    pub db: String,
    pub status: String,
    pub elapsed_ms: Option<u64>,
    #[serde(default)]
    pub found_authors: Vec<String>,
    pub paper_url: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredDoiInfo {
    pub doi: String,
    pub valid: bool,
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredArxivInfo {
    pub arxiv_id: String,
    pub valid: bool,
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredRetractionInfo {
    pub is_retracted: bool,
    pub retraction_doi: Option<String>,
    pub retraction_source: Option<String>,
}

pub fn db_status_str(s: &DbStatus) -> &'static str {
    match s {
        DbStatus::Match => "match",
        DbStatus::NoMatch => "no_match",
        DbStatus::AuthorMismatch => "author_mismatch",
        DbStatus::Timeout => "timeout",
        DbStatus::RateLimited => "rate_limited",
        DbStatus::Error => "error",
        DbStatus::Skipped => "skipped",
    }
}

fn parse_db_status(s: &str) -> DbStatus {
    match s {
        "match" => DbStatus::Match,
        "no_match" => DbStatus::NoMatch,
        "author_mismatch" => DbStatus::AuthorMismatch,
        "timeout" => DbStatus::Timeout,
        "rate_limited" => DbStatus::RateLimited,
        "skipped" => DbStatus::Skipped,
        _ => DbStatus::Error,
    }
}

const MISMATCH_FLAGS: [(MismatchKind, &str); 3] = [
    (MismatchKind::AUTHOR, "author"),
    (MismatchKind::DOI, "doi"),
    (MismatchKind::ARXIV_ID, "arxiv_id"),
];

impl From<&ValidationResult> for StoredResult {
    fn from(r: &ValidationResult) -> Self {
        let (status, mismatch) = match &r.status {
            Status::Verified => ("verified", vec![]),
            Status::NotFound => ("not_found", vec![]),
            Status::Mismatch(kind) => (
                "mismatch",
                MISMATCH_FLAGS
                    .iter()
                    .filter(|(k, _)| kind.contains(*k))
                    .map(|(_, s)| s.to_string())
                    .collect(),
            ),
        };
        StoredResult {
            title: r.title.clone(),
            raw_citation: r.raw_citation.clone(),
            ref_authors: r.ref_authors.clone(),
            status: status.to_string(),
            mismatch,
            source: r.source.clone(),
            found_authors: r.found_authors.clone(),
            paper_url: r.paper_url.clone(),
            failed_dbs: r.failed_dbs.clone(),
            db_results: r
                .db_results
                .iter()
                .map(|d| StoredDbResult {
                    db: d.db_name.clone(),
                    status: db_status_str(&d.status).to_string(),
                    elapsed_ms: d.elapsed.map(|e| e.as_millis() as u64),
                    found_authors: d.found_authors.clone(),
                    paper_url: d.paper_url.clone(),
                    error: d.error_message.clone(),
                })
                .collect(),
            doi_info: r.doi_info.as_ref().map(|d| StoredDoiInfo {
                doi: d.doi.clone(),
                valid: d.valid,
                title: d.title.clone(),
            }),
            arxiv_info: r.arxiv_info.as_ref().map(|a| StoredArxivInfo {
                arxiv_id: a.arxiv_id.clone(),
                valid: a.valid,
                title: a.title.clone(),
            }),
            retraction_info: r.retraction_info.as_ref().map(|ri| StoredRetractionInfo {
                is_retracted: ri.is_retracted,
                retraction_doi: ri.retraction_doi.clone(),
                retraction_source: ri.retraction_source.clone(),
            }),
            url_check_skipped: r.url_check_skipped,
        }
    }
}

impl StoredResult {
    pub fn mismatch_kind(&self) -> MismatchKind {
        let mut kind = MismatchKind::empty();
        for (k, s) in MISMATCH_FLAGS {
            if self.mismatch.iter().any(|m| m == s) {
                kind |= k;
            }
        }
        kind
    }

    /// Rebuild the upstream type (for `hallucinator-reporting` exports).
    pub fn to_core(&self) -> ValidationResult {
        let status = match self.status.as_str() {
            "verified" => Status::Verified,
            "mismatch" => Status::Mismatch(self.mismatch_kind()),
            _ => Status::NotFound,
        };
        ValidationResult {
            title: self.title.clone(),
            raw_citation: self.raw_citation.clone(),
            ref_authors: self.ref_authors.clone(),
            status,
            source: self.source.clone(),
            found_authors: self.found_authors.clone(),
            paper_url: self.paper_url.clone(),
            failed_dbs: self.failed_dbs.clone(),
            db_results: self
                .db_results
                .iter()
                .map(|d| DbResult {
                    db_name: d.db.clone(),
                    status: parse_db_status(&d.status),
                    elapsed: d.elapsed_ms.map(Duration::from_millis),
                    found_authors: d.found_authors.clone(),
                    paper_url: d.paper_url.clone(),
                    error_message: d.error.clone(),
                })
                .collect(),
            doi_info: self.doi_info.as_ref().map(|d| DoiInfo {
                doi: d.doi.clone(),
                valid: d.valid,
                title: d.title.clone(),
            }),
            arxiv_info: self.arxiv_info.as_ref().map(|a| ArxivInfo {
                arxiv_id: a.arxiv_id.clone(),
                valid: a.valid,
                title: a.title.clone(),
            }),
            retraction_info: self.retraction_info.as_ref().map(|ri| RetractionInfo {
                is_retracted: ri.is_retracted,
                retraction_doi: ri.retraction_doi.clone(),
                retraction_source: ri.retraction_source.clone(),
            }),
            url_check_skipped: self.url_check_skipped,
        }
    }

    pub fn is_retracted(&self) -> bool {
        self.retraction_info
            .as_ref()
            .is_some_and(|r| r.is_retracted)
    }

    /// The bucket a reader should see, mirroring upstream reporting
    /// (`effective_status_str`): a URL-gated NotFound is "skipped" and a
    /// NotFound built on a failed lookup is "inconclusive".
    pub fn verdict(&self) -> &'static str {
        if self.url_check_skipped {
            return "skipped";
        }
        match self.status.as_str() {
            "verified" => "verified",
            "mismatch" => "mismatch",
            _ if !self.failed_dbs.is_empty() => "inconclusive",
            _ => "not_found",
        }
    }
}

/// Aggregate counters shown in the UI (superset of upstream `CheckStats`).
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct Stats {
    pub total: usize,
    pub checked: usize,
    pub pending: usize,
    pub verified: usize,
    pub not_found: usize,
    pub mismatch: usize,
    pub author_mismatch: usize,
    pub doi_mismatch: usize,
    pub arxiv_mismatch: usize,
    pub retracted: usize,
    pub skipped: usize,
    pub inconclusive: usize,
    pub marked_safe: usize,
    pub problems: usize,
}

/// The per-reference facts statistics are computed from. Stored as
/// denormalised columns on `refs` so history listings can aggregate
/// without parsing every result blob.
#[derive(Debug, Clone, Default)]
pub struct RefFacts {
    pub parse_skipped: bool,
    pub verdict: Option<String>,
    pub mismatch_flags: u8,
    pub retracted: bool,
    pub fp: bool,
}

impl Stats {
    pub fn add(&mut self, f: &RefFacts) {
        self.total += 1;
        if f.fp {
            self.marked_safe += 1;
        }
        if f.parse_skipped {
            self.skipped += 1;
            return;
        }
        let Some(verdict) = f.verdict.as_deref() else {
            self.pending += 1;
            return;
        };
        self.checked += 1;
        match verdict {
            "verified" => self.verified += 1,
            "not_found" => self.not_found += 1,
            "inconclusive" => self.inconclusive += 1,
            "skipped" => self.skipped += 1,
            "mismatch" => {
                self.mismatch += 1;
                let kind = MismatchKind::from_bits_truncate(f.mismatch_flags);
                if kind.contains(MismatchKind::AUTHOR) {
                    self.author_mismatch += 1;
                }
                if kind.contains(MismatchKind::DOI) {
                    self.doi_mismatch += 1;
                }
                if kind.contains(MismatchKind::ARXIV_ID) {
                    self.arxiv_mismatch += 1;
                }
            }
            _ => {}
        }
        if f.retracted {
            self.retracted += 1;
        }
        let problem = matches!(verdict, "not_found" | "mismatch") || f.retracted;
        if problem && !f.fp {
            self.problems += 1;
        }
    }

    pub fn merge(&mut self, o: &Stats) {
        self.total += o.total;
        self.checked += o.checked;
        self.pending += o.pending;
        self.verified += o.verified;
        self.not_found += o.not_found;
        self.mismatch += o.mismatch;
        self.author_mismatch += o.author_mismatch;
        self.doi_mismatch += o.doi_mismatch;
        self.arxiv_mismatch += o.arxiv_mismatch;
        self.retracted += o.retracted;
        self.skipped += o.skipped;
        self.inconclusive += o.inconclusive;
        self.marked_safe += o.marked_safe;
        self.problems += o.problems;
    }
}

/// Upstream `CheckStats` for exports, with marked-safe refs moved into
/// `verified` (the TUI stores already-adjusted stats; reporting relies on it).
pub fn export_check_stats(facts: &[RefFacts]) -> CheckStats {
    let mut s = CheckStats {
        total: facts.len(),
        ..Default::default()
    };
    for f in facts {
        if f.parse_skipped {
            s.skipped += 1;
            continue;
        }
        let Some(verdict) = f.verdict.as_deref() else {
            continue;
        };
        if f.fp && verdict != "skipped" {
            s.verified += 1;
            continue;
        }
        match verdict {
            "verified" => s.verified += 1,
            "not_found" => s.not_found += 1,
            "inconclusive" => s.inconclusive += 1,
            "skipped" => s.skipped += 1,
            "mismatch" => {
                s.mismatch += 1;
                let kind = MismatchKind::from_bits_truncate(f.mismatch_flags);
                if kind.contains(MismatchKind::AUTHOR) {
                    s.author_mismatch += 1;
                }
                if kind.contains(MismatchKind::DOI) {
                    s.doi_mismatch += 1;
                }
                if kind.contains(MismatchKind::ARXIV_ID) {
                    s.arxiv_mismatch += 1;
                }
            }
            _ => {}
        }
        if f.retracted {
            s.retracted += 1;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ValidationResult {
        ValidationResult {
            title: "A Title".into(),
            raw_citation: "raw".into(),
            ref_authors: vec!["A. Author".into()],
            status: Status::Mismatch(MismatchKind::AUTHOR | MismatchKind::DOI),
            source: Some("DBLP".into()),
            found_authors: vec!["B. Author".into()],
            paper_url: Some("https://example.org".into()),
            failed_dbs: vec!["Semantic Scholar".into()],
            db_results: vec![DbResult {
                db_name: "DBLP".into(),
                status: DbStatus::AuthorMismatch,
                elapsed: Some(Duration::from_millis(12)),
                found_authors: vec!["B. Author".into()],
                paper_url: None,
                error_message: None,
            }],
            doi_info: Some(DoiInfo {
                doi: "10.1/x".into(),
                valid: false,
                title: None,
            }),
            arxiv_info: None,
            retraction_info: Some(RetractionInfo {
                is_retracted: true,
                retraction_doi: Some("10.1/r".into()),
                retraction_source: Some("CrossRef".into()),
            }),
            url_check_skipped: false,
        }
    }

    #[test]
    fn round_trip_is_lossless() {
        let core = sample();
        let stored = StoredResult::from(&core);
        let json = serde_json::to_string(&stored).unwrap();
        let back: StoredResult = serde_json::from_str(&json).unwrap();
        assert_eq!(stored, back);
        let core2 = back.to_core();
        assert_eq!(core2.status, core.status);
        assert_eq!(core2.db_results[0].status, DbStatus::AuthorMismatch);
        assert_eq!(StoredResult::from(&core2), stored);
    }

    #[test]
    fn verdict_buckets() {
        let mut r = StoredResult::from(&sample());
        assert_eq!(r.verdict(), "mismatch");
        r.status = "not_found".into();
        assert_eq!(r.verdict(), "inconclusive");
        r.failed_dbs.clear();
        assert_eq!(r.verdict(), "not_found");
        r.url_check_skipped = true;
        assert_eq!(r.verdict(), "skipped");
    }

    #[test]
    fn stats_count_problems_minus_marked_safe() {
        let mut s = Stats::default();
        s.add(&RefFacts {
            verdict: Some("not_found".into()),
            ..Default::default()
        });
        s.add(&RefFacts {
            verdict: Some("not_found".into()),
            fp: true,
            ..Default::default()
        });
        s.add(&RefFacts {
            parse_skipped: true,
            ..Default::default()
        });
        s.add(&RefFacts::default());
        assert_eq!(s.total, 4);
        assert_eq!(s.not_found, 2);
        assert_eq!(s.problems, 1);
        assert_eq!(s.marked_safe, 1);
        assert_eq!(s.skipped, 1);
        assert_eq!(s.pending, 1);
        assert_eq!(s.checked, 2);
    }
}
