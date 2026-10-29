//! The common paths of the agent tool standard (Catelier CAT-200, section 1):
//! `GET /api/health`, `GET /api/agent/guide[?section=<slug>]` and
//! `GET /api/agent/whoami`.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};

use super::docs::{GUIDE, markdown};
use super::{ApiError, ApiResult};
use crate::auth::AuthUser;
use crate::state::AppState;

/// Plain even when end-to-end encryption is required, so clients learn
/// that it is and which key ids the server takes.
pub async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({ "ok": true, "e2e": crate::e2e::health_block(state.e2e.as_deref()) }))
}

pub async fn whoami(AuthUser { user, .. }: AuthUser) -> Json<Value> {
    Json(json!({ "name": user.username, "kind": user.kind, "role": user.role }))
}

#[derive(Deserialize)]
pub struct GuideQuery {
    section: Option<String>,
}

pub async fn guide(_user: AuthUser, Query(q): Query<GuideQuery>) -> ApiResult<Response> {
    let Some(wanted) = q
        .section
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Ok(markdown(GUIDE.to_string()));
    };
    let sections = sections(GUIDE);
    let found = sections
        .iter()
        .find(|s| s.slug == wanted)
        .map(|s| s.text)
        .or_else(|| {
            sections
                .iter()
                .flat_map(|s| &s.parts)
                .find(|(slug, _)| slug == wanted)
                .map(|(_, text)| *text)
        });
    match found {
        Some(text) => Ok(markdown(text.to_string())),
        None => Err(ApiError::not_found(format!(
            "No section '{wanted}'. Sections, with their parts in brackets: {}.",
            sections
                .iter()
                .map(|s| if s.parts.is_empty() {
                    s.slug.clone()
                } else {
                    let parts: Vec<_> = s.parts.iter().map(|(p, _)| p.as_str()).collect();
                    format!("{} [{}]", s.slug, parts.join(", "))
                })
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// `## Quick start` → `quick-start`.
pub fn slug(heading: &str) -> String {
    let mut out = String::new();
    for c in heading.trim().chars() {
        if c.is_alphanumeric() {
            out.extend(c.to_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

/// One `## ` section of a Markdown text, with its `### ` parts.
pub struct Section<'a> {
    pub slug: String,
    pub text: &'a str,
    /// `(slug, text)` of each `### ` part.
    pub parts: Vec<(String, &'a str)>,
}

/// Each `## ` section of a Markdown text. A section runs to the next `## `
/// heading, a part to the next `## ` or `### ` heading; `#` lines inside
/// code fences do not count.
pub fn sections(text: &str) -> Vec<Section<'_>> {
    // (start, level, slug) of each heading.
    let mut heads: Vec<(usize, usize, String)> = Vec::new();
    let mut fenced = false;
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
        } else if !fenced && let Some(h) = line.strip_prefix("## ") {
            heads.push((at, 2, slug(h)));
        } else if !fenced && let Some(h) = line.strip_prefix("### ") {
            heads.push((at, 3, slug(h)));
        }
        at += line.len();
    }
    let mut out: Vec<Section> = Vec::new();
    for (i, (start, level, slug)) in heads.iter().enumerate() {
        let end = heads[i + 1..]
            .iter()
            .find(|(_, l, _)| l <= level)
            .map_or(text.len(), |(s, _, _)| *s);
        let body = text[*start..end].trim_end();
        if *level == 2 {
            out.push(Section {
                slug: slug.clone(),
                text: body,
                parts: Vec::new(),
            });
        } else if let Some(section) = out.last_mut() {
            section.parts.push((slug.clone(), body));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_and_sections() {
        assert_eq!(slug("Quick start"), "quick-start");
        assert_eq!(slug("Reference: runs & results "), "reference-runs-results");
        assert_eq!(slug("GET /api/runs/{id}/report"), "get-api-runs-id-report");
        let text =
            "# T\nintro\n## One\na\n```\n## not a heading\n```\n### P\np\n### Q\nq\n## Two: b\nc\n";
        let s = sections(text);
        assert_eq!(
            s.iter().map(|s| s.slug.as_str()).collect::<Vec<_>>(),
            ["one", "two-b"]
        );
        assert!(s[0].text.starts_with("## One") && s[0].text.contains("## not a heading"));
        assert!(s[0].text.ends_with("### Q\nq"));
        assert_eq!(
            s[0].parts,
            [("p".into(), "### P\np"), ("q".into(), "### Q\nq")]
        );
        assert_eq!(s[1].text, "## Two: b\nc");
        assert!(s[1].parts.is_empty());
    }

    #[test]
    fn guide_starts_with_a_short_quick_start() {
        let s = sections(GUIDE);
        let quick = &s[0];
        assert_eq!(
            quick.slug, "quick-start",
            "the guide must open with ## Quick start"
        );
        let lines = quick.text.lines().count();
        assert!(lines <= 150, "the quick start has {lines} lines (max 150)");
        assert_eq!(
            quick
                .parts
                .iter()
                .map(|(p, _)| p.as_str())
                .collect::<Vec<_>>(),
            [
                "check-access",
                "check-a-paper",
                "read-the-report",
                "follow-ups",
                "limits-and-rules"
            ]
        );
        for call in [
            "taskctl tool hallucinator whoami",
            "taskctl tool hallucinator POST /api/runs",
            "/report?wait=",
        ] {
            assert!(quick.text.contains(call), "the quick start lacks `{call}`");
        }
        assert_eq!(s[1].slug, "endpoint-reference");
    }

    #[test]
    fn guide_slugs_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for s in sections(GUIDE) {
            assert!(seen.insert(s.slug.clone()), "two sections are '{}'", s.slug);
            for (p, _) in s.parts {
                assert!(seen.insert(p.clone()), "two sections are '{p}'");
            }
        }
    }
}
