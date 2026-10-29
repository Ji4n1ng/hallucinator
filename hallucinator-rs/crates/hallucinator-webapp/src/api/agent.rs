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
    match sections.iter().find(|(slug, _)| slug == wanted) {
        Some((_, text)) => Ok(markdown(text.to_string())),
        None => Err(ApiError::not_found(format!(
            "No section '{wanted}'. Sections: {}.",
            sections
                .iter()
                .map(|(s, _)| s.as_str())
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

/// Each `## ` section of a Markdown text, with its slug. A section runs to
/// the next `## ` heading; `#` lines inside code fences do not count.
pub fn sections(text: &str) -> Vec<(String, &str)> {
    let mut starts: Vec<(usize, String)> = Vec::new();
    let mut fenced = false;
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
        } else if !fenced && let Some(h) = line.strip_prefix("## ") {
            starts.push((at, slug(h)));
        }
        at += line.len();
    }
    starts
        .iter()
        .enumerate()
        .map(|(i, (start, slug))| {
            let end = starts.get(i + 1).map_or(text.len(), |(s, _)| *s);
            (slug.clone(), text[*start..end].trim_end())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_and_sections() {
        assert_eq!(slug("Quick start"), "quick-start");
        assert_eq!(slug("Reference: runs & results "), "reference-runs-results");
        let text = "# T\nintro\n## One\na\n```\n## not a heading\n```\n## Two: b\nc\n";
        let s = sections(text);
        assert_eq!(
            s.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
            ["one", "two-b"]
        );
        assert!(s[0].1.starts_with("## One") && s[0].1.contains("## not a heading"));
        assert_eq!(s[1].1, "## Two: b\nc");
    }

    #[test]
    fn guide_starts_with_a_short_quick_start() {
        let s = sections(GUIDE);
        assert_eq!(
            s[0].0, "quick-start",
            "the guide must open with ## Quick start"
        );
        // Everything before the endpoint reference is the quick start.
        let reference = GUIDE
            .find("\n## Endpoint reference")
            .expect("## Endpoint reference section");
        let lines = GUIDE[..reference].lines().count();
        assert!(
            lines <= 150,
            "the quick start part has {lines} lines (max 150)"
        );
    }
}
