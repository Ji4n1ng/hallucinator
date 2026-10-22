//! API documentation served to scripts and agents: the task-oriented guide
//! (`API-GUIDE.md`) and the full contract (`API.md`), both public.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

const GUIDE: &str = include_str!("../../API-GUIDE.md");
const REFERENCE: &str = include_str!("../../API.md");

/// `scheme://host` the client reached us at, for copy-paste examples.
fn base_url(state: &AppState, headers: &HeaderMap) -> String {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .filter(|h| {
            !h.is_empty()
                && h.len() <= 255
                && h.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
        })
        .unwrap_or("localhost");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .filter(|p| matches!(*p, "http" | "https"))
        .unwrap_or(if state.settings.secure_cookies {
            "https"
        } else {
            "http"
        });
    format!("{proto}://{host}")
}

fn markdown(body: String) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/markdown; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

pub async fn guide(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    markdown(GUIDE.replace("{{BASE_URL}}", &base_url(&state, &headers)))
}

pub async fn reference() -> Response {
    markdown(REFERENCE.to_string())
}
