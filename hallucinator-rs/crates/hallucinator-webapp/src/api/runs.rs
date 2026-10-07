use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Json;
use axum::extract::{Multipart, Path as UrlPath, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{ApiError, ApiResult, EventStream, broadcast_events, sse_event, sse_response};
use crate::auth::AuthUser;
use crate::inputs::{self, InputFile, InputKind};
use crate::refdb::RunOptions;
use crate::runs::{RetryError, RetryScope, run_summary};
use crate::state::AppState;
use crate::store::{RunRow, User};

/// Database names, in the TUI's order (`hallucinator-tui/src/model/config.rs`).
/// Upstream keeps the authoritative list `pub(crate)`, so it is mirrored here.
const BACKENDS: &[&str] = &[
    "CrossRef",
    "arXiv",
    "DBLP",
    "Semantic Scholar",
    "ACL Anthology",
    "Europe PMC",
    "PubMed",
    "IACR ePrint",
    "OpenAlex",
    "DOI",
    "GovInfo",
    "Standards",
    "Open Library",
    "Local Corpus",
];

const MAX_FILES: usize = 500;

pub async fn options(State(state): State<Arc<AppState>>, _user: AuthUser) -> Json<Value> {
    let r = &state.refdb;
    let defaults = r.default_disabled();
    let dbs: Vec<Value> = BACKENDS
        .iter()
        .map(|name| {
            let offline = crate::refdb::SPECS
                .iter()
                .find(|s| s.backend_name == *name)
                .is_some_and(|s| r.is_loaded(s.key));
            let (available, note) = match *name {
                "IACR ePrint" | "Local Corpus" if !offline => {
                    (false, "Offline only — build it on the Databases page.")
                }
                "OpenAlex" if !offline && !r.has_openalex_key() => {
                    (false, "Needs an OpenAlex API key or the offline index.")
                }
                "GovInfo" if !r.has_govinfo_key() => (false, "Needs a GovInfo API key."),
                "DBLP" if !offline => (
                    true,
                    "Online API is blocked by bot protection — build the offline database.",
                ),
                "DOI" => (true, "Only used when a reference carries a DOI."),
                _ if offline => (true, "Offline database"),
                _ => (true, ""),
            };
            json!({
                "name": name,
                "enabled_by_default": !defaults.iter().any(|d| d.eq_ignore_ascii_case(name)),
                "offline": offline,
                "available": available,
                "note": note,
            })
        })
        .collect();
    Json(json!({
        "databases": dbs,
        "defaults": {
            "disabled_dbs": defaults,
            "url_match": false,
            "searxng": false,
            "check_openalex_authors": false,
            "num_workers": r.num_workers,
        },
        "searxng_configured": r.searxng_configured(),
        "max_upload_mb": state.settings.max_upload_bytes / (1024 * 1024),
        "accepted": [".pdf", ".bib", ".bbl", ".xml", ".zip", ".tar.gz", ".tgz"],
    }))
}

fn can_access(user: &User, run: &RunRow) -> bool {
    user.is_admin() || run.user_id == user.id
}

fn load_run(state: &AppState, user: &User, id: &str) -> ApiResult<RunRow> {
    match state.store.get_run(id)? {
        Some(r) if can_access(user, &r) => Ok(r),
        _ => Err(ApiError::not_found("Run not found.")),
    }
}

#[derive(Deserialize)]
pub struct ListQuery {
    q: Option<String>,
    status: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
    all: Option<String>,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    AuthUser { user, .. }: AuthUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let all = user.is_admin() && matches!(q.all.as_deref(), Some("1" | "true"));
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0).max(0);
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let status = q.status.as_deref().filter(|s| !s.is_empty() && *s != "all");
    let (total, runs) =
        state
            .store
            .list_runs((!all).then_some(user.id), search, status, limit, offset)?;
    let ids: Vec<String> = runs.iter().map(|r| r.id.clone()).collect();
    let stats = state.store.run_stats(&ids)?;
    let runs: Vec<Value> = runs
        .iter()
        .map(|r| run_summary(r, stats.get(&r.id).unwrap_or(&Default::default())))
        .collect();
    Ok(Json(json!({ "total": total, "runs": runs })))
}

/// Keep a safe basename: no directories, no control characters.
fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let clean: String = base
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| {
            if matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let clean = clean.trim().trim_start_matches('.').to_string();
    let clean = if clean.is_empty() {
        "upload".to_string()
    } else {
        clean
    };
    // Cap length while keeping the extension.
    if clean.chars().count() > 120 {
        let ext = clean
            .rfind('.')
            .map(|i| clean[i..].to_string())
            .unwrap_or_default();
        let stem: String = clean
            .chars()
            .take(120 - ext.chars().count().min(20))
            .collect();
        format!("{stem}{ext}")
    } else {
        clean
    }
}

fn is_archive(name: &str) -> bool {
    let l = name.to_lowercase();
    l.ends_with(".zip") || l.ends_with(".tar.gz") || l.ends_with(".tgz")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Saved {
    display_name: String,
    path: PathBuf,
    sha256: String,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    AuthUser { user, .. }: AuthUser,
    mut multipart: Multipart,
) -> ApiResult<Response> {
    let tmp_root = state.settings.data_dir.join("tmp");
    std::fs::create_dir_all(&tmp_root).map_err(anyhow::Error::from)?;
    let uploads = tempfile::Builder::new()
        .prefix("upload-")
        .tempdir_in(&tmp_root)
        .map_err(anyhow::Error::from)?;

    let mut opts = RunOptions::default();
    let mut saved: Vec<Saved> = Vec::new();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad_request(format!("Malformed upload: {e}")))?
    {
        match field.name().unwrap_or("") {
            "options" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(format!("Malformed options: {e}")))?;
                opts = serde_json::from_str(&text)
                    .map_err(|e| ApiError::bad_request(format!("Invalid options: {e}")))?;
            }
            "files" | "file" | "pdf" => {
                if saved.len() >= MAX_FILES {
                    return Err(ApiError::bad_request(format!(
                        "At most {MAX_FILES} files per check."
                    )));
                }
                let display = sanitize_filename(field.file_name().unwrap_or("upload"));
                if InputKind::from_name(&display).is_none() && !is_archive(&display) {
                    return Err(ApiError::bad_request(format!(
                        "{display}: unsupported file type. Upload .pdf, .bib, .bbl, .xml, .zip or .tar.gz files."
                    )));
                }
                let path = uploads.path().join(format!("{:03}-{display}", saved.len()));
                let mut file = std::fs::File::create(&path).map_err(anyhow::Error::from)?;
                let mut hasher = Sha256::new();
                let mut size = 0usize;
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|e| ApiError::bad_request(format!("Upload interrupted: {e}")))?
                {
                    size += chunk.len();
                    hasher.update(&chunk);
                    file.write_all(&chunk).map_err(anyhow::Error::from)?;
                }
                if size == 0 {
                    return Err(ApiError::bad_request(format!("{display} is empty.")));
                }
                saved.push(Saved {
                    display_name: display,
                    path,
                    sha256: hex(&hasher.finalize()),
                });
            }
            _ => {
                let _ = field.bytes().await;
            }
        }
    }
    if saved.is_empty() {
        return Err(ApiError::bad_request("Choose at least one file to check."));
    }
    opts.disabled_dbs.retain(|d| d.len() <= 64);
    opts.disabled_dbs.truncate(64);
    opts.title = opts
        .title
        .map(|t| t.trim().chars().take(200).collect::<String>())
        .filter(|t| !t.is_empty());

    let files = expand_inputs(saved, uploads.path()).await?;
    if files.is_empty() {
        return Err(ApiError::bad_request(
            "No PDF, .bib, .bbl or .xml files found in the upload.",
        ));
    }
    let planned = inputs::plan_papers(files, opts.bib_mode);
    let title = opts.title.clone().unwrap_or_else(|| {
        let first = &planned[0];
        let name = match &first.companion {
            Some(c) => format!("{} + {}", first.main.display_name, c.display_name),
            None => first.main.display_name.clone(),
        };
        if planned.len() > 1 {
            format!("{name} and {} more", planned.len() - 1)
        } else {
            name
        }
    });
    let papers: Vec<(String, String, Option<String>, Option<String>)> = planned
        .iter()
        .map(|p| {
            (
                p.main.display_name.clone(),
                p.input_kind(),
                p.companion.as_ref().map(|c| c.display_name.clone()),
                p.main.sha256.clone(),
            )
        })
        .collect();
    let run_id = crate::auth::random_id();
    let options_json = serde_json::to_string(&opts).map_err(anyhow::Error::from)?;
    state
        .store
        .create_run(&run_id, user.id, &title, &options_json, &papers)?;
    tracing::info!(run = %run_id, user = %user.username, papers = papers.len(), "run created");
    state.runs.start(run_id.clone(), planned, opts, uploads);
    Ok((StatusCode::CREATED, Json(json!({ "run_id": run_id }))).into_response())
}

/// Validate uploaded files and expand archives into their PDFs/bibs.
async fn expand_inputs(saved: Vec<Saved>, dir: &Path) -> ApiResult<Vec<InputFile>> {
    let mut out = Vec::new();
    for (i, s) in saved.into_iter().enumerate() {
        if is_archive(&s.display_name) {
            let target = dir.join(format!("archive-{i}"));
            let path = s.path.clone();
            let res = tokio::task::spawn_blocking(move || {
                std::fs::create_dir_all(&target)
                    .map_err(|e| e.to_string())
                    .and_then(|_| {
                        hallucinator_ingest::archive::extract_archive(
                            &path,
                            &target,
                            1024 * 1024 * 1024,
                        )
                    })
            })
            .await
            .map_err(anyhow::Error::from)?
            .map_err(|e| ApiError::bad_request(format!("{}: {e}", s.display_name)))?;
            for f in res.pdfs {
                let Some(kind) = InputKind::from_name(&f.filename) else {
                    continue;
                };
                out.push(InputFile {
                    display_name: format!("{}/{}", s.display_name, f.filename),
                    path: f.path,
                    kind,
                    sha256: None,
                });
            }
            continue;
        }
        let kind = InputKind::from_name(&s.display_name).expect("checked on upload");
        if kind == InputKind::Pdf {
            let mut head = [0u8; 5];
            let ok = std::fs::File::open(&s.path)
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head))
                .is_ok()
                && &head == b"%PDF-";
            if !ok {
                return Err(ApiError::bad_request(format!(
                    "{} does not look like a PDF.",
                    s.display_name
                )));
            }
        }
        out.push(InputFile {
            display_name: s.display_name,
            path: s.path,
            kind,
            sha256: Some(s.sha256),
        });
    }
    Ok(out)
}

pub async fn detail(
    State(state): State<Arc<AppState>>,
    AuthUser { user, .. }: AuthUser,
    UrlPath(id): UrlPath<String>,
) -> ApiResult<Json<Value>> {
    load_run(&state, &user, &id)?;
    let d = state
        .runs
        .detail(&id)?
        .ok_or_else(|| ApiError::not_found("Run not found."))?;
    Ok(Json(d))
}

pub async fn events(
    State(state): State<Arc<AppState>>,
    AuthUser { user, .. }: AuthUser,
    UrlPath(id): UrlPath<String>,
) -> ApiResult<impl IntoResponse> {
    load_run(&state, &user, &id)?;
    // Subscribe before taking the snapshot so nothing falls in between.
    let rx = state.runs.subscribe(&id);
    let snapshot = state
        .runs
        .detail(&id)?
        .ok_or_else(|| ApiError::not_found("Run not found."))?;
    let first = futures_util::stream::once(async move { sse_event("snapshot", &snapshot) });
    let stream: EventStream = match rx {
        Some(rx) => {
            let runs = state.runs.clone();
            let rid = id.clone();
            let live = broadcast_events(rx, move || runs.detail(&rid).ok().flatten());
            Box::pin(first.chain(live))
        }
        None => Box::pin(first.chain(futures_util::stream::once(async {
            sse_event("end", &json!({}))
        }))),
    };
    Ok(sse_response(&state, stream))
}

pub async fn cancel(
    State(state): State<Arc<AppState>>,
    AuthUser { user, .. }: AuthUser,
    UrlPath(id): UrlPath<String>,
) -> ApiResult<StatusCode> {
    load_run(&state, &user, &id)?;
    state.runs.cancel(&id);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove(
    State(state): State<Arc<AppState>>,
    AuthUser { user, .. }: AuthUser,
    UrlPath(id): UrlPath<String>,
) -> ApiResult<StatusCode> {
    load_run(&state, &user, &id)?;
    state.runs.cancel(&id);
    state.store.delete_run(&id)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct RetryBody {
    scope: RetryScope,
    ref_idx: Option<usize>,
}

pub async fn retry(
    State(state): State<Arc<AppState>>,
    AuthUser { user, .. }: AuthUser,
    UrlPath((id, pidx)): UrlPath<(String, usize)>,
    Json(body): Json<RetryBody>,
) -> ApiResult<Response> {
    load_run(&state, &user, &id)?;
    match state.runs.retry(&id, pidx, body.scope, body.ref_idx) {
        Ok(n) => Ok((StatusCode::ACCEPTED, Json(json!({ "queued": n }))).into_response()),
        Err(RetryError::Busy) => Err(ApiError::conflict(
            "This run is still in progress. Wait for it to finish, then retry.",
        )),
        Err(RetryError::NotFound) => Err(ApiError::not_found("Reference not found.")),
        Err(RetryError::Other(e)) => Err(e.into()),
    }
}

#[derive(Deserialize)]
pub struct FpBody {
    reason: Option<String>,
}

const FP_REASONS: &[&str] = &[
    "broken_parse",
    "exists_elsewhere",
    "all_timed_out",
    "known_good",
    "non_academic",
];

pub async fn set_fp(
    State(state): State<Arc<AppState>>,
    AuthUser { user, .. }: AuthUser,
    UrlPath((id, pidx, ridx)): UrlPath<(String, usize, usize)>,
    Json(body): Json<FpBody>,
) -> ApiResult<Json<Value>> {
    load_run(&state, &user, &id)?;
    let reason = body.reason.filter(|r| !r.is_empty());
    if let Some(r) = &reason
        && !FP_REASONS.contains(&r.as_str())
    {
        return Err(ApiError::bad_request("Unknown reason."));
    }
    if !state.store.set_ref_fp(&id, pidx, ridx, reason.as_deref())? {
        return Err(ApiError::not_found("Reference not found."));
    }
    let refs = state.store.load_paper_refs(&id, pidx)?;
    let row = refs
        .iter()
        .find(|r| r.idx == ridx)
        .ok_or_else(|| ApiError::not_found("Reference not found."))?;
    let live = state.runs.live(&id);
    let view = crate::runs::ref_view(row, live.as_deref(), pidx);
    let stats = crate::runs::paper_stats(&refs);
    Ok(Json(json!({ "ref": view, "stats": stats })))
}

#[derive(Deserialize)]
pub struct VerdictBody {
    verdict: Option<String>,
}

pub async fn set_verdict(
    State(state): State<Arc<AppState>>,
    AuthUser { user, .. }: AuthUser,
    UrlPath((id, pidx)): UrlPath<(String, usize)>,
    Json(body): Json<VerdictBody>,
) -> ApiResult<StatusCode> {
    load_run(&state, &user, &id)?;
    let v = body.verdict.filter(|v| !v.is_empty());
    if let Some(v) = &v
        && v != "safe"
        && v != "questionable"
    {
        return Err(ApiError::bad_request(
            "Verdict must be safe, questionable or null.",
        ));
    }
    if !state.store.set_paper_verdict(&id, pidx, v.as_deref())? {
        return Err(ApiError::not_found("Paper not found."));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct ExportQuery {
    format: Option<String>,
    paper: Option<usize>,
    problematic: Option<String>,
}

fn download_name(title: &str, ext: &str) -> String {
    let stem: String = title
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(80)
        .collect();
    let stem = stem.trim_matches('_');
    format!(
        "{}.{}",
        if stem.is_empty() {
            "hallucinator-report"
        } else {
            stem
        },
        ext
    )
}

pub async fn export(
    State(state): State<Arc<AppState>>,
    AuthUser { user, .. }: AuthUser,
    UrlPath(id): UrlPath<String>,
    Query(q): Query<ExportQuery>,
) -> ApiResult<Response> {
    let run = load_run(&state, &user, &id)?;
    let format = crate::export::parse_format(q.format.as_deref().unwrap_or("json"))
        .ok_or_else(|| ApiError::bad_request("Unknown format."))?;
    let mut papers = state.store.load_papers(&id)?;
    let mut title = run.title.clone();
    if let Some(p) = q.paper {
        papers.retain(|(row, _)| row.idx == p);
        let Some((row, _)) = papers.first() else {
            return Err(ApiError::not_found("Paper not found."));
        };
        title = row.filename.clone();
    }
    let problematic = matches!(q.problematic.as_deref(), Some("1" | "true"));
    let body =
        tokio::task::spawn_blocking(move || crate::export::render(&papers, format, problematic))
            .await
            .map_err(anyhow::Error::from)??;
    let name = download_name(&title, format.extension());
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(crate::export::content_type(format)),
    );
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    // Reports embed untrusted citation text; never render them on our origin.
    h.insert(
        "content-security-policy",
        HeaderValue::from_static("sandbox; default-src 'none'; style-src 'unsafe-inline'"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filenames_are_sanitized() {
        assert_eq!(sanitize_filename("../../etc/passwd.pdf"), "passwd.pdf");
        assert_eq!(sanitize_filename("C:\\x\\a<b>.bib"), "a_b_.bib");
        assert_eq!(sanitize_filename(".hidden.pdf"), "hidden.pdf");
        assert_eq!(sanitize_filename(""), "upload");
        let long = format!("{}.pdf", "a".repeat(300));
        let s = sanitize_filename(&long);
        assert!(s.ends_with(".pdf") && s.chars().count() <= 120);
        assert_eq!(
            download_name("my paper (v2).pdf", "json"),
            "my_paper__v2__pdf.json"
        );
    }
}
