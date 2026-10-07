use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{ApiError, ApiResult, EventStream, broadcast_events, sse_event, sse_response};
use crate::auth::{AdminUser, AuthUser};
use crate::jobs::{JobSpec, StartError};
use crate::refdb::{self, ALL_KEYS, DbKey, disk_size, modified_at, spec};
use crate::state::AppState;
use crate::store::JobRow;

/// Server filesystem details — database, config, cache and CLI paths, job
/// command lines and logs — are for admins only. Non-admins get the same
/// status, dates and counts without them.
fn public_job(mut job: JobRow) -> JobRow {
    job.argv.clear();
    job
}

fn db_status(state: &AppState, key: DbKey, admin: bool) -> Value {
    let sp = spec(key);
    let r = &state.refdb;
    let (path, source) = r.path_of(key);
    let exists = path.exists();
    let fresh = r.freshness(key);
    let update = match key {
        DbKey::Corpus => json!({
            "supported": state.jobs.cli().is_some(),
            "action": "import",
            "notes": sp.notes,
            "params": [],
        }),
        _ => json!({
            "supported": state.jobs.cli().is_some() && sp.update_subcommand.is_some(),
            "action": "update",
            "notes": sp.notes,
            "params": sp.params,
        }),
    };
    let mut v = json!({
        "key": key.as_str(),
        "label": sp.label,
        "description": sp.description,
        "path": path.display().to_string(),
        "path_source": source,
        "exists": exists,
        "size_bytes": if exists { disk_size(&path) } else { None },
        "modified_at": modified_at(&path),
        "loaded": r.is_loaded(key),
        "load_error": r.load_error(key),
        "build_date": fresh.build_date,
        "age_days": fresh.age_days,
        "stale": fresh.stale,
        "records": r.records(key),
        "update": update,
        "active_job": state.jobs.active_for(key.as_str()).map(|j| if admin { j } else { public_job(j) }),
        "last_job": state.store.last_job_for(key.as_str()).ok().flatten().map(|j| if admin { j } else { public_job(j) }),
    });
    if key == DbKey::Corpus {
        v["sources"] = json!(r.corpus_sources());
    }
    if !admin && let Some(obj) = v.as_object_mut() {
        obj.remove("path");
        obj.remove("path_source");
        if obj.get("load_error").is_some_and(|e| !e.is_null()) {
            obj.insert(
                "load_error".into(),
                json!("The database could not be loaded. An administrator can see the details."),
            );
        }
    }
    v
}

pub async fn list(State(state): State<Arc<AppState>>, user: AuthUser) -> ApiResult<Json<Value>> {
    let admin = user.user.is_admin();
    let s = state.clone();
    let databases = tokio::task::spawn_blocking(move || {
        ALL_KEYS
            .iter()
            .map(|k| db_status(&s, *k, admin))
            .collect::<Vec<_>>()
    })
    .await
    .map_err(anyhow::Error::from)?;
    let cli = state.jobs.cli();
    let cache = &state.refdb.query_cache;
    let cache_path = state.refdb.cache_path.clone();
    let mut out = json!({
        "cli_available": cli.is_some(),
        "cli_path": cli.map(|c| c.path.display().to_string()),
        "cli_version": cli.and_then(|c| c.version.clone()),
        "config_path": state.refdb.config_path.as_ref().map(|p| p.display().to_string()),
        "databases": databases,
        "cache": {
            "path": cache_path.as_ref().map(|p| p.display().to_string()),
            "exists": cache_path.as_ref().is_some_and(|p| p.exists()),
            "size_bytes": cache_path.as_ref().and_then(|p| disk_size(p)),
            "entries": cache.len(),
        },
        "venues": cli.map(|c| c.venues.clone()).unwrap_or_default(),
        "marked_safe_count": state.store.count_marked_safe()?,
    });
    if !admin {
        for ptr in ["/cli_path", "/config_path", "/cache/path"] {
            if let Some(field) = out.pointer_mut(ptr) {
                *field = Value::Null;
            }
        }
    }
    Ok(Json(out))
}

fn start_error(e: StartError) -> ApiError {
    match e {
        StartError::NoCli => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "hallucinator-cli was not found. Build it with `cargo build --release -p hallucinator-cli` \
             in hallucinator-rs/ or pass --cli-path.",
        ),
        StartError::Busy => ApiError::conflict("A job for this database is already running."),
        StartError::Other(e) => e.into(),
    }
}

fn server_file(raw: &str, what: &str) -> ApiResult<String> {
    let p = PathBuf::from(raw.trim());
    if !p.is_absolute() {
        return Err(ApiError::bad_request(format!(
            "{what} must be an absolute server path."
        )));
    }
    if !p.is_file() {
        return Err(ApiError::bad_request(format!(
            "{what}: no such file on the server."
        )));
    }
    Ok(p.display().to_string())
}

fn ensure_parent(path: &std::path::Path) -> ApiResult<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(anyhow::Error::from)?;
    }
    Ok(())
}

#[derive(Deserialize, Default)]
pub struct UpdateBody {
    #[serde(default)]
    params: HashMap<String, Value>,
}

fn param_str(params: &HashMap<String, Value>, k: &str) -> Option<String> {
    match params.get(k)? {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

pub async fn update(
    State(state): State<Arc<AppState>>,
    AdminUser(admin): AdminUser,
    UrlPath(key): UrlPath<String>,
    body: Option<Json<UpdateBody>>,
) -> ApiResult<Response> {
    let key = refdb::parse_key(&key).ok_or_else(|| ApiError::not_found("Unknown database."))?;
    let sp = spec(key);
    let sub = sp
        .update_subcommand
        .ok_or_else(|| ApiError::bad_request("This database is grown by imports, not rebuilt."))?;
    let params = body.map(|b| b.0.params).unwrap_or_default();
    let (path, _) = state.refdb.path_of(key);
    ensure_parent(&path)?;
    let mut argv = vec![sub.to_string(), path.display().to_string()];
    match key {
        DbKey::Dblp => {
            if let Some(f) = param_str(&params, "from_file") {
                argv.extend(["--from-file".into(), server_file(&f, "dblp.xml.gz")?]);
            }
        }
        DbKey::Arxiv => {
            if let Some(f) = param_str(&params, "dump") {
                argv.extend(["--dump".into(), server_file(&f, "Kaggle dump")?]);
            }
        }
        DbKey::OpenAlex => {
            if let Some(d) = param_str(&params, "since") {
                let ok = d.len() == 10
                    && d.chars().enumerate().all(|(i, c)| {
                        if i == 4 || i == 7 {
                            c == '-'
                        } else {
                            c.is_ascii_digit()
                        }
                    });
                if !ok {
                    return Err(ApiError::bad_request("Date must be YYYY-MM-DD."));
                }
                argv.extend(["--since".into(), d]);
            }
            if let Some(y) = param_str(&params, "min_year") {
                match y.parse::<u32>() {
                    Ok(y) if (1900..=2100).contains(&y) => {
                        argv.extend(["--min-year".into(), y.to_string()])
                    }
                    _ => return Err(ApiError::bad_request("Year must be between 1900 and 2100.")),
                }
            }
        }
        _ => {}
    }
    let job = state
        .jobs
        .start(
            &admin.user,
            JobSpec {
                db_key: key,
                action: "update",
                label: format!("Update {}", sp.label),
                argv,
                cleanup: None,
            },
        )
        .map_err(start_error)?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "job": job }))).into_response())
}

#[derive(Deserialize)]
pub struct ImportBody {
    venue: String,
    source_tag: String,
    url: Option<String>,
    pdf_path: Option<String>,
}

fn valid_source_tag(t: &str) -> bool {
    let mut chars = t.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && t.len() <= 64
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
}

pub async fn corpus_import(
    State(state): State<Arc<AppState>>,
    AdminUser(admin): AdminUser,
    Json(body): Json<ImportBody>,
) -> ApiResult<Response> {
    let cli = state
        .jobs
        .cli()
        .ok_or_else(|| start_error(StartError::NoCli))?;
    let venue = cli
        .venues
        .iter()
        .find(|v| v.key == body.venue)
        .cloned()
        .ok_or_else(|| ApiError::bad_request("Unknown venue."))?;
    let tag = body.source_tag.trim();
    if !valid_source_tag(tag) {
        return Err(ApiError::bad_request(
            "Source tag must be 1–64 letters, digits, '.', '_', '-' or ':' (e.g. usenix2026).",
        ));
    }
    let (path, _) = state.refdb.path_of(DbKey::Corpus);
    ensure_parent(&path)?;
    let mut argv = vec![
        venue.subcommand.clone(),
        "--corpus".into(),
        path.display().to_string(),
        "--source-tag".into(),
        tag.to_string(),
    ];
    if venue.input == "url" {
        let url = body.url.as_deref().map(str::trim).unwrap_or("");
        let ok = (url.starts_with("https://") || url.starts_with("http://"))
            && url.len() <= 2048
            && !url.chars().any(|c| c.is_whitespace() || c.is_control());
        if !ok {
            return Err(ApiError::bad_request(
                "Enter the program page URL (http:// or https://).",
            ));
        }
        argv.extend(["--url".into(), url.to_string()]);
    } else {
        let p = body.pdf_path.as_deref().unwrap_or("");
        argv.extend(["--pdf-path".into(), server_file(p, "PDF path")?]);
    }
    let job = state
        .jobs
        .start(
            &admin.user,
            JobSpec {
                db_key: DbKey::Corpus,
                action: "import",
                label: format!("Import {} ({tag}) into Local Corpus", venue.key),
                argv,
                cleanup: None,
            },
        )
        .map_err(start_error)?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "job": job }))).into_response())
}

pub async fn corpus_import_marked_safe(
    State(state): State<Arc<AppState>>,
    AdminUser(admin): AdminUser,
) -> ApiResult<Response> {
    let items = state.store.marked_safe()?;
    if items.is_empty() {
        return Err(ApiError::bad_request(
            "No references have been marked safe yet.",
        ));
    }
    let report = crate::export::marked_safe_report(&items);
    let dir = state.settings.data_dir.join("tmp");
    std::fs::create_dir_all(&dir).map_err(anyhow::Error::from)?;
    let file = dir.join(format!("marked-safe-{}.json", crate::auth::random_id()));
    std::fs::write(&file, report).map_err(anyhow::Error::from)?;
    let (path, _) = state.refdb.path_of(DbKey::Corpus);
    ensure_parent(&path)?;
    let argv = vec![
        "import-corpus-reports".into(),
        "--corpus".into(),
        path.display().to_string(),
        file.display().to_string(),
    ];
    let job = state
        .jobs
        .start(
            &admin.user,
            JobSpec {
                db_key: DbKey::Corpus,
                action: "import",
                label: format!(
                    "Import {} marked-safe references into Local Corpus",
                    items.len()
                ),
                argv,
                cleanup: Some(file.clone()),
            },
        )
        .map_err(|e| {
            let _ = std::fs::remove_file(&file);
            start_error(e)
        })?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "job": job }))).into_response())
}

#[derive(Deserialize, Default)]
pub struct CacheClearBody {
    #[serde(default)]
    not_found_only: bool,
}

pub async fn cache_clear(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    body: Option<Json<CacheClearBody>>,
) -> ApiResult<Json<Value>> {
    let not_found_only = body.map(|b| b.0.not_found_only).unwrap_or(false);
    let cache = state.refdb.query_cache.clone();
    let removed = tokio::task::spawn_blocking(move || {
        if not_found_only {
            Some(cache.clear_not_found())
        } else {
            cache.clear();
            None
        }
    })
    .await
    .map_err(anyhow::Error::from)?;
    Ok(Json(json!({ "removed": removed })))
}

#[derive(Deserialize)]
pub struct JobsQuery {
    limit: Option<i64>,
}

pub async fn jobs(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(q): Query<JobsQuery>,
) -> ApiResult<Json<Value>> {
    let mut jobs: Vec<JobRow> = state.store.list_jobs(q.limit.unwrap_or(20).clamp(1, 200))?;
    // Live status wins over the row persisted at start.
    for j in jobs.iter_mut() {
        if let Ok(Some((live, _))) = state.jobs.get(&j.id) {
            *j = live;
        }
    }
    if !user.user.is_admin() {
        jobs = jobs.into_iter().map(public_job).collect();
    }
    Ok(Json(json!({ "jobs": jobs })))
}

pub async fn job(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    UrlPath(id): UrlPath<String>,
) -> ApiResult<Json<Value>> {
    let (job, log) = state
        .jobs
        .get(&id)?
        .ok_or_else(|| ApiError::not_found("Job not found."))?;
    Ok(Json(json!({ "job": job, "log": log })))
}

pub async fn job_events(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    UrlPath(id): UrlPath<String>,
) -> ApiResult<impl IntoResponse> {
    let rx = state.jobs.subscribe(&id);
    let (job, log) = state
        .jobs
        .get(&id)?
        .ok_or_else(|| ApiError::not_found("Job not found."))?;
    let snap = json!({ "job": job, "log": log });
    let first = futures_util::stream::once(async move { sse_event("snapshot", &snap) });
    let stream: EventStream = match rx {
        Some(rx) => {
            let jobs = state.jobs.clone();
            let jid = id.clone();
            let live = broadcast_events(rx, move || {
                jobs.get(&jid)
                    .ok()
                    .flatten()
                    .map(|(job, log)| json!({ "job": job, "log": log }))
            });
            Box::pin(first.chain(live))
        }
        None => Box::pin(first.chain(futures_util::stream::once(async {
            sse_event("end", &json!({}))
        }))),
    };
    Ok(sse_response(&state, stream))
}

pub async fn job_cancel(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    UrlPath(id): UrlPath<String>,
) -> ApiResult<StatusCode> {
    if state.jobs.cancel(&id) {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("No running job with that id."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_tags() {
        assert!(valid_source_tag("usenix2026"));
        assert!(valid_source_tag("marked_safe:known_good"));
        assert!(!valid_source_tag(""));
        assert!(!valid_source_tag("-x"));
        assert!(!valid_source_tag("a b"));
        assert!(!valid_source_tag("a;rm"));
    }
}
