//! HTTP layer. Route table lives in [`router`]; the contract is in API.md.

use std::convert::Infallible;
use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{delete, get, patch, post, put};
use futures_util::{Stream, StreamExt};
use serde_json::json;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

use crate::runs::SseMsg;
use crate::state::AppState;

pub mod admin;
pub mod auth;
pub mod dbs;
pub mod runs;

// ── errors ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
    pub retry_after: Option<i64>,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        ApiError {
            status,
            message: message.into(),
            retry_after: None,
        }
    }
    pub fn bad_request(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, m)
    }
    pub fn unauthorized(m: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, m)
    }
    pub fn forbidden(m: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, m)
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, m)
    }
    pub fn conflict(m: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, m)
    }
    pub fn too_many(m: impl Into<String>, retry_after: i64) -> Self {
        ApiError {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: m.into(),
            retry_after: Some(retry_after.max(1)),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!(error = %format!("{e:#}"), "internal error");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error.")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({ "error": self.message });
        if let Some(r) = self.retry_after {
            body["retry_after"] = json!(r);
        }
        let mut resp = (self.status, axum::Json(body)).into_response();
        if let Some(r) = self.retry_after
            && let Ok(v) = HeaderValue::from_str(&r.to_string())
        {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        resp
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

// ── SSE helpers ────────────────────────────────────────────────────────

pub type EventStream = std::pin::Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send>>;

pub fn sse_event(event: &str, data: &serde_json::Value) -> Result<Event, Infallible> {
    Ok(Event::default().event(event).data(data.to_string()))
}

/// Turn a broadcast receiver into SSE events. `on_lag` produces a fresh
/// snapshot when a slow client missed messages.
pub fn broadcast_events(
    rx: tokio::sync::broadcast::Receiver<Arc<SseMsg>>,
    on_lag: impl Fn() -> Option<serde_json::Value> + Send + Sync + 'static,
) -> impl Stream<Item = Result<Event, Infallible>> + Send {
    let on_lag = Arc::new(on_lag);
    BroadcastStream::new(rx).filter_map(move |msg| {
        let on_lag = on_lag.clone();
        async move {
            match msg {
                Ok(m) => Some(Ok(Event::default().event(m.event).data(m.data.clone()))),
                Err(BroadcastStreamRecvError::Lagged(_)) => {
                    on_lag().map(|snap| sse_event("snapshot", &snap))
                }
            }
        }
    })
}

pub fn sse_response(state: &AppState, stream: EventStream) -> Response {
    let shutdown = state.shutdown.clone();
    let stream = stream.take_until(async move { shutdown.cancelled().await });
    let mut resp = Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response();
    // Disable proxy buffering (nginx) so progress arrives live.
    resp.headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    resp
}

// ── pages & assets ─────────────────────────────────────────────────────

struct Asset {
    name: &'static str,
    content_type: &'static str,
    bytes: &'static [u8],
}

macro_rules! asset {
    ($name:literal, $ct:literal) => {
        Asset {
            name: $name,
            content_type: $ct,
            bytes: include_bytes!(concat!("../../static/", $name)),
        }
    };
}

const ASSETS: &[Asset] = &[
    asset!("index.html", "text/html; charset=utf-8"),
    asset!("login.html", "text/html; charset=utf-8"),
    asset!("app.css", "text/css; charset=utf-8"),
    asset!("app.js", "text/javascript; charset=utf-8"),
    asset!("login.js", "text/javascript; charset=utf-8"),
    asset!("logo.svg", "image/svg+xml"),
];

fn asset_response(state: &AppState, name: &str) -> Response {
    let Some(asset) = ASSETS.iter().find(|a| a.name == name) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let bytes: Vec<u8> = match &state.settings.static_dir {
        Some(dir) => std::fs::read(dir.join(asset.name)).unwrap_or_else(|_| asset.bytes.to_vec()),
        None => asset.bytes.to_vec(),
    };
    let cache = if name.ends_with(".html") || state.settings.static_dir.is_some() {
        "no-store"
    } else {
        "public, max-age=300"
    };
    (
        [
            (header::CONTENT_TYPE, asset.content_type),
            (header::CACHE_CONTROL, cache),
        ],
        bytes,
    )
        .into_response()
}

async fn static_file(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    asset_response(&state, &name)
}

async fn app_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if crate::auth::session_from_headers(&state, &headers).is_none() {
        return Redirect::to("/login").into_response();
    }
    asset_response(&state, "index.html")
}

async fn login_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if crate::auth::session_from_headers(&state, &headers).is_some() {
        return Redirect::to("/").into_response();
    }
    asset_response(&state, "login.html")
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    let set = |h: &mut HeaderMap, k: &'static str, v: &'static str| {
        if !h.contains_key(k) {
            h.insert(k, HeaderValue::from_static(v));
        }
    };
    set(
        h,
        "content-security-policy",
        "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; \
         font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; \
         frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
    );
    set(h, "x-content-type-options", "nosniff");
    set(h, "x-frame-options", "DENY");
    set(h, "referrer-policy", "same-origin");
    set(
        h,
        "permissions-policy",
        "camera=(), microphone=(), geolocation=()",
    );
    resp
}

async fn api_not_found() -> ApiError {
    ApiError::not_found("No such API endpoint.")
}

pub fn router(state: Arc<AppState>) -> Router {
    let upload_limit = DefaultBodyLimit::max(state.settings.max_upload_bytes);
    let api = Router::new()
        .route("/auth/me", get(auth::me))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/password", post(auth::change_password))
        .route("/options", get(runs::options))
        .route(
            "/runs",
            get(runs::list).post(runs::create).layer(upload_limit),
        )
        .route("/runs/{id}", get(runs::detail).delete(runs::remove))
        .route("/runs/{id}/events", get(runs::events))
        .route("/runs/{id}/cancel", post(runs::cancel))
        .route("/runs/{id}/export", get(runs::export))
        .route("/runs/{id}/papers/{pidx}/retry", post(runs::retry))
        .route("/runs/{id}/papers/{pidx}/verdict", put(runs::set_verdict))
        .route("/runs/{id}/papers/{pidx}/refs/{ridx}/fp", put(runs::set_fp))
        .route("/databases", get(dbs::list))
        .route("/databases/{key}/update", post(dbs::update))
        .route("/databases/corpus/import", post(dbs::corpus_import))
        .route(
            "/databases/corpus/import-marked-safe",
            post(dbs::corpus_import_marked_safe),
        )
        .route("/databases/cache/clear", post(dbs::cache_clear))
        .route("/jobs", get(dbs::jobs))
        .route("/jobs/{id}", get(dbs::job))
        .route("/jobs/{id}/events", get(dbs::job_events))
        .route("/jobs/{id}/cancel", post(dbs::job_cancel))
        .route("/admin/users", get(admin::users).post(admin::create_user))
        .route(
            "/admin/users/{id}",
            patch(admin::update_user).delete(admin::delete_user),
        )
        .route("/admin/auth-events", get(admin::auth_events))
        .route("/admin/ip-blocks/{ip}", delete(admin::unblock_ip))
        .fallback(api_not_found);

    Router::new()
        .route("/", get(app_page))
        .route("/login", get(login_page))
        .route("/static/{name}", get(static_file))
        .nest("/api", api)
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state)
}
