use std::sync::Arc;

use axum::Json;
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{ApiError, ApiResult};
use crate::auth::{AdminUser, hash_password_async, validate_password, validate_username};
use crate::state::AppState;
use crate::store::StoreError;

pub async fn users(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "users": state.store.list_users()? })))
}

#[derive(Deserialize)]
pub struct NewUser {
    username: String,
    password: String,
    #[serde(default)]
    role: Option<String>,
}

pub async fn create_user(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    Json(body): Json<NewUser>,
) -> ApiResult<Response> {
    let username = body.username.trim().to_string();
    validate_username(&username).map_err(ApiError::bad_request)?;
    validate_password(&body.password).map_err(ApiError::bad_request)?;
    let role = match body.role.as_deref() {
        Some("admin") => "admin",
        None | Some("user") => "user",
        _ => return Err(ApiError::bad_request("Role must be admin or user.")),
    };
    let hash = hash_password_async(body.password).await?;
    match state.store.create_user(&username, &hash, role, "active") {
        Ok(u) => Ok((StatusCode::CREATED, Json(json!({ "user": u }))).into_response()),
        Err(StoreError::Conflict) => Err(ApiError::conflict("That username is already taken.")),
        Err(StoreError::Other(e)) => Err(e.into()),
    }
}

#[derive(Deserialize)]
pub struct UserPatch {
    status: Option<String>,
    role: Option<String>,
    #[serde(default)]
    unlock: bool,
}

pub async fn update_user(
    State(state): State<Arc<AppState>>,
    AdminUser(admin): AdminUser,
    UrlPath(id): UrlPath<i64>,
    Json(body): Json<UserPatch>,
) -> ApiResult<Json<Value>> {
    let target = state
        .store
        .get_user(id)?
        .ok_or_else(|| ApiError::not_found("User not found."))?;
    let is_self = target.id == admin.user.id;
    if let Some(s) = body.status.as_deref() {
        if !matches!(s, "active" | "disabled") {
            return Err(ApiError::bad_request("Status must be active or disabled."));
        }
        if is_self && s != "active" {
            return Err(ApiError::bad_request(
                "You cannot disable your own account.",
            ));
        }
        if s != "active" && target.is_admin() && state.store.count_active_admins()? <= 1 {
            return Err(ApiError::bad_request(
                "Keep at least one active administrator.",
            ));
        }
        state.store.set_user_status(id, s)?;
    }
    if let Some(r) = body.role.as_deref() {
        if !matches!(r, "admin" | "user") {
            return Err(ApiError::bad_request("Role must be admin or user."));
        }
        if r == "admin" && target.is_agent() {
            return Err(ApiError::bad_request(
                "Agent accounts cannot be administrators.",
            ));
        }
        if r == "user" && target.is_admin() {
            if is_self {
                return Err(ApiError::bad_request(
                    "You cannot remove your own admin role.",
                ));
            }
            if state.store.count_active_admins()? <= 1 {
                return Err(ApiError::bad_request(
                    "Keep at least one active administrator.",
                ));
            }
        }
        state.store.set_user_role(id, r)?;
    }
    if body.unlock {
        state.store.unlock_user(id)?;
    }
    let user = state
        .store
        .get_user(id)?
        .ok_or_else(|| ApiError::not_found("User not found."))?;
    Ok(Json(json!({ "user": user })))
}

pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    AdminUser(admin): AdminUser,
    UrlPath(id): UrlPath<i64>,
) -> ApiResult<StatusCode> {
    if id == admin.user.id {
        return Err(ApiError::bad_request("You cannot delete your own account."));
    }
    let target = state
        .store
        .get_user(id)?
        .ok_or_else(|| ApiError::not_found("User not found."))?;
    if target.is_admin() && state.store.count_active_admins()? <= 1 {
        return Err(ApiError::bad_request(
            "Keep at least one active administrator.",
        ));
    }
    state.store.delete_user(id)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Every user's API tokens (never the secrets).
pub async fn tokens(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        json!({ "tokens": state.store.list_api_tokens(None)? }),
    ))
}

#[derive(Deserialize)]
pub struct EventsQuery {
    limit: Option<i64>,
}

pub async fn auth_events(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    Query(q): Query<EventsQuery>,
) -> ApiResult<Json<Value>> {
    let events = state
        .store
        .list_auth_events(q.limit.unwrap_or(100).clamp(1, 1000))?;
    Ok(Json(json!({
        "events": events,
        "blocked_ips": state.store.list_ip_blocks()?,
    })))
}

#[derive(Deserialize)]
pub struct AuditQuery {
    /// A username (any case).
    account: Option<String>,
    /// `agent` or `person`.
    kind: Option<String>,
    /// Entries older than this id (the last `id` of the previous page).
    before: Option<i64>,
    limit: Option<i64>,
}

/// The API audit log, newest first, filtered by account and kind.
pub async fn audit(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Value>> {
    let account = q
        .account
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty());
    let kind = match q.kind.as_deref().map(str::trim) {
        None | Some("" | "all") => None,
        Some(k @ ("agent" | "person")) => Some(k),
        Some(_) => return Err(ApiError::bad_request("kind must be agent or person.")),
    };
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let entries = state.store.list_audit(account, kind, q.before, limit)?;
    let next_before = (entries.len() as i64 == limit)
        .then(|| entries.last().map(|e| e.id))
        .flatten();
    Ok(Json(json!({
        "entries": entries,
        "next_before": next_before,
        "retention_days": crate::audit::RETENTION_SECS / 86400,
    })))
}

pub async fn unblock_ip(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    UrlPath(ip): UrlPath<String>,
) -> ApiResult<StatusCode> {
    state.store.unblock_ip(&ip)?;
    Ok(StatusCode::NO_CONTENT)
}
