//! Personal API tokens for scripts and agents (`Authorization: Bearer`).
//! Managing them needs a browser session ([`SessionUser`]).

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{ApiError, ApiResult};
use crate::auth::{ClientIp, SessionUser, issue_api_token, validate_token_name};
use crate::state::AppState;
use crate::store::now;

const MAX_TOKENS_PER_USER: i64 = 50;
const MAX_TOKEN_DAYS: i64 = 3650;

pub async fn list(
    State(state): State<Arc<AppState>>,
    SessionUser { user, .. }: SessionUser,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        json!({ "tokens": state.store.list_api_tokens(Some(user.id))? }),
    ))
}

#[derive(Deserialize)]
pub struct NewToken {
    name: String,
    /// Days until the token stops working; `null` = never expires.
    #[serde(default)]
    expires_in_days: Option<i64>,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    SessionUser { user, .. }: SessionUser,
    Json(body): Json<NewToken>,
) -> ApiResult<Response> {
    let name = body.name.trim();
    validate_token_name(name).map_err(ApiError::bad_request)?;
    let expires_at = match body.expires_in_days {
        None => None,
        Some(d) if (1..=MAX_TOKEN_DAYS).contains(&d) => Some(now() + d * 86400),
        Some(_) => {
            return Err(ApiError::bad_request(format!(
                "Expiry must be between 1 and {MAX_TOKEN_DAYS} days, or none."
            )));
        }
    };
    if state.store.count_api_tokens(user.id)? >= MAX_TOKENS_PER_USER {
        return Err(ApiError::bad_request(format!(
            "You already have {MAX_TOKENS_PER_USER} API tokens. Revoke one first."
        )));
    }
    let (secret, token) = issue_api_token(&state.store, user.id, name, expires_at)?;
    state.store.add_auth_event(
        &ip,
        Some(&user.username),
        "token_create",
        Some(&format!("{} ({}…)", token.name, token.prefix)),
    )?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "token": token, "secret": secret })),
    )
        .into_response())
}

/// Revoke one of your tokens; administrators may revoke anyone's.
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    SessionUser { user, .. }: SessionUser,
    UrlPath(id): UrlPath<i64>,
) -> ApiResult<StatusCode> {
    let owner = (!user.is_admin()).then_some(user.id);
    let token = state
        .store
        .delete_api_token(id, owner)?
        .ok_or_else(|| ApiError::not_found("API token not found."))?;
    let mut detail = format!("{} ({}…)", token.name, token.prefix);
    if token.user_id != user.id {
        detail.push_str(&format!(" of {}", token.username));
    }
    state
        .store
        .add_auth_event(&ip, Some(&user.username), "token_revoke", Some(&detail))?;
    Ok(StatusCode::NO_CONTENT)
}
