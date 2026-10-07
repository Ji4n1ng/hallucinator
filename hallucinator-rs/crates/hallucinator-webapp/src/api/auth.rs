use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use super::{ApiError, ApiResult};
use crate::auth::{
    self, AuthUser, ClientIp, clear_session_cookie, hash_password_async, hash_token, minutes_text,
    random_token, session_cookie, validate_password, validate_username, verify_password_async,
};
use crate::state::{AppState, SignupMode};
use crate::store::{StoreError, User, now};

#[derive(Deserialize)]
pub struct Credentials {
    username: String,
    password: String,
}

pub async fn me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let session = auth::session_from_headers(&state, &headers);
    let bootstrap = state.store.count_users()? == 0;
    Ok(Json(json!({
        "user": session.as_ref().map(|(_, s)| &s.user),
        "csrf": session.as_ref().map(|(_, s)| &s.csrf_token),
        "signup_mode": state.settings.signup.as_str(),
        "bootstrap": bootstrap,
    })))
}

/// Create a session and return the `Set-Cookie` value.
fn start_session(
    state: &AppState,
    user: &User,
    ip: &str,
    headers: &HeaderMap,
) -> ApiResult<HeaderValue> {
    let token = random_token();
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(256).collect::<String>());
    state.store.create_session(
        &hash_token(&token),
        user.id,
        &random_token(),
        state.settings.session_ttl_secs,
        ip,
        ua.as_deref(),
    )?;
    HeaderValue::from_str(&session_cookie(
        &token,
        state.settings.session_ttl_secs,
        state.settings.secure_cookies,
    ))
    .map_err(|e| anyhow::anyhow!(e).into())
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(body): Json<Credentials>,
) -> ApiResult<Response> {
    if !auth::origin_allowed(&headers) {
        return Err(ApiError::forbidden("Cross-origin request rejected."));
    }
    let username = body.username.trim().to_string();
    validate_username(&username).map_err(ApiError::bad_request)?;
    validate_password(&body.password).map_err(ApiError::bad_request)?;

    let bootstrap = state.store.count_users()? == 0;
    if !bootstrap && state.settings.signup == SignupMode::Closed {
        return Err(ApiError::forbidden(
            "Sign-up is closed. Ask an administrator for an account.",
        ));
    }
    if let Some(until) = state.store.ip_blocked_until(&ip)? {
        return Err(ApiError::too_many(
            "Too many requests from your network. Try again later.",
            until - now(),
        ));
    }
    let policy = &state.settings.policy;
    if state.store.count_auth_events(&ip, "signup", now() - 3600)? >= policy.signup_per_ip_per_hour
    {
        return Err(ApiError::too_many(
            "Too many accounts created from your network. Try again in an hour.",
            3600,
        ));
    }

    let hash = hash_password_async(body.password).await?;
    let (role, status) = if bootstrap {
        ("admin", "active")
    } else if state.settings.signup == SignupMode::Approval {
        ("user", "pending")
    } else {
        ("user", "active")
    };
    let user = match state.store.create_user(&username, &hash, role, status) {
        Ok(u) => u,
        Err(StoreError::Conflict) => {
            return Err(ApiError::conflict("That username is already taken."));
        }
        Err(StoreError::Other(e)) => return Err(e.into()),
    };
    state
        .store
        .add_auth_event(&ip, Some(&user.username), "signup", Some(status))?;

    if user.status != "active" {
        let body = json!({
            "user": user,
            "message": "Account created. An administrator must approve it before you can sign in.",
        });
        return Ok((StatusCode::CREATED, Json(body)).into_response());
    }
    let cookie = start_session(&state, &user, &ip, &headers)?;
    let message = if bootstrap {
        "Administrator account created."
    } else {
        "Account created."
    };
    let mut resp = (
        StatusCode::CREATED,
        Json(json!({ "user": user, "message": message })),
    )
        .into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(resp)
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(body): Json<Credentials>,
) -> ApiResult<Response> {
    if !auth::origin_allowed(&headers) {
        return Err(ApiError::forbidden("Cross-origin request rejected."));
    }
    let store = &state.store;
    let policy = state.settings.policy.clone();
    let username: String = body.username.trim().chars().take(64).collect();
    let t = now();

    // 1. Per-IP block (password spraying across usernames).
    if let Some(until) = store.ip_blocked_until(&ip)? {
        store.add_auth_event(&ip, Some(&username), "login_blocked", Some("ip"))?;
        return Err(ApiError::too_many(
            format!(
                "Too many failed sign-in attempts from your network. Try again in {}.",
                minutes_text(until - t)
            ),
            until - t,
        ));
    }

    // 2. Per-account lockout: do not even check the password. Unknown
    //    usernames are locked the same way, from the audit trail.
    let account = store.user_auth_by_name(&username)?;
    let locked_until = match &account {
        Some(a) => a.locked_until,
        None => {
            let (n, last) = store.username_failures(&username, t - policy.base_lock_secs)?;
            last.filter(|_| n >= policy.account_threshold)
                .map(|l| l + policy.base_lock_secs)
        }
    };
    if let Some(until) = locked_until.filter(|u| *u > t) {
        store.add_auth_event(&ip, Some(&username), "login_blocked", Some("account"))?;
        return Err(ApiError::too_many(
            format!(
                "Too many failed sign-in attempts. This account is locked; try again in {}.",
                minutes_text(until - t)
            ),
            until - t,
        ));
    }

    // 3. Verify (dummy hash for unknown users: same cost, no enumeration).
    let hash = account
        .as_ref()
        .map(|a| a.password_hash.clone())
        .unwrap_or_else(|| auth::dummy_hash().to_string());
    let ok = verify_password_async(body.password, hash).await && account.is_some();

    if !ok {
        store.add_auth_event(&ip, Some(&username), "login_fail", None)?;
        let mut locked: Option<i64> = None;
        if let Some(a) = &account {
            locked = store.record_login_failure(
                a.user.id,
                policy.account_threshold,
                policy.base_lock_secs,
                policy.max_lock_secs,
            )?;
            if let Some(until) = locked {
                store.add_auth_event(
                    &ip,
                    Some(&username),
                    "lockout",
                    Some(&format!("locked {}", minutes_text(until - now()))),
                )?;
            }
        } else {
            let (n, _) = store.username_failures(&username, t - policy.base_lock_secs)?;
            if n >= policy.account_threshold {
                locked = Some(now() + policy.base_lock_secs);
                store.add_auth_event(&ip, Some(&username), "lockout", Some("unknown user"))?;
            }
        }
        let recent = store.count_auth_events(&ip, "login_fail", t - policy.ip_window_secs)?;
        if recent >= policy.ip_threshold {
            let until = now() + policy.ip_block_secs;
            store.block_ip(&ip, until)?;
            store.add_auth_event(&ip, None, "ip_block", Some(&format!("{recent} failures")))?;
            tracing::warn!(%ip, "blocked IP after repeated failed sign-ins");
            return Err(ApiError::too_many(
                format!(
                    "Too many failed sign-in attempts from your network. Try again in {}.",
                    minutes_text(policy.ip_block_secs)
                ),
                policy.ip_block_secs,
            ));
        }
        if let Some(until) = locked {
            return Err(ApiError::too_many(
                format!(
                    "Too many failed sign-in attempts. This account is locked; try again in {}.",
                    minutes_text(until - now())
                ),
                until - now(),
            ));
        }
        // Small fixed delay on failure blunts online guessing further.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        return Err(ApiError::unauthorized("Invalid username or password."));
    }

    let account = account.expect("verified above");
    match account.user.status.as_str() {
        "active" => {}
        "pending" => {
            return Err(ApiError::forbidden(
                "Your account is waiting for administrator approval.",
            ));
        }
        _ => return Err(ApiError::forbidden("This account has been disabled.")),
    }
    store.record_login_success(account.user.id)?;
    store.add_auth_event(&ip, Some(&account.user.username), "login_ok", None)?;
    let cookie = start_session(&state, &account.user, &ip, &headers)?;
    let user = store.get_user(account.user.id)?.unwrap_or(account.user);
    let mut resp = Json(json!({ "user": user })).into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(resp)
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    user: AuthUser,
) -> ApiResult<Response> {
    state.store.delete_session(&user.token_hash)?;
    state
        .store
        .add_auth_event(&ip, Some(&user.user.username), "logout", None)?;
    let mut resp = StatusCode::NO_CONTENT.into_response();
    if let Ok(v) = HeaderValue::from_str(&clear_session_cookie(state.settings.secure_cookies)) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    Ok(resp)
}

#[derive(Deserialize)]
pub struct PasswordChange {
    current_password: String,
    new_password: String,
}

pub async fn change_password(
    State(state): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    user: AuthUser,
    Json(body): Json<PasswordChange>,
) -> ApiResult<StatusCode> {
    validate_password(&body.new_password).map_err(ApiError::bad_request)?;
    let account = state
        .store
        .user_auth_by_id(user.user.id)?
        .ok_or_else(|| ApiError::unauthorized("Please sign in."))?;
    if !verify_password_async(body.current_password, account.password_hash).await {
        state.store.add_auth_event(
            &ip,
            Some(&user.user.username),
            "login_fail",
            Some("password change"),
        )?;
        return Err(ApiError::bad_request("Current password is incorrect."));
    }
    let hash = hash_password_async(body.new_password).await?;
    state.store.set_password(user.user.id, &hash)?;
    state
        .store
        .delete_user_sessions(user.user.id, Some(&user.token_hash))?;
    Ok(StatusCode::NO_CONTENT)
}
