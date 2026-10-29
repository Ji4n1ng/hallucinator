//! Authentication: Argon2id password hashes, opaque session tokens (only a
//! SHA-256 of the token is stored), per-session CSRF tokens, personal API
//! tokens for scripts and agents, and brute-force protection for sign-in.
//!
//! API tokens (`Authorization: Bearer hallu_…`) act with their owner's
//! permissions and need no CSRF token: browsers never attach that header on
//! their own, so a cross-site request cannot carry it. Like sessions, only a
//! SHA-256 of the token is stored. Tokens cannot sign out, change the
//! password or manage tokens ([`SessionUser`]), so a leaked token cannot
//! mint more of itself.
//!
//! Agent accounts (`kind = agent`) have no password and are never
//! administrators, whatever their stored role ([`User::is_admin`]).
//!
//! A request that came through the end-to-end tunnel (e2e.rs) carries the
//! [`Sealed`] marker and needs no CSRF token: a cross-site page cannot seal
//! an envelope without the key, and the session cookie travels only inside it.
//!
//! Brute-force policy (see [`LoginPolicy`]):
//! * per account: `account_threshold` consecutive failures lock the account
//!   for `base_lock`, doubling for each consecutive lockout up to `max_lock`;
//!   a successful sign-in resets it. While locked, the password is not even
//!   checked, so a locked account cannot be used as a password oracle.
//! * per client IP: `ip_threshold` failures within `ip_window` block the IP
//!   for `ip_block` (catches password spraying across many usernames).
//! * unknown usernames are verified against a dummy hash so response timing
//!   does not reveal which usernames exist, and errors are generic.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::api::ApiError;
use crate::audit::{Actor, Slot};
use crate::state::AppState;
use crate::store::{Session, Store, User};

pub const SESSION_COOKIE: &str = "hallu_session";

/// Every API token starts with this, so leaked tokens are easy to spot.
pub const API_TOKEN_PREFIX: &str = "hallu_";

/// Marks a request that came through the end-to-end tunnel (e2e.rs).
#[derive(Debug, Clone, Copy)]
pub struct Sealed;

#[derive(Debug, Clone)]
pub struct LoginPolicy {
    pub account_threshold: i64,
    pub base_lock_secs: i64,
    pub max_lock_secs: i64,
    pub ip_threshold: i64,
    pub ip_window_secs: i64,
    pub ip_block_secs: i64,
}

impl Default for LoginPolicy {
    fn default() -> Self {
        LoginPolicy {
            account_threshold: 5,
            base_lock_secs: 15 * 60,
            max_lock_secs: 24 * 3600,
            ip_threshold: 20,
            ip_window_secs: 15 * 60,
            ip_block_secs: 30 * 60,
        }
    }
}

pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn new_api_token() -> String {
    format!("{API_TOKEN_PREFIX}{}", random_token())
}

/// The start of a token kept in listings so owners can tell tokens apart.
pub fn token_display_prefix(token: &str) -> String {
    token.chars().take(API_TOKEN_PREFIX.len() + 4).collect()
}

pub fn validate_token_name(name: &str) -> Result<(), &'static str> {
    let n = name.chars().count();
    if (1..=64).contains(&n) && !name.chars().any(char::is_control) {
        Ok(())
    } else {
        Err("Token name must be 1–64 characters.")
    }
}

/// Create an API token for `user_id`. Returns the secret, which is never
/// stored or shown again, and the stored record.
pub fn issue_api_token(
    store: &Store,
    user_id: i64,
    name: &str,
    expires_at: Option<i64>,
) -> anyhow::Result<(String, crate::store::ApiToken)> {
    let secret = new_api_token();
    let token = store.create_api_token(
        user_id,
        name,
        &hash_token(&secret),
        &token_display_prefix(&secret),
        expires_at,
    )?;
    Ok((secret, token))
}

pub fn random_id() -> String {
    let mut bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hashing password: {e}"))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Run Argon2 off the async executor (it is deliberately CPU-expensive).
pub async fn hash_password_async(password: String) -> anyhow::Result<String> {
    tokio::task::spawn_blocking(move || hash_password(&password)).await?
}

pub async fn verify_password_async(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await
        .unwrap_or(false)
}

pub fn validate_username(u: &str) -> Result<(), &'static str> {
    let ok_len = (3..=32).contains(&u.len());
    let ok_chars = u
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if ok_len && ok_chars {
        Ok(())
    } else {
        Err("Username must be 3–32 characters: letters, digits, '.', '_' or '-'.")
    }
}

pub fn validate_password(p: &str) -> Result<(), &'static str> {
    let n = p.chars().count();
    if n < 10 {
        Err("Password must be at least 10 characters.")
    } else if n > 256 {
        Err("Password must be at most 256 characters.")
    } else {
        Ok(())
    }
}

pub fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            (k == name).then_some(v)
        })
        .next()
}

pub fn session_cookie(token: &str, max_age_secs: i64, secure: bool) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}{}",
        if secure { "; Secure" } else { "" }
    )
}

pub fn clear_session_cookie(secure: bool) -> String {
    session_cookie("", 0, secure)
}

/// The client address used for rate limiting. Proxy headers are honoured
/// only with `--trust-proxy`, otherwise any client could forge them.
pub fn client_ip(parts_headers: &HeaderMap, peer: Option<SocketAddr>, trust_proxy: bool) -> String {
    if trust_proxy {
        let forwarded = parts_headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .and_then(|s| s.parse::<IpAddr>().ok())
            .or_else(|| {
                parts_headers
                    .get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.trim().parse::<IpAddr>().ok())
            });
        if let Some(ip) = forwarded {
            return ip.to_string();
        }
    }
    peer.map(|p| p.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Same-origin check for the session-less auth endpoints. Browsers always
/// send `Origin` on cross-site POSTs; a missing header (curl, tests) is fine.
pub fn origin_allowed(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let origin_host = origin
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(origin)
        .trim_end_matches('/');
    let forwarded_host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok());
    origin_host.eq_ignore_ascii_case(host)
        || forwarded_host.is_some_and(|h| origin_host.eq_ignore_ascii_case(h))
}

/// Client IP extractor.
pub struct ClientIp(pub String);

impl FromRequestParts<Arc<AppState>> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0);
        Ok(ClientIp(client_ip(
            &parts.headers,
            peer,
            state.settings.trust_proxy,
        )))
    }
}

/// Look up the session for a request without enforcing CSRF.
pub fn session_from_headers(state: &AppState, headers: &HeaderMap) -> Option<(String, Session)> {
    lookup_session(&state.store, headers)
}

fn lookup_session(store: &Store, headers: &HeaderMap) -> Option<(String, Session)> {
    let token = cookie_value(headers, SESSION_COOKIE)?;
    if token.is_empty() {
        return None;
    }
    let token_hash = hash_token(token);
    let session = store.get_session(&token_hash).ok()??;
    if session.expires_at < crate::store::now() || session.user.status != "active" {
        return None;
    }
    if crate::store::now() - session.last_seen_at > 60 {
        let _ = store.touch_session(&token_hash);
    }
    Some((token_hash, session))
}

/// The token of an `Authorization: Bearer <token>` header, if any.
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.trim().split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|t| !t.is_empty())
}

/// Resolve the request's API token. `Ok(None)`: no bearer header was sent.
/// A bearer header that does not name a live token of an active account is
/// rejected outright rather than falling back to the session cookie.
pub fn lookup_api_token(
    store: &Store,
    headers: &HeaderMap,
    ip: &str,
) -> Result<Option<(i64, User)>, ApiError> {
    let Some(token) = bearer_token(headers) else {
        return Ok(None);
    };
    let invalid = || ApiError::unauthorized("Invalid, expired or revoked API token.");
    let t = crate::store::now();
    let auth = store
        .get_api_token(&hash_token(token))?
        .filter(|a| a.expires_at.is_none_or(|e| e > t) && a.user.status == "active")
        .ok_or_else(invalid)?;
    if auth.last_used_at.is_none_or(|l| t - l > 60) {
        let _ = store.touch_api_token(auth.id, ip);
    }
    Ok(Some((auth.id, auth.user)))
}

/// How a request proved who it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// Browser session cookie; holds the SHA-256 of the session token.
    Session(String),
    /// Personal API token, by id.
    ApiToken(i64),
}

/// Authenticate a request: an API token if one is sent, else the session
/// cookie, which must come with the CSRF token on state-changing methods
/// (unless the request came `sealed` through the tunnel).
pub fn authenticate(
    store: &Store,
    headers: &HeaderMap,
    method: &Method,
    ip: &str,
    sealed: bool,
) -> Result<(User, Credential), ApiError> {
    if let Some((id, user)) = lookup_api_token(store, headers, ip)? {
        return Ok((user, Credential::ApiToken(id)));
    }
    let (token_hash, session) =
        lookup_session(store, headers).ok_or_else(|| ApiError::unauthorized("Please sign in."))?;
    let safe = matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    if !safe && !sealed {
        let sent = headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !constant_time_eq(sent.as_bytes(), session.csrf_token.as_bytes()) {
            return Err(ApiError::forbidden(
                "Missing or invalid CSRF token. Reload the page and try again.",
            ));
        }
    }
    Ok((session.user, Credential::Session(token_hash)))
}

/// An authenticated, active user, by session cookie or API token. Rejects
/// with 401 without valid credentials, and with 403 when a cookie-session
/// request that changes state lacks the CSRF header.
pub struct AuthUser {
    pub user: User,
    pub credential: Credential,
}

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let ClientIp(ip) = ClientIp::from_request_parts(parts, state)
            .await
            .unwrap_or_else(|never| match never {});
        let sealed = parts.extensions.get::<Sealed>().is_some();
        let (user, credential) =
            authenticate(&state.store, &parts.headers, &parts.method, &ip, sealed)?;
        if let Some(slot) = parts.extensions.get::<Slot>() {
            let via = match credential {
                Credential::Session(_) => "session",
                Credential::ApiToken(_) => "token",
            };
            slot.set(Actor::of(&user, via));
        }
        Ok(AuthUser { user, credential })
    }
}

/// A user signed in with a browser session. Used where an API token must
/// not do: signing out, changing the password, managing API tokens.
pub struct SessionUser {
    pub user: User,
    pub token_hash: String,
}

impl FromRequestParts<Arc<AppState>> for SessionUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        match user.credential {
            Credential::Session(token_hash) => Ok(SessionUser {
                user: user.user,
                token_hash,
            }),
            Credential::ApiToken(_) => Err(ApiError::forbidden(
                "API tokens cannot be used here. Sign in to the web interface instead.",
            )),
        }
    }
}

/// An authenticated administrator.
pub struct AdminUser(pub AuthUser);

impl FromRequestParts<Arc<AppState>> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if !user.user.is_admin() {
            return Err(ApiError::forbidden("Administrator access required."));
        }
        Ok(AdminUser(user))
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A precomputed hash verified against when the username does not exist,
/// so both paths cost one Argon2 verification.
pub fn dummy_hash() -> &'static str {
    use std::sync::OnceLock;
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_password(&random_token()).unwrap_or_default())
}

pub fn minutes_text(secs: i64) -> String {
    let mins = (secs + 59) / 60;
    if mins >= 120 {
        format!("{} hours", (mins + 59) / 60)
    } else if mins <= 1 {
        "1 minute".to_string()
    } else {
        format!("{mins} minutes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_round_trip() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("wrong horse battery", &h));
        assert!(!verify_password("x", "not a hash"));
    }

    #[test]
    fn username_and_password_rules() {
        assert!(validate_username("alice_01").is_ok());
        assert!(validate_username("al").is_err());
        assert!(validate_username("bad name").is_err());
        assert!(validate_username("<script>").is_err());
        assert!(validate_password("short").is_err());
        assert!(validate_password("long enough pw").is_ok());
    }

    #[test]
    fn cookie_parsing() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            "a=1; hallu_session=tok; b=2".parse().unwrap(),
        );
        assert_eq!(cookie_value(&h, SESSION_COOKIE), Some("tok"));
        assert_eq!(cookie_value(&h, "missing"), None);
    }

    #[test]
    fn origin_check() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "localhost:5001".parse().unwrap());
        assert!(origin_allowed(&h));
        h.insert(header::ORIGIN, "http://localhost:5001".parse().unwrap());
        assert!(origin_allowed(&h));
        h.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        assert!(!origin_allowed(&h));
    }

    fn store_with_user(status: &str) -> (Store, User) {
        let store = Store::open_in_memory().unwrap();
        let user = store.create_user("agent", "h", "user", status).unwrap();
        (store, user)
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        h
    }

    #[test]
    fn bearer_header_parsing() {
        assert_eq!(bearer_token(&bearer("hallu_x")), Some("hallu_x"));
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "bearer  tok ".parse().unwrap());
        assert_eq!(bearer_token(&h), Some("tok"));
        h.insert(header::AUTHORIZATION, "Basic dXNlcjpwYXNz".parse().unwrap());
        assert_eq!(bearer_token(&h), None);
        h.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
        assert_eq!(bearer_token(&h), None);
        assert_eq!(bearer_token(&HeaderMap::new()), None);
        let t = new_api_token();
        assert!(t.starts_with(API_TOKEN_PREFIX) && t.len() > 40);
        assert_eq!(token_display_prefix(&t).len(), API_TOKEN_PREFIX.len() + 4);
    }

    #[test]
    fn api_token_authenticates_without_csrf() {
        let (store, user) = store_with_user("active");
        let token = new_api_token();
        let t = store
            .create_api_token(user.id, "agent", &hash_token(&token), "hallu_", None)
            .unwrap();
        let (u, cred) =
            authenticate(&store, &bearer(&token), &Method::POST, "1.2.3.4", false).unwrap();
        assert_eq!((u.id, cred), (user.id, Credential::ApiToken(t.id)));
        let listed = &store.list_api_tokens(Some(user.id)).unwrap()[0];
        assert_eq!(listed.last_used_ip.as_deref(), Some("1.2.3.4"));

        // A wrong token is a 401 even when a session cookie is also sent.
        let mut h = bearer("hallu_wrong");
        h.insert(header::COOKIE, "hallu_session=whatever".parse().unwrap());
        let e = authenticate(&store, &h, &Method::GET, "ip", false).unwrap_err();
        assert_eq!(e.status, axum::http::StatusCode::UNAUTHORIZED);

        // Revoked.
        store.delete_api_token(t.id, None).unwrap();
        assert!(authenticate(&store, &bearer(&token), &Method::GET, "ip", false).is_err());
    }

    #[test]
    fn api_token_rejected_when_expired_or_account_disabled() {
        let (store, user) = store_with_user("active");
        let token = new_api_token();
        store
            .create_api_token(user.id, "old", &hash_token(&token), "hallu_", Some(1))
            .unwrap();
        assert!(authenticate(&store, &bearer(&token), &Method::GET, "ip", false).is_err());

        let fresh = new_api_token();
        store
            .create_api_token(user.id, "new", &hash_token(&fresh), "hallu_", None)
            .unwrap();
        assert!(authenticate(&store, &bearer(&fresh), &Method::GET, "ip", false).is_ok());
        store.set_user_status(user.id, "disabled").unwrap();
        assert!(authenticate(&store, &bearer(&fresh), &Method::GET, "ip", false).is_err());
    }

    #[test]
    fn session_needs_csrf_on_writes() {
        let (store, user) = store_with_user("active");
        let token = random_token();
        store
            .create_session(&hash_token(&token), user.id, "csrf-1", 3600, "ip", None)
            .unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            format!("{SESSION_COOKIE}={token}").parse().unwrap(),
        );
        let (_, cred) = authenticate(&store, &h, &Method::GET, "ip", false).unwrap();
        assert_eq!(cred, Credential::Session(hash_token(&token)));
        let e = authenticate(&store, &h, &Method::POST, "ip", false).unwrap_err();
        assert_eq!(e.status, axum::http::StatusCode::FORBIDDEN);
        h.insert("x-csrf-token", "csrf-1".parse().unwrap());
        assert!(authenticate(&store, &h, &Method::POST, "ip", false).is_ok());
        let e = authenticate(&store, &HeaderMap::new(), &Method::GET, "ip", false).unwrap_err();
        assert_eq!(e.status, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn proxy_headers_only_when_trusted() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "9.9.9.9, 10.0.0.1".parse().unwrap());
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        assert_eq!(client_ip(&h, Some(peer), false), "127.0.0.1");
        assert_eq!(client_ip(&h, Some(peer), true), "9.9.9.9");
    }
}
