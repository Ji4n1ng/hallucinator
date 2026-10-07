//! Authentication: Argon2id password hashes, opaque session tokens (only a
//! SHA-256 of the token is stored), per-session CSRF tokens, and
//! brute-force protection for sign-in.
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
use crate::state::AppState;
use crate::store::{Session, User};

pub const SESSION_COOKIE: &str = "hallu_session";

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
    let token = cookie_value(headers, SESSION_COOKIE)?;
    if token.is_empty() {
        return None;
    }
    let token_hash = hash_token(token);
    let session = state.store.get_session(&token_hash).ok()??;
    if session.expires_at < crate::store::now() || session.user.status != "active" {
        return None;
    }
    if crate::store::now() - session.last_seen_at > 60 {
        let _ = state.store.touch_session(&token_hash);
    }
    Some((token_hash, session))
}

/// An authenticated, active user. Rejects with 401 without a valid session,
/// and with 403 when a state-changing request lacks the CSRF header.
pub struct AuthUser {
    pub user: User,
    pub token_hash: String,
}

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let (token_hash, session) = session_from_headers(state, &parts.headers)
            .ok_or_else(|| ApiError::unauthorized("Please sign in."))?;
        let safe = matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS);
        if !safe {
            let sent = parts
                .headers
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !constant_time_eq(sent.as_bytes(), session.csrf_token.as_bytes()) {
                return Err(ApiError::forbidden(
                    "Missing or invalid CSRF token. Reload the page and try again.",
                ));
            }
        }
        Ok(AuthUser {
            user: session.user,
            token_hash,
        })
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

    #[test]
    fn proxy_headers_only_when_trusted() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "9.9.9.9, 10.0.0.1".parse().unwrap());
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        assert_eq!(client_ip(&h, Some(peer), false), "127.0.0.1");
        assert_eq!(client_ip(&h, Some(peer), true), "9.9.9.9");
    }
}
