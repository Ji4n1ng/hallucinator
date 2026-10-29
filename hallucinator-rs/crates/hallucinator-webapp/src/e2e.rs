//! End-to-end encryption with one shared key: the Catelier E2E protocol,
//! version 1, byte for byte (agent tool standard, section 2). It is a port of
//! Catelier's `server/catelier/e2e.py`; `tests/e2e_vectors.json` there holds
//! worked examples, and this module's tests check them.
//!
//! With a key set (`--e2e-key-file`), every request goes through
//! `POST /api/e2e`: one sealed request (method, path, headers, body) in, one
//! sealed response out. [`middleware`] opens it, runs the app on the inner
//! request as if it came plain (marked [`Sealed`]), and seals the answer.
//! Plain requests are refused with HTTP 400 `{"detail", "e2e": "required"}`,
//! except `GET /api/health` and the static pages, which hold no data. A
//! session cookie or API token never goes plain: a session whose cookie came
//! plain is ended.
//!
//! Wire format:
//!
//! * key: `cek1_` + 32 bytes in base64url without padding. `enc` and `kid`
//!   come from it with HKDF-SHA256 (no salt), infos `catelier e2e v1 enc`
//!   (32 bytes) and `catelier e2e v1 kid` (8).
//! * envelope: version `01` | direction (`01` request, `02` response) | kid (8)
//!   | Unix ms (uint64 BE) | nonce (12) | AES-256-GCM ciphertext and tag. The
//!   AAD is those first 30 bytes, and for a response also the request's
//!   nonce. The plaintext is a 4-byte BE length, meta JSON, body.
//! * WebSocket frames (no route here uses them; kept for the shared vectors):
//!   type | counter (uint64 BE) | ciphertext and tag under
//!   `HKDF(key, salt=cn‖sn, info="catelier e2e v1 ws")`.
//!
//! An address that sends [`BLOCK_AFTER`] envelopes that fail to decrypt in
//! [`BLOCK_WINDOW`] seconds is refused at the tunnel for [`BLOCK_FOR`] seconds
//! (HTTP 429, `"e2e": "blocked"`) before its body is read.

use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use rand::RngCore;
use serde_json::{Map, Value, json};
use sha2::Sha256;

use crate::auth::{
    SESSION_COOKIE, Sealed, clear_session_cookie, client_ip, cookie_value, hash_token,
};
use crate::state::AppState;

pub const PREFIX: &str = "cek1_";
const VERSION: u8 = 1;
pub const REQUEST: u8 = 1;
pub const RESPONSE: u8 = 2;
const HEADER: usize = 30; // version, direction, kid, time, nonce
const TAG: usize = 16;
pub const CONTENT_TYPE: &str = "application/vnd.catelier.e2e";
const MAX_SKEW: f64 = 120.0; // seconds a request's time may be off the server's clock
const NONCES_FOR: f64 = 2.0 * MAX_SKEW;
// Envelopes that fail to decrypt, counted per address: IPv4 whole, IPv6 by its /64.
const WARN_AT: usize = 5;
pub const BLOCK_AFTER: usize = 10;
pub const BLOCK_WINDOW: f64 = 600.0;
pub const BLOCK_FOR: f64 = 900.0;
const MAX_TRACKED: usize = 10_000; // addresses kept with failures, and blocks kept
const REFUSALS_EVERY: f64 = 60.0; // a blocked address's refusals are logged at most once a minute
/// Largest inner response the tunnel seals.
const MAX_REPLY: usize = 512 * 1024 * 1024;
/// Envelopes larger than this are opened (and big replies compressed) off
/// the async workers.
const BLOCKING_ABOVE: usize = 1024 * 1024;
/// Default memory the tunnel may hold for envelopes being read and opened
/// at once (see [`Keyring::with_budget`]).
const DEFAULT_BUDGET: usize = 256 * 1024 * 1024;

pub const TUNNEL: &str = "/api/e2e";
/// Inner request headers taken from the envelope. The outer host and
/// X-Forwarded-For / -Proto stay, so the sign-in throttle sees the real address.
const INNER_HEADERS: [&str; 6] = [
    "authorization",
    "content-type",
    "accept",
    "user-agent",
    "cookie",
    "accept-encoding",
];
const OUTER_HEADERS: [&str; 4] = ["host", "x-forwarded-for", "x-forwarded-proto", "x-real-ip"];
const METHODS: [&str; 6] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];

/// An envelope the server refuses: answered as plain 400 `{"detail", "e2e": code}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E2eError {
    pub code: &'static str,
    pub detail: String,
}

impl E2eError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        E2eError {
            code,
            detail: detail.into(),
        }
    }
    fn bad(detail: impl Into<String>) -> Self {
        Self::new("bad_envelope", detail)
    }
}

fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hkdf(master: &[u8], info: &str, out: &mut [u8], salt: Option<&[u8]>) {
    Hkdf::<Sha256>::new(salt.filter(|s| !s.is_empty()), master)
        .expand(info.as_bytes(), out)
        .expect("HKDF output of at most 32 bytes");
}

/// The 32 bytes of a `cek1_` key, or why it is not one.
pub fn parse_key(value: &str) -> Result<[u8; 32], String> {
    let value = value.trim();
    let Some(body) = value.strip_prefix(PREFIX) else {
        return Err(format!("it must start with {PREFIX}"));
    };
    if body.len() != 43
        || !body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!(
            "it must be {PREFIX} and 43 base64url characters (it has {})",
            body.chars().count()
        ));
    }
    let raw = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| "it is not base64url".to_string())?;
    raw.try_into()
        .map_err(|_| "it does not hold 32 bytes".to_string())
}

pub fn new_key() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

#[derive(Clone)]
pub struct Key {
    #[allow(dead_code)] // the base of WebSocket keys
    master: [u8; 32],
    enc: [u8; 32],
    pub kid: [u8; 8],
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key(kid {})", hex(&self.kid))
    }
}

impl Key {
    pub fn from_string(value: &str) -> Result<Self, String> {
        Ok(Self::from_master(parse_key(value)?))
    }

    pub fn from_master(master: [u8; 32]) -> Self {
        let mut enc = [0u8; 32];
        let mut kid = [0u8; 8];
        hkdf(&master, "catelier e2e v1 enc", &mut enc, None);
        hkdf(&master, "catelier e2e v1 kid", &mut kid, None);
        Key { master, enc, kid }
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(&self.enc).expect("32-byte key")
    }

    /// A WebSocket's own key: `HKDF(master, salt = cn ‖ sn, "catelier e2e v1 ws")`.
    #[allow(dead_code)]
    pub fn ws_key(&self, cn: &[u8], sn: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        hkdf(
            &self.master,
            "catelier e2e v1 ws",
            &mut out,
            Some(&[cn, sn].concat()),
        );
        out
    }
}

// ── envelopes ──────────────────────────────────────────────────────────

/// uint32 BE length of the meta JSON, the meta JSON, the body.
pub fn pack_plaintext(meta_json: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + meta_json.len() + body.len());
    out.extend_from_slice(&(meta_json.len() as u32).to_be_bytes());
    out.extend_from_slice(meta_json);
    out.extend_from_slice(body);
    out
}

pub fn unpack_plaintext(plain: &[u8]) -> Result<(Map<String, Value>, &[u8]), E2eError> {
    if plain.len() < 4 {
        return Err(E2eError::bad("The envelope is too short"));
    }
    let n = u32::from_be_bytes(plain[..4].try_into().expect("4 bytes")) as usize;
    if 4 + n > plain.len() {
        return Err(E2eError::bad("The envelope meta is cut short"));
    }
    match serde_json::from_slice::<Value>(&plain[4..4 + n]) {
        Ok(Value::Object(meta)) => Ok((meta, &plain[4 + n..])),
        Ok(_) => Err(E2eError::bad("The envelope meta is not an object")),
        Err(_) => Err(E2eError::bad("The envelope meta is not JSON")),
    }
}

pub fn seal(
    key: &Key,
    direction: u8,
    plaintext: &[u8],
    ts_ms: u64,
    nonce: &[u8; 12],
    request_nonce: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + plaintext.len() + TAG);
    out.push(VERSION);
    out.push(direction);
    out.extend_from_slice(&key.kid);
    out.extend_from_slice(&ts_ms.to_be_bytes());
    out.extend_from_slice(nonce);
    let aad = [&out[..], request_nonce].concat();
    let sealed = key
        .cipher()
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("AES-GCM encryption");
    out.extend_from_slice(&sealed);
    out
}

fn random_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// kid, time and nonce of an envelope, after checking its size, version and direction.
fn read_header(data: &[u8], direction: u8) -> Result<([u8; 8], u64, [u8; 12]), E2eError> {
    if data.len() < HEADER + TAG {
        return Err(E2eError::bad("The envelope is too short"));
    }
    if data[0] != VERSION || data[1] != direction {
        return Err(E2eError::bad("Unknown envelope version or direction"));
    }
    let kid = data[2..10].try_into().expect("8 bytes");
    let ts_ms = u64::from_be_bytes(data[10..18].try_into().expect("8 bytes"));
    let nonce = data[18..30].try_into().expect("12 bytes");
    Ok((kid, ts_ms, nonce))
}

#[derive(Debug)]
pub struct Opened {
    /// The envelope used the previous key (a rotation is under way).
    pub previous: bool,
    #[allow(dead_code)]
    pub ts_ms: u64,
    pub nonce: [u8; 12],
    pub plaintext: Vec<u8>,
}

pub fn open_envelope(
    key: &Key,
    data: &[u8],
    direction: u8,
    request_nonce: &[u8],
) -> Result<Opened, E2eError> {
    let (_, ts_ms, nonce) = read_header(data, direction)?;
    let aad = [&data[..HEADER], request_nonce].concat();
    let plaintext = key
        .cipher()
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &data[HEADER..],
                aad: &aad,
            },
        )
        .map_err(|_| E2eError::bad("The envelope could not be decrypted"))?;
    Ok(Opened {
        previous: false,
        ts_ms,
        nonce,
        plaintext,
    })
}

// ── WebSocket frames ───────────────────────────────────────────────────
// No route here opens a WebSocket (there is no `/api/e2e/ws`); the frame
// code is kept so the shared vectors are checked in full.

#[allow(dead_code)]
pub fn frame_nonce(direction: u32, counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&direction.to_be_bytes());
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

#[allow(dead_code)]
pub fn seal_frame(
    ws_key: &[u8; 32],
    direction: u32,
    counter: u64,
    kind: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut head = vec![kind];
    head.extend_from_slice(&counter.to_be_bytes());
    let sealed = Aes256Gcm::new_from_slice(ws_key)
        .expect("32-byte key")
        .encrypt(
            Nonce::from_slice(&frame_nonce(direction, counter)),
            Payload {
                msg: data,
                aad: &head,
            },
        )
        .expect("AES-GCM encryption");
    head.extend_from_slice(&sealed);
    head
}

#[allow(dead_code)]
pub fn open_frame(
    ws_key: &[u8; 32],
    direction: u32,
    expected: u64,
    frame: &[u8],
) -> Result<(u8, Vec<u8>), E2eError> {
    if frame.len() < 9 + TAG || !matches!(frame[0], 1 | 2) {
        return Err(E2eError::bad("Bad frame"));
    }
    let counter = u64::from_be_bytes(frame[1..9].try_into().expect("8 bytes"));
    if counter != expected {
        return Err(E2eError::new(
            "replay",
            format!("Frame {counter} came where frame {expected} was expected"),
        ));
    }
    let data = Aes256Gcm::new_from_slice(ws_key)
        .expect("32-byte key")
        .decrypt(
            Nonce::from_slice(&frame_nonce(direction, counter)),
            Payload {
                msg: &frame[9..],
                aad: &frame[..9],
            },
        )
        .map_err(|_| E2eError::bad("The frame could not be decrypted"))?;
    Ok((frame[0], data))
}

// ── the keyring: keys, replay and failure tracking ─────────────────────

/// The address failures count against, and whether it may be blocked. An
/// IPv6 host or home has a whole /64, so that is one address. Loopback and no
/// address are never blocked: behind a proxy on this machine that sends no
/// X-Forwarded-For, every client has that address.
pub fn address_group(ip: &str) -> (String, bool) {
    let Ok(addr) = ip.split('%').next().unwrap_or("").parse::<IpAddr>() else {
        return (ip.to_string(), !ip.is_empty() && ip != "unknown");
    };
    let addr = match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        v4 => v4,
    };
    if addr.is_loopback() {
        return (addr.to_string(), false);
    }
    match addr {
        IpAddr::V6(v6) => {
            let net = std::net::Ipv6Addr::from(u128::from(v6) >> 64 << 64);
            (format!("{net}/64"), true)
        }
        v4 => (v4.to_string(), true),
    }
}

/// An address refused at the tunnel until `until`.
#[derive(Debug, Clone)]
pub struct Block {
    pub ip: String,
    pub group: String,
    pub failures: usize,
    pub until: f64,
    refused: usize,
    logged_at: f64,
}

#[derive(Default)]
struct Guard {
    /// Nonces seen in the last `NONCES_FOR` seconds, with when they expire.
    nonces: HashMap<[u8; 12], f64>,
    next_nonce_prune: f64,
    /// Address group → times of recent envelopes that failed to decrypt.
    bad: HashMap<String, Vec<f64>>,
    blocked: HashMap<String, Block>,
    next_prune: f64,
    warned_unblockable: bool,
}

/// Keep at most `MAX_TRACKED` entries: drop the one with the oldest time.
fn keep_bounded<V>(table: &mut HashMap<String, V>, time: impl Fn(&V) -> f64) {
    while table.len() > MAX_TRACKED {
        let oldest = table
            .iter()
            .min_by(|a, b| time(a.1).total_cmp(&time(b.1)))
            .map(|(k, _)| k.clone());
        match oldest {
            Some(k) => table.remove(&k),
            None => break,
        };
    }
}

pub struct Keyring {
    pub current: Key,
    pub previous: Option<Key>,
    guard: Mutex<Guard>,
    /// KiB of envelopes being read and opened at once. Each takes twice
    /// its size (the envelope and its plaintext) before it is read, so a
    /// flood of large bodies without the key cannot exhaust memory.
    budget: tokio::sync::Semaphore,
    budget_kib: u32,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keyring(kids {:?})", self.kids())
    }
}

impl Keyring {
    pub fn new(current: Key, previous: Option<Key>) -> Self {
        let previous = previous.filter(|p| p.kid != current.kid);
        let budget_kib = (DEFAULT_BUDGET / 1024) as u32;
        Keyring {
            current,
            previous,
            guard: Mutex::new(Guard::default()),
            budget: tokio::sync::Semaphore::new(budget_kib as usize),
            budget_kib,
        }
    }

    /// Let the tunnel hold up to `bytes` of envelopes at once (at least
    /// the default), e.g. a few of the largest uploads.
    pub fn with_budget(mut self, bytes: usize) -> Self {
        let kib = (bytes.max(DEFAULT_BUDGET) / 1024).min(u32::MAX as usize) as u32;
        self.budget = tokio::sync::Semaphore::new(kib as usize);
        self.budget_kib = kib;
        self
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, Guard> {
        self.guard.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn kids(&self) -> Vec<String> {
        std::iter::once(&self.current)
            .chain(self.previous.as_ref())
            .map(|k| hex(&k.kid))
            .collect()
    }

    fn find(&self, kid: &[u8; 8]) -> Option<(&Key, bool)> {
        if &self.current.kid == kid {
            return Some((&self.current, false));
        }
        self.previous
            .as_ref()
            .filter(|p| &p.kid == kid)
            .map(|p| (p, true))
    }

    /// True when the nonce is new (and is now remembered). A repeat is a replay.
    fn add_nonce(&self, nonce: [u8; 12], t: f64) -> bool {
        let mut g = self.guard();
        if t >= g.next_nonce_prune {
            g.nonces.retain(|_, exp| *exp > t);
            g.next_nonce_prune = t + 10.0;
        }
        if g.nonces.get(&nonce).is_some_and(|exp| *exp > t) {
            return false;
        }
        g.nonces.insert(nonce, t + NONCES_FOR);
        true
    }

    /// Check and decrypt a client's envelope: kid, clock, tag, then replay.
    pub fn open_request(&self, data: &[u8], now: f64) -> Result<Opened, E2eError> {
        let (kid, ts_ms, nonce) = read_header(data, REQUEST)?;
        let (key, previous) = self.find(&kid).ok_or_else(|| {
            E2eError::new(
                "unknown_kid",
                "This encryption key does not match the server's key",
            )
        })?;
        if (ts_ms as f64 / 1000.0 - now).abs() > MAX_SKEW {
            return Err(E2eError::new(
                "stale",
                "The clock on this device is off by more than 2 minutes",
            ));
        }
        let mut opened = open_envelope(key, data, REQUEST, &[])?;
        if !self.add_nonce(nonce, now) {
            return Err(E2eError::new("replay", "This request was already received"));
        }
        opened.previous = previous;
        Ok(opened)
    }

    /// Seal the reply to `opened` with the key it came with. `meta_json` is
    /// the reply's meta object; `"rotate": true` is added for the old key.
    pub fn seal_response(
        &self,
        opened: &Opened,
        mut meta: Map<String, Value>,
        body: &[u8],
    ) -> Vec<u8> {
        if opened.previous {
            meta.insert("rotate".into(), Value::Bool(true));
        }
        let key = if opened.previous {
            self.previous.as_ref().unwrap_or(&self.current)
        } else {
            &self.current
        };
        let meta_json = serde_json::to_vec(&meta).expect("JSON");
        let ts_ms = (now_secs() * 1000.0) as u64;
        seal(
            key,
            RESPONSE,
            &pack_plaintext(&meta_json, body),
            ts_ms,
            &random_nonce(),
            &opened.nonce,
        )
    }

    /// Count an envelope from `ip` that `open_request` refused; the new block
    /// if this one starts it. Only `bad_envelope` counts: `unknown_kid` is a
    /// real device with an old key after a rotation, and `stale` and `replay`
    /// cost no work worth limiting.
    pub fn note_failure(&self, ip: &str, code: &str, now: f64) -> Option<Block> {
        if code != "bad_envelope" {
            return None;
        }
        let mut g = self.guard();
        prune(&mut g, now);
        let (group, blockable) = address_group(ip);
        if g.blocked.get(&group).is_some_and(|b| b.until > now) {
            return None; // an envelope that was read before the block started
        }
        let mut recent: Vec<f64> = g
            .bad
            .remove(&group)
            .unwrap_or_default()
            .into_iter()
            .filter(|x| *x > now - BLOCK_WINDOW)
            .collect();
        recent.push(now);
        let ip_text = if ip.is_empty() { "?" } else { ip };
        if recent.len() == WARN_AT {
            tracing::warn!(
                "{WARN_AT} envelopes from {ip_text} failed to decrypt in {} minutes",
                BLOCK_WINDOW as i64 / 60
            );
        }
        if recent.len() < BLOCK_AFTER || !blockable {
            if recent.len() >= BLOCK_AFTER && !g.warned_unblockable {
                g.warned_unblockable = true;
                tracing::warn!(
                    "{} envelopes from {ip_text} failed to decrypt in {} minutes. It is not \
                     blocked: a proxy on this machine that sends no X-Forwarded-For gives every \
                     client this address. Check the proxy and --trust-proxy.",
                    recent.len(),
                    BLOCK_WINDOW as i64 / 60
                );
            }
            let keep = recent.len().saturating_sub(BLOCK_AFTER);
            g.bad.insert(group, recent.split_off(keep));
            keep_bounded(&mut g.bad, |v| v.last().copied().unwrap_or(0.0));
            return None;
        }
        let block = Block {
            ip: ip.to_string(),
            group: group.clone(),
            failures: recent.len(),
            until: now + BLOCK_FOR,
            refused: 0,
            logged_at: now,
        };
        g.blocked.insert(group.clone(), block.clone());
        keep_bounded(&mut g.blocked, |b| b.until);
        tracing::warn!(
            "Blocked {group} for {} minutes at the end-to-end tunnel: {} envelopes from it \
             failed to decrypt in {} minutes",
            BLOCK_FOR as i64 / 60,
            recent.len(),
            BLOCK_WINDOW as i64 / 60
        );
        Some(block)
    }

    /// Seconds the tunnel still refuses `ip`, or 0.
    pub fn blocked_for(&self, ip: &str, now: f64) -> f64 {
        let mut g = self.guard();
        prune(&mut g, now);
        let Some(block) = g.blocked.get_mut(&address_group(ip).0) else {
            return 0.0;
        };
        if block.until <= now {
            return 0.0;
        }
        block.refused += 1;
        if now - block.logged_at >= REFUSALS_EVERY {
            tracing::warn!(
                "Refused {} encrypted requests from {} (blocked for {} more minutes)",
                block.refused,
                block.group,
                ((block.until - now) / 60.0).ceil() as i64
            );
            block.refused = 0;
            block.logged_at = now;
        }
        block.until - now
    }
}

/// Once a minute: forget addresses with no failure in the window, and blocks that ended.
fn prune(g: &mut Guard, t: f64) {
    if t < g.next_prune {
        return;
    }
    g.next_prune = t + 60.0;
    g.bad
        .retain(|_, v| v.last().is_some_and(|l| *l > t - BLOCK_WINDOW));
    g.blocked.retain(|_, b| b.until > t);
}

// ── settings ───────────────────────────────────────────────────────────

/// Read a key file. It must hold one `cek1_` key and be readable by its
/// owner only (mode 600).
pub fn read_key_file(path: &Path, what: &str) -> anyhow::Result<Key> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("{what} {} cannot be read: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "{what} {} can be read by other users (mode {:o}); run chmod 600 on it",
                path.display(),
                mode & 0o777
            );
        }
    }
    Key::from_string(&text).map_err(|e| {
        anyhow::anyhow!(
            "{what} {} is not a valid encryption key: {e}",
            path.display()
        )
    })
}

/// Write a new key to `path` with mode 600. Refuses to overwrite.
pub fn write_new_key(path: &Path) -> anyhow::Result<Key> {
    let key = new_key();
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| anyhow::anyhow!("cannot create {}: {e}", path.display()))?;
    writeln!(file, "{key}")?;
    Key::from_string(&key).map_err(|e| anyhow::anyhow!(e))
}

/// The `e2e` field of `GET /api/health`.
pub fn health_block(keyring: Option<&Keyring>) -> Value {
    match keyring {
        Some(k) => json!({ "required": true, "kids": k.kids() }),
        None => json!({ "required": false }),
    }
}

// ── which requests may stay plain ──────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Refuse,
    /// A plain request that carries a session cookie: the cookie is exposed,
    /// so the server ends that session and clears the cookie. A browser that
    /// signed in before the key was set holds an HttpOnly cookie its scripts
    /// cannot remove, so the pages and the health check still load (without it).
    AllowClear,
    RefuseClear,
}

/// Paths that hold no data: the page shells and their static files.
fn page_path(path: &str) -> bool {
    !(path == "/api" || path.starts_with("/api/") || path == "/llms.txt")
}

/// What to do with a request that did not come through the tunnel.
pub fn plain_verdict(method: &Method, path: &str, headers: &HeaderMap) -> Verdict {
    let token = crate::auth::bearer_token(headers).is_some();
    let cookie = cookie_value(headers, SESSION_COOKIE).is_some_and(|c| !c.is_empty());
    let read = matches!(*method, Method::GET | Method::HEAD);
    let open_path = path == "/api/health" || page_path(path);
    if cookie {
        return if read && !token && open_path {
            Verdict::AllowClear
        } else {
            Verdict::RefuseClear
        };
    }
    if !token && read && open_path {
        Verdict::Allow
    } else {
        Verdict::Refuse
    }
}

// ── the middleware ─────────────────────────────────────────────────────

fn plain_json(status: StatusCode, body: Value) -> Response {
    let mut resp = (status, axum::Json(body)).into_response();
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    resp
}

fn required() -> Response {
    plain_json(
        StatusCode::BAD_REQUEST,
        json!({ "detail": "This server requires end-to-end encryption", "e2e": "required" }),
    )
}

fn blocked_detail(wait: f64) -> String {
    let n = ((wait / 60.0).ceil() as i64).max(1);
    format!(
        "Too many requests from this address could not be decrypted. Try again in {n} minute{}.",
        if n == 1 { "" } else { "s" }
    )
}

fn request_ip(state: &AppState, req: &Request) -> String {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    client_ip(req.headers(), peer, state.settings.trust_proxy)
}

/// Wraps the whole router (outside routing, so the inner request is routed
/// by its own path). Without a key it passes everything through.
pub async fn middleware(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let Some(keyring) = state.e2e.clone() else {
        return next.run(req).await;
    };
    if req.uri().path() == TUNNEL && req.method() == Method::POST {
        // The tunnel ignores outer cookies, but one sent plain next to the
        // envelope (an old cookie on an upload) is exposed all the same.
        let exposed = cookie_value(req.headers(), SESSION_COOKIE).is_some_and(|c| !c.is_empty());
        if exposed {
            end_exposed_session(&state, &req);
        }
        let mut resp = tunnel(&state, keyring, req, next).await;
        if exposed
            && let Ok(clear) =
                HeaderValue::from_str(&clear_session_cookie(state.settings.secure_cookies))
        {
            resp.headers_mut().append(header::SET_COOKIE, clear);
        }
        return resp;
    }
    match plain_verdict(req.method(), req.uri().path(), req.headers()) {
        Verdict::Allow => next.run(req).await,
        Verdict::Refuse => required(),
        verdict @ (Verdict::AllowClear | Verdict::RefuseClear) => {
            end_exposed_session(&state, &req);
            let clear = HeaderValue::from_str(&clear_session_cookie(state.settings.secure_cookies))
                .expect("cookie header");
            let mut resp = if verdict == Verdict::RefuseClear {
                required()
            } else {
                next.run(without_session_cookie(req)).await
            };
            resp.headers_mut().append(header::SET_COOKIE, clear);
            resp
        }
    }
}

/// End the session whose cookie came plain: it went over the wire unsealed.
fn end_exposed_session(state: &AppState, req: &Request) {
    let Some(token) = cookie_value(req.headers(), SESSION_COOKIE).filter(|t| !t.is_empty()) else {
        return;
    };
    let hash = hash_token(token);
    match state.store.get_session(&hash) {
        Ok(Some(_)) => {
            let ip = request_ip(state, req);
            if let Err(e) = state.store.delete_session(&hash) {
                tracing::warn!(error = %e, "could not end a session whose cookie came plain");
            } else {
                tracing::warn!(%ip, "ended a session whose cookie came without end-to-end encryption");
                let _ = state.store.add_auth_event(
                    &ip,
                    None,
                    "session_exposed",
                    Some("session ended: its cookie came plain"),
                );
            }
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(error = %e, "could not look up a session whose cookie came plain"),
    }
}

/// The request with the session cookie taken out, so nothing downstream can sign in with it.
fn without_session_cookie(mut req: Request) -> Request {
    let kept: Vec<String> = req
        .headers()
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .map(str::trim)
        .filter(|kv| !kv.is_empty() && kv.split('=').next() != Some(SESSION_COOKIE))
        .map(str::to_string)
        .collect();
    req.headers_mut().remove(header::COOKIE);
    if !kept.is_empty()
        && let Ok(v) = HeaderValue::from_str(&kept.join("; "))
    {
        req.headers_mut().insert(header::COOKIE, v);
    }
    req
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// The request inside an envelope.
fn inner_request(
    outer: &Request,
    meta: &Map<String, Value>,
    body: Vec<u8>,
) -> Result<Request, E2eError> {
    let method = meta
        .get("m")
        .and_then(Value::as_str)
        .map(str::to_ascii_uppercase)
        .filter(|m| METHODS.contains(&m.as_str()))
        .ok_or_else(|| E2eError::bad("Unknown method"))?;
    let target = meta
        .get("p")
        .and_then(Value::as_str)
        .filter(|p| p.starts_with('/') && !p.starts_with("//"))
        .ok_or_else(|| E2eError::bad("The inner path must start with /"))?;
    let raw_path = target.split('?').next().unwrap_or("");
    let path = percent_decode(raw_path);
    if path == TUNNEL || path.starts_with(&format!("{TUNNEL}/")) {
        return Err(E2eError::bad("The tunnel cannot be nested"));
    }
    let uri: Uri = target
        .parse()
        .map_err(|_| E2eError::bad("The inner path is not a valid URL path"))?;
    let sent = match meta.get("h") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(h)) => h.clone(),
        Some(_) => return Err(E2eError::bad("The inner headers must be an object")),
    };

    let mut req = Request::builder()
        .method(Method::from_bytes(method.as_bytes()).expect("known method"))
        .uri(uri)
        .body(Body::from(body))
        .map_err(|_| E2eError::bad("The inner request is not valid"))?;
    let headers = req.headers_mut();
    for name in OUTER_HEADERS {
        for v in outer.headers().get_all(name) {
            headers.append(HeaderName::from_static(name), v.clone());
        }
    }
    for (name, value) in &sent {
        let name = name.to_ascii_lowercase();
        let Some(allowed) = INNER_HEADERS.iter().find(|h| **h == name) else {
            continue;
        };
        if let Some(v) = value
            .as_str()
            .and_then(|v| HeaderValue::from_bytes(v.as_bytes()).ok())
        {
            headers.insert(HeaderName::from_static(allowed), v);
        }
    }
    if let Some(ci) = outer.extensions().get::<ConnectInfo<SocketAddr>>() {
        req.extensions_mut().insert(*ci);
    }
    req.extensions_mut().insert(Sealed);
    Ok(req)
}

fn wants_gzip(req: &Request) -> bool {
    req.headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',').any(|part| {
                let mut it = part.split(';');
                let name = it.next().unwrap_or("").trim();
                let q0 = it.any(|p| {
                    p.trim()
                        .strip_prefix("q=")
                        .is_some_and(|q| q.trim().parse::<f32>().is_ok_and(|q| q == 0.0))
                });
                name.eq_ignore_ascii_case("gzip") && !q0
            })
        })
}

fn gzip(body: &[u8]) -> Option<Vec<u8>> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(body).ok()?;
    enc.finish().ok()
}

async fn tunnel(state: &AppState, keyring: Arc<Keyring>, req: Request, next: Next) -> Response {
    // Another site cannot send this type without a CORS preflight, which
    // fails, so its garbage never counts toward blocking a victim's address.
    let typed = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case(CONTENT_TYPE));
    if !typed {
        return plain_json(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            json!({ "detail": format!("The tunnel takes {CONTENT_TYPE}"), "e2e": "bad_envelope" }),
        );
    }
    let ip = request_ip(state, &req);
    let wait = keyring.blocked_for(&ip, now_secs());
    if wait > 0.0 {
        // Before the body is read: a blocked flood costs no read and no decrypt.
        let mut resp = plain_json(
            StatusCode::TOO_MANY_REQUESTS,
            json!({ "detail": blocked_detail(wait), "e2e": "blocked" }),
        );
        if let Ok(v) = HeaderValue::from_str(&(wait.ceil() as i64).to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        return resp;
    }
    let limit = state.settings.max_upload_bytes + HEADER + TAG + 65536 + 1024 * 1024;
    let too_large = || {
        plain_json(
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({ "detail": "The request is too large" }),
        )
    };
    let Some(len) = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<usize>().ok())
    else {
        return plain_json(
            StatusCode::LENGTH_REQUIRED,
            json!({ "detail": "The tunnel needs a Content-Length" }),
        );
    };
    if len > limit {
        return too_large();
    }
    // Reserve memory for the envelope and its plaintext before reading it.
    let kib = (len.saturating_mul(2) / 1024 + 1).min(keyring.budget_kib as usize) as u32;
    let Ok(_permit) = keyring.budget.try_acquire_many(kib) else {
        let mut resp = plain_json(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "detail": "The server is busy with other encrypted requests. Try again shortly." }),
        );
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        return resp;
    };
    let (parts, body) = req.into_parts();
    let outer = Request::from_parts(parts, Body::empty());
    let data = match axum::body::to_bytes(body, len).await {
        Ok(b) => b,
        Err(_) => return too_large(),
    };
    let opened = if data.len() > BLOCKING_ABOVE {
        let k = keyring.clone();
        tokio::task::spawn_blocking(move || k.open_request(&data, now_secs()))
            .await
            .unwrap_or_else(|_| Err(E2eError::bad("The envelope could not be decrypted")))
    } else {
        keyring.open_request(&data, now_secs())
    };
    let opened = match opened {
        Ok(o) => o,
        Err(e) => {
            if let Some(block) = keyring.note_failure(&ip, e.code, now_secs()) {
                let mut detail = format!("{} failures", block.failures);
                if block.group != block.ip {
                    detail.push_str(&format!(", range {}", block.group));
                }
                if let Err(err) =
                    state
                        .store
                        .add_auth_event(&ip, None, "e2e_blocked", Some(&detail))
                {
                    tracing::warn!(error = %err, "could not record a blocked address");
                }
            }
            return plain_json(
                StatusCode::BAD_REQUEST,
                json!({ "detail": e.detail, "e2e": e.code }),
            );
        }
    };
    // Decrypted: the client has the key, so these errors do not count toward a block.
    let inner = unpack_plaintext(&opened.plaintext)
        .and_then(|(meta, body)| inner_request(&outer, &meta, body.to_vec()));
    let inner = match inner {
        Ok(r) => r,
        Err(e) => {
            return plain_json(
                StatusCode::BAD_REQUEST,
                json!({ "detail": e.detail, "e2e": e.code }),
            );
        }
    };
    let gzip_ok = wants_gzip(&inner);
    let method = inner.method().clone();
    let path = inner.uri().path().to_string();

    let resp = next.run(inner).await;
    let (parts, body) = resp.into_parts();
    let event_stream = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/event-stream"));
    let (status, headers, mut out) = if event_stream {
        // A stream never ends, so it cannot be sealed whole. Drop it.
        let body = serde_json::to_vec(&json!({
            "error": "Live event streams do not work through the encrypted tunnel. \
                      Poll the resource instead (GET /api/runs/{id} or GET /api/jobs/{id}).",
        }))
        .expect("JSON");
        let mut h = HeaderMap::new();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        (StatusCode::NOT_ACCEPTABLE, h, body)
    } else {
        match axum::body::to_bytes(body, MAX_REPLY).await {
            Ok(b) => (parts.status, parts.headers, b.to_vec()),
            Err(e) => {
                tracing::error!(error = %e, %method, %path, "could not read a reply to seal");
                let mut h = HeaderMap::new();
                h.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    h,
                    br#"{"error":"Internal server error."}"#.to_vec(),
                )
            }
        }
    };

    let mut meta_h = Map::new();
    for (name, value) in &headers {
        let name = name.as_str();
        let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
        if name == "set-cookie" {
            match meta_h
                .entry(name)
                .or_insert_with(|| Value::Array(Vec::new()))
            {
                Value::Array(list) => list.push(Value::String(value)),
                _ => unreachable!("set-cookie is a list"),
            }
        } else if let Some(Value::String(prev)) = meta_h.get_mut(name) {
            prev.push_str(", ");
            prev.push_str(&value);
        } else {
            meta_h.insert(name.to_string(), Value::String(value));
        }
    }
    let compressible = meta_h
        .get("content-type")
        .and_then(Value::as_str)
        .is_some_and(|ct| {
            ct.starts_with("text/") || ct.contains("json") || ct.contains("javascript")
        });
    if gzip_ok && compressible && out.len() >= 1024 && !meta_h.contains_key("content-encoding") {
        let zipped = if out.len() > BLOCKING_ABOVE {
            let body = std::mem::take(&mut out);
            match tokio::task::spawn_blocking(move || (gzip(&body), body)).await {
                Ok((z, body)) => {
                    out = body;
                    z
                }
                Err(_) => None,
            }
        } else {
            gzip(&out)
        };
        if let Some(z) = zipped {
            out = z;
            meta_h.insert("content-encoding".into(), Value::String("gzip".into()));
            meta_h.remove("content-length");
        }
    } else if meta_h.contains_key("content-length") {
        meta_h.insert(
            "content-length".into(),
            Value::String(out.len().to_string()),
        );
    }
    let mut meta = Map::new();
    meta.insert("s".into(), json!(status.as_u16()));
    meta.insert("h".into(), Value::Object(meta_h));
    let sealed = keyring.seal_response(&opened, meta, &out);

    let mut resp = Response::new(Body::from(sealed));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../tests/e2e_vectors.json");

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).unwrap()
    }

    fn key_of(v: &Value, kid: &str) -> Key {
        v["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| Key::from_string(k["key"].as_str().unwrap()).unwrap())
            .find(|k| hex(&k.kid) == kid)
            .unwrap()
    }

    #[test]
    fn vector_keys() {
        let v = vectors();
        for k in v["keys"].as_array().unwrap() {
            let key = Key::from_string(k["key"].as_str().unwrap()).unwrap();
            assert_eq!(hex(&key.master), k["master"].as_str().unwrap());
            assert_eq!(hex(&key.enc), k["enc"].as_str().unwrap());
            assert_eq!(hex(&key.kid), k["kid"].as_str().unwrap());
        }
        for bad in v["bad_keys"].as_array().unwrap() {
            assert!(
                parse_key(bad.as_str().unwrap()).is_err(),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn vector_requests_seal_and_open() {
        let v = vectors();
        for r in v["requests"].as_array().unwrap() {
            let key = key_of(&v, r["kid"].as_str().unwrap());
            let meta = r["meta_json"].as_str().unwrap().as_bytes();
            let body = unhex(r["body"].as_str().unwrap());
            let plain = pack_plaintext(meta, &body);
            assert_eq!(
                hex(&plain),
                r["plaintext"].as_str().unwrap(),
                "{}",
                r["name"]
            );
            let nonce: [u8; 12] = unhex(r["nonce"].as_str().unwrap()).try_into().unwrap();
            let env = seal(
                &key,
                REQUEST,
                &plain,
                r["ts_ms"].as_u64().unwrap(),
                &nonce,
                &[],
            );
            assert_eq!(hex(&env), r["envelope"].as_str().unwrap(), "{}", r["name"]);

            // The keyring opens it at the time it was made, once.
            let ring = Keyring::new(key.clone(), None);
            let at = r["ts_ms"].as_u64().unwrap() as f64 / 1000.0;
            let opened = ring.open_request(&env, at).unwrap();
            assert_eq!(opened.plaintext, plain);
            let (m, b) = unpack_plaintext(&opened.plaintext).unwrap();
            let want: Value = serde_json::from_slice(meta).unwrap();
            assert_eq!(Value::Object(m), want);
            assert_eq!(b, &body[..]);
            assert_eq!(ring.open_request(&env, at).unwrap_err().code, "replay");
            assert_eq!(
                ring.open_request(&env, at + 121.0).unwrap_err().code,
                "stale"
            );
        }
    }

    #[test]
    fn vector_responses_seal_and_open() {
        let v = vectors();
        for r in v["responses"].as_array().unwrap() {
            let key = key_of(&v, r["kid"].as_str().unwrap());
            let plain = pack_plaintext(
                r["meta_json"].as_str().unwrap().as_bytes(),
                &unhex(r["body"].as_str().unwrap()),
            );
            assert_eq!(hex(&plain), r["plaintext"].as_str().unwrap());
            let nonce: [u8; 12] = unhex(r["nonce"].as_str().unwrap()).try_into().unwrap();
            let req_nonce = unhex(r["request_nonce"].as_str().unwrap());
            let env = seal(
                &key,
                RESPONSE,
                &plain,
                r["ts_ms"].as_u64().unwrap(),
                &nonce,
                &req_nonce,
            );
            assert_eq!(hex(&env), r["envelope"].as_str().unwrap(), "{}", r["name"]);
            let opened = open_envelope(&key, &env, RESPONSE, &req_nonce).unwrap();
            assert_eq!(opened.plaintext, plain);
            // Without the request's nonce in the AAD it does not open.
            assert!(open_envelope(&key, &env, RESPONSE, &[]).is_err());
        }
    }

    #[test]
    fn vector_invalid_envelopes() {
        let v = vectors();
        let ring = Keyring::new(key_of(&v, "1f112aa78ba5eef7"), None);
        for r in v["invalid"].as_array().unwrap() {
            let env = unhex(r["envelope"].as_str().unwrap());
            let at = if env.len() >= 18 {
                u64::from_be_bytes(env[10..18].try_into().unwrap()) as f64 / 1000.0
            } else {
                0.0
            };
            let err = ring.open_request(&env, at).unwrap_err();
            assert_eq!(err.code, r["error"].as_str().unwrap(), "{}", r["name"]);
        }
    }

    #[test]
    fn vector_websocket_frames() {
        let v = vectors();
        let ws = &v["ws"];
        let key = Key::from_string(ws["key"].as_str().unwrap()).unwrap();
        let ws_key = key.ws_key(
            &unhex(ws["cn"].as_str().unwrap()),
            &unhex(ws["sn"].as_str().unwrap()),
        );
        assert_eq!(hex(&ws_key), ws["ws_key"].as_str().unwrap());
        for f in ws["frames"].as_array().unwrap() {
            let dir = f["direction"].as_u64().unwrap() as u32;
            let counter = f["counter"].as_u64().unwrap();
            let kind = f["type"].as_u64().unwrap() as u8;
            let data = unhex(f["data"].as_str().unwrap());
            let frame = seal_frame(&ws_key, dir, counter, kind, &data);
            assert_eq!(hex(&frame), f["frame"].as_str().unwrap());
            assert_eq!(
                open_frame(&ws_key, dir, counter, &frame).unwrap(),
                (kind, data)
            );
            assert_eq!(
                open_frame(&ws_key, dir, counter + 1, &frame)
                    .unwrap_err()
                    .code,
                "replay"
            );
        }
    }

    #[test]
    fn previous_key_answers_with_rotate() {
        let v = vectors();
        let old = key_of(&v, "1f112aa78ba5eef7");
        let new = key_of(&v, "717350049d01d7e6");
        let ring = Keyring::new(new.clone(), Some(old.clone()));
        assert_eq!(ring.kids(), ["717350049d01d7e6", "1f112aa78ba5eef7"]);
        let r = &v["requests"][1];
        let env = unhex(r["envelope"].as_str().unwrap());
        let at = r["ts_ms"].as_u64().unwrap() as f64 / 1000.0;
        let opened = ring.open_request(&env, at).unwrap();
        assert!(opened.previous);
        let reply = ring.seal_response(&opened, Map::new(), b"{}");
        assert_eq!(&reply[2..10], &old.kid);
        let back = open_envelope(&old, &reply, RESPONSE, &opened.nonce).unwrap();
        let (meta, body) = unpack_plaintext(&back.plaintext).unwrap();
        assert_eq!(meta.get("rotate"), Some(&Value::Bool(true)));
        assert_eq!(body, b"{}");
        // Only the current key without a previous one: the old kid is unknown.
        let ring = Keyring::new(new, None);
        assert_eq!(ring.open_request(&env, at).unwrap_err().code, "unknown_kid");
    }

    #[test]
    fn failures_block_an_address() {
        let ring = Keyring::new(Key::from_master([7; 32]), None);
        let t = 1_000_000.0;
        for i in 0..BLOCK_AFTER - 1 {
            assert!(
                ring.note_failure("203.0.113.9", "bad_envelope", t + i as f64)
                    .is_none()
            );
        }
        // Other codes do not count.
        assert!(
            ring.note_failure("203.0.113.9", "unknown_kid", t + 20.0)
                .is_none()
        );
        let block = ring
            .note_failure("203.0.113.9", "bad_envelope", t + 30.0)
            .unwrap();
        assert_eq!(block.failures, BLOCK_AFTER);
        assert!(ring.blocked_for("203.0.113.9", t + 31.0) > 0.0);
        assert_eq!(ring.blocked_for("203.0.113.10", t + 31.0), 0.0);
        assert_eq!(ring.blocked_for("203.0.113.9", t + 31.0 + BLOCK_FOR), 0.0);
        // Loopback is never blocked.
        for i in 0..BLOCK_AFTER + 2 {
            assert!(
                ring.note_failure("127.0.0.1", "bad_envelope", t + i as f64)
                    .is_none()
            );
        }
        // An IPv6 /64 counts as one address.
        assert_eq!(
            address_group("2001:db8:1:2:aaaa::1"),
            ("2001:db8:1:2::/64".to_string(), true)
        );
        assert_eq!(
            address_group("::ffff:10.0.0.1"),
            ("10.0.0.1".to_string(), true)
        );
    }

    #[test]
    fn plain_verdicts() {
        let get = Method::GET;
        let post = Method::POST;
        let none = HeaderMap::new();
        let mut cookie = HeaderMap::new();
        cookie.insert(
            header::COOKIE,
            format!("{SESSION_COOKIE}=abc").parse().unwrap(),
        );
        let mut token = HeaderMap::new();
        token.insert(header::AUTHORIZATION, "Bearer hallu_x".parse().unwrap());

        assert_eq!(plain_verdict(&get, "/api/health", &none), Verdict::Allow);
        assert_eq!(plain_verdict(&get, "/", &none), Verdict::Allow);
        assert_eq!(plain_verdict(&get, "/static/app.js", &none), Verdict::Allow);
        assert_eq!(plain_verdict(&get, "/api/auth/me", &none), Verdict::Refuse);
        assert_eq!(plain_verdict(&get, "/llms.txt", &none), Verdict::Refuse);
        assert_eq!(
            plain_verdict(&post, "/api/auth/login", &none),
            Verdict::Refuse
        );
        assert_eq!(plain_verdict(&post, "/login", &none), Verdict::Refuse);
        assert_eq!(plain_verdict(&get, "/api/health", &token), Verdict::Refuse);
        assert_eq!(plain_verdict(&get, "/", &cookie), Verdict::AllowClear);
        assert_eq!(
            plain_verdict(&get, "/api/runs", &cookie),
            Verdict::RefuseClear
        );
    }
}
