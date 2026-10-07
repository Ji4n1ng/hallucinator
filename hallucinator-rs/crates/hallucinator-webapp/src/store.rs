//! SQLite persistence: users, sessions, sign-in audit trail, check history
//! and reference-database job history.
//!
//! One connection behind a mutex (WAL mode). Every statement here is a
//! short indexed read/write, so callers use it inline from async handlers.

use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::Serialize;

use crate::model::{RefFacts, Stats};

const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER,
    failed_streak INTEGER NOT NULL DEFAULT 0,
    locked_until  INTEGER,
    lockout_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash   TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token   TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    ip           TEXT,
    user_agent   TEXT
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS auth_events (
    id       INTEGER PRIMARY KEY,
    at       INTEGER NOT NULL,
    ip       TEXT NOT NULL,
    username TEXT,
    kind     TEXT NOT NULL,
    detail   TEXT
);
CREATE INDEX IF NOT EXISTS auth_events_ip_at ON auth_events(ip, kind, at);
CREATE INDEX IF NOT EXISTS auth_events_at ON auth_events(at);
CREATE INDEX IF NOT EXISTS auth_events_user ON auth_events(username COLLATE NOCASE, kind, at);

CREATE TABLE IF NOT EXISTS ip_blocks (
    ip    TEXT PRIMARY KEY,
    until INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id           TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title        TEXT NOT NULL,
    status       TEXT NOT NULL,
    options_json TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    started_at   INTEGER,
    finished_at  INTEGER,
    error        TEXT
);
CREATE INDEX IF NOT EXISTS runs_user_created ON runs(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS papers (
    id                 INTEGER PRIMARY KEY,
    run_id             TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    idx                INTEGER NOT NULL,
    filename           TEXT NOT NULL,
    input_kind         TEXT NOT NULL,
    companion_filename TEXT,
    sha256             TEXT,
    status             TEXT NOT NULL,
    error              TEXT,
    verdict            TEXT,
    skip_stats_json    TEXT,
    merge_json         TEXT,
    UNIQUE(run_id, idx)
);

CREATE TABLE IF NOT EXISTS refs (
    id              INTEGER PRIMARY KEY,
    paper_id        INTEGER NOT NULL REFERENCES papers(id) ON DELETE CASCADE,
    idx             INTEGER NOT NULL,
    original_number INTEGER NOT NULL,
    title           TEXT,
    raw_citation    TEXT NOT NULL,
    authors_json    TEXT NOT NULL,
    doi             TEXT,
    arxiv_id        TEXT,
    urls_json       TEXT NOT NULL,
    skip_reason     TEXT,
    origin          TEXT NOT NULL,
    result_json     TEXT,
    verdict         TEXT,
    mismatch_flags  INTEGER NOT NULL DEFAULT 0,
    retracted       INTEGER NOT NULL DEFAULT 0,
    fp_reason       TEXT,
    checked_at      INTEGER,
    UNIQUE(paper_id, idx)
);

CREATE TABLE IF NOT EXISTS db_jobs (
    id          TEXT PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    db_key      TEXT NOT NULL,
    action      TEXT NOT NULL,
    label       TEXT NOT NULL,
    argv_json   TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    finished_at INTEGER,
    exit_code   INTEGER,
    log         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS db_jobs_key_created ON db_jobs(db_key, created_at DESC);
"#;

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── Row types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub status: String,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
}

impl User {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

#[derive(Debug, Clone)]
pub struct UserAuth {
    pub user: User,
    pub password_hash: String,
    pub locked_until: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminUser {
    #[serde(flatten)]
    pub user: User,
    pub locked_until: Option<i64>,
    pub failed_streak: i64,
    pub run_count: i64,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user: User,
    pub csrf_token: String,
    pub expires_at: i64,
    pub last_seen_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthEvent {
    pub id: i64,
    pub at: i64,
    pub ip: String,
    pub username: Option<String>,
    pub kind: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpBlock {
    pub ip: String,
    pub until: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunRow {
    pub id: String,
    pub user_id: i64,
    pub username: String,
    pub title: String,
    pub status: String,
    #[serde(skip)]
    pub options_json: String,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub error: Option<String>,
    pub paper_count: i64,
}

#[derive(Debug, Clone)]
pub struct PaperRow {
    pub id: i64,
    pub idx: usize,
    pub filename: String,
    pub input_kind: String,
    pub companion_filename: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub verdict: Option<String>,
    pub skip_stats_json: Option<String>,
    pub merge_json: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RefRow {
    pub idx: usize,
    pub original_number: usize,
    pub title: Option<String>,
    pub raw_citation: String,
    pub authors: Vec<String>,
    pub doi: Option<String>,
    pub arxiv_id: Option<String>,
    pub urls: Vec<String>,
    pub skip_reason: Option<String>,
    pub origin: String,
    pub result_json: Option<String>,
    pub verdict: Option<String>,
    pub mismatch_flags: u8,
    pub retracted: bool,
    pub fp_reason: Option<String>,
}

impl RefRow {
    pub fn facts(&self) -> RefFacts {
        RefFacts {
            parse_skipped: self.skip_reason.is_some(),
            verdict: self.verdict.clone(),
            mismatch_flags: self.mismatch_flags,
            retracted: self.retracted,
            fp: self.fp_reason.is_some(),
        }
    }
}

/// A reference to insert after extraction.
#[derive(Debug, Clone)]
pub struct NewRef {
    pub original_number: usize,
    pub title: Option<String>,
    pub raw_citation: String,
    pub authors: Vec<String>,
    pub doi: Option<String>,
    pub arxiv_id: Option<String>,
    pub urls: Vec<String>,
    pub skip_reason: Option<String>,
    pub origin: String,
}

/// A checked result to persist (see `model::StoredResult`).
pub struct ResultUpdate<'a> {
    pub result_json: &'a str,
    pub verdict: &'a str,
    pub mismatch_flags: u8,
    pub retracted: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobRow {
    pub id: String,
    #[serde(skip)]
    pub user_id: Option<i64>,
    pub username: Option<String>,
    pub db_key: String,
    pub action: String,
    pub label: String,
    /// Empty (and omitted) in responses to non-admins — it names server paths.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    pub status: String,
    pub created_at: i64,
    pub finished_at: Option<i64>,
    pub exit_code: Option<i32>,
}

/// A reference marked safe, for the local-corpus import.
pub struct MarkedSafe {
    pub filename: String,
    pub run_id: String,
    pub paper_idx: usize,
    pub original_number: usize,
    pub title: String,
    pub raw_citation: String,
    pub authors: Vec<String>,
    pub fp_reason: String,
    pub result_json: Option<String>,
}

#[derive(Debug)]
pub enum StoreError {
    Conflict,
    Other(anyhow::Error),
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Other(e.into())
    }
}

// ── Store ──────────────────────────────────────────────────────────────

pub struct Store {
    conn: Mutex<Connection>,
}

fn user_from_row(row: &Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get("id")?,
        username: row.get("username")?,
        role: row.get("role")?,
        status: row.get("status")?,
        created_at: row.get("created_at")?,
        last_login_at: row.get("last_login_at")?,
    })
}

fn json_vec(s: Option<String>) -> Vec<String> {
    s.and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

const USER_COLS: &str = "u.id, u.username, u.role, u.status, u.created_at, u.last_login_at";
const RUN_COLS: &str = "r.id, r.user_id, u.username, r.title, r.status, r.options_json, \
     r.created_at, r.started_at, r.finished_at, r.error, \
     (SELECT COUNT(*) FROM papers p WHERE p.run_id = r.id) AS paper_count";
const REF_COLS: &str = "idx, original_number, title, raw_citation, authors_json, doi, arxiv_id, \
     urls_json, skip_reason, origin, result_json, verdict, mismatch_flags, retracted, fp_reason";

fn run_from_row(row: &Row<'_>) -> rusqlite::Result<RunRow> {
    Ok(RunRow {
        id: row.get(0)?,
        user_id: row.get(1)?,
        username: row.get(2)?,
        title: row.get(3)?,
        status: row.get(4)?,
        options_json: row.get(5)?,
        created_at: row.get(6)?,
        started_at: row.get(7)?,
        finished_at: row.get(8)?,
        error: row.get(9)?,
        paper_count: row.get(10)?,
    })
}

fn ref_from_row(row: &Row<'_>) -> rusqlite::Result<RefRow> {
    Ok(RefRow {
        idx: row.get::<_, i64>(0)? as usize,
        original_number: row.get::<_, i64>(1)? as usize,
        title: row.get(2)?,
        raw_citation: row.get(3)?,
        authors: json_vec(row.get(4)?),
        doi: row.get(5)?,
        arxiv_id: row.get(6)?,
        urls: json_vec(row.get(7)?),
        skip_reason: row.get(8)?,
        origin: row.get(9)?,
        result_json: row.get(10)?,
        verdict: row.get(11)?,
        mismatch_flags: row.get::<_, i64>(12)? as u8,
        retracted: row.get::<_, i64>(13)? != 0,
        fp_reason: row.get(14)?,
    })
}

fn job_from_row(row: &Row<'_>) -> rusqlite::Result<JobRow> {
    Ok(JobRow {
        id: row.get(0)?,
        user_id: row.get(1)?,
        username: row.get(2)?,
        db_key: row.get(3)?,
        action: row.get(4)?,
        label: row.get(5)?,
        argv: json_vec(row.get(6)?),
        status: row.get(7)?,
        created_at: row.get(8)?,
        finished_at: row.get(9)?,
        exit_code: row.get(10)?,
    })
}

const JOB_COLS: &str = "j.id, j.user_id, u.username, j.db_key, j.action, j.label, j.argv_json, \
     j.status, j.created_at, j.finished_at, j.exit_code";

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        Self::init(conn)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;",
        )?;
        conn.execute_batch(SCHEMA)?;
        conn.execute(
            "INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', ?1)",
            params![SCHEMA_VERSION.to_string()],
        )?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A panic while holding the lock leaves the connection itself intact.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Startup housekeeping: anything "running" belongs to a dead process.
    pub fn mark_interrupted(&self) -> Result<()> {
        let c = self.conn();
        let t = now();
        c.execute(
            "UPDATE runs SET status = 'interrupted', finished_at = ?1 \
             WHERE status IN ('queued', 'running')",
            params![t],
        )?;
        c.execute(
            "UPDATE papers SET status = 'cancelled' \
             WHERE status IN ('queued', 'extracting', 'checking')",
            [],
        )?;
        c.execute(
            "UPDATE db_jobs SET status = 'interrupted', finished_at = ?1 WHERE status = 'running'",
            params![t],
        )?;
        Ok(())
    }

    pub fn purge(&self, auth_event_retention_secs: i64) -> Result<()> {
        let c = self.conn();
        let t = now();
        c.execute("DELETE FROM sessions WHERE expires_at < ?1", params![t])?;
        c.execute("DELETE FROM ip_blocks WHERE until < ?1", params![t])?;
        c.execute(
            "DELETE FROM auth_events WHERE at < ?1",
            params![t - auth_event_retention_secs],
        )?;
        Ok(())
    }

    // ── users ──

    pub fn count_users(&self) -> Result<i64> {
        Ok(self
            .conn()
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?)
    }

    pub fn count_active_admins(&self) -> Result<i64> {
        Ok(self.conn().query_row(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'",
            [],
            |r| r.get(0),
        )?)
    }

    pub fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        role: &str,
        status: &str,
    ) -> Result<User, StoreError> {
        let c = self.conn();
        let t = now();
        match c.execute(
            "INSERT INTO users (username, password_hash, role, status, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![username, password_hash, role, status, t],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(StoreError::Conflict);
            }
            Err(e) => return Err(e.into()),
        }
        let id = c.last_insert_rowid();
        Ok(User {
            id,
            username: username.to_string(),
            role: role.to_string(),
            status: status.to_string(),
            created_at: t,
            last_login_at: None,
        })
    }

    pub fn user_auth_by_name(&self, username: &str) -> Result<Option<UserAuth>> {
        let c = self.conn();
        Ok(c.query_row(
            &format!(
                "SELECT {USER_COLS}, u.password_hash, u.locked_until \
                 FROM users u WHERE u.username = ?1"
            ),
            params![username],
            |row| {
                Ok(UserAuth {
                    user: user_from_row(row)?,
                    password_hash: row.get("password_hash")?,
                    locked_until: row.get("locked_until")?,
                })
            },
        )
        .optional()?)
    }

    pub fn user_auth_by_id(&self, id: i64) -> Result<Option<UserAuth>> {
        let c = self.conn();
        Ok(c.query_row(
            &format!(
                "SELECT {USER_COLS}, u.password_hash, u.locked_until \
                 FROM users u WHERE u.id = ?1"
            ),
            params![id],
            |row| {
                Ok(UserAuth {
                    user: user_from_row(row)?,
                    password_hash: row.get("password_hash")?,
                    locked_until: row.get("locked_until")?,
                })
            },
        )
        .optional()?)
    }

    pub fn get_user(&self, id: i64) -> Result<Option<User>> {
        Ok(self.user_auth_by_id(id)?.map(|u| u.user))
    }

    pub fn list_users(&self) -> Result<Vec<AdminUser>> {
        let c = self.conn();
        let mut stmt = c.prepare(&format!(
            "SELECT {USER_COLS}, u.locked_until, u.failed_streak, \
             (SELECT COUNT(*) FROM runs r WHERE r.user_id = u.id) AS run_count \
             FROM users u ORDER BY u.created_at"
        ))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(AdminUser {
                    user: user_from_row(row)?,
                    locked_until: row.get("locked_until")?,
                    failed_streak: row.get("failed_streak")?,
                    run_count: row.get("run_count")?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn set_user_status(&self, id: i64, status: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE users SET status = ?2 WHERE id = ?1",
            params![id, status],
        )?;
        if status != "active" {
            self.delete_user_sessions(id, None)?;
        }
        Ok(())
    }

    pub fn set_user_role(&self, id: i64, role: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE users SET role = ?2 WHERE id = ?1",
            params![id, role],
        )?;
        Ok(())
    }

    pub fn unlock_user(&self, id: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE users SET failed_streak = 0, locked_until = NULL, lockout_count = 0 WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn delete_user(&self, id: i64) -> Result<()> {
        self.conn()
            .execute("DELETE FROM users WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn set_password(&self, id: i64, hash: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE users SET password_hash = ?2 WHERE id = ?1",
            params![id, hash],
        )?;
        Ok(())
    }

    pub fn record_login_success(&self, id: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE users SET last_login_at = ?2, failed_streak = 0, locked_until = NULL, \
             lockout_count = 0 WHERE id = ?1",
            params![id, now()],
        )?;
        Ok(())
    }

    /// Count a failed password for an account. Returns `Some(locked_until)`
    /// when this failure tripped a lockout. Lock duration doubles with each
    /// consecutive lockout (`base * 2^n`, capped at `max`).
    pub fn record_login_failure(
        &self,
        id: i64,
        threshold: i64,
        base_lock_secs: i64,
        max_lock_secs: i64,
    ) -> Result<Option<i64>> {
        let c = self.conn();
        let (streak, lockouts): (i64, i64) = c.query_row(
            "UPDATE users SET failed_streak = failed_streak + 1 WHERE id = ?1 \
             RETURNING failed_streak, lockout_count",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if streak < threshold {
            return Ok(None);
        }
        let secs = base_lock_secs
            .saturating_mul(1i64 << lockouts.clamp(0, 16))
            .min(max_lock_secs);
        let until = now() + secs;
        c.execute(
            "UPDATE users SET failed_streak = 0, locked_until = ?2, \
             lockout_count = lockout_count + 1 WHERE id = ?1",
            params![id, until],
        )?;
        Ok(Some(until))
    }

    // ── sessions ──

    pub fn create_session(
        &self,
        token_hash: &str,
        user_id: i64,
        csrf: &str,
        ttl_secs: i64,
        ip: &str,
        user_agent: Option<&str>,
    ) -> Result<()> {
        let t = now();
        self.conn().execute(
            "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, expires_at, \
             last_seen_at, ip, user_agent) VALUES (?1, ?2, ?3, ?4, ?5, ?4, ?6, ?7)",
            params![token_hash, user_id, csrf, t, t + ttl_secs, ip, user_agent],
        )?;
        Ok(())
    }

    pub fn get_session(&self, token_hash: &str) -> Result<Option<Session>> {
        let c = self.conn();
        Ok(c.query_row(
            &format!(
                "SELECT {USER_COLS}, s.csrf_token, s.expires_at, s.last_seen_at \
                 FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?1"
            ),
            params![token_hash],
            |row| {
                Ok(Session {
                    user: user_from_row(row)?,
                    csrf_token: row.get("csrf_token")?,
                    expires_at: row.get("expires_at")?,
                    last_seen_at: row.get("last_seen_at")?,
                })
            },
        )
        .optional()?)
    }

    pub fn touch_session(&self, token_hash: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE sessions SET last_seen_at = ?2 WHERE token_hash = ?1",
            params![token_hash, now()],
        )?;
        Ok(())
    }

    pub fn delete_session(&self, token_hash: &str) -> Result<()> {
        self.conn().execute(
            "DELETE FROM sessions WHERE token_hash = ?1",
            params![token_hash],
        )?;
        Ok(())
    }

    pub fn delete_user_sessions(&self, user_id: i64, except: Option<&str>) -> Result<()> {
        self.conn().execute(
            "DELETE FROM sessions WHERE user_id = ?1 AND token_hash != COALESCE(?2, '')",
            params![user_id, except],
        )?;
        Ok(())
    }

    // ── auth audit / rate limiting ──

    pub fn add_auth_event(
        &self,
        ip: &str,
        username: Option<&str>,
        kind: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT INTO auth_events (at, ip, username, kind, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![now(), ip, username, kind, detail],
        )?;
        Ok(())
    }

    pub fn count_auth_events(&self, ip: &str, kind: &str, since: i64) -> Result<i64> {
        Ok(self.conn().query_row(
            "SELECT COUNT(*) FROM auth_events WHERE ip = ?1 AND kind = ?2 AND at >= ?3",
            params![ip, kind, since],
            |r| r.get(0),
        )?)
    }

    /// Recent failed sign-ins naming `username` (any IP): count and the
    /// latest timestamp. Used to lock out non-existent usernames exactly
    /// like real ones, so lockout behaviour does not reveal which exist.
    pub fn username_failures(&self, username: &str, since: i64) -> Result<(i64, Option<i64>)> {
        Ok(self.conn().query_row(
            "SELECT COUNT(*), MAX(at) FROM auth_events \
             WHERE username = ?1 COLLATE NOCASE AND kind = 'login_fail' AND at >= ?2",
            params![username, since],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    }

    pub fn list_auth_events(&self, limit: i64) -> Result<Vec<AuthEvent>> {
        let c = self.conn();
        let mut stmt = c.prepare(
            "SELECT id, at, ip, username, kind, detail FROM auth_events ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(AuthEvent {
                    id: row.get(0)?,
                    at: row.get(1)?,
                    ip: row.get(2)?,
                    username: row.get(3)?,
                    kind: row.get(4)?,
                    detail: row.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn ip_blocked_until(&self, ip: &str) -> Result<Option<i64>> {
        let c = self.conn();
        let until: Option<i64> = c
            .query_row(
                "SELECT until FROM ip_blocks WHERE ip = ?1",
                params![ip],
                |r| r.get(0),
            )
            .optional()?;
        Ok(until.filter(|u| *u > now()))
    }

    pub fn block_ip(&self, ip: &str, until: i64) -> Result<()> {
        self.conn().execute(
            "INSERT INTO ip_blocks (ip, until) VALUES (?1, ?2) \
             ON CONFLICT(ip) DO UPDATE SET until = MAX(until, excluded.until)",
            params![ip, until],
        )?;
        Ok(())
    }

    pub fn unblock_ip(&self, ip: &str) -> Result<()> {
        self.conn()
            .execute("DELETE FROM ip_blocks WHERE ip = ?1", params![ip])?;
        Ok(())
    }

    pub fn list_ip_blocks(&self) -> Result<Vec<IpBlock>> {
        let c = self.conn();
        let mut stmt =
            c.prepare("SELECT ip, until FROM ip_blocks WHERE until > ?1 ORDER BY until DESC")?;
        let rows = stmt
            .query_map(params![now()], |row| {
                Ok(IpBlock {
                    ip: row.get(0)?,
                    until: row.get(1)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ── runs ──

    pub fn create_run(
        &self,
        id: &str,
        user_id: i64,
        title: &str,
        options_json: &str,
        papers: &[(String, String, Option<String>, Option<String>)],
    ) -> Result<()> {
        let mut c = self.conn();
        let tx = c.transaction()?;
        tx.execute(
            "INSERT INTO runs (id, user_id, title, status, options_json, created_at) \
             VALUES (?1, ?2, ?3, 'queued', ?4, ?5)",
            params![id, user_id, title, options_json, now()],
        )?;
        for (idx, (filename, kind, companion, sha)) in papers.iter().enumerate() {
            tx.execute(
                "INSERT INTO papers (run_id, idx, filename, input_kind, companion_filename, \
                 sha256, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'queued')",
                params![id, idx as i64, filename, kind, companion, sha],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn set_run_started(&self, id: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE runs SET status = 'running', started_at = COALESCE(started_at, ?2), \
             finished_at = NULL WHERE id = ?1",
            params![id, now()],
        )?;
        Ok(())
    }

    pub fn set_run_finished(&self, id: &str, status: &str, error: Option<&str>) -> Result<()> {
        self.conn().execute(
            "UPDATE runs SET status = ?2, finished_at = ?3, error = ?4 WHERE id = ?1",
            params![id, status, now(), error],
        )?;
        Ok(())
    }

    pub fn set_paper_status(
        &self,
        run_id: &str,
        idx: usize,
        status: &str,
        error: Option<&str>,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE papers SET status = ?3, error = COALESCE(?4, error) \
             WHERE run_id = ?1 AND idx = ?2",
            params![run_id, idx as i64, status, error],
        )?;
        Ok(())
    }

    /// Store the extracted reference list for a paper (replacing any
    /// previous one) and the extraction metadata.
    pub fn set_paper_extraction(
        &self,
        run_id: &str,
        idx: usize,
        input_kind: &str,
        skip_stats_json: &str,
        merge_json: Option<&str>,
        refs: &[NewRef],
    ) -> Result<()> {
        let mut c = self.conn();
        let tx = c.transaction()?;
        let paper_id: i64 = tx.query_row(
            "SELECT id FROM papers WHERE run_id = ?1 AND idx = ?2",
            params![run_id, idx as i64],
            |r| r.get(0),
        )?;
        tx.execute(
            "UPDATE papers SET input_kind = ?2, skip_stats_json = ?3, merge_json = ?4 WHERE id = ?1",
            params![paper_id, input_kind, skip_stats_json, merge_json],
        )?;
        tx.execute("DELETE FROM refs WHERE paper_id = ?1", params![paper_id])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO refs (paper_id, idx, original_number, title, raw_citation, \
                 authors_json, doi, arxiv_id, urls_json, skip_reason, origin, verdict) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )?;
            for (i, r) in refs.iter().enumerate() {
                stmt.execute(params![
                    paper_id,
                    i as i64,
                    r.original_number as i64,
                    r.title,
                    r.raw_citation,
                    serde_json::to_string(&r.authors)?,
                    r.doi,
                    r.arxiv_id,
                    serde_json::to_string(&r.urls)?,
                    r.skip_reason,
                    r.origin,
                    r.skip_reason.as_ref().map(|_| "skipped"),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn set_ref_result(
        &self,
        run_id: &str,
        paper_idx: usize,
        ref_idx: usize,
        u: &ResultUpdate<'_>,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE refs SET result_json = ?4, verdict = ?5, mismatch_flags = ?6, retracted = ?7, \
             checked_at = ?8 \
             WHERE idx = ?3 AND paper_id = (SELECT id FROM papers WHERE run_id = ?1 AND idx = ?2)",
            params![
                run_id,
                paper_idx as i64,
                ref_idx as i64,
                u.result_json,
                u.verdict,
                u.mismatch_flags as i64,
                u.retracted as i64,
                now()
            ],
        )?;
        Ok(())
    }

    pub fn set_ref_fp(
        &self,
        run_id: &str,
        paper_idx: usize,
        ref_idx: usize,
        fp: Option<&str>,
    ) -> Result<bool> {
        let n = self.conn().execute(
            "UPDATE refs SET fp_reason = ?4 \
             WHERE idx = ?3 AND paper_id = (SELECT id FROM papers WHERE run_id = ?1 AND idx = ?2)",
            params![run_id, paper_idx as i64, ref_idx as i64, fp],
        )?;
        Ok(n > 0)
    }

    pub fn set_paper_verdict(
        &self,
        run_id: &str,
        paper_idx: usize,
        verdict: Option<&str>,
    ) -> Result<bool> {
        let n = self.conn().execute(
            "UPDATE papers SET verdict = ?3 WHERE run_id = ?1 AND idx = ?2",
            params![run_id, paper_idx as i64, verdict],
        )?;
        Ok(n > 0)
    }

    pub fn get_run(&self, id: &str) -> Result<Option<RunRow>> {
        let c = self.conn();
        Ok(c.query_row(
            &format!(
                "SELECT {RUN_COLS} FROM runs r JOIN users u ON u.id = r.user_id WHERE r.id = ?1"
            ),
            params![id],
            run_from_row,
        )
        .optional()?)
    }

    pub fn list_runs(
        &self,
        user_id: Option<i64>,
        q: Option<&str>,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(i64, Vec<RunRow>)> {
        let c = self.conn();
        let like = q.map(|q| format!("%{}%", q.replace('%', "\\%").replace('_', "\\_")));
        let filter = "WHERE (?1 IS NULL OR r.user_id = ?1) \
             AND (?2 IS NULL OR r.title LIKE ?2 ESCAPE '\\' OR EXISTS (SELECT 1 FROM papers p \
                  WHERE p.run_id = r.id AND (p.filename LIKE ?2 ESCAPE '\\' \
                  OR p.companion_filename LIKE ?2 ESCAPE '\\'))) \
             AND (?3 IS NULL OR r.status = ?3)";
        let total: i64 = c.query_row(
            &format!("SELECT COUNT(*) FROM runs r {filter}"),
            params![user_id, like, status],
            |r| r.get(0),
        )?;
        let mut stmt = c.prepare(&format!(
            "SELECT {RUN_COLS} FROM runs r JOIN users u ON u.id = r.user_id {filter} \
             ORDER BY r.created_at DESC, r.rowid DESC LIMIT ?4 OFFSET ?5"
        ))?;
        let rows = stmt
            .query_map(params![user_id, like, status, limit, offset], run_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((total, rows))
    }

    pub fn delete_run(&self, id: &str) -> Result<()> {
        self.conn()
            .execute("DELETE FROM runs WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn load_papers(&self, run_id: &str) -> Result<Vec<(PaperRow, Vec<RefRow>)>> {
        let c = self.conn();
        let mut stmt = c.prepare(
            "SELECT id, idx, filename, input_kind, companion_filename, status, error, verdict, \
             skip_stats_json, merge_json FROM papers WHERE run_id = ?1 ORDER BY idx",
        )?;
        let papers = stmt
            .query_map(params![run_id], |row| {
                Ok(PaperRow {
                    id: row.get(0)?,
                    idx: row.get::<_, i64>(1)? as usize,
                    filename: row.get(2)?,
                    input_kind: row.get(3)?,
                    companion_filename: row.get(4)?,
                    status: row.get(5)?,
                    error: row.get(6)?,
                    verdict: row.get(7)?,
                    skip_stats_json: row.get(8)?,
                    merge_json: row.get(9)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut ref_stmt = c.prepare(&format!(
            "SELECT {REF_COLS} FROM refs WHERE paper_id = ?1 ORDER BY idx"
        ))?;
        let mut out = Vec::with_capacity(papers.len());
        for p in papers {
            let refs = ref_stmt
                .query_map(params![p.id], ref_from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            out.push((p, refs));
        }
        Ok(out)
    }

    pub fn load_paper_refs(&self, run_id: &str, paper_idx: usize) -> Result<Vec<RefRow>> {
        let c = self.conn();
        let mut stmt = c.prepare(&format!(
            "SELECT {REF_COLS} FROM refs WHERE paper_id = \
             (SELECT id FROM papers WHERE run_id = ?1 AND idx = ?2) ORDER BY idx"
        ))?;
        let refs = stmt
            .query_map(params![run_id, paper_idx as i64], ref_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(refs)
    }

    pub fn load_ref(
        &self,
        run_id: &str,
        paper_idx: usize,
        ref_idx: usize,
    ) -> Result<Option<RefRow>> {
        let c = self.conn();
        Ok(c.query_row(
            &format!(
                "SELECT {REF_COLS} FROM refs WHERE idx = ?3 AND paper_id = \
                 (SELECT id FROM papers WHERE run_id = ?1 AND idx = ?2)"
            ),
            params![run_id, paper_idx as i64, ref_idx as i64],
            ref_from_row,
        )
        .optional()?)
    }

    /// Aggregate stats for a set of runs in one query.
    pub fn run_stats(
        &self,
        run_ids: &[String],
    ) -> Result<std::collections::HashMap<String, Stats>> {
        let mut out: std::collections::HashMap<String, Stats> = run_ids
            .iter()
            .map(|id| (id.clone(), Stats::default()))
            .collect();
        if run_ids.is_empty() {
            return Ok(out);
        }
        let c = self.conn();
        let placeholders = vec!["?"; run_ids.len()].join(",");
        let mut stmt = c.prepare(&format!(
            "SELECT p.run_id, r.skip_reason IS NOT NULL, r.verdict, r.mismatch_flags, r.retracted, \
             r.fp_reason IS NOT NULL FROM refs r JOIN papers p ON p.id = r.paper_id \
             WHERE p.run_id IN ({placeholders})"
        ))?;
        let mut rows = stmt.query(rusqlite::params_from_iter(run_ids.iter()))?;
        while let Some(row) = rows.next()? {
            let run_id: String = row.get(0)?;
            let facts = RefFacts {
                parse_skipped: row.get(1)?,
                verdict: row.get(2)?,
                mismatch_flags: row.get::<_, i64>(3)? as u8,
                retracted: row.get::<_, i64>(4)? != 0,
                fp: row.get(5)?,
            };
            out.entry(run_id).or_default().add(&facts);
        }
        Ok(out)
    }

    pub fn marked_safe(&self) -> Result<Vec<MarkedSafe>> {
        let c = self.conn();
        let mut stmt = c.prepare(
            "SELECT p.filename, p.run_id, p.idx, r.original_number, \
             COALESCE(r.title, ''), r.raw_citation, r.authors_json, r.fp_reason, r.result_json \
             FROM refs r JOIN papers p ON p.id = r.paper_id \
             WHERE r.fp_reason IS NOT NULL ORDER BY p.run_id, p.idx, r.idx",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(MarkedSafe {
                    filename: row.get(0)?,
                    run_id: row.get(1)?,
                    paper_idx: row.get::<_, i64>(2)? as usize,
                    original_number: row.get::<_, i64>(3)? as usize,
                    title: row.get(4)?,
                    raw_citation: row.get(5)?,
                    authors: json_vec(row.get(6)?),
                    fp_reason: row.get(7)?,
                    result_json: row.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn count_marked_safe(&self) -> Result<i64> {
        Ok(self.conn().query_row(
            "SELECT COUNT(*) FROM refs WHERE fp_reason IS NOT NULL",
            [],
            |r| r.get(0),
        )?)
    }

    // ── db jobs ──

    pub fn create_job(&self, job: &JobRow) -> Result<()> {
        self.conn().execute(
            "INSERT INTO db_jobs (id, user_id, db_key, action, label, argv_json, status, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                job.id,
                job.user_id,
                job.db_key,
                job.action,
                job.label,
                serde_json::to_string(&job.argv)?,
                job.status,
                job.created_at
            ],
        )?;
        Ok(())
    }

    pub fn save_job_log(&self, id: &str, log: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE db_jobs SET log = ?2 WHERE id = ?1",
            params![id, log],
        )?;
        Ok(())
    }

    pub fn finish_job(
        &self,
        id: &str,
        status: &str,
        exit_code: Option<i32>,
        log: &str,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE db_jobs SET status = ?2, exit_code = ?3, log = ?4, finished_at = ?5 WHERE id = ?1",
            params![id, status, exit_code, log, now()],
        )?;
        Ok(())
    }

    pub fn get_job(&self, id: &str) -> Result<Option<(JobRow, String)>> {
        let c = self.conn();
        Ok(c.query_row(
            &format!(
                "SELECT {JOB_COLS}, j.log FROM db_jobs j LEFT JOIN users u ON u.id = j.user_id \
                 WHERE j.id = ?1"
            ),
            params![id],
            |row| Ok((job_from_row(row)?, row.get(11)?)),
        )
        .optional()?)
    }

    pub fn list_jobs(&self, limit: i64) -> Result<Vec<JobRow>> {
        let c = self.conn();
        let mut stmt = c.prepare(&format!(
            "SELECT {JOB_COLS} FROM db_jobs j LEFT JOIN users u ON u.id = j.user_id \
             ORDER BY j.created_at DESC, j.rowid DESC LIMIT ?1"
        ))?;
        let rows = stmt
            .query_map(params![limit], job_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn last_job_for(&self, db_key: &str) -> Result<Option<JobRow>> {
        let c = self.conn();
        Ok(c.query_row(
            &format!(
                "SELECT {JOB_COLS} FROM db_jobs j LEFT JOIN users u ON u.id = j.user_id \
                 WHERE j.db_key = ?1 ORDER BY j.created_at DESC, j.rowid DESC LIMIT 1"
            ),
            params![db_key],
            job_from_row,
        )
        .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_lockout_doubles() {
        let s = Store::open_in_memory().unwrap();
        let u = s.create_user("alice", "h", "user", "active").unwrap();
        for _ in 0..4 {
            assert_eq!(s.record_login_failure(u.id, 5, 60, 3600).unwrap(), None);
        }
        let first = s.record_login_failure(u.id, 5, 60, 3600).unwrap().unwrap();
        assert!((first - now() - 60).abs() <= 1);
        for _ in 0..4 {
            s.record_login_failure(u.id, 5, 60, 3600).unwrap();
        }
        let second = s.record_login_failure(u.id, 5, 60, 3600).unwrap().unwrap();
        assert!((second - now() - 120).abs() <= 1);
        s.record_login_success(u.id).unwrap();
        let a = s.user_auth_by_id(u.id).unwrap().unwrap();
        assert_eq!(a.locked_until, None);
        // A success resets the doubling: the next lockout is the base length.
        for _ in 0..4 {
            s.record_login_failure(u.id, 5, 60, 3600).unwrap();
        }
        let third = s.record_login_failure(u.id, 5, 60, 3600).unwrap().unwrap();
        assert!((third - now() - 60).abs() <= 1);
    }

    #[test]
    fn duplicate_username_is_conflict_case_insensitive() {
        let s = Store::open_in_memory().unwrap();
        s.create_user("Alice", "h", "user", "active").unwrap();
        assert!(matches!(
            s.create_user("alice", "h", "user", "active"),
            Err(StoreError::Conflict)
        ));
    }

    #[test]
    fn run_round_trip_and_stats() {
        let s = Store::open_in_memory().unwrap();
        let u = s.create_user("bob", "h", "user", "active").unwrap();
        s.create_run(
            "r1",
            u.id,
            "paper.pdf",
            "{}",
            &[("paper.pdf".into(), "pdf".into(), None, None)],
        )
        .unwrap();
        let refs = vec![
            NewRef {
                original_number: 1,
                title: Some("A long enough title here".into()),
                raw_citation: "raw".into(),
                authors: vec!["A".into()],
                doi: None,
                arxiv_id: None,
                urls: vec![],
                skip_reason: None,
                origin: "pdf".into(),
            },
            NewRef {
                original_number: 2,
                title: None,
                raw_citation: "raw2".into(),
                authors: vec![],
                doi: None,
                arxiv_id: None,
                urls: vec![],
                skip_reason: Some("no_title".into()),
                origin: "pdf".into(),
            },
        ];
        s.set_paper_extraction("r1", 0, "pdf", "{}", None, &refs)
            .unwrap();
        s.set_ref_result(
            "r1",
            0,
            0,
            &ResultUpdate {
                result_json: "{}",
                verdict: "not_found",
                mismatch_flags: 0,
                retracted: false,
            },
        )
        .unwrap();
        let stats = s.run_stats(&["r1".to_string()]).unwrap();
        let st = &stats["r1"];
        assert_eq!(
            (st.total, st.not_found, st.skipped, st.problems),
            (2, 1, 1, 1)
        );
        assert!(s.set_ref_fp("r1", 0, 0, Some("known_good")).unwrap());
        let stats = s.run_stats(&["r1".to_string()]).unwrap();
        assert_eq!(stats["r1"].problems, 0);
        assert_eq!(s.marked_safe().unwrap().len(), 1);
        let (total, runs) = s.list_runs(Some(u.id), Some("paper"), None, 10, 0).unwrap();
        assert_eq!((total, runs.len()), (1, 1));
        let (total, _) = s
            .list_runs(Some(u.id), Some("nomatch"), None, 10, 0)
            .unwrap();
        assert_eq!(total, 0);
        s.delete_run("r1").unwrap();
        assert!(s.load_papers("r1").unwrap().is_empty());
    }
}
