//! Reference-database maintenance jobs.
//!
//! Updates and corpus imports run the upstream `hallucinator-cli` binary as
//! a child process instead of re-implementing its builders, so whatever
//! upstream changes in `update-*` / `import-*` is picked up for free. The
//! available venue importers are discovered from `hallucinator-cli --help`
//! at startup, so new upstream `import-<venue>` subcommands appear in the
//! UI without touching this crate.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::refdb::{DbKey, RefDbRegistry};
use crate::runs::SseMsg;
use crate::store::{JobRow, Store, User, now};

#[derive(Debug, Clone, Serialize)]
pub struct Venue {
    pub key: String,
    pub subcommand: String,
    pub about: String,
    /// "url" (program page fetched live) or "pdf" (front-matter PDF on the server)
    pub input: &'static str,
}

#[derive(Debug, Clone)]
pub struct CliInfo {
    pub path: PathBuf,
    pub version: Option<String>,
    pub venues: Vec<Venue>,
}

const MAX_LOG_BYTES: usize = 2 * 1024 * 1024;

struct LiveJob {
    row: Mutex<JobRow>,
    log: Mutex<String>,
    tx: broadcast::Sender<Arc<SseMsg>>,
    cancel: CancellationToken,
}

impl LiveJob {
    fn send(&self, event: &'static str, data: &impl Serialize) {
        if let Ok(data) = serde_json::to_string(data) {
            let _ = self.tx.send(Arc::new(SseMsg { event, data }));
        }
    }

    fn push_line(&self, line: &str) {
        {
            let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
            log.push_str(line);
            log.push('\n');
            if log.len() > MAX_LOG_BYTES {
                let cut = log.len() - MAX_LOG_BYTES / 2;
                let cut = (cut..log.len())
                    .find(|&i| log.is_char_boundary(i))
                    .unwrap_or(log.len());
                log.replace_range(..cut, "[… earlier output truncated …]\n");
            }
        }
        self.send("line", &json!({ "line": line }));
    }

    fn log(&self) -> String {
        self.log.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn row(&self) -> JobRow {
        self.row.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

pub struct JobManager {
    store: Arc<Store>,
    refdb: Arc<RefDbRegistry>,
    cli: Option<CliInfo>,
    live: Mutex<HashMap<String, Arc<LiveJob>>>,
}

/// What to run: `hallucinator-cli <argv…>` on behalf of `db_key`.
pub struct JobSpec {
    pub db_key: DbKey,
    pub action: &'static str,
    pub label: String,
    pub argv: Vec<String>,
    /// Deleted when the job ends (e.g. a generated input file).
    pub cleanup: Option<PathBuf>,
}

pub enum StartError {
    NoCli,
    Busy,
    Other(anyhow::Error),
}

impl JobManager {
    pub fn new(store: Arc<Store>, refdb: Arc<RefDbRegistry>, cli: Option<CliInfo>) -> Self {
        JobManager {
            store,
            refdb,
            cli,
            live: Mutex::new(HashMap::new()),
        }
    }

    pub fn cli(&self) -> Option<&CliInfo> {
        self.cli.as_ref()
    }

    fn live_map(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<LiveJob>>> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn active_for(&self, db_key: &str) -> Option<JobRow> {
        self.live_map()
            .values()
            .map(|j| j.row())
            .find(|r| r.db_key == db_key)
    }

    /// Current row + log; live jobs come from memory, finished ones from the DB.
    pub fn get(&self, id: &str) -> anyhow::Result<Option<(JobRow, String)>> {
        if let Some(j) = self.live_map().get(id) {
            return Ok(Some((j.row(), j.log())));
        }
        self.store.get_job(id)
    }

    pub fn subscribe(&self, id: &str) -> Option<broadcast::Receiver<Arc<SseMsg>>> {
        self.live_map().get(id).map(|j| j.tx.subscribe())
    }

    pub fn cancel(&self, id: &str) -> bool {
        match self.live_map().get(id) {
            Some(j) => {
                j.cancel.cancel();
                true
            }
            None => false,
        }
    }

    /// Launch a job. At most one job per database runs at a time.
    pub fn start(self: &Arc<Self>, user: &User, spec: JobSpec) -> Result<JobRow, StartError> {
        let JobSpec {
            db_key,
            action,
            label,
            argv,
            cleanup,
        } = spec;
        let cli = self.cli.clone().ok_or(StartError::NoCli)?;
        let row = {
            let mut map = self.live_map();
            if map.values().any(|j| j.row().db_key == db_key.as_str()) {
                return Err(StartError::Busy);
            }
            let row = JobRow {
                id: crate::auth::random_id(),
                user_id: Some(user.id),
                username: Some(user.username.clone()),
                db_key: db_key.as_str().to_string(),
                action: action.to_string(),
                label,
                argv: argv.clone(),
                status: "running".to_string(),
                created_at: now(),
                finished_at: None,
                exit_code: None,
            };
            self.store.create_job(&row).map_err(StartError::Other)?;
            let (tx, _) = broadcast::channel(4096);
            map.insert(
                row.id.clone(),
                Arc::new(LiveJob {
                    row: Mutex::new(row.clone()),
                    log: Mutex::new(String::new()),
                    tx,
                    cancel: CancellationToken::new(),
                }),
            );
            row
        };
        let job = self
            .live_map()
            .get(&row.id)
            .cloned()
            .expect("just inserted");
        let this = self.clone();
        tokio::spawn(async move {
            let (status, code) = this.execute(&cli.path, &argv, &job).await;
            if let Some(p) = cleanup {
                let _ = std::fs::remove_file(p);
            }
            // Pick up the rebuilt database (also after a failure: the CLI
            // may have swapped files before failing late).
            let refdb = this.refdb.clone();
            let _ = tokio::task::spawn_blocking(move || refdb.reload(db_key)).await;
            let log = job.log();
            if let Err(e) = this.store.finish_job(&job.row().id, status, code, &log) {
                tracing::error!(error = %e, "failed to store job result");
            }
            let final_row = {
                let mut r = job.row.lock().unwrap_or_else(|e| e.into_inner());
                r.status = status.to_string();
                r.exit_code = code;
                r.finished_at = Some(now());
                r.clone()
            };
            job.send("status", &json!({ "job": final_row }));
            job.send("end", &json!({}));
            this.live_map().remove(&final_row.id);
        });
        Ok(row)
    }

    async fn execute(
        &self,
        cli: &Path,
        argv: &[String],
        job: &Arc<LiveJob>,
    ) -> (&'static str, Option<i32>) {
        job.push_line(&format!("$ hallucinator-cli {}", argv.join(" ")));
        let mut child = match pty_command(cli, argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("NO_COLOR", "1")
            .kill_on_drop(true)
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                job.push_line(&format!("failed to start {}: {e}", cli.display()));
                return ("failed", None);
            }
        };
        let out = child
            .stdout
            .take()
            .map(|s| tokio::spawn(pump(s, job.clone())));
        let err = child
            .stderr
            .take()
            .map(|s| tokio::spawn(pump(s, job.clone())));

        // Persist the log periodically so a crash keeps most of it.
        let flusher = {
            let job = job.clone();
            let store = self.store.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(5));
                loop {
                    tick.tick().await;
                    let _ = store.save_job_log(&job.row().id, &job.log());
                }
            })
        };

        let result = tokio::select! {
            s = child.wait() => match s {
                Ok(s) if s.success() => ("succeeded", s.code()),
                Ok(s) => ("failed", s.code()),
                Err(e) => {
                    job.push_line(&format!("wait failed: {e}"));
                    ("failed", None)
                }
            },
            _ = job.cancel.cancelled() => {
                let _ = child.kill().await;
                job.push_line("cancelled by user");
                ("cancelled", None)
            }
        };
        for h in [out, err].into_iter().flatten() {
            let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
        }
        flusher.abort();
        job.push_line(&format!("[{}]", result.0));
        result
    }
}

fn shell_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', r"'\''"))
}

/// The CLI reports progress only through `indicatif` bars, which stay
/// silent unless attached to a terminal. Run it under a pseudo-terminal via
/// the system `script(1)` utility when available so the job log shows that
/// progress; otherwise spawn it directly.
fn pty_command(cli: &Path, argv: &[String]) -> tokio::process::Command {
    let script = Path::new("/usr/bin/script");
    if script.is_file() && cfg!(target_os = "linux") {
        // util-linux takes the command as one shell string, so every
        // argument is quoted (they are validated too, but never trust that).
        let line = std::iter::once(cli.display().to_string())
            .chain(argv.iter().cloned())
            .map(|a| shell_quote(&a))
            .collect::<Vec<_>>()
            .join(" ");
        let mut c = tokio::process::Command::new(script);
        c.args(["-q", "-f", "-e", "-c", &line, "/dev/null"])
            .env("COLUMNS", "120")
            .env("TERM", "xterm");
        return c;
    }
    if script.is_file() && cfg!(target_os = "macos") {
        // BSD script takes the command as plain argv.
        let mut c = tokio::process::Command::new(script);
        c.args(["-q", "/dev/null"])
            .arg(cli)
            .args(argv)
            .env("COLUMNS", "120")
            .env("TERM", "xterm");
        return c;
    }
    let mut c = tokio::process::Command::new(cli);
    c.args(argv);
    c
}

/// Forward a child's output to the job log. Lines end at `\n`; progress
/// bars redraw in place with `\r`, so those redraws are logged at most once
/// a second (plus the last state before the next real line).
async fn pump(stream: impl AsyncRead + Unpin, job: Arc<LiveJob>) {
    let mut reader = BufReader::new(stream);
    let mut chunk = vec![0u8; 8192];
    let mut current: Vec<u8> = Vec::new();
    let mut progress: Option<String> = None;
    let mut last_progress: Option<std::time::Instant> = None;
    let clean = |bytes: &[u8]| strip_ansi(String::from_utf8_lossy(bytes).trim_end());
    loop {
        let n = match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        for &b in &chunk[..n] {
            match b {
                b'\n' => {
                    let line = clean(&current);
                    current.clear();
                    if !line.trim().is_empty() {
                        job.push_line(&line);
                        progress = None;
                    } else if let Some(p) = progress.take() {
                        job.push_line(&p);
                    }
                }
                b'\r' => {
                    let line = clean(&current);
                    current.clear();
                    if line.trim().is_empty() {
                        continue;
                    }
                    if last_progress.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
                        job.push_line(&line);
                        last_progress = Some(std::time::Instant::now());
                        progress = None;
                    } else {
                        progress = Some(line);
                    }
                }
                _ => current.push(b),
            }
        }
    }
    let line = clean(&current);
    if !line.trim().is_empty() {
        job.push_line(&line);
    } else if let Some(p) = progress {
        job.push_line(&p);
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for c2 in chars.by_ref() {
                    if c2.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

// ── CLI discovery ──────────────────────────────────────────────────────

async fn run_capture(cli: &Path, args: &[&str]) -> Option<String> {
    let fut = tokio::process::Command::new(cli)
        .args(args)
        .stdin(Stdio::null())
        .env("NO_COLOR", "1")
        .output();
    let out = tokio::time::timeout(Duration::from_secs(15), fut)
        .await
        .ok()?
        .ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(text)
}

fn candidates(explicit: Option<PathBuf>) -> Vec<PathBuf> {
    let mut c = Vec::new();
    c.extend(explicit);
    if let Ok(p) = std::env::var("HALLUCINATOR_CLI") {
        c.push(PathBuf::from(p));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        c.push(dir.join("hallucinator-cli"));
    }
    // This crate lives at hallucinator-rs/crates/hallucinator-webapp; the
    // upstream workspace builds the CLI into hallucinator-rs/target/.
    let ws = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    c.push(ws.join("target/release/hallucinator-cli"));
    c.push(ws.join("target/debug/hallucinator-cli"));
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            c.push(dir.join("hallucinator-cli"));
        }
    }
    c
}

/// Find a working `hallucinator-cli` and learn which importers it offers.
pub async fn discover_cli(explicit: Option<PathBuf>) -> Option<CliInfo> {
    let mut found = None;
    for path in candidates(explicit) {
        if !path.is_file() {
            continue;
        }
        if let Some(v) = run_capture(&path, &["--version"]).await
            && v.contains("hallucinator")
        {
            let path = std::fs::canonicalize(&path).unwrap_or(path);
            found = Some((path, v.trim().rsplit(' ').next().map(String::from)));
            break;
        }
    }
    let (path, version) = found?;
    let help = run_capture(&path, &["--help"]).await.unwrap_or_default();
    let mut venues = Vec::new();
    for (sub, about) in parse_subcommands(&help) {
        let Some(key) = sub.strip_prefix("import-") else {
            continue;
        };
        if key == "corpus-reports" {
            continue;
        }
        let sub_help = run_capture(&path, &[&sub, "--help"])
            .await
            .unwrap_or_default();
        let input = if sub_help.contains("--url") {
            "url"
        } else if sub_help.contains("--pdf-path") {
            "pdf"
        } else {
            continue;
        };
        venues.push(Venue {
            key: key.to_string(),
            subcommand: sub.clone(),
            about,
            input,
        });
    }
    Some(CliInfo {
        path,
        version,
        venues,
    })
}

/// Parse clap's "Commands:" section into (name, about) pairs.
pub fn parse_subcommands(help: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut in_commands = false;
    for line in help.lines() {
        if line.trim_end() == "Commands:" {
            in_commands = true;
            continue;
        }
        if !in_commands {
            continue;
        }
        if !line.starts_with("  ") {
            if !line.trim().is_empty() {
                break;
            }
            continue;
        }
        let trimmed = line.trim_start();
        let (name, about) = match trimmed.split_once(char::is_whitespace) {
            Some((n, a)) => (n, a.trim()),
            None => (trimmed, ""),
        };
        if name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit())
        {
            out.push((name.to_string(), about.to_string()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clap_help() {
        let help = "Detect things\n\nUsage: hallucinator-cli [OPTIONS] <COMMAND>\n\nCommands:\n  check                  Check a PDF\n  import-ndss            Import an NDSS accepted-papers page into the local corpus\n  help                   Print this message\n\nOptions:\n  --config <CONFIG>  Path\n";
        let subs = parse_subcommands(help);
        assert_eq!(subs.len(), 3);
        assert_eq!(subs[1].0, "import-ndss");
        assert!(subs[1].1.starts_with("Import an NDSS"));
    }

    #[test]
    fn quotes_for_the_shell() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn strips_ansi() {
        assert_eq!(strip_ansi("\u{1b}[33mWarn\u{1b}[0m ok"), "Warn ok");
    }
}
