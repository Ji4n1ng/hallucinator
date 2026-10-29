//! hallucinator-webapp — multi-user web interface for the hallucinated
//! reference detector. See README.md in this crate.

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;

mod api;
mod audit;
mod auth;
mod e2e;
mod export;
mod inputs;
mod jobs;
mod model;
mod refdb;
mod runs;
mod state;
mod store;

use state::{AppState, Settings};

#[derive(Parser, Debug)]
#[command(version, about = "Web interface for hallucinated reference detection")]
struct Cli {
    /// Address to listen on.
    #[arg(
        long,
        env = "HALLUCINATOR_WEB_BIND",
        default_value = "127.0.0.1:5001",
        global = true
    )]
    bind: SocketAddr,

    /// Directory for the web app's own data (accounts, history, query cache).
    /// Default: <data_dir>/hallucinator/webapp (e.g. ~/.local/share/hallucinator/webapp).
    #[arg(long, env = "HALLUCINATOR_WEB_DATA", global = true)]
    data_dir: Option<PathBuf>,

    /// hallucinator config.toml (default: the same auto-detection as the
    /// CLI/TUI — ~/.config/hallucinator/config.toml overlaid by ./.hallucinator.toml).
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Mark the session cookie `Secure` (set when served over HTTPS).
    #[arg(long, env = "HALLUCINATOR_WEB_SECURE_COOKIES", global = true)]
    secure_cookies: bool,

    /// Trust X-Forwarded-For / X-Real-IP for the client address (only
    /// behind a reverse proxy you control — otherwise clients can spoof it
    /// to dodge sign-in rate limits).
    #[arg(long, env = "HALLUCINATOR_WEB_TRUST_PROXY", global = true)]
    trust_proxy: bool,

    /// Path to the hallucinator-cli binary used for database updates.
    #[arg(long, env = "HALLUCINATOR_CLI", global = true)]
    cli_path: Option<PathBuf>,

    /// Runs checked at the same time; further runs wait in a queue.
    #[arg(long, default_value_t = 2, global = true)]
    max_concurrent_runs: usize,

    /// Maximum upload size per check, in MiB.
    #[arg(long, default_value_t = 200, global = true)]
    max_upload_mb: usize,

    /// Session lifetime in hours.
    #[arg(long, default_value_t = 168, global = true)]
    session_hours: i64,

    /// Days after which an offline database is flagged stale.
    #[arg(long, default_value_t = 30, global = true)]
    stale_after_days: u64,

    /// Serve the UI from this directory instead of the embedded copy
    /// (for editing static/ without recompiling).
    #[arg(long, env = "HALLUCINATOR_WEB_STATIC_DIR", global = true)]
    static_dir: Option<PathBuf>,

    /// File with the end-to-end encryption key (`cek1_…`, mode 600). When
    /// set, every API call and sign-in must come through the tunnel
    /// (`POST /api/e2e`); plain ones get HTTP 400 `"e2e": "required"`.
    /// Make one with `e2e-key new <path>`.
    #[arg(long, env = "HALLUCINATOR_E2E_KEY_FILE", global = true)]
    e2e_key_file: Option<PathBuf>,

    /// The previous key during a rotation (mode 600). Clients that still use
    /// it are served, and told to change (`"rotate": true`).
    #[arg(long, env = "HALLUCINATOR_E2E_KEY_PREVIOUS_FILE", global = true)]
    e2e_key_previous_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the web server (default).
    Serve,
    /// Create an account from the command line (password read from the
    /// HALLUCINATOR_WEB_PASSWORD env var, or prompted on stdin).
    CreateUser {
        #[arg(long)]
        username: String,
        #[arg(long)]
        admin: bool,
    },
    /// Reset a password and clear any lockout.
    ResetPassword {
        #[arg(long)]
        username: String,
    },
    /// Create an API token for scripts and agents and print it (it is
    /// shown only once). It acts with the account's permissions.
    CreateToken {
        #[arg(long)]
        username: String,
        /// A label to tell tokens apart, e.g. "claude skill".
        #[arg(long)]
        name: String,
        /// Days until the token expires (default: never).
        #[arg(long)]
        expires_days: Option<i64>,
    },
    /// Agent accounts for Catelier agents (kind `agent`, never admins) and
    /// their tokens. A token is written only to standard output, which must
    /// be a pipe: `agent issue Frieren | catelier-admin tool token hallucinator Frieren`.
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// End-to-end encryption keys.
    E2eKey {
        #[command(subcommand)]
        action: E2eKeyAction,
    },
}

#[derive(Subcommand, Debug)]
enum AgentAction {
    /// Create agent accounts: role `user`, kind `agent`, no password (they
    /// sign in only with their token). Existing agent accounts are kept.
    Add {
        #[arg(required = true)]
        names: Vec<String>,
    },
    /// List the agent accounts and their tokens (never the secrets).
    List,
    /// Issue a token for an agent that has none, to standard output.
    Issue {
        name: String,
        /// Days until the token expires (default: never).
        #[arg(long)]
        expires_days: Option<i64>,
    },
    /// Issue a new token to standard output and revoke the agent's old ones.
    Rotate {
        name: String,
        #[arg(long)]
        expires_days: Option<i64>,
    },
    /// Revoke every token of the agent. It works at once, with no restart.
    Revoke { name: String },
}

#[derive(Subcommand, Debug)]
enum E2eKeyAction {
    /// Write a new random key to PATH (mode 600; never printed) and print its key id.
    New { path: PathBuf },
    /// Print the key id of the key in PATH (as `GET /api/health` lists it).
    Kid { path: PathBuf },
}

/// The label of tokens made by `agent issue` and `agent rotate`.
const AGENT_TOKEN_NAME: &str = "catelier";

fn expires_at(days: Option<i64>) -> anyhow::Result<Option<i64>> {
    match days {
        Some(d) if d < 1 => anyhow::bail!("--expires-days must be at least 1"),
        Some(d) => Ok(Some(store::now() + d * 86400)),
        None => Ok(None),
    }
}

fn agent_account(store: &store::Store, name: &str) -> anyhow::Result<store::User> {
    let a = store
        .user_auth_by_name(name)?
        .ok_or_else(|| anyhow::anyhow!("no account '{name}'; create it with `agent add {name}`"))?;
    if !a.user.is_agent() {
        anyhow::bail!(
            "'{}' is a person's account, not an agent's",
            a.user.username
        );
    }
    Ok(a.user)
}

/// Record an account or token change made on the command line in the audit log.
fn audit_command(
    store: &store::Store,
    user: &store::User,
    command: &str,
    detail: &str,
) -> anyhow::Result<()> {
    store.add_audit(&store::NewAudit {
        username: Some(&user.username),
        kind: &user.kind,
        method: "CLI",
        path: command,
        status: 0,
        ip: "local",
        via: "cli",
        sealed: false,
        detail: Some(detail),
    })?;
    Ok(())
}

/// Record an agent token change from the command line in the audit log.
fn audit_cli(
    store: &store::Store,
    user: &store::User,
    action: &str,
    detail: &str,
) -> anyhow::Result<()> {
    store.add_audit(&store::NewAudit {
        username: Some(&user.username),
        kind: &user.kind,
        method: "CLI",
        path: &format!("agent {action}"),
        status: 0,
        ip: "local",
        via: "cli",
        sealed: false,
        detail: Some(detail),
    })?;
    store.add_auth_event(
        "cli",
        Some(&user.username),
        &format!("token_{action}"),
        Some(detail),
    )?;
    Ok(())
}

fn run_agent(store: &store::Store, action: AgentAction) -> anyhow::Result<()> {
    let issue = |name: &str, days: Option<i64>, rotate: bool| -> anyhow::Result<()> {
        if std::io::stdout().is_terminal() {
            anyhow::bail!(
                "standard output is a terminal, and a token must not be shown. Pipe it, e.g. \
                 `hallucinator-webapp agent {} {name} | catelier-admin tool token hallucinator {name}`",
                if rotate { "rotate" } else { "issue" }
            );
        }
        let user = agent_account(store, name)?;
        let expires = expires_at(days)?;
        let existing = store.count_api_tokens(user.id)?;
        if !rotate && existing > 0 {
            anyhow::bail!(
                "{} already has {existing} token(s); use `agent rotate {}` to replace them",
                user.username,
                user.username
            );
        }
        let (secret, token) = auth::issue_api_token(store, user.id, AGENT_TOKEN_NAME, expires)?;
        let revoked = if rotate {
            store.delete_user_tokens(user.id, Some(token.id))?
        } else {
            0
        };
        let action = if rotate { "rotate" } else { "issue" };
        audit_cli(
            store,
            &user,
            action,
            &format!("token {}… issued, {revoked} revoked", token.prefix),
        )?;
        println!("{secret}");
        eprintln!(
            "{} a token for agent {} ({}…){}.",
            if rotate { "Rotated" } else { "Issued" },
            user.username,
            token.prefix,
            if rotate {
                format!("; revoked {revoked} old token(s)")
            } else {
                String::new()
            }
        );
        Ok(())
    };
    match action {
        AgentAction::Add { names } => {
            for name in names {
                auth::validate_username(&name).map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
                match store.user_auth_by_name(&name)? {
                    Some(a) if a.user.is_agent() => {
                        println!("Agent {} exists (id {}).", a.user.username, a.user.id)
                    }
                    Some(a) => anyhow::bail!(
                        "'{}' is a person's account, not an agent's",
                        a.user.username
                    ),
                    None => {
                        let u = store.create_agent(&name).map_err(|e| match e {
                            store::StoreError::Conflict => anyhow::anyhow!("'{name}' exists"),
                            store::StoreError::Other(e) => e,
                        })?;
                        println!("Created agent {} (id {}).", u.username, u.id);
                    }
                }
            }
        }
        AgentAction::List => {
            let tokens = store.list_api_tokens(None)?;
            for u in store
                .list_users()?
                .into_iter()
                .map(|a| a.user)
                .filter(|u| u.is_agent())
            {
                let mine: Vec<String> = tokens
                    .iter()
                    .filter(|t| t.user_id == u.id)
                    .map(|t| format!("{}… ({})", t.prefix, t.name))
                    .collect();
                println!(
                    "{:<12} {:<8} {:<8} tokens: {}",
                    u.username,
                    u.role,
                    u.status,
                    if mine.is_empty() {
                        "none".to_string()
                    } else {
                        mine.join(", ")
                    }
                );
            }
        }
        AgentAction::Issue { name, expires_days } => issue(&name, expires_days, false)?,
        AgentAction::Rotate { name, expires_days } => issue(&name, expires_days, true)?,
        AgentAction::Revoke { name } => {
            let user = agent_account(store, &name)?;
            let n = store.delete_user_tokens(user.id, None)?;
            audit_cli(store, &user, "revoke", &format!("{n} token(s) revoked"))?;
            println!("Revoked {n} token(s) of agent {}.", user.username);
        }
    }
    Ok(())
}

/// The keyring from the key files, or `None` when no key file is set.
fn load_keyring(
    key_file: Option<&PathBuf>,
    previous_file: Option<&PathBuf>,
    max_upload_bytes: usize,
) -> anyhow::Result<Option<Arc<e2e::Keyring>>> {
    let Some(path) = key_file else {
        if previous_file.is_some() {
            anyhow::bail!("--e2e-key-previous-file is set, but there is no --e2e-key-file");
        }
        return Ok(None);
    };
    let current = e2e::read_key_file(path, "the E2E key file")?;
    let previous = match previous_file {
        Some(p) => Some(e2e::read_key_file(p, "the previous E2E key file")?),
        None => None,
    };
    // Room for a few of the largest uploads at once (each counts twice).
    let keyring = e2e::Keyring::new(current, previous).with_budget(6 * max_upload_bytes);
    Ok(Some(Arc::new(keyring)))
}

fn read_password() -> anyhow::Result<String> {
    if let Ok(p) = std::env::var("HALLUCINATOR_WEB_PASSWORD") {
        return Ok(p);
    }
    eprint!("Password: ");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,hallucinator_core=warn".into()),
        )
        .init();
    let cli = Cli::parse();

    let data_dir = cli
        .data_dir
        .clone()
        .unwrap_or_else(|| refdb::shared_data_dir().join("webapp"));
    std::fs::create_dir_all(&data_dir)?;
    let store = Arc::new(store::Store::open(&data_dir.join("webapp.db"))?);

    match cli.command {
        Some(Command::CreateUser { username, admin }) => {
            auth::validate_username(&username).map_err(|e| anyhow::anyhow!(e))?;
            let pw = read_password()?;
            auth::validate_password(&pw).map_err(|e| anyhow::anyhow!(e))?;
            let role = if admin { "admin" } else { "user" };
            match store.create_user(&username, &auth::hash_password(&pw)?, role, "active") {
                Ok(u) => {
                    audit_command(&store, &u, "create-user", &format!("role {}", u.role))?;
                    println!("Created {} '{}' (id {}).", u.role, u.username, u.id)
                }
                Err(store::StoreError::Conflict) => anyhow::bail!("username already exists"),
                Err(store::StoreError::Other(e)) => return Err(e),
            }
            return Ok(());
        }
        Some(Command::ResetPassword { username }) => {
            let a = store
                .user_auth_by_name(&username)?
                .ok_or_else(|| anyhow::anyhow!("no such user"))?;
            if a.user.is_agent() {
                anyhow::bail!("{} is an agent: agents have no password", a.user.username);
            }
            let pw = read_password()?;
            auth::validate_password(&pw).map_err(|e| anyhow::anyhow!(e))?;
            store.set_password(a.user.id, &auth::hash_password(&pw)?)?;
            store.unlock_user(a.user.id)?;
            store.delete_user_sessions(a.user.id, None)?;
            audit_command(
                &store,
                &a.user,
                "reset-password",
                "password reset, lockout cleared",
            )?;
            println!("Password reset for '{}'.", a.user.username);
            return Ok(());
        }
        Some(Command::CreateToken {
            username,
            name,
            expires_days,
        }) => {
            let a = store
                .user_auth_by_name(&username)?
                .ok_or_else(|| anyhow::anyhow!("no such user"))?;
            let name = name.trim();
            auth::validate_token_name(name).map_err(|e| anyhow::anyhow!(e))?;
            if a.user.is_agent() {
                anyhow::bail!(
                    "{} is an agent: use `agent issue` or `agent rotate`",
                    a.user.username
                );
            }
            let (secret, token) =
                auth::issue_api_token(&store, a.user.id, name, expires_at(expires_days)?)?;
            store.add_auth_event(
                "cli",
                Some(&a.user.username),
                "token_create",
                Some(&format!("{} ({}…)", token.name, token.prefix)),
            )?;
            audit_command(
                &store,
                &a.user,
                "create-token",
                &format!("token {} ({}…)", token.name, token.prefix),
            )?;
            eprintln!(
                "Created API token '{}' for {} '{}'. It is shown only once:",
                token.name, a.user.role, a.user.username
            );
            println!("{secret}");
            return Ok(());
        }
        Some(Command::Agent { action }) => return run_agent(&store, action),
        Some(Command::E2eKey { action }) => {
            let key = match action {
                E2eKeyAction::New { path } => {
                    let k = e2e::write_new_key(&path)?;
                    eprintln!("Wrote a new key to {} (mode 600).", path.display());
                    k
                }
                E2eKeyAction::Kid { path } => e2e::read_key_file(&path, "the key file")?,
            };
            println!("{}", e2e::hex(&key.kid));
            return Ok(());
        }
        Some(Command::Serve) | None => {}
    }

    let e2e_keys = load_keyring(
        cli.e2e_key_file.as_ref(),
        cli.e2e_key_previous_file.as_ref(),
        cli.max_upload_mb.max(1) * 1024 * 1024,
    )?;
    match &e2e_keys {
        Some(k) => tracing::info!(kids = ?k.kids(), "end-to-end encryption is required"),
        None => tracing::warn!(
            "end-to-end encryption is off (no --e2e-key-file): API calls and sign-ins go plain"
        ),
    }

    store.mark_interrupted()?;
    store.purge(audit::RETENTION_SECS, audit::RETENTION_SECS)?;

    // Same config resolution as hallucinator-cli.
    let (file_config, config_path) = match &cli.config {
        Some(p) => (
            hallucinator_core::config_file::load_from_path(p)
                .ok_or_else(|| anyhow::anyhow!("cannot read config file {}", p.display()))?,
            Some(p.clone()),
        ),
        None => {
            let platform = hallucinator_core::config_file::config_path().filter(|p| p.exists());
            let cwd = PathBuf::from(".hallucinator.toml");
            let source = if cwd.exists() { Some(cwd) } else { platform };
            (hallucinator_core::config_file::load_config(), source)
        }
    };
    match &config_path {
        Some(p) => tracing::info!(path = %p.display(), "using hallucinator config"),
        None => tracing::info!("no hallucinator config file found; using defaults"),
    }

    let refdb_reg = {
        let cache = data_dir.join("query-cache.db");
        let stale = cli.stale_after_days;
        let cp = config_path.clone();
        Arc::new(
            tokio::task::spawn_blocking(move || {
                refdb::RefDbRegistry::new(file_config, cp, cache, stale)
            })
            .await?,
        )
    };

    let cli_info = jobs::discover_cli(cli.cli_path.clone()).await;
    match &cli_info {
        Some(c) => tracing::info!(
            path = %c.path.display(),
            venues = c.venues.len(),
            "found hallucinator-cli for database updates"
        ),
        None => tracing::warn!(
            "hallucinator-cli not found; database updates are disabled \
             (build it with `cargo build --release -p hallucinator-cli` in hallucinator-rs/)"
        ),
    }

    let settings = Settings {
        data_dir: data_dir.clone(),
        secure_cookies: cli.secure_cookies,
        trust_proxy: cli.trust_proxy,
        max_concurrent_runs: cli.max_concurrent_runs,
        max_upload_bytes: cli.max_upload_mb.max(1) * 1024 * 1024,
        session_ttl_secs: cli.session_hours.max(1) * 3600,
        static_dir: cli.static_dir.clone(),
        policy: auth::LoginPolicy::default(),
    };
    let runs = Arc::new(runs::RunManager::new(
        store.clone(),
        refdb_reg.clone(),
        settings.max_concurrent_runs,
    ));
    let jobs_mgr = Arc::new(jobs::JobManager::new(
        store.clone(),
        refdb_reg.clone(),
        cli_info,
    ));
    let shutdown = CancellationToken::new();
    let state = Arc::new(AppState {
        settings,
        store: store.clone(),
        refdb: refdb_reg,
        runs,
        jobs: jobs_mgr,
        shutdown: shutdown.clone(),
        e2e: e2e_keys,
    });

    // Hourly housekeeping: expired sessions, stale IP blocks, old audit rows.
    {
        let store = store.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                tick.tick().await;
                if let Err(e) = store.purge(audit::RETENTION_SECS, audit::RETENTION_SECS) {
                    tracing::warn!(error = %e, "housekeeping failed");
                }
            }
        });
    }
    // Warm the dummy hash so the first failed sign-in is not faster.
    tokio::task::spawn_blocking(|| {
        let _ = auth::dummy_hash();
    });

    if store.count_users()? == 0 {
        tracing::info!(
            "no accounts yet — create the administrator with \
             `hallucinator-webapp create-user --username <name> --admin`"
        );
    }

    let app = api::app(state.clone());
    let listener = tokio::net::TcpListener::bind(cli.bind).await?;
    tracing::info!("listening on http://{}", cli.bind);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        tracing::info!("shutting down");
        shutdown.cancel();
    })
    .await?;
    Ok(())
}

/// Ctrl-C, or SIGTERM from a service manager (`systemctl stop`, `docker stop`).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
                return;
            }
            Err(e) => tracing::warn!(error = %e, "cannot listen for SIGTERM"),
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
