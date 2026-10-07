//! hallucinator-webapp — multi-user web interface for the hallucinated
//! reference detector. See README.md in this crate.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;

mod api;
mod auth;
mod export;
mod inputs;
mod jobs;
mod model;
mod refdb;
mod runs;
mod state;
mod store;

use state::{AppState, Settings, SignupMode};

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

    /// Who may create accounts. The very first account is always allowed
    /// and becomes the administrator.
    #[arg(
        long,
        env = "HALLUCINATOR_WEB_SIGNUP",
        value_enum,
        default_value = "approval",
        global = true
    )]
    signup: SignupMode,

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
                Ok(u) => println!("Created {} '{}' (id {}).", u.role, u.username, u.id),
                Err(store::StoreError::Conflict) => anyhow::bail!("username already exists"),
                Err(store::StoreError::Other(e)) => return Err(e),
            }
            return Ok(());
        }
        Some(Command::ResetPassword { username }) => {
            let a = store
                .user_auth_by_name(&username)?
                .ok_or_else(|| anyhow::anyhow!("no such user"))?;
            let pw = read_password()?;
            auth::validate_password(&pw).map_err(|e| anyhow::anyhow!(e))?;
            store.set_password(a.user.id, &auth::hash_password(&pw)?)?;
            store.unlock_user(a.user.id)?;
            store.delete_user_sessions(a.user.id, None)?;
            println!("Password reset for '{}'.", a.user.username);
            return Ok(());
        }
        Some(Command::Serve) | None => {}
    }

    store.mark_interrupted()?;
    store.purge(30 * 86400)?;

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
        signup: cli.signup,
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
    });

    // Hourly housekeeping: expired sessions, stale IP blocks, old audit rows.
    {
        let store = store.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                tick.tick().await;
                if let Err(e) = store.purge(30 * 86400) {
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
            "no accounts yet — open the web UI and create the first account (it becomes the administrator)"
        );
    }

    let app = api::router(state.clone());
    let listener = tokio::net::TcpListener::bind(cli.bind).await?;
    tracing::info!("listening on http://{}", cli.bind);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
        shutdown.cancel();
    })
    .await?;
    Ok(())
}
