use std::path::PathBuf;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::auth::LoginPolicy;
use crate::jobs::JobManager;
use crate::refdb::RefDbRegistry;
use crate::runs::RunManager;
use crate::store::Store;

#[derive(Debug, Clone)]
pub struct Settings {
    pub data_dir: PathBuf,
    pub secure_cookies: bool,
    pub trust_proxy: bool,
    pub max_concurrent_runs: usize,
    pub max_upload_bytes: usize,
    pub session_ttl_secs: i64,
    /// Serve `static/` from disk instead of the embedded copy (development).
    pub static_dir: Option<PathBuf>,
    pub policy: LoginPolicy,
}

pub struct AppState {
    pub settings: Settings,
    pub store: Arc<Store>,
    pub refdb: Arc<RefDbRegistry>,
    pub runs: Arc<RunManager>,
    pub jobs: Arc<JobManager>,
    /// Cancelled on shutdown so long-lived SSE streams end.
    pub shutdown: CancellationToken,
}
