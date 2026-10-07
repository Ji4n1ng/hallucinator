//! Offline reference databases: where they live, whether they are loaded,
//! how fresh they are, and the `hallucinator_core::Config` built on top.
//!
//! Path resolution follows the CLI/TUI conventions so the web app shares the
//! same setup (`~/.config/hallucinator/config.toml` and
//! `~/.local/share/hallucinator/*.db`): env var > config file > auto-detect
//! (`./<file>`, then `<data_dir>/hallucinator/<file>`) > default build target.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use hallucinator_core::config_file::ConfigFile;
use hallucinator_core::{Config, QueryCache, RateLimiters};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DbKey {
    Dblp,
    Acl,
    Arxiv,
    Iacr,
    OpenAlex,
    Corpus,
}

pub const ALL_KEYS: [DbKey; 6] = [
    DbKey::Dblp,
    DbKey::Acl,
    DbKey::Arxiv,
    DbKey::Iacr,
    DbKey::OpenAlex,
    DbKey::Corpus,
];

#[derive(Debug, Clone, Serialize)]
pub struct UpdateParam {
    pub name: &'static str,
    pub label: &'static str,
    /// "path" (absolute server path), "date" (YYYY-MM-DD), "number", "text", "bool"
    pub kind: &'static str,
    pub required: bool,
}

pub struct DbSpec {
    pub key: DbKey,
    pub label: &'static str,
    /// Name used in `Config::disabled_dbs` / the orchestrator.
    pub backend_name: &'static str,
    pub description: &'static str,
    pub file_name: &'static str,
    pub env_var: &'static str,
    /// `hallucinator-cli` subcommand that (re)builds it, if any.
    pub update_subcommand: Option<&'static str>,
    pub notes: &'static str,
    pub params: &'static [UpdateParam],
}

pub const SPECS: &[DbSpec] = &[
    DbSpec {
        key: DbKey::Dblp,
        label: "DBLP",
        backend_name: "DBLP",
        description: "Computer-science bibliography — offline SQLite + FTS5 index.",
        file_name: "dblp.db",
        env_var: "DBLP_OFFLINE_PATH",
        update_subcommand: Some("update-dblp"),
        notes: "Downloads ~4.6 GB from dblp.org and rebuilds the index (can take an hour). \
                If dblp.org's bot protection blocks the download, save dblp.xml.gz from a \
                browser and pass it as a local file.",
        params: &[UpdateParam {
            name: "from_file",
            label: "Build from a local dblp.xml.gz (server path)",
            kind: "path",
            required: false,
        }],
    },
    DbSpec {
        key: DbKey::Acl,
        label: "ACL Anthology",
        backend_name: "ACL Anthology",
        description: "Computational-linguistics papers — offline SQLite + FTS5 index.",
        file_name: "acl.db",
        env_var: "ACL_OFFLINE_PATH",
        update_subcommand: Some("update-acl"),
        notes: "Downloads the ACL Anthology metadata from GitHub (a few minutes).",
        params: &[],
    },
    DbSpec {
        key: DbKey::Arxiv,
        label: "arXiv",
        backend_name: "arXiv",
        description: "arXiv metadata snapshot (Kaggle) — offline SQLite + FTS5 index.",
        file_name: "arxiv.db",
        env_var: "ARXIV_OFFLINE_PATH",
        update_subcommand: Some("update-arxiv"),
        notes: "Downloads the ~4 GB Kaggle snapshot; needs a Kaggle API token on the server \
                (KAGGLE_API_TOKEN or ~/.kaggle/access_token). Alternatively point at an \
                already-downloaded dump.",
        params: &[UpdateParam {
            name: "dump",
            label: "Use a downloaded Kaggle zip / JSON dump (server path)",
            kind: "path",
            required: false,
        }],
    },
    DbSpec {
        key: DbKey::Iacr,
        label: "IACR ePrint",
        backend_name: "IACR ePrint",
        description: "Cryptology ePrint Archive harvested over OAI-PMH — offline only.",
        file_name: "iacr.db",
        env_var: "IACR_EPRINT_OFFLINE_PATH",
        update_subcommand: Some("update-iacr-eprint"),
        notes: "Incremental: only fetches records newer than the last harvest (minutes).",
        params: &[],
    },
    DbSpec {
        key: DbKey::OpenAlex,
        label: "OpenAlex",
        backend_name: "OpenAlex",
        description: "OpenAlex works — offline Tantivy index (replaces the online API).",
        file_name: "openalex.idx",
        env_var: "OPENALEX_OFFLINE_PATH",
        update_subcommand: Some("update-openalex"),
        notes: "Very large download from the OpenAlex S3 snapshot. Use a minimum year to \
                limit the index size.",
        params: &[
            UpdateParam {
                name: "since",
                label: "Only partitions newer than (YYYY-MM-DD)",
                kind: "date",
                required: false,
            },
            UpdateParam {
                name: "min_year",
                label: "Only works published in or after year",
                kind: "number",
                required: false,
            },
        ],
    },
    DbSpec {
        key: DbKey::Corpus,
        label: "Local Corpus",
        backend_name: "Local Corpus",
        description: "Recent conference proceedings not yet indexed elsewhere, plus references \
                      marked safe during review — fuzzy-matched, offline only.",
        file_name: "local-corpus.db",
        env_var: "LOCAL_CORPUS_PATH",
        update_subcommand: None,
        notes: "Grown incrementally by importing venue program pages or marked-safe \
                references; each import dedupes against existing records.",
        params: &[],
    },
];

pub fn spec(key: DbKey) -> &'static DbSpec {
    SPECS
        .iter()
        .find(|s| s.key == key)
        .expect("spec for every key")
}

pub fn parse_key(s: &str) -> Option<DbKey> {
    ALL_KEYS.into_iter().find(|k| k.as_str() == s)
}

impl DbKey {
    pub fn as_str(self) -> &'static str {
        match self {
            DbKey::Dblp => "dblp",
            DbKey::Acl => "acl",
            DbKey::Arxiv => "arxiv",
            DbKey::Iacr => "iacr",
            DbKey::OpenAlex => "openalex",
            DbKey::Corpus => "corpus",
        }
    }
}

fn config_path_for(cfg: &ConfigFile, key: DbKey) -> Option<String> {
    let d = cfg.databases.as_ref()?;
    match key {
        DbKey::Dblp => d.dblp_offline_path.clone(),
        DbKey::Acl => d.acl_offline_path.clone(),
        DbKey::Arxiv => d.arxiv_offline_path.clone(),
        DbKey::Iacr => d.iacr_eprint_offline_path.clone(),
        DbKey::OpenAlex => d.openalex_offline_path.clone(),
        DbKey::Corpus => d.local_corpus_path.clone(),
    }
    .filter(|s| !s.trim().is_empty())
}

pub fn shared_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("hallucinator")
}

/// Where a database is (or would be built), and why.
pub fn resolve_path(cfg: &ConfigFile, key: DbKey) -> (PathBuf, &'static str) {
    let sp = spec(key);
    if let Ok(v) = std::env::var(sp.env_var)
        && !v.trim().is_empty()
    {
        return (PathBuf::from(v), "env");
    }
    if let Some(p) = config_path_for(cfg, key) {
        return (PathBuf::from(p), "config");
    }
    let candidates = [
        PathBuf::from(sp.file_name),
        shared_data_dir().join(sp.file_name),
    ];
    for c in &candidates {
        if c.exists() {
            let abs = std::fs::canonicalize(c).unwrap_or_else(|_| c.clone());
            return (abs, "auto");
        }
    }
    (shared_data_dir().join(sp.file_name), "default")
}

#[derive(Default)]
struct Pools {
    dblp: Option<Arc<hallucinator_dblp::DblpPool>>,
    acl: Option<Arc<hallucinator_acl::AclPool>>,
    arxiv: Option<Arc<hallucinator_arxiv_offline::ArxivPool>>,
    iacr: Option<Arc<hallucinator_iacr_eprint::IacrPool>>,
    openalex: Option<Arc<hallucinator_openalex::OpenAlexDatabase>>,
    corpus: Option<Arc<hallucinator_local_corpus::CorpusPool>>,
    paths: HashMap<DbKey, (PathBuf, &'static str)>,
    errors: HashMap<DbKey, String>,
}

impl Pools {
    fn is_loaded(&self, key: DbKey) -> bool {
        match key {
            DbKey::Dblp => self.dblp.is_some(),
            DbKey::Acl => self.acl.is_some(),
            DbKey::Arxiv => self.arxiv.is_some(),
            DbKey::Iacr => self.iacr.is_some(),
            DbKey::OpenAlex => self.openalex.is_some(),
            DbKey::Corpus => self.corpus.is_some(),
        }
    }

    fn clear(&mut self, key: DbKey) {
        match key {
            DbKey::Dblp => self.dblp = None,
            DbKey::Acl => self.acl = None,
            DbKey::Arxiv => self.arxiv = None,
            DbKey::Iacr => self.iacr = None,
            DbKey::OpenAlex => self.openalex = None,
            DbKey::Corpus => self.corpus = None,
        }
    }
}

/// Freshness facts read from a database's own metadata.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Freshness {
    pub build_date: Option<String>,
    pub age_days: Option<u64>,
    pub stale: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecordCount {
    pub label: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceCount {
    pub source: String,
    pub count: i64,
}

pub struct RefDbRegistry {
    file_config: RwLock<ConfigFile>,
    pub config_path: Option<PathBuf>,
    pools: RwLock<Pools>,
    pub num_workers: usize,
    pub stale_after_days: u64,
    pub rate_limiters: Arc<RateLimiters>,
    pub query_cache: Arc<QueryCache>,
    pub cache_path: Option<PathBuf>,
}

/// Turn a stored build date (unix seconds or ISO date) into ISO 8601.
pub fn format_build_date(raw: &str) -> String {
    match raw.trim().parse::<i64>() {
        Ok(secs) => iso_utc(secs),
        Err(_) => raw.trim().to_string(),
    }
}

/// Days since a stored build date (unix seconds or `YYYY-MM-DD…`).
pub fn age_days_of(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    let secs = match raw.parse::<i64>() {
        Ok(secs) => secs,
        Err(_) => {
            let date = raw.get(..10)?;
            let mut it = date.split('-');
            let y: i64 = it.next()?.parse().ok()?;
            let m: i64 = it.next()?.parse().ok()?;
            let d: i64 = it.next()?.parse().ok()?;
            if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
                return None;
            }
            days_from_civil(y, m, d) * 86400
        }
    };
    Some((crate::store::now() - secs).max(0) as u64 / 86400)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn iso_utc(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

impl RefDbRegistry {
    pub fn new(
        file_config: ConfigFile,
        config_path: Option<PathBuf>,
        default_cache_path: PathBuf,
        stale_after_days: u64,
    ) -> Self {
        let num_workers = file_config
            .concurrency
            .as_ref()
            .and_then(|c| c.num_workers)
            .unwrap_or(4)
            .max(1);
        let crossref_mailto = std::env::var("CROSSREF_MAILTO")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                file_config
                    .api_keys
                    .as_ref()
                    .and_then(|a| a.crossref_mailto.clone())
            });
        let s2_key = std::env::var("S2_API_KEY").ok().or_else(|| {
            file_config
                .api_keys
                .as_ref()
                .and_then(|a| a.s2_api_key.clone())
        });
        let rate_limiters = Arc::new(RateLimiters::new(
            crossref_mailto.is_some(),
            s2_key.is_some(),
        ));
        let cache_path = std::env::var("HALLUCINATOR_CACHE_PATH")
            .ok()
            .map(PathBuf::from)
            .or_else(|| {
                file_config
                    .databases
                    .as_ref()
                    .and_then(|d| d.cache_path.as_ref())
                    .map(PathBuf::from)
            })
            .unwrap_or(default_cache_path);
        let query_cache = hallucinator_core::build_query_cache(
            Some(&cache_path),
            hallucinator_core::DEFAULT_POSITIVE_TTL.as_secs(),
            hallucinator_core::DEFAULT_NEGATIVE_TTL.as_secs(),
        );
        let reg = RefDbRegistry {
            file_config: RwLock::new(file_config),
            config_path,
            pools: RwLock::new(Pools::default()),
            num_workers,
            stale_after_days,
            rate_limiters,
            query_cache,
            cache_path: Some(cache_path),
        };
        for key in ALL_KEYS {
            reg.reload(key);
        }
        reg
    }

    pub fn file_config(&self) -> ConfigFile {
        self.file_config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn path_of(&self, key: DbKey) -> (PathBuf, &'static str) {
        let pools = self.pools.read().unwrap_or_else(|e| e.into_inner());
        pools
            .paths
            .get(&key)
            .cloned()
            .unwrap_or_else(|| resolve_path(&self.file_config(), key))
    }

    /// (Re)open one database. Called at startup and after an update job.
    pub fn reload(&self, key: DbKey) {
        let (path, source) = resolve_path(&self.file_config(), key);
        let n = self.num_workers;
        let mut err: Option<String> = None;
        let mut pools = self.pools.write().unwrap_or_else(|e| e.into_inner());
        pools.clear(key);
        pools.errors.remove(&key);
        if path.exists() {
            let r: Result<(), String> = match key {
                DbKey::Dblp => hallucinator_dblp::DblpPool::open_with_size(&path, n)
                    .map(|p| pools.dblp = Some(Arc::new(p)))
                    .map_err(|e| e.to_string()),
                DbKey::Acl => hallucinator_acl::AclPool::open_with_size(&path, n)
                    .map(|p| pools.acl = Some(Arc::new(p)))
                    .map_err(|e| e.to_string()),
                DbKey::Arxiv => hallucinator_arxiv_offline::ArxivPool::open_with_size(&path, n)
                    .map(|p| pools.arxiv = Some(Arc::new(p)))
                    .map_err(|e| e.to_string()),
                DbKey::Iacr => hallucinator_iacr_eprint::IacrPool::open_with_size(&path, n)
                    .map(|p| pools.iacr = Some(Arc::new(p)))
                    .map_err(|e| e.to_string()),
                DbKey::OpenAlex => hallucinator_openalex::OpenAlexDatabase::open(&path)
                    .map(|p| pools.openalex = Some(Arc::new(p)))
                    .map_err(|e| e.to_string()),
                DbKey::Corpus => hallucinator_local_corpus::CorpusPool::open_with_size(&path, n)
                    .map(|p| pools.corpus = Some(Arc::new(p)))
                    .map_err(|e| e.to_string()),
            };
            if let Err(e) = r {
                err = Some(e);
            }
        }
        if let Some(e) = err {
            tracing::warn!(db = key.as_str(), path = %path.display(), error = %e, "failed to open offline database");
            pools.errors.insert(key, e);
        } else if pools.is_loaded(key) {
            tracing::info!(db = key.as_str(), path = %path.display(), "offline database loaded");
        }
        pools.paths.insert(key, (path, source));
    }

    pub fn is_loaded(&self, key: DbKey) -> bool {
        self.pools
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_loaded(key)
    }

    pub fn load_error(&self, key: DbKey) -> Option<String> {
        self.pools
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .errors
            .get(&key)
            .cloned()
    }

    pub fn freshness(&self, key: DbKey) -> Freshness {
        let pools = self.pools.read().unwrap_or_else(|e| e.into_inner());
        let t = self.stale_after_days;
        let r: Option<(Option<String>, Option<u64>, bool)> = match key {
            DbKey::Dblp => pools
                .dblp
                .as_ref()
                .and_then(|p| p.check_staleness(t).ok())
                .map(|s| (s.build_date, s.age_days, s.is_stale)),
            DbKey::Acl => pools
                .acl
                .as_ref()
                .and_then(|p| p.check_staleness(t).ok())
                .map(|s| (s.build_date, s.age_days, s.is_stale)),
            DbKey::Arxiv => pools
                .arxiv
                .as_ref()
                .and_then(|p| p.staleness(t).ok())
                .map(|s| (s.build_date, s.age_days, s.is_stale)),
            DbKey::Iacr => pools
                .iacr
                .as_ref()
                .and_then(|p| p.staleness(t).ok())
                .map(|s| (s.build_date, s.age_days, s.is_stale)),
            DbKey::OpenAlex => pools
                .openalex
                .as_ref()
                .and_then(|p| p.check_staleness(t).ok())
                .map(|s| (s.build_date, s.age_days, s.is_stale)),
            // Grown incrementally, never rebuilt from a dated snapshot.
            DbKey::Corpus => None,
        };
        match r {
            Some((date, age, stale)) => {
                // Prefer our own arithmetic on the raw date: upstream's
                // per-crate age helpers are not all correct (arXiv's ISO-date
                // conversion uses a wrong epoch offset).
                let own = date.as_deref().and_then(age_days_of);
                Freshness {
                    build_date: date.as_deref().map(format_build_date),
                    age_days: own.or(age),
                    stale: own.map(|a| a >= t).unwrap_or(stale),
                }
            }
            None => Freshness::default(),
        }
    }

    /// Record counts from the database's own `metadata` table (`*_count`
    /// keys), read through a separate read-only connection.
    pub fn records(&self, key: DbKey) -> Vec<RecordCount> {
        let (path, _) = self.path_of(key);
        if key == DbKey::OpenAlex || !path.is_file() {
            return vec![];
        }
        if key == DbKey::Corpus {
            let pools = self.pools.read().unwrap_or_else(|e| e.into_inner());
            return pools
                .corpus
                .as_ref()
                .and_then(|c| c.total_count().ok())
                .map(|n| {
                    vec![RecordCount {
                        label: "publications".into(),
                        count: n,
                    }]
                })
                .unwrap_or_default();
        }
        let Ok(conn) = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) else {
            return vec![];
        };
        let Ok(mut stmt) = conn.prepare("SELECT key, value FROM metadata ORDER BY key") else {
            return vec![];
        };
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
            })
            .map(|it| it.flatten().collect::<Vec<_>>())
            .unwrap_or_default();
        rows.into_iter()
            .filter_map(|(k, v)| {
                let label = k.strip_suffix("_count")?;
                let count = v?.trim().parse::<i64>().ok()?;
                Some(RecordCount {
                    label: label.replace('_', " ") + "s",
                    count,
                })
            })
            .collect()
    }

    pub fn corpus_sources(&self) -> Vec<SourceCount> {
        let (path, _) = self.path_of(DbKey::Corpus);
        if !path.is_file() {
            return vec![];
        }
        let Ok(conn) = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) else {
            return vec![];
        };
        let Ok(mut stmt) = conn
            .prepare("SELECT source, COUNT(*) FROM publications GROUP BY source ORDER BY source")
        else {
            return vec![];
        };
        stmt.query_map([], |r| {
            Ok(SourceCount {
                source: r.get(0)?,
                count: r.get(1)?,
            })
        })
        .map(|it| it.flatten().collect())
        .unwrap_or_default()
    }

    /// The `Config` for one check run, mirroring the CLI's resolution
    /// (flags > env > config file > defaults), with per-run overrides.
    pub fn build_config(&self, opts: &RunOptions) -> Config {
        let cfg = self.file_config();
        let api = cfg.api_keys.clone().unwrap_or_default();
        let dbs = cfg.databases.clone().unwrap_or_default();
        let conc = cfg.concurrency.clone().unwrap_or_default();
        let env = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());
        let pools = self.pools.read().unwrap_or_else(|e| e.into_inner());
        let path = |k: DbKey| pools.paths.get(&k).map(|(p, _)| p.clone());

        let searxng_url = if opts.searxng {
            env("SEARXNG_URL")
                .or(dbs.searxng_url.clone())
                .or_else(|| Some("http://localhost:8080".to_string()))
        } else {
            None
        };

        Config {
            openalex_key: env("OPENALEX_KEY").or(api.openalex_key),
            s2_api_key: env("S2_API_KEY").or(api.s2_api_key),
            govinfo_key: env("GOVINFO_KEY").or(api.govinfo_key),
            patentsview_key: env("PATENTSVIEW_KEY").or(api.patentsview_key),
            dblp_offline_path: pools.dblp.as_ref().and(path(DbKey::Dblp)),
            dblp_offline_db: pools.dblp.clone(),
            acl_offline_path: pools.acl.as_ref().and(path(DbKey::Acl)),
            acl_offline_db: pools.acl.clone(),
            arxiv_offline_path: pools.arxiv.as_ref().and(path(DbKey::Arxiv)),
            arxiv_offline_db: pools.arxiv.clone(),
            iacr_eprint_offline_path: pools.iacr.as_ref().and(path(DbKey::Iacr)),
            iacr_eprint_offline_db: pools.iacr.clone(),
            openalex_offline_path: pools.openalex.as_ref().and(path(DbKey::OpenAlex)),
            openalex_offline_db: pools.openalex.clone(),
            local_corpus_path: pools.corpus.as_ref().and(path(DbKey::Corpus)),
            local_corpus_db: pools.corpus.clone(),
            num_workers: self.num_workers,
            db_timeout_secs: env("DB_TIMEOUT")
                .and_then(|v| v.parse().ok())
                .or(conc.db_timeout_secs)
                .unwrap_or(10),
            db_timeout_short_secs: env("DB_TIMEOUT_SHORT")
                .and_then(|v| v.parse().ok())
                .or(conc.db_timeout_short_secs)
                .unwrap_or(5),
            disabled_dbs: opts.disabled_dbs.clone(),
            check_openalex_authors: opts.check_openalex_authors,
            crossref_mailto: env("CROSSREF_MAILTO").or(api.crossref_mailto),
            max_rate_limit_retries: conc.max_rate_limit_retries.unwrap_or(3),
            rate_limiters: self.rate_limiters.clone(),
            searxng_url,
            query_cache: Some(self.query_cache.clone()),
            cache_path: self.cache_path.clone(),
            cache_positive_ttl_secs: hallucinator_core::DEFAULT_POSITIVE_TTL.as_secs(),
            cache_negative_ttl_secs: hallucinator_core::DEFAULT_NEGATIVE_TTL.as_secs(),
            url_match: opts.url_match,
        }
    }

    pub fn default_disabled(&self) -> Vec<String> {
        self.file_config()
            .databases
            .and_then(|d| d.disabled)
            .unwrap_or_default()
    }

    pub fn searxng_configured(&self) -> bool {
        std::env::var("SEARXNG_URL").is_ok_and(|s| !s.is_empty())
            || self
                .file_config()
                .databases
                .and_then(|d| d.searxng_url)
                .is_some()
    }

    pub fn has_openalex_key(&self) -> bool {
        std::env::var("OPENALEX_KEY").is_ok_and(|s| !s.is_empty())
            || self
                .file_config()
                .api_keys
                .and_then(|a| a.openalex_key)
                .is_some()
    }

    pub fn has_govinfo_key(&self) -> bool {
        std::env::var("GOVINFO_KEY").is_ok_and(|s| !s.is_empty())
            || self
                .file_config()
                .api_keys
                .and_then(|a| a.govinfo_key)
                .is_some()
    }
}

/// Per-run options chosen in the UI (persisted as the run's `options_json`).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct RunOptions {
    pub title: Option<String>,
    pub disabled_dbs: Vec<String>,
    pub url_match: bool,
    pub searxng: bool,
    pub check_openalex_authors: bool,
    pub bib_mode: crate::inputs::BibMode,
}

/// Size of a file, or the total of a directory tree (Tantivy index).
pub fn disk_size(path: &Path) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.is_file() {
        return Some(meta.len());
    }
    let mut total = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).ok()?.flatten() {
            let Ok(m) = entry.metadata() else { continue };
            if m.is_dir() {
                stack.push(entry.path());
            } else {
                total += m.len();
            }
        }
    }
    Some(total)
}

pub fn modified_at(path: &Path) -> Option<i64> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_dates() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(1_755_456_900), "2025-08-17T18:55:00Z");
        assert_eq!(format_build_date("2026-08-17"), "2026-08-17");
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2025, 10, 15) * 86400, 1_760_486_400);
        let now = crate::store::now();
        assert_eq!(age_days_of(&(now - 3 * 86400).to_string()), Some(3));
        assert_eq!(age_days_of(&iso_utc(now - 10 * 86400)), Some(10));
        assert_eq!(age_days_of("garbage"), None);
    }

    #[test]
    fn keys_round_trip() {
        for k in ALL_KEYS {
            assert_eq!(parse_key(k.as_str()), Some(k));
        }
        assert_eq!(parse_key("nope"), None);
    }
}
