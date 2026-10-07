//! Executing checks and streaming their progress.
//!
//! Mirrors the TUI backend (`hallucinator-tui/src/backend.rs`): one shared
//! `ValidationPool` per run, every paper extracted on the blocking pool and
//! its checkable references fed into the shared pool. Every result is
//! persisted the moment it arrives, so the history database is always the
//! source of truth; the in-memory [`LiveRun`] only adds transient state
//! (which reference is being checked, per-database progress) and the
//! broadcast channel SSE subscribers listen on.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use hallucinator_core::pool::{RefJob, ValidationPool};
use hallucinator_core::{ProgressEvent, Reference};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::{Semaphore, broadcast};
use tokio_util::sync::CancellationToken;

use crate::inputs::{self, InputKind, PlannedPaper, SourcedRef};
use crate::model::{Stats, StoredResult, db_status_str};
use crate::refdb::{RefDbRegistry, RunOptions};
use crate::store::{NewRef, PaperRow, RefRow, ResultUpdate, RunRow, Store};

/// One server-sent event, serialised once and shared by all subscribers.
#[derive(Debug)]
pub struct SseMsg {
    pub event: &'static str,
    pub data: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveDb {
    pub db: String,
    pub status: &'static str,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Default)]
struct Transient {
    phase: &'static str,
    live_dbs: Vec<LiveDb>,
}

pub struct LiveRun {
    pub id: String,
    pub cancel: CancellationToken,
    tx: broadcast::Sender<Arc<SseMsg>>,
    transient: Mutex<HashMap<(usize, usize), Transient>>,
}

impl LiveRun {
    fn new(id: &str) -> Self {
        let (tx, _) = broadcast::channel(4096);
        LiveRun {
            id: id.to_string(),
            cancel: CancellationToken::new(),
            tx,
            transient: Mutex::new(HashMap::new()),
        }
    }

    fn send(&self, event: &'static str, data: &impl Serialize) {
        if let Ok(data) = serde_json::to_string(data) {
            let _ = self.tx.send(Arc::new(SseMsg { event, data }));
        }
    }

    fn transient(&self) -> std::sync::MutexGuard<'_, HashMap<(usize, usize), Transient>> {
        self.transient.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set_phase(&self, p: usize, r: usize, phase: &'static str) {
        let mut t = self.transient();
        let e = t.entry((p, r)).or_default();
        // A (re-)check starts a fresh round of database answers; a hand-off
        // to the retry worker keeps the answers gathered so far.
        if phase == "checking" {
            e.live_dbs.clear();
        }
        e.phase = phase;
    }

    fn push_db(&self, p: usize, r: usize, db: LiveDb) {
        let mut t = self.transient();
        let e = t.entry((p, r)).or_default();
        if e.phase.is_empty() {
            e.phase = "checking";
        }
        e.live_dbs.retain(|d| d.db != db.db);
        e.live_dbs.push(db);
    }

    fn clear(&self, p: usize, r: usize) {
        self.transient().remove(&(p, r));
    }
}

// ── JSON views (shapes documented in API.md) ───────────────────────────

pub fn ref_view(row: &RefRow, live: Option<&LiveRun>, paper_idx: usize) -> Value {
    let transient = live.and_then(|l| l.transient().get(&(paper_idx, row.idx)).cloned());
    let phase = if row.skip_reason.is_some() {
        "skipped"
    } else if let Some(t) = transient.as_ref().filter(|t| !t.phase.is_empty()) {
        t.phase
    } else if row.result_json.is_some() {
        "done"
    } else {
        "pending"
    };
    let result: Value = row
        .result_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(Value::Null);
    json!({
        "idx": row.idx,
        "original_number": row.original_number,
        "title": row.title,
        "raw_citation": row.raw_citation,
        "authors": row.authors,
        "doi": row.doi,
        "arxiv_id": row.arxiv_id,
        "urls": row.urls,
        "skip_reason": row.skip_reason,
        "origin": row.origin,
        "phase": phase,
        "verdict": row.verdict,
        "retracted": row.retracted,
        "fp_reason": row.fp_reason,
        "live_dbs": transient.map(|t| t.live_dbs).unwrap_or_default(),
        "result": result,
    })
}

pub fn paper_stats(refs: &[RefRow]) -> Stats {
    let mut s = Stats::default();
    for r in refs {
        s.add(&r.facts());
    }
    s
}

fn parse_json(s: &Option<String>) -> Value {
    s.as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(Value::Null)
}

pub fn paper_header(p: &PaperRow, stats: &Stats) -> Value {
    json!({
        "paper_idx": p.idx,
        "status": p.status,
        "error": p.error,
        "stats": stats,
        "verdict": p.verdict,
        "merge": parse_json(&p.merge_json),
        "skip_stats": parse_json(&p.skip_stats_json),
        "input_kind": p.input_kind,
    })
}

pub fn paper_view(p: &PaperRow, refs: &[RefRow], live: Option<&LiveRun>) -> Value {
    json!({
        "idx": p.idx,
        "filename": p.filename,
        "input_kind": p.input_kind,
        "companion_filename": p.companion_filename,
        "status": p.status,
        "error": p.error,
        "verdict": p.verdict,
        "stats": paper_stats(refs),
        "skip_stats": parse_json(&p.skip_stats_json),
        "merge": parse_json(&p.merge_json),
        "refs": refs.iter().map(|r| ref_view(r, live, p.idx)).collect::<Vec<_>>(),
    })
}

pub fn run_summary(r: &RunRow, stats: &Stats) -> Value {
    json!({
        "id": r.id,
        "title": r.title,
        "status": r.status,
        "username": r.username,
        "created_at": r.created_at,
        "started_at": r.started_at,
        "finished_at": r.finished_at,
        "paper_count": r.paper_count,
        "error": r.error,
        "stats": stats,
    })
}

fn run_header(r: &RunRow) -> Value {
    json!({
        "status": r.status,
        "started_at": r.started_at,
        "finished_at": r.finished_at,
        "error": r.error,
    })
}

// ── Manager ────────────────────────────────────────────────────────────

pub struct RunManager {
    store: Arc<Store>,
    refdb: Arc<RefDbRegistry>,
    live: Mutex<HashMap<String, Arc<LiveRun>>>,
    run_slots: Arc<Semaphore>,
    extract_slots: Arc<Semaphore>,
}

/// What a retry re-checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryScope {
    /// Refs whose result lists failed databases: re-query only those.
    Failed,
    /// Not found / inconclusive refs: full re-check.
    NotFound,
    /// Every problematic ref (not found, mismatch, inconclusive, retracted).
    Problems,
    /// A single reference.
    Ref,
}

pub enum RetryError {
    Busy,
    NotFound,
    Other(anyhow::Error),
}

impl RunManager {
    pub fn new(store: Arc<Store>, refdb: Arc<RefDbRegistry>, max_concurrent_runs: usize) -> Self {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(1, 16);
        RunManager {
            store,
            refdb,
            live: Mutex::new(HashMap::new()),
            run_slots: Arc::new(Semaphore::new(max_concurrent_runs.max(1))),
            extract_slots: Arc::new(Semaphore::new(cpus)),
        }
    }

    fn live_map(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<LiveRun>>> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn live(&self, id: &str) -> Option<Arc<LiveRun>> {
        self.live_map().get(id).cloned()
    }

    pub fn subscribe(&self, id: &str) -> Option<broadcast::Receiver<Arc<SseMsg>>> {
        self.live(id).map(|l| l.tx.subscribe())
    }

    pub fn cancel(&self, id: &str) -> bool {
        match self.live(id) {
            Some(l) => {
                l.cancel.cancel();
                true
            }
            None => false,
        }
    }

    /// Full `RunDetail` (DB state + transient overlay).
    pub fn detail(&self, id: &str) -> anyhow::Result<Option<Value>> {
        let Some(run) = self.store.get_run(id)? else {
            return Ok(None);
        };
        let live = self.live(id);
        let papers = self.store.load_papers(id)?;
        let mut total = Stats::default();
        let papers: Vec<Value> = papers
            .iter()
            .map(|(p, refs)| {
                total.merge(&paper_stats(refs));
                paper_view(p, refs, live.as_deref())
            })
            .collect();
        let mut summary = run_summary(&run, &total);
        summary["options"] = serde_json::from_str(&run.options_json).unwrap_or(Value::Null);
        Ok(Some(json!({ "run": summary, "papers": papers })))
    }

    /// Start checking a freshly created run. `uploads` keeps the uploaded
    /// files alive until every paper has been extracted.
    pub fn start(
        self: &Arc<Self>,
        run_id: String,
        planned: Vec<PlannedPaper>,
        opts: RunOptions,
        uploads: tempfile::TempDir,
    ) {
        let live = Arc::new(LiveRun::new(&run_id));
        self.live_map().insert(run_id.clone(), live.clone());
        let this = self.clone();
        tokio::spawn(async move {
            let _uploads = uploads;
            let permit = tokio::select! {
                p = this.run_slots.clone().acquire_owned() => p.ok(),
                _ = live.cancel.cancelled() => None,
            };
            if permit.is_none() {
                for i in 0..planned.len() {
                    let _ = this.store.set_paper_status(&run_id, i, "cancelled", None);
                }
                this.finish(&live, "cancelled", None);
                return;
            }
            if let Err(e) = this.store.set_run_started(&run_id) {
                tracing::error!(run = %run_id, error = %e, "failed to mark run started");
            }
            this.emit_run(&live);

            let config = Arc::new(this.refdb.build_config(&opts));
            let pool = ValidationPool::new(
                config.clone(),
                live.cancel.clone(),
                config.num_workers.max(1),
            );
            let mut handles = Vec::new();
            for (idx, paper) in planned.into_iter().enumerate() {
                let this = this.clone();
                let live = live.clone();
                let tx = pool.sender();
                handles.push(tokio::spawn(async move {
                    this.process_paper(&live, idx, paper, tx).await
                }));
            }
            let mut any_ok = false;
            let n = handles.len();
            for h in handles {
                any_ok |= h.await.unwrap_or(false);
            }
            pool.shutdown().await;
            let status = if live.cancel.is_cancelled() {
                "cancelled"
            } else if !any_ok && n > 0 {
                "failed"
            } else {
                "done"
            };
            let error = (status == "failed").then_some("No paper could be processed.");
            this.finish(&live, status, error);
            drop(permit);
        });
    }

    fn finish(&self, live: &Arc<LiveRun>, status: &str, error: Option<&str>) {
        if let Err(e) = self.store.set_run_finished(&live.id, status, error) {
            tracing::error!(run = %live.id, error = %e, "failed to mark run finished");
        }
        self.emit_run(live);
        live.send("end", &json!({}));
        self.live_map().remove(&live.id);
    }

    fn emit_run(&self, live: &LiveRun) {
        if let Ok(Some(run)) = self.store.get_run(&live.id) {
            live.send("run", &run_header(&run));
        }
    }

    fn emit_paper(&self, live: &LiveRun, idx: usize) {
        if let Ok(papers) = self.store.load_papers(&live.id)
            && let Some((p, refs)) = papers.iter().find(|(p, _)| p.idx == idx)
        {
            live.send("paper", &paper_header(p, &paper_stats(refs)));
        }
    }

    fn emit_ref(&self, live: &LiveRun, paper_idx: usize, ref_idx: usize) {
        let Ok(refs) = self.store.load_paper_refs(&live.id, paper_idx) else {
            return;
        };
        if let Some(r) = refs.iter().find(|r| r.idx == ref_idx) {
            live.send(
                "ref",
                &json!({
                    "paper_idx": paper_idx,
                    "ref": ref_view(r, Some(live), paper_idx),
                    "stats": paper_stats(&refs),
                }),
            );
        }
    }

    fn set_paper_status(&self, live: &LiveRun, idx: usize, status: &str, error: Option<&str>) {
        let _ = self.store.set_paper_status(&live.id, idx, status, error);
        self.emit_paper(live, idx);
    }

    fn persist_result(
        &self,
        run_id: &str,
        paper_idx: usize,
        ref_idx: usize,
        result: &hallucinator_core::ValidationResult,
    ) {
        let stored = StoredResult::from(result);
        let Ok(json) = serde_json::to_string(&stored) else {
            return;
        };
        let update = ResultUpdate {
            result_json: &json,
            verdict: stored.verdict(),
            mismatch_flags: stored.mismatch_kind().bits(),
            retracted: stored.is_retracted(),
        };
        if let Err(e) = self
            .store
            .set_ref_result(run_id, paper_idx, ref_idx, &update)
        {
            tracing::error!(run = run_id, error = %e, "failed to store result");
        }
    }

    /// Extract one paper and feed its references into the shared pool.
    /// Returns whether the paper could be processed at all.
    async fn process_paper(
        self: &Arc<Self>,
        live: &Arc<LiveRun>,
        pidx: usize,
        paper: PlannedPaper,
        pool_tx: async_channel::Sender<RefJob>,
    ) -> bool {
        if live.cancel.is_cancelled() {
            self.set_paper_status(live, pidx, "cancelled", None);
            return false;
        }
        self.set_paper_status(live, pidx, "extracting", None);

        let extracted = {
            let _slot = self.extract_slots.clone().acquire_owned().await;
            tokio::task::spawn_blocking(move || extract_planned(&paper))
                .await
                .unwrap_or_else(|e| Err(format!("extraction task failed: {e}")))
        };
        let extracted = match extracted {
            Ok(x) => x,
            Err(e) => {
                self.set_paper_status(live, pidx, "failed", Some(&e));
                return false;
            }
        };
        for n in &extracted.notices {
            live.send("notice", &json!({"level": "warn", "message": n}));
        }

        let new_refs: Vec<NewRef> = extracted
            .refs
            .iter()
            .map(|s| NewRef {
                original_number: s.reference.original_number,
                title: s.reference.title.clone(),
                raw_citation: s.reference.raw_citation.clone(),
                authors: s.reference.authors.clone(),
                doi: s.reference.doi.clone(),
                arxiv_id: s.reference.arxiv_id.clone(),
                urls: s.reference.urls.clone(),
                skip_reason: s.reference.skip_reason.clone(),
                origin: s.origin.to_string(),
            })
            .collect();
        let skip_json = json!({
            "url_only": extracted.skip_stats.url_only,
            "short_title": extracted.skip_stats.short_title,
            "no_title": extracted.skip_stats.no_title,
            "no_authors": extracted.skip_stats.no_authors,
            "total_raw": extracted.skip_stats.total_raw,
        })
        .to_string();
        let merge_json = extracted
            .merge
            .as_ref()
            .and_then(|m| serde_json::to_string(m).ok());
        if let Err(e) = self.store.set_paper_extraction(
            &live.id,
            pidx,
            &extracted.input_kind,
            &skip_json,
            merge_json.as_deref(),
            &new_refs,
        ) {
            self.set_paper_status(live, pidx, "failed", Some(&format!("storage error: {e}")));
            return false;
        }
        if let Ok(rows) = self.store.load_paper_refs(&live.id, pidx) {
            live.send(
                "refs",
                &json!({
                    "paper_idx": pidx,
                    "refs": rows.iter().map(|r| ref_view(r, Some(live), pidx)).collect::<Vec<_>>(),
                }),
            );
        }

        // Index map: position among checkable refs → position in the full list.
        let checkable: Vec<(usize, Reference)> = extracted
            .refs
            .into_iter()
            .enumerate()
            .filter(|(_, s)| s.reference.skip_reason.is_none())
            .map(|(i, s)| (i, s.reference))
            .collect();
        if checkable.is_empty() {
            self.set_paper_status(live, pidx, "done", None);
            return true;
        }
        self.set_paper_status(live, pidx, "checking", None);
        let index_map: Arc<Vec<usize>> = Arc::new(checkable.iter().map(|(i, _)| *i).collect());
        let total = checkable.len();

        let mut pending = FuturesUnordered::new();
        for (i, (full_idx, reference)) in checkable.into_iter().enumerate() {
            if live.cancel.is_cancelled() {
                break;
            }
            let (result_tx, result_rx) = tokio::sync::oneshot::channel();
            let progress = {
                let this = self.clone();
                let live = live.clone();
                let index_map = index_map.clone();
                move |event: ProgressEvent| this.on_progress(&live, pidx, &index_map, event)
            };
            let job = RefJob {
                reference,
                result_tx,
                ref_index: i,
                total,
                progress: Arc::new(progress),
            };
            if pool_tx.send(job).await.is_err() {
                break;
            }
            pending.push(async move { (full_idx, result_rx.await) });
        }
        drop(pool_tx);

        while let Some((full_idx, res)) = pending.next().await {
            if let Ok(result) = res {
                self.persist_result(&live.id, pidx, full_idx, &result);
                live.clear(pidx, full_idx);
                self.emit_ref(live, pidx, full_idx);
            }
        }
        let unfinished = self
            .store
            .load_paper_refs(&live.id, pidx)
            .map(|refs| {
                refs.iter()
                    .any(|r| r.skip_reason.is_none() && r.result_json.is_none())
            })
            .unwrap_or(false);
        let status = if unfinished && live.cancel.is_cancelled() {
            "cancelled"
        } else {
            "done"
        };
        self.set_paper_status(live, pidx, status, None);
        true
    }

    fn on_progress(&self, live: &LiveRun, pidx: usize, index_map: &[usize], event: ProgressEvent) {
        let map = |i: usize| index_map.get(i).copied().unwrap_or(i);
        match event {
            ProgressEvent::Checking { index, .. } => {
                let r = map(index);
                live.set_phase(pidx, r, "checking");
                self.emit_ref(live, pidx, r);
            }
            ProgressEvent::Retrying { index, .. } => {
                let r = map(index);
                live.set_phase(pidx, r, "retrying");
                self.emit_ref(live, pidx, r);
            }
            ProgressEvent::DatabaseQueryComplete {
                ref_index,
                db_name,
                status,
                elapsed,
                ..
            } => {
                let r = map(ref_index);
                let db = LiveDb {
                    db: db_name,
                    status: db_status_str(&status),
                    elapsed_ms: elapsed.as_millis() as u64,
                };
                live.send(
                    "db",
                    &json!({"paper_idx": pidx, "ref_idx": r, "db": db.db, "status": db.status, "elapsed_ms": db.elapsed_ms}),
                );
                live.push_db(pidx, r, db);
            }
            ProgressEvent::RateLimitWait {
                db_name,
                wait_duration,
            } if wait_duration.as_secs() >= 5 => {
                live.send(
                    "notice",
                    &json!({"level": "info", "message": format!("{db_name} rate limit: waiting {}s", wait_duration.as_secs())}),
                );
            }
            _ => {}
        }
    }

    /// Re-check references of a finished run (see [`RetryScope`]).
    pub fn retry(
        self: &Arc<Self>,
        run_id: &str,
        paper_idx: usize,
        scope: RetryScope,
        ref_idx: Option<usize>,
    ) -> Result<usize, RetryError> {
        let run = match self.store.get_run(run_id) {
            Ok(Some(r)) => r,
            Ok(None) => return Err(RetryError::NotFound),
            Err(e) => return Err(RetryError::Other(e)),
        };
        let refs = self
            .store
            .load_paper_refs(run_id, paper_idx)
            .map_err(RetryError::Other)?;
        let mut targets: Vec<(usize, Reference, Vec<String>)> = Vec::new();
        for r in &refs {
            if r.skip_reason.is_some() {
                continue;
            }
            let stored: Option<StoredResult> = r
                .result_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok());
            let verdict = r.verdict.as_deref();
            let failed = stored
                .as_ref()
                .map(|s| s.failed_dbs.clone())
                .unwrap_or_default();
            let pick = match scope {
                RetryScope::Ref => Some(r.idx) == ref_idx,
                RetryScope::Failed => !failed.is_empty(),
                RetryScope::NotFound => {
                    matches!(verdict, Some("not_found" | "inconclusive")) || verdict.is_none()
                }
                RetryScope::Problems => {
                    matches!(verdict, Some("not_found" | "inconclusive" | "mismatch"))
                        || r.retracted
                        || verdict.is_none()
                }
            };
            if !pick {
                continue;
            }
            let only = if scope == RetryScope::Failed {
                failed
            } else {
                vec![]
            };
            targets.push((r.idx, reference_from_row(r), only));
        }
        if scope == RetryScope::Ref && targets.is_empty() {
            return Err(RetryError::NotFound);
        }
        if targets.is_empty() {
            return Ok(0);
        }

        let live = {
            let mut map = self.live_map();
            if map.contains_key(run_id) {
                return Err(RetryError::Busy);
            }
            let live = Arc::new(LiveRun::new(run_id));
            map.insert(run_id.to_string(), live.clone());
            live
        };
        let n = targets.len();
        let opts: RunOptions = serde_json::from_str(&run.options_json).unwrap_or_default();
        let previous_status = run.status.clone();
        let this = self.clone();
        tokio::spawn(async move {
            let _ = this.store.set_run_started(&live.id);
            this.emit_run(&live);
            for (idx, _, only) in &targets {
                live.set_phase(
                    paper_idx,
                    *idx,
                    if only.is_empty() {
                        "checking"
                    } else {
                        "retrying"
                    },
                );
                this.emit_ref(&live, paper_idx, *idx);
            }
            let config = Arc::new(this.refdb.build_config(&opts));
            let client = reqwest::Client::builder()
                .user_agent(concat!("hallucinator-webapp/", env!("CARGO_PKG_VERSION")))
                .pool_max_idle_per_host(2)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());
            let sem = Arc::new(Semaphore::new(config.num_workers.max(1)));
            let mut tasks = Vec::new();
            for (idx, reference, only) in targets {
                let Ok(permit) = sem.clone().acquire_owned().await else {
                    break;
                };
                if live.cancel.is_cancelled() {
                    break;
                }
                let (this, live, config, client) =
                    (this.clone(), live.clone(), config.clone(), client.clone());
                tasks.push(tokio::spawn(async move {
                    let _permit = permit;
                    let on_db = {
                        let live = live.clone();
                        move |d: hallucinator_core::DbResult| {
                            let db = LiveDb {
                                db: d.db_name,
                                status: db_status_str(&d.status),
                                elapsed_ms: d.elapsed.map(|e| e.as_millis() as u64).unwrap_or(0),
                            };
                            live.send(
                                "db",
                                &json!({"paper_idx": paper_idx, "ref_idx": idx, "db": db.db, "status": db.status, "elapsed_ms": db.elapsed_ms}),
                            );
                            live.push_db(paper_idx, idx, db);
                        }
                    };
                    let result = if only.is_empty() {
                        hallucinator_core::checker::check_single_reference(
                            &reference,
                            &config,
                            &client,
                            true,
                            Some(&on_db),
                        )
                        .await
                    } else {
                        hallucinator_core::checker::check_single_reference_retry(
                            &reference,
                            &config,
                            &client,
                            &only,
                            Some(&on_db),
                        )
                        .await
                    };
                    let result = if only.is_empty() {
                        result
                    } else {
                        merge_partial_retry(&this.store, &live.id, paper_idx, idx, result)
                    };
                    this.persist_result(&live.id, paper_idx, idx, &result);
                    live.clear(paper_idx, idx);
                    this.emit_ref(&live, paper_idx, idx);
                }));
            }
            for t in tasks {
                let _ = t.await;
            }
            live.transient().clear();
            let status = match previous_status.as_str() {
                "running" | "queued" => "done",
                s => s,
            }
            .to_string();
            this.emit_paper(&live, paper_idx);
            this.finish(&live, &status, None);
        });
        Ok(n)
    }
}

/// A failed-DB-only retry answers just for the retried databases. Keep the
/// original per-database rows for the others so the detail view stays whole.
fn merge_partial_retry(
    store: &Store,
    run_id: &str,
    paper_idx: usize,
    ref_idx: usize,
    mut result: hallucinator_core::ValidationResult,
) -> hallucinator_core::ValidationResult {
    let Ok(Some(row)) = store.load_ref(run_id, paper_idx, ref_idx) else {
        return result;
    };
    let Some(old) = row
        .result_json
        .as_deref()
        .and_then(|s| serde_json::from_str::<StoredResult>(s).ok())
    else {
        return result;
    };
    let old = old.to_core();
    let retried: Vec<String> = result
        .db_results
        .iter()
        .map(|d| d.db_name.clone())
        .collect();
    let mut merged: Vec<_> = old
        .db_results
        .into_iter()
        .filter(|d| !retried.contains(&d.db_name))
        .collect();
    merged.append(&mut result.db_results);
    result.db_results = merged;
    result
}

fn reference_from_row(r: &RefRow) -> Reference {
    Reference {
        raw_citation: r.raw_citation.clone(),
        title: r.title.clone(),
        authors: r.authors.clone(),
        doi: r.doi.clone(),
        arxiv_id: r.arxiv_id.clone(),
        urls: r.urls.clone(),
        original_number: r.original_number,
        skip_reason: None,
    }
}

struct Extracted {
    refs: Vec<SourcedRef>,
    skip_stats: hallucinator_core::SkipStats,
    merge: Option<inputs::MergeSummary>,
    input_kind: String,
    notices: Vec<String>,
}

fn origin_for(kind: InputKind) -> &'static str {
    kind.as_str()
}

/// Blocking: run the upstream extractor(s) for one planned paper.
fn extract_planned(paper: &PlannedPaper) -> Result<Extracted, String> {
    let main = hallucinator_ingest::extract_references(&paper.main.path);
    let Some(companion) = &paper.companion else {
        let ex = main.map_err(|e| format!("Could not extract references: {e}"))?;
        let origin = origin_for(paper.main.kind);
        return Ok(Extracted {
            refs: ex
                .references
                .into_iter()
                .map(|reference| SourcedRef { reference, origin })
                .collect(),
            skip_stats: ex.skip_stats,
            merge: None,
            input_kind: paper.input_kind(),
            notices: vec![],
        });
    };

    let comp_origin = origin_for(companion.kind);
    let comp = hallucinator_ingest::extract_references(&companion.path);
    match (main, comp) {
        (Ok(pdf), Ok(bib)) => {
            let (refs, skip_stats, merge) =
                inputs::merge_with_companion(pdf, bib, &companion.display_name, comp_origin);
            let mut notices = vec![];
            if merge.fallback.is_some() {
                notices.push(format!(
                    "No references found in {}; checked every entry of {} instead.",
                    paper.main.display_name, companion.display_name
                ));
            }
            Ok(Extracted {
                refs,
                skip_stats,
                merge: Some(merge),
                input_kind: paper.input_kind(),
                notices,
            })
        }
        (Err(e), Ok(bib)) => {
            let (refs, skip_stats, merge) =
                inputs::companion_only(bib, &companion.display_name, comp_origin, 0, "pdf_failed");
            Ok(Extracted {
                refs,
                skip_stats,
                merge: Some(merge),
                input_kind: paper.input_kind(),
                notices: vec![format!(
                    "Could not read {} ({e}); checked every entry of {} instead.",
                    paper.main.display_name, companion.display_name
                )],
            })
        }
        (Ok(pdf), Err(e)) => {
            let origin = origin_for(paper.main.kind);
            Ok(Extracted {
                refs: pdf
                    .references
                    .into_iter()
                    .map(|reference| SourcedRef { reference, origin })
                    .collect(),
                skip_stats: pdf.skip_stats,
                merge: None,
                input_kind: paper.main.kind.as_str().to_string(),
                notices: vec![format!(
                    "Could not read {} ({e}); used the PDF parse only.",
                    companion.display_name
                )],
            })
        }
        (Err(e1), Err(e2)) => Err(format!("Could not extract references: {e1}; {e2}")),
    }
}
