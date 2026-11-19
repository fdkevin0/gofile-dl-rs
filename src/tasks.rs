//! Thread-safe download task registry and background worker lifecycle manager.
//!
//! Replaces the legacy unprotected global `download_tasks` dictionary in `app.py:133`
//! with an `Arc<RwLock<HashMap<String, ManagedTask>>>`, lock-free `AtomicBool`
//! cancellation/pause flags, `Condvar`-synchronized file deletion, automatic
//! eviction of expired terminal tasks (`task_expiry`), and atomic `tasks.json`
//! persistence under `CONFIG_DIR`.

pub use crate::browse::{
    browse_confined_directory, check_directory_writable, derive_initial_task_name,
    resolve_confined_output_dir, FileProgressRecord, StartTaskRequest, TaskSnapshot,
};

use crate::client::{GoFileClient, ReqwestTransport};
use crate::config::AppConfig;
use crate::downloader::{execute_download, DownloadOptions, ProgressHooks};
use crate::error::GoFileError;
use crate::sanitize::DEFAULT_FOLDER_PATTERNS;
use crate::token::WebsiteTokenConfig;
use crate::transfer::remove_path_and_part;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const TASK_STORE_FILENAME: &str = "tasks.json";
const TASK_STORE_VERSION: u32 = 1;
const INTERRUPTED_RESTART_MSG: &str = "Interrupted by server restart";

#[derive(Debug, Serialize, Deserialize)]
struct PersistedTaskStore {
    #[serde(default = "default_store_version")]
    version: u32,
    #[serde(default)]
    tasks: HashMap<String, PersistedTask>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedTask {
    snapshot: TaskSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    out_path: Option<PathBuf>,
    request: PersistedTaskRequest,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedTaskRequest {
    url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    directory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    throttle_kbps: Option<u64>,
    #[serde(default = "default_persisted_retries")]
    retries: u32,
    #[serde(default)]
    strip_emojis: bool,
    #[serde(default)]
    incremental: bool,
    #[serde(default = "default_persisted_folder_pattern")]
    folder_pattern: String,
}

const fn default_store_version() -> u32 {
    TASK_STORE_VERSION
}

const fn default_persisted_retries() -> u32 {
    3
}

fn default_persisted_folder_pattern() -> String {
    DEFAULT_FOLDER_PATTERNS.to_string()
}

impl From<&StartTaskRequest> for PersistedTaskRequest {
    fn from(req: &StartTaskRequest) -> Self {
        Self {
            url: req.url.clone(),
            directory: req.directory.clone(),
            throttle_kbps: req.throttle_kbps,
            retries: req.retries,
            strip_emojis: req.strip_emojis,
            incremental: req.incremental,
            folder_pattern: req.folder_pattern.clone(),
        }
    }
}

impl PersistedTaskRequest {
    fn into_start_request(self) -> StartTaskRequest {
        StartTaskRequest {
            url: self.url,
            directory: self.directory,
            password: None,
            throttle_kbps: self.throttle_kbps,
            retries: self.retries.min(10),
            strip_emojis: self.strip_emojis,
            incremental: self.incremental,
            folder_pattern: self.folder_pattern,
            premium_token: None,
        }
    }
}

struct ManagedTask {
    request: StartTaskRequest,
    snapshot: TaskSnapshot,
    attempt: u64,
    cancelled: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    completion: Arc<(Mutex<bool>, Condvar)>,
}

/// Outcome of attempting to retry an existing task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryTaskStatus {
    /// Task was terminal and has been restarted in place.
    Restarted,
    /// Task exists but is still running or paused.
    AlreadyActive,
    /// No task exists for the requested ID.
    NotFound,
}

struct WorkerLaunch {
    task_id: String,
    attempt: u64,
    req: StartTaskRequest,
    out_base: PathBuf,
    cancelled: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    completion: Arc<(Mutex<bool>, Condvar)>,
    prev_completion: Option<Arc<(Mutex<bool>, Condvar)>>,
}

struct CompletionGuard(Arc<(Mutex<bool>, Condvar)>);

impl Drop for CompletionGuard {
    fn drop(&mut self) {
        if let Ok(mut done) = self.0 .0.lock() {
            *done = true;
            self.0 .1.notify_all();
        }
    }
}

fn is_terminal_status(status: &str) -> bool {
    matches!(status, "completed" | "error" | "cancelled")
}

fn now_epoch_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// Pluggable task execution callback (allows offline deterministic worker tests).
pub type TaskWorkerFn = Arc<
    dyn Fn(StartTaskRequest, Arc<AppConfig>, Arc<dyn ProgressHooks>) -> Result<(), GoFileError>
        + Send
        + Sync,
>;

/// Thread-safe download task registry shared across HTTP handlers and worker threads.
#[derive(Clone)]
pub struct TaskManager {
    inner: Arc<RwLock<HashMap<String, ManagedTask>>>,
    config: Arc<AppConfig>,
    worker: TaskWorkerFn,
    store_path: Option<PathBuf>,
    persist_lock: Arc<Mutex<()>>,
}

impl TaskManager {
    /// Creates a manager backed by live [`ReqwestTransport`] worker threads.
    #[must_use]
    pub fn new(config: Arc<AppConfig>) -> Self {
        Self::with_worker(config, Arc::new(run_live_task_worker))
    }

    /// Creates a manager with a custom worker closure (ideal for deterministic tests).
    #[must_use]
    pub fn with_worker(config: Arc<AppConfig>, worker: TaskWorkerFn) -> Self {
        let store_path = effective_config_dir(config.config_dir.as_deref())
            .map(|dir| dir.join(TASK_STORE_FILENAME));
        let (initial_tasks, recovered) = store_path.as_deref().map_or_else(
            || (HashMap::new(), false),
            |p| load_persisted_tasks(p, &config),
        );
        let mgr = Self {
            inner: Arc::new(RwLock::new(initial_tasks)),
            config,
            worker,
            store_path,
            persist_lock: Arc::new(Mutex::new(())),
        };
        mgr.prune_expired_tasks();
        if recovered {
            mgr.persist_tasks();
        }
        mgr
    }

    fn persist_tasks(&self) {
        persist_tasks_to_disk(&self.inner, self.store_path.as_deref(), &self.persist_lock);
    }

    /// Evicts terminal (`completed`/`error`/`cancelled`) tasks older than `config.task_expiry`.
    pub fn prune_expired_tasks(&self) {
        let ttl = self.config.task_expiry;
        if ttl == 0 {
            return;
        }
        let changed = {
            let Ok(mut map) = self.inner.write() else {
                return;
            };
            let before = map.len();
            let cutoff = now_epoch_secs() - (ttl as f64);
            map.retain(|_, t| {
                !is_terminal_status(&t.snapshot.status) || t.snapshot.timestamp > cutoff
            });
            map.len() < before
        };
        if changed {
            self.persist_tasks();
        }
    }

    /// Registers a new download task, spawns its worker thread, and returns `task_id`.
    #[must_use]
    pub fn start_task(&self, req: StartTaskRequest) -> String {
        self.prune_expired_tasks();
        let task_id = Uuid::new_v4().to_string();
        let initial_name = derive_initial_task_name(&req.url, req.directory.as_deref());
        let cancelled = Arc::new(AtomicBool::new(false));
        let paused = Arc::new(AtomicBool::new(false));
        let completion = Arc::new((Mutex::new(false), Condvar::new()));
        let out_base = resolve_confined_output_dir(&self.config.base_dir, req.directory.as_deref())
            .unwrap_or_else(|_| self.config.base_dir.clone());
        let snapshot = TaskSnapshot {
            progress: 0,
            overall_progress: 0,
            current_folder: "N/A".to_string(),
            download_speed: 0.0,
            status: "running".to_string(),
            error_message: String::new(),
            url: req.url.clone(),
            directory: Some(out_base.to_string_lossy().into_owned()),
            name: initial_name,
            timestamp: now_epoch_secs(),
            files: Vec::new(),
            paused: false,
            out_path: None,
        };

        if let Ok(mut map) = self.inner.write() {
            map.insert(
                task_id.clone(),
                ManagedTask {
                    request: req.clone(),
                    snapshot,
                    attempt: 0,
                    cancelled: Arc::clone(&cancelled),
                    paused: Arc::clone(&paused),
                    completion: Arc::clone(&completion),
                },
            );
        }
        self.persist_tasks();

        self.spawn_worker(WorkerLaunch {
            task_id: task_id.clone(),
            attempt: 0,
            req,
            out_base,
            cancelled,
            paused,
            completion,
            prev_completion: None,
        });

        task_id
    }

    /// Restarts a terminal (`completed`, `error`, or `cancelled`) task in place using its
    /// original [`StartTaskRequest`] parameters.
    #[must_use]
    pub fn retry_task(&self, task_id: &str) -> RetryTaskStatus {
        let launch = {
            let Ok(mut map) = self.inner.write() else {
                return RetryTaskStatus::NotFound;
            };
            let Some(entry) = map.get_mut(task_id) else {
                return RetryTaskStatus::NotFound;
            };
            if !is_terminal_status(&entry.snapshot.status) {
                return RetryTaskStatus::AlreadyActive;
            }

            let req = entry.request.clone();
            let out_base =
                resolve_confined_output_dir(&self.config.base_dir, req.directory.as_deref())
                    .unwrap_or_else(|_| self.config.base_dir.clone());
            let next_attempt = entry.attempt.saturating_add(1);
            let cancelled = Arc::new(AtomicBool::new(false));
            let paused = Arc::new(AtomicBool::new(false));
            let completion = Arc::new((Mutex::new(false), Condvar::new()));
            let prev_completion = Arc::clone(&entry.completion);

            entry.attempt = next_attempt;
            entry.cancelled = Arc::clone(&cancelled);
            entry.paused = Arc::clone(&paused);
            entry.completion = Arc::clone(&completion);
            entry.snapshot.progress = 0;
            entry.snapshot.overall_progress = 0;
            entry.snapshot.current_folder = "N/A".to_string();
            entry.snapshot.download_speed = 0.0;
            entry.snapshot.status = "running".to_string();
            entry.snapshot.error_message.clear();
            entry.snapshot.timestamp = now_epoch_secs();
            entry.snapshot.files.clear();
            entry.snapshot.paused = false;

            WorkerLaunch {
                task_id: task_id.to_string(),
                attempt: next_attempt,
                req,
                out_base,
                cancelled,
                paused,
                completion,
                prev_completion: Some(prev_completion),
            }
        };

        self.persist_tasks();
        self.spawn_worker(launch);
        RetryTaskStatus::Restarted
    }

    /// Blocks until the current attempt of `task_id` finishes or `timeout` elapses.
    ///
    /// Returns `true` if the task exists and its active worker has completed.
    #[must_use]
    pub fn wait_for_task(&self, task_id: &str, timeout: Duration) -> bool {
        let completion = {
            let Ok(map) = self.inner.read() else {
                return false;
            };
            let Some(entry) = map.get(task_id) else {
                return false;
            };
            Arc::clone(&entry.completion)
        };
        let Ok(done_guard) = completion.0.lock() else {
            return false;
        };
        completion
            .1
            .wait_timeout_while(done_guard, timeout, |done| !*done)
            .is_ok_and(|(guard, _)| *guard)
    }

    fn spawn_worker(&self, launch: WorkerLaunch) {
        let worker = Arc::clone(&self.worker);
        let cfg = Arc::clone(&self.config);
        let inner = Arc::clone(&self.inner);
        let store_path = self.store_path.clone();
        let persist_lock = Arc::clone(&self.persist_lock);

        std::thread::spawn(move || {
            let _guard = CompletionGuard(launch.completion);
            if let Some(prev) = launch.prev_completion {
                if let Ok(done_guard) = prev.0.lock() {
                    let _ = prev
                        .1
                        .wait_timeout_while(done_guard, Duration::from_secs(5), |done| !*done);
                }
            }
            let result = if launch.cancelled.load(Ordering::Relaxed) {
                Err(GoFileError::Cancelled)
            } else {
                let hooks: Arc<dyn ProgressHooks> = Arc::new(TaskProgressBridge {
                    task_id: launch.task_id.clone(),
                    attempt: launch.attempt,
                    out_base: launch.out_base,
                    started_at: Instant::now(),
                    inner: Arc::clone(&inner),
                    store_path: store_path.clone(),
                    persist_lock: Arc::clone(&persist_lock),
                    cancelled: Arc::clone(&launch.cancelled),
                    paused: Arc::clone(&launch.paused),
                });
                resolve_confined_output_dir(&cfg.base_dir, launch.req.directory.as_deref())
                    .and_then(|_| worker(launch.req, cfg, hooks))
            };
            finalize_task_status(
                &inner,
                &launch.task_id,
                launch.attempt,
                &launch.cancelled,
                result,
            );
            persist_tasks_to_disk(&inner, store_path.as_deref(), &persist_lock);
        });
    }

    /// Returns a snapshot of all registered tasks keyed by `task_id`.
    #[must_use]
    pub fn list_tasks(&self) -> HashMap<String, TaskSnapshot> {
        self.prune_expired_tasks();
        let Ok(map) = self.inner.read() else {
            return HashMap::new();
        };
        map.iter()
            .map(|(k, v)| (k.clone(), v.snapshot.clone()))
            .collect()
    }

    /// Returns the current progress percentage for `task_id`, if present.
    #[must_use]
    pub fn get_progress(&self, task_id: &str) -> Option<u8> {
        let map = self.inner.read().ok()?;
        map.get(task_id).map(|t| t.snapshot.progress)
    }

    /// Counts tasks currently in `"running"` or `"paused"` states.
    #[must_use]
    pub fn active_count(&self) -> usize {
        let Ok(map) = self.inner.read() else {
            return 0;
        };
        map.values()
            .filter(|t| matches!(t.snapshot.status.as_str(), "running" | "paused"))
            .count()
    }

    /// Toggles pause/resume state for `task_id`, returning `(paused, status)`.
    #[must_use]
    pub fn toggle_pause(&self, task_id: &str) -> Option<(bool, String)> {
        let mut map = self.inner.write().ok()?;
        let entry = map.get_mut(task_id)?;
        if is_terminal_status(&entry.snapshot.status) {
            return Some((entry.snapshot.paused, entry.snapshot.status.clone()));
        }
        let next_paused = !entry.paused.load(Ordering::Relaxed);
        entry.paused.store(next_paused, Ordering::Relaxed);
        entry.snapshot.paused = next_paused;
        let status = if next_paused { "paused" } else { "running" }.to_string();
        entry.snapshot.status.clone_from(&status);
        Some((next_paused, status))
    }

    /// Signals cancellation for `task_id`.
    #[must_use]
    pub fn cancel_task(&self, task_id: &str) -> bool {
        let (found, changed) = {
            let Ok(mut map) = self.inner.write() else {
                return false;
            };
            let Some(entry) = map.get_mut(task_id) else {
                return false;
            };
            let changed = if !is_terminal_status(&entry.snapshot.status) {
                entry.cancelled.store(true, Ordering::Relaxed);
                entry.paused.store(false, Ordering::Relaxed);
                entry.snapshot.paused = false;
                entry.snapshot.status = "cancelled".to_string();
                true
            } else {
                false
            };
            (true, changed)
        };
        if changed {
            self.persist_tasks();
        }
        found
    }

    /// Removes `task_id` from the in-memory list without touching downloaded files.
    #[must_use]
    pub fn remove_task(&self, task_id: &str) -> bool {
        let removed = {
            let Ok(mut map) = self.inner.write() else {
                return false;
            };
            map.remove(task_id).is_some()
        };
        if removed {
            self.persist_tasks();
        }
        removed
    }

    /// Deletes downloaded files on disk for `task_id` and removes the task entry.
    ///
    /// # Errors
    ///
    /// Returns [`GoFileError::Io`] if deletion fails for a reason other than `NotFound`.
    pub fn delete_task_files(&self, task_id: &str) -> Result<Option<String>, GoFileError> {
        let (out_path, completion) = {
            let Ok(mut map) = self.inner.write() else {
                return Ok(None);
            };
            let Some(removed) = map.remove(task_id) else {
                return Ok(None);
            };
            removed.cancelled.store(true, Ordering::Relaxed);
            removed.paused.store(false, Ordering::Relaxed);
            (removed.snapshot.out_path, removed.completion)
        };
        self.persist_tasks();

        if let Ok(done_guard) = completion.0.lock() {
            let _ = completion
                .1
                .wait_timeout_while(done_guard, Duration::from_secs(5), |done| !*done);
        }

        let Some(path) =
            out_path.and_then(|p| confine_deletable_out_path(&self.config.base_dir, &p))
        else {
            return Ok(Some(
                "Files already removed or not found; task removed.".to_string(),
            ));
        };
        let msg = if remove_path_and_part(&path)? {
            format!("Task {task_id} files deleted and task removed.")
        } else {
            "Files already removed or not found; task removed.".to_string()
        };
        Ok(Some(msg))
    }
}

fn confine_deletable_out_path(base_dir: &Path, candidate: &Path) -> Option<PathBuf> {
    let raw = candidate
        .to_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    let canon_base = fs::canonicalize(base_dir).ok()?;
    let resolved = resolve_confined_output_dir(base_dir, Some(raw)).ok()?;
    (resolved != canon_base && resolved.starts_with(&canon_base)).then_some(resolved)
}

fn run_live_task_worker(
    req: StartTaskRequest,
    cfg: Arc<AppConfig>,
    hooks: Arc<dyn ProgressHooks>,
) -> Result<(), GoFileError> {
    let out_dir = resolve_confined_output_dir(&cfg.base_dir, req.directory.as_deref())?;
    check_directory_writable(&out_dir)?;

    let transport = ReqwestTransport::new(cfg.proxy.as_deref(), 45)?;
    let premium = req
        .premium_token
        .filter(|s| !s.trim().is_empty())
        .or_else(|| cfg.premium_token.clone());
    let mut client = GoFileClient::new(transport, premium, WebsiteTokenConfig::from_env());

    let opts = DownloadOptions {
        output_dir: out_dir,
        password: req.password.filter(|s| !s.is_empty()),
        chunk_size: 8192,
        throttle_kbps: req.throttle_kbps,
        retry_attempts: req.retries.min(10),
        retry_delay_secs: cfg.retry_delay,
        strip_emojis: req.strip_emojis,
        incremental: req.incremental,
        folder_pattern: req.folder_pattern,
        config_dir: resolve_tracker_config_dir(&cfg),
    };
    execute_download(&mut client, &req.url, &opts, hooks.as_ref()).map(|_| ())
}

fn effective_config_dir(dir: Option<&Path>) -> Option<&Path> {
    dir.filter(|p| !p.to_string_lossy().trim().is_empty())
}

fn resolve_tracker_config_dir(cfg: &AppConfig) -> Option<PathBuf> {
    let dir = effective_config_dir(cfg.config_dir.as_deref())?;
    if check_directory_writable(dir).is_ok() {
        Some(dir.to_path_buf())
    } else {
        Some(cfg.base_dir.join(".gofile_config"))
    }
}

fn load_persisted_tasks(path: &Path, config: &AppConfig) -> (HashMap<String, ManagedTask>, bool) {
    let Ok(raw) = fs::read_to_string(path) else {
        return (HashMap::new(), false);
    };
    let Ok(store) = serde_json::from_str::<PersistedTaskStore>(&raw) else {
        return (HashMap::new(), false);
    };

    let mut out = HashMap::with_capacity(store.tasks.len());
    let mut recovered = false;
    for (task_id, persisted) in store.tasks {
        let mut snapshot = persisted.snapshot;
        snapshot.download_speed = 0.0;
        snapshot.paused = false;
        snapshot.out_path = persisted
            .out_path
            .and_then(|p| confine_deletable_out_path(&config.base_dir, &p));
        if !is_terminal_status(&snapshot.status) {
            snapshot.status = "error".to_string();
            snapshot.error_message = INTERRUPTED_RESTART_MSG.to_string();
            recovered = true;
        }
        out.insert(
            task_id,
            ManagedTask {
                request: persisted.request.into_start_request(),
                snapshot,
                attempt: 0,
                cancelled: Arc::new(AtomicBool::new(false)),
                paused: Arc::new(AtomicBool::new(false)),
                completion: Arc::new((Mutex::new(true), Condvar::new())),
            },
        );
    }
    (out, recovered)
}

fn persist_tasks_to_disk(
    inner: &RwLock<HashMap<String, ManagedTask>>,
    store_path: Option<&Path>,
    persist_lock: &Mutex<()>,
) {
    let Some(path) = store_path else {
        return;
    };
    let Ok(_io_guard) = persist_lock.lock() else {
        return;
    };
    let payload = {
        let Ok(map) = inner.read() else {
            return;
        };
        let tasks = map
            .iter()
            .map(|(id, task)| {
                (
                    id.clone(),
                    PersistedTask {
                        snapshot: task.snapshot.clone(),
                        out_path: task.snapshot.out_path.clone(),
                        request: PersistedTaskRequest::from(&task.request),
                    },
                )
            })
            .collect();
        PersistedTaskStore {
            version: TASK_STORE_VERSION,
            tasks,
        }
    };
    let Ok(encoded) = serde_json::to_string_pretty(&payload) else {
        return;
    };
    let Some(parent) = path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }
    let tmp_path = parent.join(format!(".tasks.{}.tmp", Uuid::new_v4().simple()));
    if fs::write(&tmp_path, encoded).is_err() || fs::rename(&tmp_path, path).is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
}

fn finalize_task_status(
    inner: &RwLock<HashMap<String, ManagedTask>>,
    tid: &str,
    attempt: u64,
    cancelled: &AtomicBool,
    result: Result<(), GoFileError>,
) {
    let Ok(mut map) = inner.write() else {
        return;
    };
    let Some(entry) = map.get_mut(tid) else {
        return;
    };
    if entry.attempt != attempt {
        return;
    }
    let is_cancelled = cancelled.load(Ordering::Relaxed);
    entry.snapshot.status = match result {
        Ok(()) if !is_cancelled => "completed".to_string(),
        Ok(()) | Err(GoFileError::Cancelled) => "cancelled".to_string(),
        Err(err) => {
            entry.snapshot.error_message = err.to_string();
            if is_cancelled { "cancelled" } else { "error" }.to_string()
        }
    };
    entry.snapshot.progress = 100;
}

struct TaskProgressBridge {
    task_id: String,
    attempt: u64,
    out_base: PathBuf,
    started_at: Instant,
    inner: Arc<RwLock<HashMap<String, ManagedTask>>>,
    store_path: Option<PathBuf>,
    persist_lock: Arc<Mutex<()>>,
    cancelled: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
}

impl ProgressHooks for TaskProgressBridge {
    fn on_name(&self, name: &str) {
        let updated = {
            let Ok(mut map) = self.inner.write() else {
                return;
            };
            if let Some(t) = map
                .get_mut(&self.task_id)
                .filter(|t| t.attempt == self.attempt)
            {
                t.snapshot.name = name.to_string();
                t.snapshot.out_path = Some(self.out_base.join(name));
                true
            } else {
                false
            }
        };
        if updated {
            persist_tasks_to_disk(&self.inner, self.store_path.as_deref(), &self.persist_lock);
        }
    }

    fn on_progress(&self, percent: u8) {
        let Ok(mut map) = self.inner.write() else {
            return;
        };
        if let Some(t) = map
            .get_mut(&self.task_id)
            .filter(|t| t.attempt == self.attempt)
        {
            t.snapshot.progress = percent;
        }
    }

    fn on_overall_progress(&self, percent: u8, folder_name: &str) {
        let Ok(mut map) = self.inner.write() else {
            return;
        };
        let Some(t) = map
            .get_mut(&self.task_id)
            .filter(|t| t.attempt == self.attempt)
        else {
            return;
        };
        t.snapshot.overall_progress = percent;
        t.snapshot.current_folder = folder_name.to_string();
        let elapsed = self.started_at.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            t.snapshot.download_speed = estimate_downloaded_bytes(&t.snapshot.files) / elapsed;
        }
    }

    fn on_file_progress(
        &self,
        file_path: &Path,
        progress: i32,
        size: Option<u64>,
        retry_info: Option<&str>,
    ) {
        let key = file_path.to_string_lossy().into_owned();
        let Ok(mut map) = self.inner.write() else {
            return;
        };
        let Some(t) = map
            .get_mut(&self.task_id)
            .filter(|t| t.attempt == self.attempt)
        else {
            return;
        };
        upsert_file_record(&mut t.snapshot.files, key, progress, size, retry_info);
    }

    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

fn estimate_downloaded_bytes(files: &[FileProgressRecord]) -> f64 {
    files
        .iter()
        .filter_map(|f| {
            let sz = f.size? as f64;
            let p = f64::from(f.progress.max(0));
            Some((sz * p) / 100.0)
        })
        .sum()
}

fn upsert_file_record(
    files: &mut Vec<FileProgressRecord>,
    key: String,
    progress: i32,
    size: Option<u64>,
    retry_info: Option<&str>,
) {
    if let Some(rec) = files.iter_mut().find(|r| r.file == key) {
        rec.progress = progress;
        if size.is_some() {
            rec.size = size;
        }
        rec.retry_info = retry_info.map(str::to_owned);
    } else {
        files.push(FileProgressRecord {
            file: key,
            progress,
            size,
            retry_info: retry_info.map(str::to_owned),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_config_dir_handles_empty_writable_and_unwritable_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let base_dir = tmp.path().join("data");
        let writable_cfg = tmp.path().join("cfg");
        let blocking_file = tmp.path().join("not_a_dir");
        fs::create_dir_all(&base_dir).unwrap();
        fs::create_dir_all(&writable_cfg).unwrap();
        fs::write(&blocking_file, b"file").unwrap();

        let cfg_none = AppConfig {
            base_dir: base_dir.clone(),
            config_dir: None,
            ..AppConfig::default()
        };
        assert_eq!(resolve_tracker_config_dir(&cfg_none), None);

        let cfg_empty = AppConfig {
            base_dir: base_dir.clone(),
            config_dir: Some(PathBuf::from("   ")),
            ..AppConfig::default()
        };
        assert_eq!(resolve_tracker_config_dir(&cfg_empty), None);

        let cfg_ok = AppConfig {
            base_dir: base_dir.clone(),
            config_dir: Some(writable_cfg.clone()),
            ..AppConfig::default()
        };
        assert_eq!(resolve_tracker_config_dir(&cfg_ok), Some(writable_cfg));

        let cfg_unwritable = AppConfig {
            base_dir: base_dir.clone(),
            config_dir: Some(blocking_file),
            ..AppConfig::default()
        };
        assert_eq!(
            resolve_tracker_config_dir(&cfg_unwritable),
            Some(base_dir.join(".gofile_config"))
        );
    }
}
