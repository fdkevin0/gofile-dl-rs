//! Thread-safe download task registry and background worker lifecycle manager.
//!
//! Replaces the legacy unprotected global `download_tasks` dictionary in `app.py:133`
//! with an `Arc<RwLock<HashMap<String, ManagedTask>>>`, lock-free `AtomicBool`
//! cancellation/pause flags, `Condvar`-synchronized file deletion, and automatic
//! eviction of expired terminal tasks (`task_expiry`).

pub use crate::browse::{
    browse_confined_directory, check_directory_writable, derive_initial_task_name,
    resolve_confined_output_dir, FileProgressRecord, StartTaskRequest, TaskSnapshot,
};

use crate::client::{GoFileClient, ReqwestTransport};
use crate::config::AppConfig;
use crate::downloader::{execute_download, DownloadOptions, ProgressHooks};
use crate::error::GoFileError;
use crate::token::WebsiteTokenConfig;
use crate::transfer::remove_path_and_part;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

struct ManagedTask {
    snapshot: TaskSnapshot,
    cancelled: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    completion: Arc<(Mutex<bool>, Condvar)>,
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
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            config,
            worker,
        }
    }

    /// Evicts terminal (`completed`/`error`/`cancelled`) tasks older than `config.task_expiry`.
    pub fn prune_expired_tasks(&self) {
        let ttl = self.config.task_expiry;
        if ttl == 0 {
            return;
        }
        let Ok(mut map) = self.inner.write() else {
            return;
        };
        let cutoff = now_epoch_secs() - (ttl as f64);
        map.retain(|_, t| !is_terminal_status(&t.snapshot.status) || t.snapshot.timestamp > cutoff);
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
                    snapshot,
                    cancelled: Arc::clone(&cancelled),
                    paused: Arc::clone(&paused),
                    completion: Arc::clone(&completion),
                },
            );
        }

        let hooks: Arc<dyn ProgressHooks> = Arc::new(TaskProgressBridge {
            task_id: task_id.clone(),
            out_base,
            started_at: Instant::now(),
            inner: Arc::clone(&self.inner),
            cancelled: Arc::clone(&cancelled),
            paused: Arc::clone(&paused),
        });

        let worker = Arc::clone(&self.worker);
        let cfg = Arc::clone(&self.config);
        let inner = Arc::clone(&self.inner);
        let tid = task_id.clone();

        std::thread::spawn(move || {
            let _guard = CompletionGuard(completion);
            let result = resolve_confined_output_dir(&cfg.base_dir, req.directory.as_deref())
                .and_then(|_| worker(req, cfg, hooks));
            finalize_task_status(&inner, &tid, &cancelled, result);
        });

        task_id
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
        let Ok(mut map) = self.inner.write() else {
            return false;
        };
        let Some(entry) = map.get_mut(task_id) else {
            return false;
        };
        if !is_terminal_status(&entry.snapshot.status) {
            entry.cancelled.store(true, Ordering::Relaxed);
            entry.paused.store(false, Ordering::Relaxed);
            entry.snapshot.paused = false;
            entry.snapshot.status = "cancelled".to_string();
        }
        true
    }

    /// Removes `task_id` from the in-memory list without touching downloaded files.
    #[must_use]
    pub fn remove_task(&self, task_id: &str) -> bool {
        let Ok(mut map) = self.inner.write() else {
            return false;
        };
        map.remove(task_id).is_some()
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

        if let Ok(done_guard) = completion.0.lock() {
            let _ = completion
                .1
                .wait_timeout_while(done_guard, Duration::from_secs(5), |done| !*done);
        }

        let Some(path) = out_path else {
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
        config_dir: None,
    };
    execute_download(&mut client, &req.url, &opts, hooks.as_ref()).map(|_| ())
}

fn finalize_task_status(
    inner: &RwLock<HashMap<String, ManagedTask>>,
    tid: &str,
    cancelled: &AtomicBool,
    result: Result<(), GoFileError>,
) {
    let Ok(mut map) = inner.write() else {
        return;
    };
    let Some(entry) = map.get_mut(tid) else {
        return;
    };
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
    out_base: PathBuf,
    started_at: Instant,
    inner: Arc<RwLock<HashMap<String, ManagedTask>>>,
    cancelled: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
}

impl ProgressHooks for TaskProgressBridge {
    fn on_name(&self, name: &str) {
        let Ok(mut map) = self.inner.write() else {
            return;
        };
        if let Some(t) = map.get_mut(&self.task_id) {
            t.snapshot.name = name.to_string();
            t.snapshot.out_path = Some(self.out_base.join(name));
        }
    }

    fn on_progress(&self, percent: u8) {
        let Ok(mut map) = self.inner.write() else {
            return;
        };
        if let Some(t) = map.get_mut(&self.task_id) {
            t.snapshot.progress = percent;
        }
    }

    fn on_overall_progress(&self, percent: u8, folder_name: &str) {
        let Ok(mut map) = self.inner.write() else {
            return;
        };
        let Some(t) = map.get_mut(&self.task_id) else {
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
        let Some(t) = map.get_mut(&self.task_id) else {
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
