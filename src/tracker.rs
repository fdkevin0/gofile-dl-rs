//! Incremental download state tracker and renamed-folder resolver.
//!
//! Persists `file_id:file_name` completion sets in `.gofile_tracker_{content_id}.json`
//! inside `CONFIG_DIR` using atomic temporary-file writes so interrupted runs never
//! leave truncated JSON state on disk.

use crate::browse::check_directory_writable;
use crate::error::GoFileError;
use crate::sanitize::{sanitize_filename, FolderNormalizer};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// On-disk JSON schema compatible with legacy `.gofile_tracker_{id}.json` files.
#[derive(Debug, Serialize, Deserialize)]
struct TrackerDiskPayload {
    content_id: String,
    last_updated: f64,
    files: Vec<String>,
}

/// Tracks downloaded `file_id:file_name` pairs and resolves renamed target folders
/// during incremental/sync downloads.
///
/// # Examples
///
/// ```
/// use gofile_dl::tracker::DownloadTracker;
///
/// let tmp = std::env::temp_dir().join("gofile_doc_tracker");
/// let mut tracker = DownloadTracker::with_config_dir(
///     &tmp,
///     &tmp,
///     "abc123",
///     Some("⭐NEW FILES in |NEW FILES in |⭐"),
/// ).unwrap();
/// assert!(!tracker.is_downloaded("f1", "ep1.mkv"));
/// tracker.mark_downloaded("f1", "ep1.mkv").unwrap();
/// assert!(tracker.is_downloaded("f1", "ep1.mkv"));
/// let _ = std::fs::remove_dir_all(&tmp);
/// ```
#[derive(Debug, Clone)]
pub struct DownloadTracker {
    base_dir: PathBuf,
    content_id: String,
    tracking_file: PathBuf,
    normalizer: FolderNormalizer,
    downloaded_files: HashSet<String>,
}

impl DownloadTracker {
    /// Creates or loads a tracker storing JSON metadata under `CONFIG_DIR`
    /// (falling back to `base_dir/.gofile_config` if `/config` is not writable).
    ///
    /// # Errors
    ///
    /// Returns [`GoFileError::Io`] if no writable configuration directory can be created.
    pub fn new(
        base_dir: &Path,
        content_id: &str,
        folder_pattern: Option<&str>,
    ) -> Result<Self, GoFileError> {
        let env_cfg = std::env::var("CONFIG_DIR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map_or_else(|| PathBuf::from("/config"), PathBuf::from);

        let config_dir = if check_directory_writable(&env_cfg).is_ok() {
            env_cfg
        } else {
            let fallback = base_dir.join(".gofile_config");
            fs::create_dir_all(&fallback)?;
            fallback
        };

        Self::with_config_dir(base_dir, &config_dir, content_id, folder_pattern)
    }

    /// Creates or loads a tracker using an explicit `config_dir`.
    ///
    /// # Errors
    ///
    /// Returns [`GoFileError::Io`] if `config_dir` cannot be created.
    pub fn with_config_dir(
        base_dir: &Path,
        config_dir: &Path,
        content_id: &str,
        folder_pattern: Option<&str>,
    ) -> Result<Self, GoFileError> {
        fs::create_dir_all(config_dir)?;
        let safe_id = sanitize_filename(content_id);
        let tracking_file = config_dir.join(format!(".gofile_tracker_{safe_id}.json"));
        let mut tracker = Self {
            base_dir: base_dir.to_path_buf(),
            content_id: content_id.to_string(),
            tracking_file,
            normalizer: FolderNormalizer::new(folder_pattern),
            downloaded_files: HashSet::new(),
        };
        tracker.load_tracking_data();
        Ok(tracker)
    }

    /// Base download directory associated with this tracker.
    #[must_use]
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Path to the backing `.gofile_tracker_{id}.json` file.
    #[must_use]
    pub fn tracking_file(&self) -> &Path {
        &self.tracking_file
    }

    /// Number of tracked completed files.
    #[must_use]
    pub fn len(&self) -> usize {
        self.downloaded_files.len()
    }

    /// Returns `true` if no files have been recorded yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.downloaded_files.is_empty()
    }

    /// Loads previously persisted file keys if the tracking file exists and is valid JSON.
    pub fn load_tracking_data(&mut self) {
        let Ok(raw) = fs::read_to_string(&self.tracking_file) else {
            return;
        };
        if let Ok(parsed) = serde_json::from_str::<TrackerDiskPayload>(&raw) {
            self.downloaded_files = parsed.files.into_iter().collect();
        }
    }

    /// Atomically persists the current `downloaded_files` set to disk.
    ///
    /// # Errors
    ///
    /// Returns [`GoFileError`] if serialization or atomic file replacement fails.
    pub fn save_tracking_data(&self) -> Result<(), GoFileError> {
        if let Some(parent) = self.tracking_file.parent() {
            fs::create_dir_all(parent)?;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        let mut files: Vec<String> = self.downloaded_files.iter().cloned().collect();
        files.sort();
        let payload = TrackerDiskPayload {
            content_id: self.content_id.clone(),
            last_updated: now,
            files,
        };
        let encoded = serde_json::to_string_pretty(&payload)?;
        let tmp_path = self.tracking_file.with_extension("json.tmp");
        fs::write(&tmp_path, encoded)?;
        fs::rename(&tmp_path, &self.tracking_file)?;
        Ok(())
    }

    /// Checks whether `file_id:file_name` was already completed in an earlier run.
    #[must_use]
    pub fn is_downloaded(&self, file_id: &str, file_name: &str) -> bool {
        let mut key = String::with_capacity(file_id.len() + 1 + file_name.len());
        key.push_str(file_id);
        key.push(':');
        key.push_str(file_name);
        self.downloaded_files.contains(&key)
    }

    /// Records `file_id:file_name` as downloaded and persists the updated ledger.
    ///
    /// # Errors
    ///
    /// Returns [`GoFileError`] if persisting the ledger fails.
    pub fn mark_downloaded(&mut self, file_id: &str, file_name: &str) -> Result<(), GoFileError> {
        self.downloaded_files
            .insert(format!("{file_id}:{file_name}"));
        self.save_tracking_data()
    }

    /// Records `file_id:file_name` in memory without flushing immediately (used by batch arenas).
    #[inline]
    pub fn mark_downloaded_in_memory(&mut self, file_id: &str, file_name: &str) -> bool {
        self.downloaded_files
            .insert(format!("{file_id}:{file_name}"))
    }

    /// Searches `parent_dir` for either an exact folder match or a renamed folder whose
    /// normalized stem equals `normalize(folder_name)`.
    #[must_use]
    pub fn find_existing_folder(&self, folder_name: &str, parent_dir: &Path) -> Option<PathBuf> {
        if !parent_dir.exists() {
            return None;
        }
        let exact = parent_dir.join(sanitize_filename(folder_name));
        if exact.is_dir() {
            return Some(exact);
        }
        let normalized_target = self.normalizer.normalize(folder_name);
        let entries = fs::read_dir(parent_dir).ok()?;
        let mut dir_names: Vec<(String, PathBuf)> = entries
            .filter_map(Result::ok)
            .filter_map(|e| {
                let p = e.path();
                if p.is_dir() {
                    e.file_name().into_string().ok().map(|n| (n, p))
                } else {
                    None
                }
            })
            .collect();
        dir_names.sort_by(|a, b| a.0.cmp(&b.0));

        for (item_name, item_path) in dir_names {
            if self.normalizer.normalize(&item_name) == normalized_target {
                return Some(item_path);
            }
        }
        None
    }
}
