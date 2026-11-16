//! Recursive GoFile folder/file tree orchestrator, progress hooks, and incremental
//! sync integration.
//!
//! ## Architecture
//!
//! - **Tree Traversal**: [`execute_download`] resolves root and nested GoFile content
//!   nodes via [`GoFileClient::fetch_contents`], applying [`safe_child_path`] confinement
//!   at every folder and file boundary to prevent directory traversal (`../`) escapes.
//! - **Incremental Sync**: When [`DownloadOptions::incremental`] is enabled, incoming
//!   folders are matched against locally renamed folders via [`DownloadTracker::find_existing_folder`],
//!   and previously completed `(file_id, logical_name)` pairs are skipped without network I/O.
//! - **Streaming Delegation**: Single-file HTTP range streaming, `.part` staging, and
//!   bandwidth throttling live in [`crate::transfer`] and are re-exported here.

pub use crate::transfer::{download_file, part_file_path};

use crate::client::{ContentNode, GoFileClient, HttpTransport};
use crate::error::GoFileError;
use crate::sanitize::{safe_child_path, DEFAULT_FOLDER_PATTERNS};
use crate::token::parse_content_id;
use crate::tracker::DownloadTracker;
use std::fs;
use std::path::{Path, PathBuf};

/// Configuration for a single file or recursive folder download operation.
#[derive(Debug, Clone)]
pub struct DownloadOptions {
    /// Destination directory where files/subfolders are written.
    pub output_dir: PathBuf,
    /// Optional plaintext password for protected GoFile shares.
    pub password: Option<String>,
    /// Read buffer chunk size in bytes (default: `8192`).
    pub chunk_size: usize,
    /// Optional speed limit in KB/s (`None` or `Some(0)` = unlimited).
    pub throttle_kbps: Option<u64>,
    /// Maximum retry attempts per file on transient errors (`0..=10`).
    pub retry_attempts: u32,
    /// Delay between retries in seconds.
    pub retry_delay_secs: u64,
    /// Strip emojis and decorative pictographs from remote names.
    pub strip_emojis: bool,
    /// Skip files already recorded in [`DownloadTracker`] and match renamed folders.
    pub incremental: bool,
    /// Pipe-delimited prefix patterns stripped when matching renamed folders.
    pub folder_pattern: String,
    /// Optional explicit directory for `.gofile_tracker_{id}.json` files.
    pub config_dir: Option<PathBuf>,
}

impl DownloadOptions {
    /// Creates sensible defaults targeting `output_dir` (`8192`-byte chunks, `3` retries,
    /// `5`s backoff, unlimited speed, and non-incremental mode).
    ///
    /// # Examples
    ///
    /// ```
    /// use gofile_dl::downloader::DownloadOptions;
    /// use std::path::Path;
    ///
    /// let opts = DownloadOptions::new("/tmp/downloads");
    /// assert_eq!(opts.output_dir, Path::new("/tmp/downloads"));
    /// assert_eq!(opts.chunk_size, 8192);
    /// assert_eq!(opts.retry_attempts, 3);
    /// ```
    #[must_use]
    pub fn new(output_dir: impl Into<PathBuf>) -> Self {
        Self {
            output_dir: output_dir.into(),
            password: None,
            chunk_size: 8192,
            throttle_kbps: None,
            retry_attempts: 3,
            retry_delay_secs: 5,
            strip_emojis: false,
            incremental: false,
            folder_pattern: DEFAULT_FOLDER_PATTERNS.to_string(),
            config_dir: None,
        }
    }
}

/// Summary statistics returned upon finishing an [`execute_download`] call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DownloadSummary {
    /// Resolved root folder or file display name.
    pub root_name: String,
    /// Final root path written on disk.
    pub root_path: PathBuf,
    /// Number of files downloaded over HTTP.
    pub files_downloaded: usize,
    /// Number of files skipped due to incremental sync tracking.
    pub files_skipped: usize,
    /// Number of child files that failed permanently.
    pub files_failed: usize,
}

/// Callback & control interface used by CLI loggers and Web UI task state.
pub trait ProgressHooks: Send + Sync {
    /// Updates resolved root task name.
    fn on_name(&self, _name: &str) {}
    /// Updates active transfer progress (`0..=100`).
    fn on_progress(&self, _percent: u8) {}
    /// Updates overall folder completion (`0..=100`) and active folder name.
    fn on_overall_progress(&self, _percent: u8, _folder_name: &str) {}
    /// Updates per-file status (`0..=100`, `-1` retrying, `-2` failed).
    fn on_file_progress(
        &self,
        _file_path: &Path,
        _progress: i32,
        _size: Option<u64>,
        _retry_info: Option<&str>,
    ) {
    }
    /// Returns `true` while the user has paused the task.
    fn is_paused(&self) -> bool {
        false
    }
    /// Returns `true` if the user requested task cancellation.
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// Zero-overhead no-op implementation of [`ProgressHooks`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopHooks;
impl ProgressHooks for NoopHooks {}

/// Executes a full GoFile download from a share URL or bare content ID.
///
/// # Errors
///
/// Returns [`GoFileError`] if URL parsing, authentication, root metadata lookup,
/// cancellation, or transfer fails.
pub fn execute_download<T: HttpTransport>(
    client: &mut GoFileClient<T>,
    url_or_id: &str,
    options: &DownloadOptions,
    hooks: &dyn ProgressHooks,
) -> Result<DownloadSummary, GoFileError> {
    let content_id = parse_content_id(url_or_id)
        .ok_or_else(|| GoFileError::InvalidUrl(url_or_id.to_string()))?;

    let mut tracker = if options.incremental {
        let pat = Some(options.folder_pattern.as_str());
        Some(if let Some(cfg_dir) = &options.config_dir {
            DownloadTracker::with_config_dir(&options.output_dir, cfg_dir, &content_id, pat)?
        } else {
            DownloadTracker::new(&options.output_dir, &content_id, pat)?
        })
    } else {
        None
    };

    let mut summary = DownloadSummary::default();
    execute_node(
        client,
        &content_id,
        &options.output_dir,
        options,
        hooks,
        tracker.as_mut(),
        true,
        &mut summary,
    )?;

    if summary.files_failed > 0 && summary.files_downloaded == 0 {
        return Err(GoFileError::Download {
            message: format!("{} file(s) failed to download", summary.files_failed),
            filename: summary.root_name,
            url: url_or_id.to_string(),
        });
    }
    Ok(summary)
}

#[allow(clippy::too_many_arguments)]
fn execute_node<T: HttpTransport>(
    client: &mut GoFileClient<T>,
    content_id: &str,
    parent_dir: &Path,
    options: &DownloadOptions,
    hooks: &dyn ProgressHooks,
    mut tracker: Option<&mut DownloadTracker>,
    is_root: bool,
    summary: &mut DownloadSummary,
) -> Result<(), GoFileError> {
    if hooks.is_cancelled() {
        return Err(GoFileError::Cancelled);
    }

    let node: ContentNode = client.fetch_contents(content_id, options.password.as_deref())?;
    if node.node_type == "folder" {
        let folder_path = resolve_folder_path(
            parent_dir,
            &node.name,
            content_id,
            options.strip_emojis,
            tracker.as_deref(),
        )?;
        let display_name = folder_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&node.name)
            .to_string();

        if is_root {
            hooks.on_name(&display_name);
            summary.root_name.clone_from(&display_name);
            summary.root_path.clone_from(&folder_path);
        }
        fs::create_dir_all(&folder_path)?;

        let children = node.effective_children();
        if children.is_empty() {
            hooks.on_overall_progress(100, &node.name);
            return Ok(());
        }

        let total = children.len();
        for (idx, (child_id, child)) in children.iter().enumerate() {
            if hooks.is_cancelled() {
                return Err(GoFileError::Cancelled);
            }
            if child.item_type == "folder" {
                execute_node(
                    client,
                    child_id,
                    &folder_path,
                    options,
                    hooks,
                    tracker.as_deref_mut(),
                    false,
                    summary,
                )?;
            } else {
                process_child_file(
                    client,
                    child_id,
                    &child.name,
                    child.link.as_deref(),
                    &folder_path,
                    options,
                    hooks,
                    tracker.as_deref_mut(),
                    summary,
                )?;
            }
            let pct = (((idx + 1) * 100) / total).min(100) as u8;
            hooks.on_overall_progress(pct, &node.name);
        }
        hooks.on_overall_progress(100, &node.name);
    } else {
        let file_path = safe_child_path(parent_dir, &node.name, options.strip_emojis, content_id)?;
        let display_name = file_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&node.name)
            .to_string();
        if is_root {
            hooks.on_name(&display_name);
            summary.root_name = display_name;
            summary.root_path.clone_from(&file_path);
        }
        if let Some(ref trk) = tracker {
            if trk.is_downloaded(content_id, &node.name) {
                hooks.on_file_progress(&file_path, 100, None, None);
                hooks.on_overall_progress(100, &node.name);
                summary.files_skipped += 1;
                return Ok(());
            }
        }
        let link = node
            .link
            .as_deref()
            .filter(|l| !l.is_empty())
            .ok_or_else(|| GoFileError::Download {
                message: "Missing download link".to_string(),
                filename: node.name.clone(),
                url: content_id.to_string(),
            })?;
        hooks.on_file_progress(&file_path, 0, None, None);
        download_file(client, link, &file_path, options, hooks)?;
        if let Some(trk) = tracker {
            trk.mark_downloaded(content_id, &node.name)?;
        }
        hooks.on_file_progress(&file_path, 100, None, None);
        hooks.on_overall_progress(100, &node.name);
        summary.files_downloaded += 1;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn process_child_file<T: HttpTransport>(
    client: &mut GoFileClient<T>,
    child_id: &str,
    raw_name: &str,
    link_opt: Option<&str>,
    folder_path: &Path,
    options: &DownloadOptions,
    hooks: &dyn ProgressHooks,
    tracker: Option<&mut DownloadTracker>,
    summary: &mut DownloadSummary,
) -> Result<(), GoFileError> {
    let file_path = safe_child_path(folder_path, raw_name, options.strip_emojis, child_id)?;
    if let Some(ref trk) = tracker {
        if trk.is_downloaded(child_id, raw_name) {
            hooks.on_file_progress(&file_path, 100, None, None);
            summary.files_skipped += 1;
            return Ok(());
        }
    }

    let Some(link) = link_opt.filter(|l| !l.is_empty()) else {
        summary.files_failed += 1;
        hooks.on_file_progress(&file_path, -2, None, None);
        return Ok(());
    };

    hooks.on_file_progress(&file_path, 0, None, None);
    // Fix Bug #3: Only mark downloaded in `DownloadTracker` when `download_file` succeeds!
    match download_file(client, link, &file_path, options, hooks) {
        Ok(()) => {
            if let Some(trk) = tracker {
                trk.mark_downloaded(child_id, raw_name)?;
            }
            hooks.on_file_progress(&file_path, 100, None, None);
            summary.files_downloaded += 1;
            Ok(())
        }
        Err(GoFileError::Cancelled) => Err(GoFileError::Cancelled),
        Err(_) => {
            summary.files_failed += 1;
            Ok(())
        }
    }
}

fn resolve_folder_path(
    parent_dir: &Path,
    raw_dirname: &str,
    content_id: &str,
    strip_emoji_flag: bool,
    tracker: Option<&DownloadTracker>,
) -> Result<PathBuf, GoFileError> {
    let default_path = safe_child_path(parent_dir, raw_dirname, strip_emoji_flag, content_id)?;
    let cleaned_name = default_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(raw_dirname);

    if let Some(trk) = tracker {
        if let Some(existing) = trk
            .find_existing_folder(raw_dirname, parent_dir)
            .or_else(|| trk.find_existing_folder(cleaned_name, parent_dir))
        {
            return Ok(existing);
        }
    }
    Ok(default_path)
}
