//! Task DTO schemas, directory writability probing, and canonical path-confined
//! filesystem browsing (`/browse`).
//!
//! ## Confinement Model
//!
//! - [`resolve_confined_output_dir`] resolves both existing and newly requested nested
//!   output folders while verifying via `fs::canonicalize` that neither `..` components
//!   nor symlinks escape `base_dir`.
//! - [`browse_confined_directory`] confines directory listings to `base_dir`, clamping
//!   parent traversal attempts back to `base_dir`.

use crate::error::GoFileError;
use crate::sanitize::DEFAULT_FOLDER_PATTERNS;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

/// Per-file transfer state serialized to the Web UI `/tasks` JSON endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileProgressRecord {
    /// Full or relative file path.
    pub file: String,
    /// Progress percentage (`0..=100`), `-1` (retrying), or `-2` (failed).
    pub progress: i32,
    /// Optional byte size reported by `Content-Length`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Optional human-readable retry status string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_info: Option<String>,
}

/// Public task snapshot matching the exact JSON schema expected by `templates/index.html`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSnapshot {
    /// Current file transfer percentage (`0..=100`).
    pub progress: u8,
    /// Overall folder item completion percentage (`0..=100`).
    pub overall_progress: u8,
    /// Active folder display name.
    pub current_folder: String,
    /// Estimated aggregate download speed in bytes/sec.
    pub download_speed: f64,
    /// Lifecycle state (`"running"`, `"paused"`, `"completed"`, `"error"`, `"cancelled"`).
    pub status: String,
    /// Diagnostic error message when `status == "error"`.
    pub error_message: String,
    /// Original GoFile URL or content ID submitted.
    pub url: String,
    /// Optional destination directory requested by caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
    /// Friendly task title shown on dashboard cards.
    pub name: String,
    /// Unix epoch timestamp (seconds) when the task was created.
    pub timestamp: f64,
    /// Per-file progress records.
    pub files: Vec<FileProgressRecord>,
    /// True if currently paused.
    pub paused: bool,
    /// Resolved output path on disk (used by `/delete/{task_id}`).
    #[serde(skip_serializing)]
    pub out_path: Option<PathBuf>,
}

/// Validated parameters submitted to `POST /start` or `POST /`.
#[derive(Debug, Clone)]
pub struct StartTaskRequest {
    /// GoFile share URL or bare content ID.
    pub url: String,
    /// Optional destination directory override.
    pub directory: Option<String>,
    /// Optional password for protected shares.
    pub password: Option<String>,
    /// Optional bandwidth throttle in KB/s.
    pub throttle_kbps: Option<u64>,
    /// Bounded retry count (`0..=10`).
    pub retries: u32,
    /// Strip emojis from folder/file names.
    pub strip_emojis: bool,
    /// Enable incremental sync mode.
    pub incremental: bool,
    /// Pipe-separated folder rename patterns.
    pub folder_pattern: String,
    /// Optional per-task premium token override.
    pub premium_token: Option<String>,
}

impl StartTaskRequest {
    /// Creates a minimal request for `url` using default retry and pattern settings.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            directory: None,
            password: None,
            throttle_kbps: None,
            retries: 3,
            strip_emojis: false,
            incremental: false,
            folder_pattern: DEFAULT_FOLDER_PATTERNS.to_string(),
            premium_token: None,
        }
    }
}

/// Derives a friendly initial task title from `directory` or `url`.
///
/// # Examples
///
/// ```
/// use gofile_dl::browse::derive_initial_task_name;
///
/// assert_eq!(derive_initial_task_name("https://gofile.io/d/abc123", None), "abc123");
/// assert_eq!(derive_initial_task_name("https://gofile.io/d/abc123", Some("/data/Movies/")), "Movies");
/// ```
#[must_use]
pub fn derive_initial_task_name(url: &str, directory: Option<&str>) -> String {
    if let Some(dir) = directory.map(str::trim).filter(|s| !s.is_empty()) {
        let trimmed = dir.trim_end_matches(['/', '\\']);
        let base = Path::new(trimmed)
            .file_name()
            .and_then(|s| s.to_str())
            .filter(|b| !b.is_empty());
        return base.unwrap_or("download").to_string();
    }
    url.rsplit('/').next().unwrap_or(url).to_string()
}

/// Verifies `dir` can be created and written to before launching a download.
///
/// # Errors
///
/// Returns [`GoFileError::Io`] if directory creation or probe file write fails.
pub fn check_directory_writable(dir: &Path) -> Result<(), GoFileError> {
    fs::create_dir_all(dir)?;
    let probe = dir.join(format!(".gofile_probe_{}", Uuid::new_v4().simple()));
    fs::write(&probe, b"ok")?;
    let _ = fs::remove_file(&probe);
    Ok(())
}

/// Returns `true` if `dir` already exists as a directory and is writable by the current UID.
#[must_use]
pub fn probe_existing_dir_writable(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let probe = dir.join(format!(".gofile_health_{}", Uuid::new_v4().simple()));
    if fs::write(&probe, b"ok").is_ok() {
        let _ = fs::remove_file(&probe);
        true
    } else {
        false
    }
}

/// Resolves an optional task `directory` relative to canonical `base_dir`, permitting new
/// subdirectories inside `base_dir` while rejecting any `..`, symlink, or absolute path
/// escaping `base_dir`.
///
/// # Errors
///
/// Returns [`GoFileError::PathSafety`] if `requested` escapes `base_dir`, or [`GoFileError::Io`]
/// if `base_dir` cannot be created/canonicalized.
pub fn resolve_confined_output_dir(
    base_dir: &Path,
    requested: Option<&str>,
) -> Result<PathBuf, GoFileError> {
    fs::create_dir_all(base_dir)?;
    let canon_base = fs::canonicalize(base_dir)?;
    let Some(raw_str) = requested.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(canon_base);
    };

    let normalized = normalize_requested_path(&canon_base, Path::new(raw_str))?;
    if !normalized.starts_with(&canon_base) {
        return Err(GoFileError::PathSafety(
            "Output directory must reside within base_dir".to_string(),
        ));
    }
    verify_symlink_ancestor(&canon_base, &normalized)
}

fn normalize_requested_path(canon_base: &Path, raw_path: &Path) -> Result<PathBuf, GoFileError> {
    let mut normalized = if raw_path.is_absolute() {
        PathBuf::new()
    } else {
        canon_base.to_path_buf()
    };

    for comp in raw_path.components() {
        apply_path_component(canon_base, raw_path.is_absolute(), &mut normalized, comp)?;
    }
    Ok(normalized)
}

fn apply_path_component(
    canon_base: &Path,
    is_abs: bool,
    normalized: &mut PathBuf,
    comp: Component<'_>,
) -> Result<(), GoFileError> {
    match comp {
        Component::Prefix(p) => normalized.push(p.as_os_str()),
        Component::RootDir => normalized.push(comp.as_os_str()),
        Component::CurDir => {}
        Component::Normal(seg) => normalized.push(seg),
        Component::ParentDir => {
            if (!is_abs && normalized == canon_base) || !normalized.pop() {
                return Err(GoFileError::PathSafety(
                    "Output directory escapes base_dir".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn verify_symlink_ancestor(canon_base: &Path, normalized: &Path) -> Result<PathBuf, GoFileError> {
    let mut existing = normalized;
    let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
    while !existing.exists() {
        if let Some(name) = existing.file_name() {
            tail.push(name);
        }
        let Some(parent) = existing.parent() else {
            break;
        };
        existing = parent;
    }
    let mut resolved = fs::canonicalize(existing)?;
    if !resolved.starts_with(canon_base) {
        return Err(GoFileError::PathSafety(
            "Output directory symlink escapes base_dir".to_string(),
        ));
    }
    for seg in tail.into_iter().rev() {
        resolved.push(seg);
    }
    Ok(resolved)
}

/// Resolves `requested` inside canonical `base_dir`, clamping any `..` or external
/// absolute path back to `base_dir` (matching `app.py:389-415`).
///
/// # Examples
///
/// ```
/// use gofile_dl::browse::browse_confined_directory;
///
/// let tmp = std::env::temp_dir().join("gofile_browse_doc");
/// std::fs::create_dir_all(tmp.join("sub")).unwrap();
/// let (base, cur, dirs) = browse_confined_directory(&tmp, "../../../etc").unwrap();
/// assert_eq!(base, cur);
/// assert_eq!(dirs, vec!["sub".to_string()]);
/// let _ = std::fs::remove_dir_all(&tmp);
/// ```
///
/// # Errors
///
/// Returns [`GoFileError::PathSafety`] if the resolved target is not an existing directory.
pub fn browse_confined_directory(
    base_dir: &Path,
    requested: &str,
) -> Result<(PathBuf, PathBuf, Vec<String>), GoFileError> {
    fs::create_dir_all(base_dir)?;
    let canon_base = fs::canonicalize(base_dir)?;
    let candidate = resolve_browse_candidate(&canon_base, requested.trim())?;
    if !candidate.is_dir() {
        return Err(GoFileError::PathSafety("Invalid path".to_string()));
    }

    let mut dirs: Vec<String> = fs::read_dir(&candidate)?
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    dirs.sort();
    Ok((canon_base, candidate, dirs))
}

fn resolve_browse_candidate(canon_base: &Path, req_trimmed: &str) -> Result<PathBuf, GoFileError> {
    if req_trimmed.is_empty() {
        return Ok(canon_base.to_path_buf());
    }
    let joined = if Path::new(req_trimmed).is_absolute() {
        PathBuf::from(req_trimmed)
    } else {
        canon_base.join(req_trimmed)
    };
    let Ok(canon) = fs::canonicalize(&joined) else {
        return Err(GoFileError::PathSafety("Invalid path".to_string()));
    };
    if canon.starts_with(canon_base) {
        Ok(canon)
    } else {
        Ok(canon_base.to_path_buf())
    }
}
