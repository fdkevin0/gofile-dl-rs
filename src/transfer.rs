//! Streaming single-file HTTP downloader with atomic `.part` staging, HTTP `206` vs
//! `200` resume integrity, zero-division-safe progress calculation, KB/s bandwidth
//! throttling, pause/cancel polling, and bounded retries.
//!
//! ## Safety & Integrity Guarantees
//!
//! - **HTTP `206` vs `200` Resume Guard**: Only appends to an existing `.part` file when
//!   the server honors `Range` with `206 Partial Content`; truncates cleanly on `200 OK`.
//! - **`NAME_MAX` Compliance**: [`part_file_path`] truncates multi-byte UTF-8 stems on a
//!   valid codepoint boundary so `<stem>.part` never exceeds 255 bytes.

use crate::client::{GoFileClient, HttpTransport};
use crate::downloader::{DownloadOptions, ProgressHooks};
use crate::error::GoFileError;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Computes the staging `.part` path for `dest_file`, truncating the filename stem on a
/// UTF-8 boundary if needed so the `.part` filename component never exceeds 255 bytes (`NAME_MAX`).
///
/// # Examples
///
/// ```
/// use gofile_dl::transfer::part_file_path;
/// use std::path::Path;
///
/// assert_eq!(part_file_path(Path::new("/tmp/video.mkv")), Path::new("/tmp/video.mkv.part"));
/// ```
#[must_use]
pub fn part_file_path(dest_file: &Path) -> PathBuf {
    const SUFFIX: &str = ".part";
    const MAX_COMPONENT_BYTES: usize = 255;
    let Some(fname) = dest_file.file_name().and_then(|s| s.to_str()) else {
        return PathBuf::from(format!("{}{SUFFIX}", dest_file.display()));
    };
    let max_stem = MAX_COMPONENT_BYTES - SUFFIX.len();
    let stem = truncate_utf8_boundary(fname, max_stem);
    let part_name = format!("{stem}{SUFFIX}");
    match dest_file.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(part_name),
        _ => PathBuf::from(part_name),
    }
}

/// Truncates `s` to at most `max_bytes` UTF-8 bytes without splitting a multi-byte codepoint.
fn truncate_utf8_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Removes `target` (file or directory) and any companion `.part` staging file.
///
/// Returns `Ok(true)` if at least one file/directory existed and was removed, or
/// `Ok(false)` if neither existed on disk.
///
/// # Errors
///
/// Returns [`GoFileError::Io`] if removal fails for any reason other than `NotFound`.
pub fn remove_path_and_part(target: &Path) -> Result<bool, GoFileError> {
    let removed_part = remove_single_entry(&part_file_path(target))?;
    let removed_target = remove_single_entry(target)?;
    Ok(removed_part || removed_target)
}

/// Removes a single filesystem entry (recursively if directory), ignoring `NotFound` races.
fn remove_single_entry(path: &Path) -> Result<bool, GoFileError> {
    if !path.exists() {
        return Ok(false);
    }
    let res = if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    match res {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(GoFileError::Io(e)),
    }
}

/// Streams `link` into `dest_file` via an atomic `.part` file with HTTP `206` resume,
/// bandwidth throttling, pause/cancel polling, and bounded retries.
///
/// # Errors
///
/// Returns [`GoFileError::Cancelled`] on cancellation or [`GoFileError::RetryExhausted`]
/// when all retry attempts fail.
pub fn download_file<T: HttpTransport>(
    client: &GoFileClient<T>,
    link: &str,
    dest_file: &Path,
    options: &DownloadOptions,
    hooks: &dyn ProgressHooks,
) -> Result<(), GoFileError> {
    if let Some(parent) = dest_file.parent() {
        fs::create_dir_all(parent)?;
    }
    let part_path = part_file_path(dest_file);
    let max_retries = options.retry_attempts;
    let mut attempts = 0_u32;

    loop {
        if hooks.is_cancelled() {
            let _ = fs::remove_file(&part_path);
            return Err(GoFileError::Cancelled);
        }

        let existing_size = fs::metadata(&part_path).map_or(0_u64, |m| m.len());
        let attempt_res = stream_single_attempt(
            client,
            link,
            dest_file,
            &part_path,
            existing_size,
            options,
            hooks,
        );

        let Err(err) = attempt_res else {
            return Ok(());
        };
        if matches!(err, GoFileError::Cancelled) {
            let _ = fs::remove_file(&part_path);
            return Err(GoFileError::Cancelled);
        }

        attempts += 1;
        if attempts > max_retries {
            let _ = fs::remove_file(&part_path);
            hooks.on_file_progress(dest_file, -2, None, None);
            return Err(GoFileError::RetryExhausted {
                attempts,
                target: dest_file.display().to_string(),
                last_error: err.to_string(),
            });
        }
        let info = format!("Retry {attempts}/{max_retries}");
        hooks.on_file_progress(dest_file, -1, None, Some(&info));
        client
            .transport()
            .backoff_sleep(Duration::from_secs(options.retry_delay_secs));
    }
}

/// Performs one HTTP streaming attempt from `link` into `part_path`, then atomically
/// renames `part_path` onto `dest_file` upon reaching EOF.
///
/// Only appends to `part_path` when `existing_size > 0` **and** the origin server responds
/// with `206 Partial Content`; otherwise opens `part_path` with `.truncate(true)` to avoid
/// duplicating leading bytes when an origin ignores `Range`.
fn stream_single_attempt<T: HttpTransport>(
    client: &GoFileClient<T>,
    link: &str,
    dest_file: &Path,
    part_path: &Path,
    existing_size: u64,
    options: &DownloadOptions,
    hooks: &dyn ProgressHooks,
) -> Result<(), GoFileError> {
    let cookie_hdr = format!("accountToken={}", client.token());
    let range_hdr = format!("bytes={existing_size}-");
    let headers = [
        ("Cookie", cookie_hdr.as_str()),
        ("User-Agent", client.wt_config().user_agent.as_str()),
        ("Referer", "https://gofile.io/"),
        ("Range", range_hdr.as_str()),
    ];
    let mut resp = client.transport().open_stream(link, &headers)?;
    // Fix Bug #2: Only append to `.part` when the server responds 206 Partial Content!
    let is_partial = resp.status == 206 && existing_size > 0;
    let mut downloaded = if is_partial { existing_size } else { 0_u64 };
    let total_size = resp.content_length.map(|cl| cl + downloaded);

    hooks.on_file_progress(dest_file, 0, total_size, None);
    let mut file = open_part_file(part_path, is_partial)?;

    let mut buf = vec![0_u8; options.chunk_size.max(1024)];
    let mut bytes_since_check = 0_u64;
    let mut last_check = Instant::now();
    let mut last_pct: Option<u8> = None;

    loop {
        wait_while_paused(client.transport(), hooks)?;

        let n = resp.reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])?;
        downloaded += n as u64;

        // Fix Bug #1: Guard `tot > 0` and deduplicate unchanged integer percentages (<100%).
        if let Some(pct) = next_distinct_pct(downloaded, total_size, &mut last_pct) {
            hooks.on_progress(pct);
            hooks.on_file_progress(dest_file, i32::from(pct), total_size, None);
        }

        if let Some(kbps) = options.throttle_kbps.filter(|&k| k > 0) {
            apply_bandwidth_throttle(
                client.transport(),
                kbps,
                n as u64,
                &mut bytes_since_check,
                &mut last_check,
            );
        }
    }

    file.flush()?;
    drop(file);
    fs::rename(part_path, dest_file)?;
    hooks.on_progress(100);
    hooks.on_file_progress(dest_file, 100, total_size.or(Some(downloaded)), None);
    Ok(())
}

/// Computes the next distinct intermediate percentage (`0..=99`), guarding `total_size == 0`
/// and suppressing duplicate callbacks across consecutive chunks so `100%` fires strictly once
/// after atomic `.part` rename.
#[inline]
fn next_distinct_pct(
    downloaded: u64,
    total_size: Option<u64>,
    last_pct: &mut Option<u8>,
) -> Option<u8> {
    let tot = total_size.filter(|&t| t > 0)?;
    let pct = ((downloaded.saturating_mul(100)) / tot).min(99) as u8;
    if *last_pct == Some(pct) {
        return None;
    }
    *last_pct = Some(pct);
    Some(pct)
}

fn open_part_file(part_path: &Path, is_partial: bool) -> Result<File, GoFileError> {
    let file = if is_partial {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(part_path)?
    } else {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(part_path)?
    };
    Ok(file)
}

fn wait_while_paused<T: HttpTransport>(
    transport: &T,
    hooks: &dyn ProgressHooks,
) -> Result<(), GoFileError> {
    while hooks.is_paused() {
        if hooks.is_cancelled() {
            return Err(GoFileError::Cancelled);
        }
        transport.backoff_sleep(Duration::from_millis(100));
    }
    if hooks.is_cancelled() {
        return Err(GoFileError::Cancelled);
    }
    Ok(())
}

fn apply_bandwidth_throttle<T: HttpTransport>(
    transport: &T,
    kbps: u64,
    chunk_len: u64,
    bytes_since_check: &mut u64,
    last_check: &mut Instant,
) {
    *bytes_since_check += chunk_len;
    let elapsed = last_check.elapsed().as_secs_f64();
    if elapsed <= 0.0 {
        return;
    }
    let limit_bps = (kbps as f64) * 1024.0;
    let rate = (*bytes_since_check as f64) / elapsed;
    if rate > limit_bps {
        let sleep_secs = ((*bytes_since_check as f64) / limit_bps) - elapsed;
        if sleep_secs > 0.0 {
            transport.backoff_sleep(Duration::from_secs_f64(sleep_secs));
        }
        *bytes_since_check = 0;
        *last_check = Instant::now();
    }
}
