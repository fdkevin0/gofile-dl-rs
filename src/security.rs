//! Stateless HMAC-SHA256 CSRF protection, HTTP Basic Authentication verification,
//! `templates/index.html` rendering, and safe `/health` host telemetry.
//!
//! Operates in 100% Safe Rust (`#![forbid(unsafe_code)]`) without `libc` FFI calls.
//!
//! ## Security Properties
//!
//! - **Constant-Time Digest & Password Comparison**: Prevents byte-by-byte timing oracles
//!   during Basic Auth and CSRF signature checks.
//! - **Bounded Clock Skew**: Rejects forged future-dated CSRF tokens (`issued_at > now + 60`).

use crate::browse::probe_existing_dir_writable;
use crate::config::{AuthConfig, CsrfConfig};
use crate::token::encode_sha256_hex;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const EMBEDDED_INDEX_HTML: &str = include_str!("../templates/index.html");

/// Generates a signed stateless CSRF token `<unix_ts>.<nonce>.<hmac_hex>`.
///
/// # Examples
///
/// ```
/// use gofile_dl::config::CsrfConfig;
/// use gofile_dl::security::{generate_csrf_token, verify_csrf_token};
///
/// let cfg = CsrfConfig::default();
/// let tok = generate_csrf_token("super-secret");
/// assert!(verify_csrf_token(&tok, "super-secret", &cfg));
/// assert!(!verify_csrf_token(&tok, "wrong-secret", &cfg));
/// ```
#[must_use]
pub fn generate_csrf_token(secret_key: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0_u64, |d| d.as_secs());
    let nonce = Uuid::new_v4().simple().to_string();
    let payload = format!("{now}.{nonce}");
    let sig = compute_hmac_hex(secret_key, &payload);
    format!("{payload}.{sig}")
}

/// Validates a stateless CSRF token against `secret_key` and `cfg.time_limit`.
#[must_use]
pub fn verify_csrf_token(token: &str, secret_key: &str, cfg: &CsrfConfig) -> bool {
    if !cfg.enabled {
        return true;
    }
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let Ok(issued_at) = parts[0].parse::<u64>() else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0_u64, |d| d.as_secs());
    if issued_at > now.saturating_add(60) {
        return false;
    }
    if cfg.time_limit > 0 && now.saturating_sub(issued_at) > cfg.time_limit {
        return false;
    }
    let payload = format!("{}.{}", parts[0], parts[1]);
    let expected = compute_hmac_hex(secret_key, &payload);
    constant_time_eq(expected.as_bytes(), parts[2].as_bytes())
}

fn compute_hmac_hex(secret: &str, payload: &str) -> String {
    let key = if secret.is_empty() {
        b"gofile-default-key".as_slice()
    } else {
        secret.as_bytes()
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return String::new();
    };
    mac.update(payload.as_bytes());
    let bytes: [u8; 32] = mac.finalize().into_bytes().into();
    encode_sha256_hex(&bytes)
}

#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verifies an HTTP `Authorization: Basic <base64>` header against `auth_cfg`.
///
/// # Examples
///
/// ```
/// use gofile_dl::config::AuthConfig;
/// use gofile_dl::security::verify_basic_auth;
///
/// let cfg = AuthConfig {
///     enabled: true,
///     username: "admin".to_string(),
///     password: "secret".to_string(),
/// };
/// assert!(verify_basic_auth(Some("Basic YWRtaW46c2VjcmV0"), &cfg));
/// assert!(!verify_basic_auth(Some("Basic YWRtaW46d3Jvbmc="), &cfg));
/// assert!(!verify_basic_auth(None, &cfg));
/// ```
#[must_use]
pub fn verify_basic_auth(auth_header: Option<&str>, auth_cfg: &AuthConfig) -> bool {
    if !auth_cfg.enabled {
        return true;
    }
    let Some(raw) = auth_header.map(str::trim) else {
        return false;
    };
    let Some(encoded) = raw
        .strip_prefix("Basic ")
        .or_else(|| raw.strip_prefix("basic "))
    else {
        return false;
    };
    let Ok(decoded_bytes) = BASE64_STD.decode(encoded.trim()) else {
        return false;
    };
    let Ok(decoded) = String::from_utf8(decoded_bytes) else {
        return false;
    };
    let Some((user, pass)) = decoded.split_once(':') else {
        return false;
    };
    constant_time_eq(user.as_bytes(), auth_cfg.username.as_bytes())
        && constant_time_eq(pass.as_bytes(), auth_cfg.password.as_bytes())
}

/// Renders `templates/index.html` (preferring an on-disk override if present),
/// injecting the live `csrf_token` and stripping unused Jinja flash blocks.
#[must_use]
pub fn render_index_html(template_path: Option<&Path>, csrf_token: &str) -> String {
    let raw = template_path
        .and_then(|p| fs::read_to_string(p).ok())
        .unwrap_or_else(|| EMBEDDED_INDEX_HTML.to_string());

    let with_csrf = raw.replace("{{ csrf_token() }}", csrf_token);
    strip_jinja_flash_block(&with_csrf)
}

fn strip_jinja_flash_block(html: &str) -> String {
    const START_TAG: &str = "{% with messages";
    const END_TAG: &str = "{% endwith %}";
    let Some(start) = html.find(START_TAG) else {
        return html.to_string();
    };
    let Some(rel_end) = html[start..].find(END_TAG) else {
        return html.to_string();
    };
    let end = start + rel_end + END_TAG.len();
    let mut out = String::with_capacity(html.len() - (end - start));
    out.push_str(&html[..start]);
    out.push_str(&html[end..]);
    out
}

/// Parses an `application/x-www-form-urlencoded` payload into decoded key-value pairs.
///
/// # Examples
///
/// ```
/// use gofile_dl::security::parse_urlencoded_fields;
///
/// let map = parse_urlencoded_fields(b"url=https%3A%2F%2Fgofile.io%2Fd%2Fabc&strip_emojis=true");
/// assert_eq!(map.get("url").map(String::as_str), Some("https://gofile.io/d/abc"));
/// assert_eq!(map.get("strip_emojis").map(String::as_str), Some("true"));
/// ```
#[must_use]
pub fn parse_urlencoded_fields(bytes: &[u8]) -> HashMap<String, String> {
    let raw = std::str::from_utf8(bytes).unwrap_or("");
    let mut out = HashMap::new();
    for pair in raw.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(percent_decode(k), percent_decode(v));
    }
    out
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(decoded) = decode_hex_pair(bytes[i + 1], bytes[i + 2]) {
                out.push(decoded);
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[inline]
fn decode_hex_pair(hi: u8, lo: u8) -> Option<u8> {
    let h = (hi as char).to_digit(16)?;
    let l = (lo as char).to_digit(16)?;
    Some(((h << 4) | l) as u8)
}

/// Safe `/health` host and application status payload matching `app.py:163-214`.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Overall health status (`"ok"`).
    pub status: &'static str,
    /// Current Unix timestamp in seconds.
    pub timestamp: f64,
    /// Host OS and memory metrics read safely without `unsafe` FFI.
    pub system: SystemMetrics,
    /// Application version and active task count.
    pub application: ApplicationMetrics,
    /// Base download directory status and writability.
    pub directories: DirectoryMetrics,
}

/// Safe OS and `/proc/meminfo` memory telemetry.
#[derive(Debug, Serialize)]
pub struct SystemMetrics {
    /// Operating system family (`"linux"`, `"macos"`, `"windows"`).
    pub system: &'static str,
    /// Active Rust package runtime identifier.
    pub runtime: &'static str,
    /// Host memory breakdown in bytes, when `/proc/meminfo` is readable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryMetrics>,
}

/// Host RAM telemetry parsed from `/proc/meminfo`.
#[derive(Debug, Serialize)]
pub struct MemoryMetrics {
    /// Total physical RAM in bytes.
    pub total: u64,
    /// Available RAM in bytes.
    pub available: u64,
    /// Used percentage (`0.0..=100.0`).
    pub percent: f64,
}

/// Application-level health counters.
#[derive(Debug, Serialize)]
pub struct ApplicationMetrics {
    /// Service status (`"healthy"`).
    pub status: &'static str,
    /// Number of running or paused tasks.
    pub active_tasks: usize,
    /// Application version string.
    pub version: String,
}

/// Base directory health check details.
#[derive(Debug, Serialize)]
pub struct DirectoryMetrics {
    /// Configured `base_dir` path.
    pub base_dir: String,
    /// Whether `base_dir` currently exists.
    pub exists: bool,
    /// Whether `base_dir` is writable by the current process.
    pub writable: bool,
}

/// Builds a [`HealthResponse`] using pure safe Rust I/O.
#[must_use]
pub fn build_health_response(
    base_dir: &Path,
    active_tasks: usize,
    app_version: &str,
) -> HealthResponse {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64());
    let exists = base_dir.exists();
    let writable = exists && probe_existing_dir_writable(base_dir);

    HealthResponse {
        status: "ok",
        timestamp: now,
        system: SystemMetrics {
            system: std::env::consts::OS,
            runtime: "safe-rust",
            memory: read_linux_meminfo(),
        },
        application: ApplicationMetrics {
            status: "healthy",
            active_tasks,
            version: app_version.to_string(),
        },
        directories: DirectoryMetrics {
            base_dir: base_dir.display().to_string(),
            exists,
            writable,
        },
    }
}

fn read_linux_meminfo() -> Option<MemoryMetrics> {
    let raw = fs::read_to_string("/proc/meminfo").ok()?;
    let mut total_kb = None;
    let mut avail_kb = None;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total_kb = parse_first_u64(rest);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            avail_kb = parse_first_u64(rest);
        }
    }
    let total = total_kb? * 1024;
    let available = avail_kb? * 1024;
    let used_pct = if total > 0 {
        ((total.saturating_sub(available) as f64) / (total as f64)) * 100.0
    } else {
        0.0
    };
    Some(MemoryMetrics {
        total,
        available,
        percent: (used_pct * 10.0).round() / 10.0,
    })
}

fn parse_first_u64(s: &str) -> Option<u64> {
    s.split_whitespace().next()?.parse::<u64>().ok()
}
