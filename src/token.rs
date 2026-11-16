//! GoFile `X-Website-Token` (`wt`) cryptographic generator, password hashing,
//! and share URL / bare content ID parser.
//!
//! Reproduces GoFile's rotating 4-hour client token algorithm:
//!
//! $$\text{wt} = \text{SHA256}\bigl(\text{ua} \mathbin{\Vert} \text{"::"} \mathbin{\Vert} \text{lang} \mathbin{\Vert} \text{"::"} \mathbin{\Vert} \text{token} \mathbin{\Vert} \text{"::"} \mathbin{\Vert} \lfloor t / 14400 \rfloor + \Delta \mathbin{\Vert} \text{"::"} \mathbin{\Vert} \text{salt}\bigr)$$

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default browser `User-Agent` matching GoFile's expected header + token input.
pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

/// Default `X-BL` browser language hashed into `X-Website-Token`.
pub const DEFAULT_LANGUAGE: &str = "en-US";

/// Default rotating `wt.obf.js` salt (overridable via `GOFILE_WT_SALT`).
pub const DEFAULT_WT_SALT: &str = "12af056dacea0b";

/// Duration of one GoFile rotating website-token bucket in seconds (4 hours).
pub const WT_WINDOW_SECONDS: i64 = 14_400;

/// Lowercase hexadecimal lookup table for zero-branch digest encoding.
const HEX_LUT: &[u8; 16] = b"0123456789abcdef";

/// Configuration inputs hashed into GoFile's `X-Website-Token`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebsiteTokenConfig {
    /// HTTP `User-Agent` header (must match the header sent on `/contents`).
    pub user_agent: String,
    /// HTTP `X-BL` language header (must match the header sent on `/contents`).
    pub language: String,
    /// Secret salt extracted from `gofile.io/dist/js/wt.obf.js`.
    pub salt: String,
}

impl Default for WebsiteTokenConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl WebsiteTokenConfig {
    /// Loads token parameters from `GOFILE_USER_AGENT`, `GOFILE_LANGUAGE`, and
    /// `GOFILE_WT_SALT`, falling back to built-in 2026 GoFile defaults.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            user_agent: env_or_default("GOFILE_USER_AGENT", DEFAULT_USER_AGENT),
            language: env_or_default("GOFILE_LANGUAGE", DEFAULT_LANGUAGE),
            salt: env_or_default("GOFILE_WT_SALT", DEFAULT_WT_SALT),
        }
    }
}

fn env_or_default(key: &str, fallback: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

/// Encodes a 32-byte SHA-256 digest into a 64-character lowercase hex `String`.
#[inline]
#[must_use]
pub fn encode_sha256_hex(bytes: &[u8; 32]) -> String {
    let mut out = [0u8; 64];
    encode_sha256_hex_into(bytes, &mut out);
    // All bytes in `out` come from `HEX_LUT` (`0-9`, `a-f`), guaranteed valid UTF-8.
    String::from_utf8(out.to_vec()).unwrap_or_default()
}

/// Encodes a 32-byte SHA-256 digest directly into a caller-provided 64-byte ASCII buffer.
#[inline]
pub fn encode_sha256_hex_into(bytes: &[u8; 32], out: &mut [u8; 64]) {
    for (i, &b) in bytes.iter().enumerate() {
        out[i * 2] = HEX_LUT[(b >> 4) as usize];
        out[i * 2 + 1] = HEX_LUT[(b & 0x0F) as usize];
    }
}

/// Computes the SHA-256 lowercase hex digest of a GoFile share password.
///
/// # Examples
///
/// ```
/// use gofile_dl::token::hash_password;
///
/// let h = hash_password("secret123");
/// assert_eq!(h.len(), 64);
/// ```
#[must_use]
pub fn hash_password(password: &str) -> String {
    let digest: [u8; 32] = Sha256::digest(password.as_bytes()).into();
    encode_sha256_hex(&digest)
}

/// Computes GoFile's 64-character hex `X-Website-Token` for an explicit Unix timestamp.
///
/// # Examples
///
/// ```
/// use gofile_dl::token::{
///     generate_website_token_at, DEFAULT_LANGUAGE, DEFAULT_USER_AGENT, DEFAULT_WT_SALT,
/// };
///
/// let wt0 = generate_website_token_at(
///     "guest_tok_123",
///     1_770_000_000,
///     0,
///     DEFAULT_USER_AGENT,
///     DEFAULT_LANGUAGE,
///     DEFAULT_WT_SALT,
/// );
/// let wt_prev = generate_website_token_at(
///     "guest_tok_123",
///     1_770_000_000,
///     -1,
///     DEFAULT_USER_AGENT,
///     DEFAULT_LANGUAGE,
///     DEFAULT_WT_SALT,
/// );
/// assert_eq!(wt0.len(), 64);
/// assert_ne!(wt0, wt_prev);
/// ```
#[must_use]
pub fn generate_website_token_at(
    account_token: &str,
    unix_time_secs: i64,
    window_offset: i64,
    user_agent: &str,
    language: &str,
    salt: &str,
) -> String {
    let window = unix_time_secs.div_euclid(WT_WINDOW_SECONDS) + window_offset;
    let payload = format!("{user_agent}::{language}::{account_token}::{window}::{salt}");
    let digest: [u8; 32] = Sha256::digest(payload.as_bytes()).into();
    encode_sha256_hex(&digest)
}

/// Computes GoFile's `X-Website-Token` using the current system clock and `cfg`.
#[must_use]
pub fn generate_website_token(
    account_token: &str,
    window_offset: i64,
    cfg: &WebsiteTokenConfig,
) -> String {
    if account_token.is_empty() {
        return String::new();
    }
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    generate_website_token_at(
        account_token,
        now_secs,
        window_offset,
        &cfg.user_agent,
        &cfg.language,
        &cfg.salt,
    )
}

/// Extracts a GoFile content ID from either a full share URL or a bare alphanumeric ID.
///
/// Performs zero-allocation ASCII case-insensitive scanning without compiling regexes.
///
/// # Examples
///
/// ```
/// use gofile_dl::token::parse_content_id;
///
/// assert_eq!(parse_content_id("https://gofile.io/d/abc123").as_deref(), Some("abc123"));
/// assert_eq!(parse_content_id("http://www.gofile.io/d/XyZ9/").as_deref(), Some("XyZ9"));
/// assert_eq!(parse_content_id("https://gofile.io/d/abc123?x=1#f").as_deref(), Some("abc123"));
/// assert_eq!(parse_content_id("abc123").as_deref(), Some("abc123"));
/// assert_eq!(parse_content_id("https://example.com/nope"), None);
/// ```
#[must_use]
pub fn parse_content_id(input: &str) -> Option<String> {
    parse_content_id_slice(input).map(str::to_owned)
}

/// Borrowed-slice variant of [`parse_content_id`] for zero-allocation hot paths.
#[must_use]
pub fn parse_content_id_slice(input: &str) -> Option<&str> {
    let candidate = input.trim();
    if candidate.is_empty() {
        return None;
    }

    if let Some(id) = extract_gofile_url_id(candidate) {
        return Some(id);
    }

    if is_valid_content_id_token(candidate) {
        return Some(candidate);
    }
    None
}

fn extract_gofile_url_id(candidate: &str) -> Option<&str> {
    const NEEDLE: &[u8; 12] = b"gofile.io/d/";
    let bytes = candidate.as_bytes();
    if bytes.len() <= NEEDLE.len() {
        return None;
    }
    for start in 0..=(bytes.len() - NEEDLE.len()) {
        let boundary_ok = start == 0 || matches!(bytes[start - 1], b'/' | b'.');
        if !boundary_ok || !bytes[start..start + NEEDLE.len()].eq_ignore_ascii_case(NEEDLE) {
            continue;
        }
        let rest = &candidate[start + NEEDLE.len()..];
        let end = rest
            .find(['/', '?', '#', ' ', '\t', '\r', '\n'])
            .unwrap_or(rest.len());
        let id = &rest[..end];
        if is_valid_content_id_token(id) {
            return Some(id);
        }
    }
    None
}

#[inline]
fn is_valid_content_id_token(id: &str) -> bool {
    !id.is_empty()
        && id != "."
        && id != ".."
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
