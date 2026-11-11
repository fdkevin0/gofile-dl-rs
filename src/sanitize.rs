//! Cross-platform filename sanitization, Unicode emoji stripping, path-traversal
//! confinement, and GoFile incremental folder-rename normalization.
//!
//! ## Safety & Bug Fixes Over Legacy Python
//!
//! 1. **CJK / Kana / Hangul Preservation**: Legacy `run.py:166` used the broken range
//!    `\U000024C2-\U0001F251`, deleting all East Asian scripts. [`strip_emojis`]
//!    restricts removal to genuine emoji/symbol/pictograph blocks while preserving
//!    world scripts.
//! 2. **Traversal Hardening**: Legacy `sanitize_filename("..")` returned `".."`.
//!    [`safe_child_path`] ensures remote GoFile item names can never resolve to `.`,
//!    `..`, or escape their parent download directory.
//! 3. **Zero-Allocation Arena Helpers**: [`strip_emojis_into`], [`sanitize_filename_into`],
//!    and [`FolderNormalizer::normalize_slice`] eliminate per-item heap allocations in
//!    batch kernels.

use crate::error::GoFileError;
use regex::Regex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Default pipe-separated folder prefixes stripped in incremental sync mode.
pub const DEFAULT_FOLDER_PATTERNS: &str = "⭐NEW FILES in |NEW FILES in |⭐";

/// Returns `true` if `ch` belongs to a Unicode emoji, dingbat, or pictograph range.
///
/// Unlike legacy `run.py`, this intentionally excludes CJK (`U+4E00..U+9FFF`),
/// Hiragana/Katakana (`U+3040..U+30FF`), and Hangul (`U+AC00..U+D7AF`).
///
/// # Examples
///
/// ```
/// use gofile_dl::sanitize::is_emoji_codepoint;
///
/// assert!(is_emoji_codepoint('⭐'));
/// assert!(!is_emoji_codepoint('日'));
/// ```
#[inline]
#[must_use]
pub const fn is_emoji_codepoint(ch: char) -> bool {
    let cp = ch as u32;
    matches!(
        cp,
        0x24C2
            | 0x2500..=0x2BEF
            | 0xFE0F
            | 0x1F1E0..=0x1F251
            | 0x1F300..=0x1F64F
            | 0x1F680..=0x1F6FF
            | 0x1F900..=0x1FAFF
    )
}

/// Removes emojis and decorative pictographs into a caller-supplied `String` buffer
/// without allocating a new heap buffer when `out` has capacity.
#[inline]
pub fn strip_emojis_into(text: &str, out: &mut String) {
    out.clear();
    let mut prev_ws = true;
    for ch in text.chars() {
        if is_emoji_codepoint(ch) {
            continue;
        }
        let is_ws = ch.is_whitespace() || matches!(ch, '\x1c'..='\x1f');
        if is_ws {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            out.push(ch);
            prev_ws = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
}

/// Removes emojis and decorative pictographs while collapsing consecutive whitespace.
///
/// Preserves CJK, Japanese Kana, Korean Hangul, Cyrillic, and Latin characters.
///
/// # Examples
///
/// ```
/// use gofile_dl::sanitize::strip_emojis;
///
/// assert_eq!(strip_emojis("  ⭐ Episode 01 🎬.mkv  "), "Episode 01 .mkv");
/// assert_eq!(strip_emojis("⭐ 日本語 Movie 🎬.mkv"), "日本語 Movie .mkv");
/// ```
#[must_use]
pub fn strip_emojis(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    strip_emojis_into(text, &mut out);
    out
}

/// Zero-allocation check for universal/Windows reserved device stems (`CON`, `PRN`,
/// `AUX`, `NUL`, `CLOCK$`, `COM0..9`, `LPT0..9`, `COM¹..³`, `LPT¹..³`).
#[inline]
fn is_reserved_stem(stem: &str) -> bool {
    let b = stem.as_bytes();
    match b.len() {
        3 => {
            b.eq_ignore_ascii_case(b"CON")
                || b.eq_ignore_ascii_case(b"PRN")
                || b.eq_ignore_ascii_case(b"AUX")
                || b.eq_ignore_ascii_case(b"NUL")
        }
        4 => {
            b[3].is_ascii_digit()
                && (b[..3].eq_ignore_ascii_case(b"COM") || b[..3].eq_ignore_ascii_case(b"LPT"))
        }
        5 => {
            (b[..3].eq_ignore_ascii_case(b"COM") || b[..3].eq_ignore_ascii_case(b"LPT"))
                && matches!(&b[3..], b"\xc2\xb9" | b"\xc2\xb2" | b"\xc2\xb3")
        }
        6 => b.eq_ignore_ascii_case(b"CLOCK$"),
        _ => false,
    }
}

/// Sanitizes `name` into `out` using `filtered` as reusable scratch space, avoiding
/// per-item heap allocations in hot batch loops.
pub fn sanitize_filename_into(name: &str, filtered: &mut String, out: &mut String) {
    filtered.clear();
    out.clear();
    for ch in name.chars() {
        let cp = ch as u32;
        let forbidden = cp <= 0x1F
            || cp == 0x7F
            || matches!(ch, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|');
        if forbidden {
            continue;
        }
        if filtered.len() + ch.len_utf8() > 255 {
            break;
        }
        filtered.push(ch);
    }

    if filtered.is_empty() {
        return;
    }

    if filtered.starts_with(' ') {
        let trimmed = filtered.trim_matches(' ');
        if trimmed == "." || trimmed == ".." {
            out.push_str(trimmed);
        } else {
            out.push_str(trimmed.trim_end_matches([' ', '.']));
        }
        return;
    }

    let stem = filtered.split('.').next().unwrap_or("");
    if is_reserved_stem(stem) {
        out.push_str(stem);
        out.push('_');
        out.push_str(&filtered[stem.len()..]);
        while out.len() > 255 {
            out.pop();
        }
        return;
    }

    if filtered == "." || filtered == ".." {
        out.push_str(filtered);
        return;
    }

    out.push_str(filtered.trim_end_matches([' ', '.']));
}

/// Sanitizes a single filename component for universal Linux/macOS/Windows compatibility,
/// matching `pathvalidate.sanitize_filename` semantics.
///
/// - Strips ASCII control characters (`0x00..=0x1F`, `0x7F`) and `/ \ : * ? " < > |`.
/// - Truncates to at most 255 UTF-8 bytes on a character boundary.
/// - Escapes Windows reserved stems (`CON` -> `CON_`, `con.txt` -> `con_.txt`) or strips
///   leading spaces and trailing spaces/periods.
///
/// # Examples
///
/// ```
/// use gofile_dl::sanitize::sanitize_filename;
///
/// assert_eq!(sanitize_filename("a/b\\c:d*e?f\"g<h>i|j"), "abcdefghij");
/// assert_eq!(sanitize_filename("  leading_trailing  "), "leading_trailing");
/// assert_eq!(sanitize_filename("CON"), "CON_");
/// assert_eq!(sanitize_filename("con.tar.gz"), "con_.tar.gz");
/// ```
#[must_use]
pub fn sanitize_filename(name: &str) -> String {
    let mut filtered = String::with_capacity(name.len());
    let mut out = String::with_capacity(name.len() + 1);
    sanitize_filename_into(name, &mut filtered, &mut out);
    out
}

/// Safely resolves `raw_name` as a direct child inside `parent_dir`, rejecting empty,
/// `.`, or `..` traversal components.
///
/// # Errors
///
/// Returns [`GoFileError::PathSafety`] if `raw_name` sanitizes to an empty string,
/// `.`, or `..` when no `fallback_id` is available.
///
/// # Examples
///
/// ```
/// use gofile_dl::sanitize::safe_child_path;
/// use std::path::Path;
///
/// let p = safe_child_path(Path::new("/tmp/downloads"), "../etc/passwd", false, "id123456").unwrap();
/// assert_eq!(p, Path::new("/tmp/downloads/..etcpasswd"));
///
/// let dot = safe_child_path(Path::new("/tmp/downloads"), "..", false, "id123456").unwrap();
/// assert_eq!(dot, Path::new("/tmp/downloads/item_id123456"));
/// ```
pub fn safe_child_path(
    parent_dir: &Path,
    raw_name: &str,
    strip_emoji_flag: bool,
    fallback_id: &str,
) -> Result<PathBuf, GoFileError> {
    let raw_candidate = if strip_emoji_flag {
        resolve_emoji_stripped_name(raw_name, fallback_id)
    } else {
        raw_name.to_string()
    };

    let mut candidate = sanitize_filename(&raw_candidate);
    if candidate.is_empty() || candidate == "." || candidate == ".." {
        let prefix: String = fallback_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(8)
            .collect();
        if prefix.is_empty() {
            return Err(GoFileError::PathSafety(format!(
                "refusing unsafe child name: {raw_name:?}"
            )));
        }
        candidate = format!("item_{prefix}");
    }

    Ok(parent_dir.join(candidate))
}

fn resolve_emoji_stripped_name(raw_name: &str, fallback_id: &str) -> String {
    let stripped = strip_emojis(raw_name);
    let stem_wiped = !raw_name.trim_start().starts_with('.') && stripped.starts_with('.');
    if !stripped.is_empty() && !stem_wiped {
        return stripped;
    }
    let ext = Path::new(raw_name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{}", sanitize_filename(e)))
        .unwrap_or_default();
    let prefix: String = fallback_id.chars().take(8).collect();
    format!("item_{prefix}{ext}")
}

/// Pre-compiled set of case-insensitive prefix regexes for folder rename matching.
#[derive(Debug, Clone)]
pub struct FolderNormalizer {
    patterns: Vec<Regex>,
}

impl FolderNormalizer {
    /// Compiles default GoFile `"NEW FILES in"` patterns plus optional pipe-delimited
    /// `custom_patterns` (prepended in priority order, matching `run.py:202-216`).
    #[must_use]
    pub fn new(custom_patterns: Option<&str>) -> Self {
        let defaults = [
            r"(?i)^⭐\s*NEW FILES in\s+".to_string(),
            r"(?i)^NEW FILES in\s+".to_string(),
            r"(?i)^⭐\s*".to_string(),
            r"(?i)^\*+\s*NEW FILES in\s+".to_string(),
            r"(?i)^\*+\s*".to_string(),
        ];

        let mut raw_patterns = compile_custom_prefixes(custom_patterns);
        raw_patterns.extend(defaults);

        let patterns = raw_patterns
            .into_iter()
            .filter_map(|p| Regex::new(&p).ok())
            .collect();
        Self { patterns }
    }

    /// Strips matching prefixes sequentially and returns a zero-copy trimmed `&str` slice.
    #[inline]
    #[must_use]
    pub fn normalize_slice<'a>(&self, name: &'a str) -> &'a str {
        let mut current = name;
        for pat in &self.patterns {
            if let Some(m) = pat.find(current).filter(|m| m.start() == 0) {
                current = &current[m.end()..];
            }
        }
        current.trim()
    }

    /// Strips matching prefixes sequentially and trims outer whitespace.
    #[must_use]
    pub fn normalize(&self, name: &str) -> String {
        self.normalize_slice(name).to_string()
    }
}

fn compile_custom_prefixes(custom_patterns: Option<&str>) -> Vec<String> {
    let Some(custom) = custom_patterns else {
        return Vec::new();
    };
    let mut custom_compiled: Vec<String> = custom
        .split('|')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|item| {
            let escaped = regex::escape(item).replace(' ', r"\s*");
            format!(r"(?i)^{escaped}\s*")
        })
        .collect();
    // Legacy inserts each custom pattern at index 0 in loop order, reversing them.
    custom_compiled.reverse();
    custom_compiled
}

/// Normalizes a folder name by stripping common prefixes such as `"⭐NEW FILES in "`.
///
/// # Examples
///
/// ```
/// use gofile_dl::sanitize::normalize_folder_name;
///
/// assert_eq!(normalize_folder_name("⭐NEW FILES in Show S01", None), "Show S01");
/// assert_eq!(
///     normalize_folder_name("🔥HOT Show S01", Some("🔥HOT |⭐NEW FILES in ")),
///     "Show S01"
/// );
/// ```
#[must_use]
pub fn normalize_folder_name(name: &str, custom_patterns: Option<&str>) -> String {
    static DEFAULT_NORM: OnceLock<FolderNormalizer> = OnceLock::new();
    let Some(custom) = custom_patterns else {
        return DEFAULT_NORM
            .get_or_init(|| FolderNormalizer::new(None))
            .normalize(name);
    };

    thread_local! {
        static CUSTOM_CACHE: RefCell<HashMap<String, FolderNormalizer>> = RefCell::new(HashMap::new());
    }
    CUSTOM_CACHE.with(|cell| {
        let mut cache = cell.borrow_mut();
        if cache.len() >= 64 && !cache.contains_key(custom) {
            cache.clear();
        }
        cache
            .entry(custom.to_string())
            .or_insert_with(|| FolderNormalizer::new(Some(custom)))
            .normalize(name)
    })
}
