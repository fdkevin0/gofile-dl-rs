//! Strongly typed domain errors for GoFile authentication, content resolution,
//! bandwidth throttling, filesystem safety, and retryable HTTP downloads.
//!
//! Replaces the legacy `errors.py` hierarchy (whose classes were defined in
//! Python but never raised at call sites) with an exhaustive `Result<T, GoFileError>`
//! model used across every client, downloader, configuration, and web operation.

use std::error::Error;
use std::fmt;
use std::io;

/// Unified error type for all `gofile-dl` library and runtime operations.
///
/// # Examples
///
/// ```
/// use gofile_dl::error::GoFileError;
///
/// let err = GoFileError::Download {
///     message: "connection reset".to_string(),
///     filename: "video.mkv".to_string(),
///     url: "https://store1.gofile.io/download/video.mkv".to_string(),
/// };
/// assert!(err.to_string().contains("video.mkv"));
/// ```
#[derive(Debug)]
pub enum GoFileError {
    /// Failed to obtain or validate an account or website token with GoFile.
    Authentication(String),
    /// Requested content ID or share URL does not exist on GoFile (`error-notFound`).
    ContentNotFound(String),
    /// Content requires a password or the supplied password hash was rejected.
    Password(String),
    /// Input URL or bare content identifier failed validation.
    InvalidUrl(String),
    /// GoFile's edge reset the TLS/TCP connection (IP or TLS fingerprint block).
    EdgeBlocked(String),
    /// GoFile's guest API rate limiter rejected requests after backoff retries.
    RateLimited(String),
    /// File transfer error tied to a specific filename and storage URL.
    Download {
        /// Human-readable error cause.
        message: String,
        /// Target local file path or name.
        filename: String,
        /// Remote download URL.
        url: String,
    },
    /// Invalid bandwidth limit or throttling parameter.
    Throttle(String),
    /// All configured retry attempts failed for an operation.
    RetryExhausted {
        /// Number of attempts executed before giving up.
        attempts: u32,
        /// Target resource description.
        target: String,
        /// Last error message recorded.
        last_error: String,
    },
    /// Operation was explicitly cancelled by caller or user signal.
    Cancelled,
    /// Invalid or unsafe filesystem path (e.g. traversal outside base directory).
    PathSafety(String),
    /// Configuration file or environment variable validation error.
    Config(String),
    /// Underlying filesystem I/O failure.
    Io(io::Error),
    /// JSON or YAML serialization/deserialization error.
    Serialization(String),
}

impl fmt::Display for GoFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication(msg) => write!(f, "Authentication error: {msg}"),
            Self::ContentNotFound(id) => write!(f, "Content not found: {id}"),
            Self::Password(msg) => write!(f, "Password error: {msg}"),
            Self::InvalidUrl(url) => write!(f, "Invalid GoFile URL or content ID: {url}"),
            Self::EdgeBlocked(ctx) => write!(
                f,
                "GoFile API edge reset connection during {ctx}; configure GOFILE_PROXY or use a residential IP"
            ),
            Self::RateLimited(ctx) => write!(f, "GoFile rate limit persisted during {ctx}"),
            Self::Download {
                message,
                filename,
                url,
            } => write!(f, "{message}: {filename} ({url})"),
            Self::Throttle(msg) => write!(f, "Throttle configuration error: {msg}"),
            Self::RetryExhausted {
                attempts,
                target,
                last_error,
            } => write!(
                f,
                "Retry attempts exhausted ({attempts} tries) for '{target}': {last_error}"
            ),
            Self::Cancelled => write!(f, "Download cancelled"),
            Self::PathSafety(msg) => write!(f, "Path safety violation: {msg}"),
            Self::Config(msg) => write!(f, "Configuration error: {msg}"),
            Self::Io(err) => write!(f, "Filesystem I/O error: {err}"),
            Self::Serialization(msg) => write!(f, "Serialization error: {msg}"),
        }
    }
}

impl Error for GoFileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for GoFileError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for GoFileError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}

/// Inspects an error message to detect GoFile API edge connection resets.
///
/// Matches the exact diagnostic substrings used by the legacy `_is_connection_reset`
/// helper (`reset by peer`, `connection aborted`, `err_empty_response`, `recv failure`,
/// `curl: (35)`, `curl: (56)`).
///
/// # Examples
///
/// ```
/// use gofile_dl::error::is_connection_reset_message;
///
/// assert!(is_connection_reset_message("Connection reset by peer (os error 104)"));
/// assert!(!is_connection_reset_message("HTTP 404 Not Found"));
/// ```
#[must_use]
pub fn is_connection_reset_message(message: &str) -> bool {
    const HINTS: [&str; 6] = [
        "reset by peer",
        "connection aborted",
        "err_empty_response",
        "recv failure",
        "curl: (35)",
        "curl: (56)",
    ];
    let lower = message.to_ascii_lowercase();
    HINTS.iter().any(|hint| lower.contains(hint))
}
