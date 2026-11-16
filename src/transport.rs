//! HTTP transport abstraction, `reqwest` blocking client adapter, GoFile content
//! response schemas, and embedded HTML fallback parser.
//!
//! Decoupling [`HttpTransport`] as a trait enables deterministic zero-network unit
//! testing of rate-limit backoffs, token-window boundary retries, and `.part` resume
//! behavior while using `reqwest::blocking::Client` (`rustls-tls` + SOCKS5) in production.

use crate::error::{is_connection_reset_message, GoFileError};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::OnceLock;
use std::time::Duration;

/// Streaming HTTP response returned by [`HttpTransport::open_stream`].
pub struct ByteStreamResponse {
    /// HTTP status code (e.g. `200` or `206`).
    pub status: u16,
    /// Parsed `Content-Length` response header, if present.
    pub content_length: Option<u64>,
    /// Readable byte stream body.
    pub reader: Box<dyn Read + Send>,
}

/// Transport trait decoupling [`crate::client::GoFileClient`] from live network sockets.
pub trait HttpTransport: Send + Sync {
    /// Sends an HTTP `POST` and returns the response body text.
    ///
    /// # Errors
    ///
    /// Returns [`GoFileError`] on transport, timeout, or HTTP status error.
    fn post_text(&self, url: &str, headers: &[(&str, &str)]) -> Result<String, GoFileError>;

    /// Sends an HTTP `GET` with query parameters and returns the response body text.
    ///
    /// # Errors
    ///
    /// Returns [`GoFileError`] on transport, timeout, or HTTP status error.
    fn get_text(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        query: &[(&str, &str)],
    ) -> Result<String, GoFileError>;

    /// Opens a streaming HTTP `GET` for binary file download.
    ///
    /// # Errors
    ///
    /// Returns [`GoFileError`] on transport, timeout, or non-success HTTP status.
    fn open_stream(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<ByteStreamResponse, GoFileError>;

    /// Sleeps between retry/backoff attempts (overridable to zero-delay in unit tests).
    fn backoff_sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Production [`HttpTransport`] backed by `reqwest::blocking::Client` with cookie
/// jar and optional HTTP/SOCKS5 `GOFILE_PROXY` support.
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    api_client: reqwest::blocking::Client,
}

impl ReqwestTransport {
    /// Builds a blocking HTTP client with optional proxy URL and standard timeouts.
    ///
    /// # Errors
    ///
    /// Returns [`GoFileError::Config`] if `proxy_url` is malformed or TLS init fails.
    pub fn new(proxy_url: Option<&str>, timeout_secs: u64) -> Result<Self, GoFileError> {
        let mut builder = reqwest::blocking::Client::builder()
            .cookie_store(true)
            .timeout(Duration::from_secs(timeout_secs));

        if let Some(raw_proxy) = proxy_url.map(str::trim).filter(|s| !s.is_empty()) {
            let proxy = reqwest::Proxy::all(raw_proxy).map_err(|e| {
                GoFileError::Config(format!("Invalid GOFILE_PROXY '{raw_proxy}': {e}"))
            })?;
            builder = builder.proxy(proxy);
        }

        let api_client = builder
            .build()
            .map_err(|e| GoFileError::Config(format!("HTTP client initialization failed: {e}")))?;
        Ok(Self { api_client })
    }
}

impl HttpTransport for ReqwestTransport {
    fn post_text(&self, url: &str, headers: &[(&str, &str)]) -> Result<String, GoFileError> {
        let mut req = self.api_client.post(url);
        for &(k, v) in headers {
            req = req.header(k, v);
        }
        let resp = req.send().map_err(|e| map_reqwest_err(&e, url))?;
        decode_text_response(resp, url)
    }

    fn get_text(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        query: &[(&str, &str)],
    ) -> Result<String, GoFileError> {
        let mut req = self.api_client.get(url);
        for &(k, v) in headers {
            req = req.header(k, v);
        }
        if !query.is_empty() {
            req = req.query(query);
        }
        let resp = req.send().map_err(|e| map_reqwest_err(&e, url))?;
        decode_text_response(resp, url)
    }

    fn open_stream(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<ByteStreamResponse, GoFileError> {
        let mut req = self.api_client.get(url);
        for &(k, v) in headers {
            req = req.header(k, v);
        }
        let resp = req
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(|e| map_reqwest_err(&e, url))?;
        let status = resp.status().as_u16();
        let content_length = resp
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        Ok(ByteStreamResponse {
            status,
            content_length,
            reader: Box::new(resp),
        })
    }
}

fn decode_text_response(
    resp: reqwest::blocking::Response,
    url: &str,
) -> Result<String, GoFileError> {
    let status = resp.status();
    if status.is_server_error() {
        return Err(GoFileError::Authentication(format!(
            "HTTP {status} from {url}"
        )));
    }
    let body = resp.text().map_err(|e| map_reqwest_err(&e, url))?;
    if status.is_client_error() && !body.trim_start().starts_with('{') {
        return Err(GoFileError::Authentication(format!(
            "HTTP {status} from {url}"
        )));
    }
    Ok(body)
}

fn map_reqwest_err(err: &reqwest::Error, ctx: &str) -> GoFileError {
    let msg = err.to_string();
    if is_connection_reset_message(&msg) {
        return GoFileError::EdgeBlocked(ctx.to_string());
    }
    GoFileError::Authentication(format!("HTTP error for {ctx}: {msg}"))
}

/// Child file or subfolder metadata returned inside a GoFile `/contents/{id}` listing.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentChild {
    /// Item kind (`"file"` or `"folder"`).
    #[serde(rename = "type", default = "default_item_type")]
    pub item_type: String,
    /// Display name of the file or folder.
    #[serde(default = "default_item_name")]
    pub name: String,
    /// Direct download URL (present for `"file"` entries).
    #[serde(default)]
    pub link: Option<String>,
    /// Optional reported byte size.
    #[serde(default)]
    pub size: Option<u64>,
}

fn default_item_type() -> String {
    "file".to_string()
}

fn default_item_name() -> String {
    "unknown".to_string()
}

/// Normalized GoFile content payload supporting both `children` and legacy `contents` maps.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentNode {
    /// Node kind (`"folder"` or `"file"`).
    #[serde(rename = "type", default = "default_item_type")]
    pub node_type: String,
    /// Display name of this node.
    #[serde(default = "default_item_name")]
    pub name: String,
    /// Direct download link when `node_type != "folder"`.
    #[serde(default)]
    pub link: Option<String>,
    /// Password validation status (`"passwordOk"` on valid or public shares).
    #[serde(rename = "passwordStatus", default = "default_password_ok")]
    pub password_status: String,
    /// Total child count reported by GoFile for paginated folders (`childrenCount`).
    #[serde(rename = "childrenCount", default)]
    pub children_count: Option<usize>,
    /// Primary child map returned by current GoFile API versions.
    #[serde(default)]
    pub children: BTreeMap<String, ContentChild>,
    /// Fallback child map returned by older GoFile API responses.
    #[serde(default)]
    pub contents: BTreeMap<String, ContentChild>,
}

fn default_password_ok() -> String {
    "passwordOk".to_string()
}

impl ContentNode {
    /// Returns the active child map (`children` if non-empty, otherwise `contents`).
    #[must_use]
    pub fn effective_children(&self) -> &BTreeMap<String, ContentChild> {
        if !self.children.is_empty() {
            &self.children
        } else {
            &self.contents
        }
    }

    /// Counts immediate child entries in this node (matching `GoFile.count_files`).
    #[must_use]
    pub fn count_files(&self) -> usize {
        self.effective_children().len()
    }
}

/// Extracts embedded JSON content metadata from GoFile HTML fallback pages.
///
/// # Examples
///
/// ```
/// use gofile_dl::transport::extract_embedded_content_json;
///
/// let html = r#"<script>window.contentData = {"type":"file","name":"demo.zip"};</script>"#;
/// let node = extract_embedded_content_json(html).unwrap();
/// assert_eq!(node.name, "demo.zip");
/// ```
#[must_use]
pub fn extract_embedded_content_json(html: &str) -> Option<ContentNode> {
    static EMBEDDED_PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    let regexes = EMBEDDED_PATTERNS.get_or_init(|| {
        [
            r"(?s)contentData\s*=\s*(\{.*?\});",
            r"(?s)var\s+content\s*=\s*(\{.*?\});",
            r"(?s)window\.contentData\s*=\s*(\{.*?\});",
            r"(?s)const\s+contentData\s*=\s*(\{.*?\});",
        ]
        .into_iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
    });

    for re in regexes {
        if let Some(node) = find_valid_node(re, html) {
            return Some(node);
        }
    }
    None
}

fn find_valid_node(re: &Regex, html: &str) -> Option<ContentNode> {
    re.captures_iter(html)
        .filter_map(|caps| caps.get(1))
        .find_map(|m| serde_json::from_str::<ContentNode>(m.as_str()).ok())
}
