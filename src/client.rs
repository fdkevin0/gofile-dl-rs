//! Isolated GoFile HTTP API client with guest account provisioning, rate-limit
//! backoff, `-1` token-window boundary retry, and web-session HTML fallback.
//!
//! Each [`GoFileClient`] owns an isolated token state (never a process-wide singleton),
//! preventing premium-token bleed across concurrent tasks.
//!
//! ## Request Flow
//!
//! 1. [`GoFileClient::update_token`] provisions a guest account via `POST /accounts`
//!    (up to 3 attempts) unless initialized with an explicit `premium_token`.
//! 2. [`GoFileClient::fetch_contents`] queries `/contents/{id}` with `X-Website-Token`,
//!    retries `error-rateLimit` with linear backoff (`3s`, `6s`, `9s`), retries
//!    `error-notPremium` with `-1` window offset, aggregates multi-page folders
//!    (`> 1000` children), and falls back to HTML scraping for guest accounts.

pub use crate::transport::{
    extract_embedded_content_json, ByteStreamResponse, ContentChild, ContentNode, HttpTransport,
    ReqwestTransport,
};

use crate::error::GoFileError;
use crate::token::{generate_website_token, hash_password, WebsiteTokenConfig};
use serde::Deserialize;
use std::time::Duration;

const DEFAULT_API_BASE_URL: &str = "https://api.gofile.io";
const DEFAULT_WEB_BASE_URL: &str = "https://gofile.io";
const PAGE_SIZE: usize = 1000;

#[derive(Debug, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
struct ApiEnvelope<T> {
    status: String,
    #[serde(default = "Option::default")]
    data: Option<T>,
}

#[derive(Debug, Default, Deserialize)]
struct AccountData {
    #[serde(default)]
    token: String,
}

/// Isolated GoFile API client bound to a transport implementation `T`.
pub struct GoFileClient<T: HttpTransport> {
    transport: T,
    token: String,
    premium_token: Option<String>,
    wt_config: WebsiteTokenConfig,
    api_base_url: String,
    web_base_url: String,
}

impl<T: HttpTransport> GoFileClient<T> {
    /// Creates an independent client with optional `premium_token` and `wt_config`.
    #[must_use]
    pub fn new(transport: T, premium_token: Option<String>, wt_config: WebsiteTokenConfig) -> Self {
        let cleaned_premium = premium_token
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty());
        let api_base_url = env_base_url("GOFILE_API_BASE_URL", DEFAULT_API_BASE_URL);
        let web_base_url = env_base_url("GOFILE_WEB_BASE_URL", DEFAULT_WEB_BASE_URL);
        Self {
            transport,
            token: String::new(),
            premium_token: cleaned_premium,
            wt_config,
            api_base_url,
            web_base_url,
        }
    }

    /// Overrides the GoFile API and web base URLs (e.g. for local loopback servers).
    #[must_use]
    pub fn with_base_urls(
        mut self,
        api_base: impl Into<String>,
        web_base: impl Into<String>,
    ) -> Self {
        self.api_base_url = api_base.into().trim_end_matches('/').to_string();
        self.web_base_url = web_base.into().trim_end_matches('/').to_string();
        self
    }

    /// Borrows the underlying HTTP transport.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns the currently active account or guest token (empty until authenticated).
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Returns `true` if initialized with a premium account token.
    #[must_use]
    pub const fn is_premium(&self) -> bool {
        self.premium_token.is_some()
    }

    /// Returns the website-token configuration used for request headers.
    #[must_use]
    pub const fn wt_config(&self) -> &WebsiteTokenConfig {
        &self.wt_config
    }

    /// Computes `X-Website-Token` for the active account token and `window_offset`.
    #[must_use]
    pub fn website_token(&self, window_offset: i64) -> String {
        generate_website_token(&self.token, window_offset, &self.wt_config)
    }

    /// Ensures `self.token` is populated (either via `premium_token` or `POST /accounts`).
    ///
    /// # Errors
    ///
    /// Returns [`GoFileError`] if guest account creation fails across all 3 attempts.
    pub fn update_token(&mut self) -> Result<&str, GoFileError> {
        if !self.token.is_empty() {
            return Ok(&self.token);
        }
        if let Some(prem) = &self.premium_token {
            self.token.clone_from(prem);
            return Ok(&self.token);
        }
        self.token = acquire_guest_token(
            &self.transport,
            &self.api_base_url,
            &self.wt_config.user_agent,
        )?;
        Ok(&self.token)
    }

    /// Fetches `/contents/{content_id}` with automatic rate-limit backoff, `-1` window
    /// retry on `error-notPremium`, multi-page (`>1000` children) aggregation, and web
    /// HTML session fallback.
    ///
    /// # Errors
    ///
    /// Returns [`GoFileError`] on missing content, invalid password, rate limiting, or
    /// persistent authentication failure.
    pub fn fetch_contents(
        &mut self,
        content_id: &str,
        password: Option<&str>,
    ) -> Result<ContentNode, GoFileError> {
        self.update_token()?;
        let pw_hash = password.filter(|p| !p.is_empty()).map(hash_password);
        let mut node = self.fetch_contents_page(content_id, pw_hash.as_deref(), 1)?;

        let total = node.children_count.unwrap_or(0);
        if node.node_type == "folder" && total > PAGE_SIZE {
            self.append_remaining_pages(content_id, pw_hash.as_deref(), total, &mut node)?;
        }

        Ok(node)
    }

    fn append_remaining_pages(
        &self,
        content_id: &str,
        pw_hash: Option<&str>,
        total: usize,
        node: &mut ContentNode,
    ) -> Result<(), GoFileError> {
        let mut page = 2_usize;
        while node.children.len() >= PAGE_SIZE && node.children.len() < total && page <= 100 {
            let prev_len = node.children.len();
            let next_page = self.fetch_contents_page(content_id, pw_hash, page)?;
            if next_page.children.is_empty() {
                break;
            }
            node.children.extend(next_page.children);
            if node.children.len() == prev_len {
                break;
            }
            page += 1;
        }
        Ok(())
    }

    fn fetch_contents_page(
        &self,
        content_id: &str,
        pw_hash: Option<&str>,
        page: usize,
    ) -> Result<ContentNode, GoFileError> {
        let url = format!("{}/contents/{content_id}", self.api_base_url);
        let page_str = page.to_string();
        let page_size_str = PAGE_SIZE.to_string();
        let window_offsets = [0_i64, -1_i64];

        for attempt in 0..4usize {
            let offset = window_offsets[attempt.min(window_offsets.len() - 1)];
            let env = match self.request_contents_envelope(
                &url,
                &page_str,
                &page_size_str,
                pw_hash,
                offset,
            ) {
                Ok(parsed) => parsed,
                Err(GoFileError::EdgeBlocked(ctx)) => return Err(GoFileError::EdgeBlocked(ctx)),
                Err(_) if attempt < 3 => {
                    self.transport.backoff_sleep(Duration::from_secs(3));
                    continue;
                }
                Err(e) => return Err(e),
            };

            if let Some(res) = self.evaluate_envelope(content_id, pw_hash, page, attempt, env) {
                return res;
            }
        }

        Err(GoFileError::Authentication(format!(
            "Exhausted attempts fetching content {content_id}"
        )))
    }

    fn request_contents_envelope(
        &self,
        url: &str,
        page_str: &str,
        page_size_str: &str,
        pw_hash: Option<&str>,
        offset: i64,
    ) -> Result<ApiEnvelope<ContentNode>, GoFileError> {
        let auth_hdr = format!("Bearer {}", self.token);
        let wt_hdr = self.website_token(offset);
        let headers = [
            ("Authorization", auth_hdr.as_str()),
            ("X-Website-Token", wt_hdr.as_str()),
            ("X-BL", self.wt_config.language.as_str()),
            ("User-Agent", self.wt_config.user_agent.as_str()),
            ("Accept", "*/*"),
            ("Origin", "https://gofile.io"),
            ("Referer", "https://gofile.io/"),
        ];
        let mut query = vec![
            ("contentFilter", ""),
            ("page", page_str),
            ("pageSize", page_size_str),
            ("sortField", "createTime"),
            ("sortDirection", "-1"),
        ];
        if let Some(h) = pw_hash {
            query.push(("password", h));
        }
        let raw = self.transport.get_text(url, &headers, &query)?;
        serde_json::from_str(&raw).map_err(GoFileError::from)
    }

    fn evaluate_envelope(
        &self,
        content_id: &str,
        pw_hash: Option<&str>,
        page: usize,
        attempt: usize,
        env: ApiEnvelope<ContentNode>,
    ) -> Option<Result<ContentNode, GoFileError>> {
        match env.status.as_str() {
            "ok" => Some(validate_content_node(env.data)),
            "error-rateLimit" if attempt < 3 => {
                let wait_secs = 3 * ((attempt as u64) + 1);
                self.transport.backoff_sleep(Duration::from_secs(wait_secs));
                None
            }
            "error-rateLimit" => Some(Err(GoFileError::RateLimited(content_id.to_string()))),
            "error-notPremium" if attempt == 0 => None,
            "error-notPremium" => Some(self.resolve_not_premium(content_id, pw_hash, page)),
            "error-notFound" => Some(Err(GoFileError::ContentNotFound(content_id.to_string()))),
            other => Some(Err(GoFileError::Authentication(format!(
                "GoFile API returned '{other}'"
            )))),
        }
    }

    fn resolve_not_premium(
        &self,
        content_id: &str,
        pw_hash: Option<&str>,
        page: usize,
    ) -> Result<ContentNode, GoFileError> {
        if page == 1 && !self.is_premium() {
            if let Some(fallback) = self.try_web_fallback(content_id, pw_hash) {
                return Ok(fallback);
            }
        }
        Err(GoFileError::Authentication(
            "Website token rejected (error-notPremium); check GOFILE_WT_SALT or token".to_string(),
        ))
    }

    fn try_web_fallback(&self, content_id: &str, pw_hash: Option<&str>) -> Option<ContentNode> {
        let page_url = format!("{}/d/{content_id}", self.web_base_url);
        let page_headers = [
            ("User-Agent", self.wt_config.user_agent.as_str()),
            (
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
            ("Accept-Language", "en-US,en;q=0.5"),
            ("Referer", "https://gofile.io/"),
        ];
        let html = self
            .transport
            .get_text(&page_url, &page_headers, &[])
            .ok()?;

        if let Some(node) = self.retry_api_with_page_referer(content_id, &page_url, pw_hash) {
            return Some(node);
        }
        extract_embedded_content_json(&html)
    }

    fn retry_api_with_page_referer(
        &self,
        content_id: &str,
        page_url: &str,
        pw_hash: Option<&str>,
    ) -> Option<ContentNode> {
        let api_url = format!("{}/contents/{content_id}", self.api_base_url);
        let auth_hdr = format!("Bearer {}", self.token);
        let wt_hdr = self.website_token(0);
        let api_headers = [
            ("Authorization", auth_hdr.as_str()),
            ("X-Website-Token", wt_hdr.as_str()),
            ("X-BL", self.wt_config.language.as_str()),
            ("User-Agent", self.wt_config.user_agent.as_str()),
            ("Accept", "*/*"),
            ("Origin", "https://gofile.io"),
            ("Referer", page_url),
        ];
        let mut query = vec![
            ("contentFilter", ""),
            ("page", "1"),
            ("pageSize", "1000"),
            ("sortField", "createTime"),
            ("sortDirection", "-1"),
        ];
        if let Some(h) = pw_hash {
            query.push(("password", h));
        }

        let raw = self
            .transport
            .get_text(&api_url, &api_headers, &query)
            .ok()?;
        let env: ApiEnvelope<ContentNode> = serde_json::from_str(&raw).ok()?;
        if env.status != "ok" {
            return None;
        }
        env.data.filter(|n| n.password_status == "passwordOk")
    }
}

fn acquire_guest_token<T: HttpTransport>(
    transport: &T,
    api_base_url: &str,
    user_agent: &str,
) -> Result<String, GoFileError> {
    let accounts_url = format!("{api_base_url}/accounts");
    let headers = [("User-Agent", user_agent), ("Origin", "https://gofile.io")];
    let mut last_err = String::from("unknown error");
    for attempt in 0..3 {
        match try_create_guest_account(transport, &accounts_url, &headers) {
            Ok(Some(tok)) => return Ok(tok),
            Ok(None) => last_err = String::from("API returned empty guest token"),
            Err(GoFileError::EdgeBlocked(ctx)) => return Err(GoFileError::EdgeBlocked(ctx)),
            Err(err) if attempt < 2 => {
                last_err = err.to_string();
                transport.backoff_sleep(Duration::from_secs(2));
            }
            Err(err) => last_err = err.to_string(),
        }
    }
    Err(GoFileError::Authentication(format!(
        "Failed to acquire guest token: {last_err}"
    )))
}

fn try_create_guest_account<T: HttpTransport>(
    transport: &T,
    accounts_url: &str,
    headers: &[(&str, &str)],
) -> Result<Option<String>, GoFileError> {
    let body = transport.post_text(accounts_url, headers)?;
    let parsed: ApiEnvelope<AccountData> = serde_json::from_str(&body)
        .map_err(|e| GoFileError::Serialization(format!("Malformed JSON: {e}")))?;
    if parsed.status != "ok" {
        return Ok(None);
    }
    Ok(parsed.data.map(|d| d.token).filter(|t| !t.is_empty()))
}

fn validate_content_node(data: Option<ContentNode>) -> Result<ContentNode, GoFileError> {
    let node = data.ok_or_else(|| {
        GoFileError::Serialization("Missing 'data' object on status=ok".to_string())
    })?;
    if node.password_status != "passwordOk" {
        return Err(GoFileError::Password(node.password_status));
    }
    Ok(node)
}

fn env_base_url(var_name: &str, default_val: &str) -> String {
    std::env::var(var_name)
        .ok()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_val.to_string())
}
