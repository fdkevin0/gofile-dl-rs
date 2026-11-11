//! Unified YAML, `.env`, and environment-variable configuration loader.
//!
//! Resolves the legacy `app.py` / `config.yml` inconsistency where `DEFAULT_CONFIG["base_dir"]`
//! defaulted to `"/"`, `config.yml` specified `"/app"`, and `/health` + `/browse` hardcoded
//! `"/data"` while ignoring `config.yml`. Also wires `task_expiry` for automatic terminal
//! task eviction in long-running server deployments.

use crate::error::GoFileError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// HTTP Basic Authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthConfig {
    /// Whether HTTP Basic Authentication is enforced on protected routes.
    #[serde(default)]
    pub enabled: bool,
    /// Required Basic Auth username when `enabled` is `true`.
    #[serde(default = "default_auth_username")]
    pub username: String,
    /// Required Basic Auth password when `enabled` is `true`.
    #[serde(default = "default_auth_password")]
    pub password: String,
}

fn default_auth_username() -> String {
    "admin".to_string()
}

fn default_auth_password() -> String {
    "change-me-in-production".to_string()
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            username: default_auth_username(),
            password: default_auth_password(),
        }
    }
}

/// Cross-Site Request Forgery (CSRF) token configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CsrfConfig {
    /// Whether mutating HTTP endpoints validate `X-CSRFToken` / `csrf_token`.
    #[serde(default = "default_csrf_enabled")]
    pub enabled: bool,
    /// Token lifetime in seconds (default: `3600`).
    #[serde(default = "default_csrf_time_limit")]
    pub time_limit: u64,
}

const fn default_csrf_enabled() -> bool {
    true
}

const fn default_csrf_time_limit() -> u64 {
    3600
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            time_limit: 3600,
        }
    }
}

/// Top-level `gofile-dl` server and downloader configuration.
///
/// # Examples
///
/// ```
/// use gofile_dl::config::AppConfig;
/// use std::collections::HashMap;
///
/// let mut env = HashMap::new();
/// env.insert("PORT".to_string(), "8080".to_string());
/// env.insert("AUTH_ENABLED".to_string(), "true".to_string());
/// env.insert("TASK_EXPIRY".to_string(), "3600".to_string());
/// let mut cfg = AppConfig::default();
/// cfg.apply_env_map(&env).unwrap();
/// assert_eq!(cfg.port, 8080);
/// assert!(cfg.auth.enabled);
/// assert_eq!(cfg.task_expiry, 3600);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// TCP port for the web interface (default: `2355`).
    #[serde(default = "default_port")]
    pub port: u16,
    /// Bind address for the web interface (default: `"0.0.0.0"`).
    #[serde(default = "default_host")]
    pub host: String,
    /// Root download directory used by `/browse`, `/health`, and default downloads.
    #[serde(default = "default_base_dir")]
    pub base_dir: PathBuf,
    /// Secret key used to sign stateless CSRF tokens.
    #[serde(default = "default_secret_key")]
    pub secret_key: String,
    /// Default retry count for failed file transfers (`0..=10`).
    #[serde(default = "default_retries")]
    pub default_retries: u32,
    /// Delay in seconds between transfer retry attempts.
    #[serde(default = "default_retry_delay")]
    pub retry_delay: u64,
    /// Default bandwidth limit in KB/s (`None` for unlimited).
    #[serde(default)]
    pub default_throttle: Option<u64>,
    /// Seconds after which terminal (`completed`/`error`/`cancelled`) tasks are pruned (`0` = never).
    #[serde(default = "default_task_expiry")]
    pub task_expiry: u64,
    /// Logging verbosity (`INFO`, `DEBUG`, `WARN`, `ERROR`).
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Optional GoFile premium account token.
    #[serde(default)]
    pub premium_token: Option<String>,
    /// Optional HTTP/SOCKS5 proxy URL (`GOFILE_PROXY`).
    #[serde(default)]
    pub proxy: Option<String>,
    /// Basic authentication settings.
    #[serde(default)]
    pub auth: AuthConfig,
    /// CSRF protection settings.
    #[serde(default)]
    pub csrf: CsrfConfig,
}

const fn default_port() -> u16 {
    2355
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_base_dir() -> PathBuf {
    PathBuf::from("./output")
}

fn default_secret_key() -> String {
    Uuid::new_v4().simple().to_string()
}

const fn default_retries() -> u32 {
    3
}

const fn default_retry_delay() -> u64 {
    5
}

const fn default_task_expiry() -> u64 {
    604_800
}

fn default_log_level() -> String {
    "INFO".to_string()
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            host: default_host(),
            base_dir: default_base_dir(),
            secret_key: default_secret_key(),
            default_retries: default_retries(),
            retry_delay: default_retry_delay(),
            default_throttle: None,
            task_expiry: default_task_expiry(),
            log_level: default_log_level(),
            premium_token: None,
            proxy: None,
            auth: AuthConfig::default(),
            csrf: CsrfConfig::default(),
        }
    }
}

impl AppConfig {
    /// Loads configuration from `.env`, an optional `config.yml` file, and process
    /// environment variables (in increasing precedence order).
    ///
    /// # Errors
    ///
    /// Returns [`GoFileError::Config`] if YAML parsing or an environment override fails.
    pub fn load(config_path: Option<&Path>) -> Result<Self, GoFileError> {
        let _ = dotenvy::dotenv();
        let mut cfg = Self::load_yaml_or_default(config_path)?;
        let env_map: HashMap<String, String> = std::env::vars().collect();
        cfg.apply_env_map(&env_map)?;
        Ok(cfg)
    }

    fn load_yaml_or_default(config_path: Option<&Path>) -> Result<Self, GoFileError> {
        let Some(path) = config_path.filter(|p| p.exists()) else {
            return Ok(Self::default());
        };
        let raw = fs::read_to_string(path)?;
        let parsed = serde_yaml::from_str::<Option<Self>>(&raw).map_err(|e| {
            GoFileError::Config(format!(
                "Failed to parse YAML config '{}': {e}",
                path.display()
            ))
        })?;
        Ok(parsed.unwrap_or_default())
    }

    /// Applies environment overrides from an explicit key-value map (deterministic in tests).
    ///
    /// # Errors
    ///
    /// Returns [`GoFileError::Config`] if a numeric variable such as `PORT` cannot be parsed.
    pub fn apply_env_map(&mut self, env: &HashMap<String, String>) -> Result<(), GoFileError> {
        if let Some(v) = non_empty_env(env, "PORT") {
            self.port = v.parse::<u16>().map_err(|e| {
                GoFileError::Config(format!("Failed to parse PORT='{v}' as u16: {e}"))
            })?;
        }
        if let Some(v) = non_empty_env(env, "HOST") {
            self.host = v.to_string();
        }
        if let Some(v) = non_empty_env(env, "BASE_DIR") {
            self.base_dir = PathBuf::from(v);
        }
        if let Some(v) = non_empty_env(env, "SECRET_KEY") {
            self.secret_key = v.to_string();
        }
        if let Some(v) = non_empty_env(env, "DEFAULT_RETRIES") {
            let parsed = v.parse::<u32>().map_err(|e| {
                GoFileError::Config(format!("Failed to parse DEFAULT_RETRIES='{v}': {e}"))
            })?;
            self.default_retries = parsed.min(10);
        }
        if let Some(v) = non_empty_env(env, "RETRY_DELAY") {
            self.retry_delay = v.parse::<u64>().map_err(|e| {
                GoFileError::Config(format!("Failed to parse RETRY_DELAY='{v}': {e}"))
            })?;
        }
        if let Some(v) = non_empty_env(env, "TASK_EXPIRY") {
            self.task_expiry = v.parse::<u64>().map_err(|e| {
                GoFileError::Config(format!("Failed to parse TASK_EXPIRY='{v}': {e}"))
            })?;
        }
        if let Some(v) = non_empty_env(env, "GOFILE_PREMIUM_TOKEN") {
            self.premium_token = Some(v.to_string());
        }
        if let Some(v) = non_empty_env(env, "GOFILE_PROXY") {
            self.proxy = Some(v.to_string());
        }
        if let Some(v) = non_empty_env(env, "AUTH_ENABLED") {
            self.auth.enabled = v.eq_ignore_ascii_case("true") || v == "1";
        }
        if let Some(v) = non_empty_env(env, "AUTH_USERNAME") {
            self.auth.username = v.to_string();
        }
        if let Some(v) = non_empty_env(env, "AUTH_PASSWORD") {
            self.auth.password = v.to_string();
        }
        Ok(())
    }
}

fn non_empty_env<'a>(env: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    env.get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Reads the application version from `version.txt`, falling back to `CARGO_PKG_VERSION`.
///
/// # Examples
///
/// ```
/// use gofile_dl::config::read_app_version;
/// use std::path::Path;
///
/// let v = read_app_version(Path::new("/nonexistent/version.txt"));
/// assert!(!v.is_empty());
/// ```
#[must_use]
pub fn read_app_version(version_file: &Path) -> String {
    fs::read_to_string(version_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
}
