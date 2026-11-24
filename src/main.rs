#![forbid(unsafe_code)]
//! Command-line and web-server entry point for `gofile-dl`.
//!
//! Supports two execution modes:
//! 1. **CLI Download**: `gofile-dl <URL_OR_ID> [-d DIR] [-p PASS] ...`
//! 2. **Web Dashboard Server**: `gofile-dl serve [--config config.yml] [--host H] [--port P]`

use clap::{Parser, Subcommand};
use gofile_dl::client::{GoFileClient, HttpTransport, ReqwestTransport};
use gofile_dl::config::AppConfig;
use gofile_dl::downloader::{execute_download, DownloadOptions, DownloadSummary, ProgressHooks};
use gofile_dl::error::GoFileError;
use gofile_dl::sanitize::DEFAULT_FOLDER_PATTERNS;
use gofile_dl::tasks::TaskManager;
use gofile_dl::token::WebsiteTokenConfig;
use gofile_dl::web::{build_router, WebAppState};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Parser)]
#[command(
    name = "gofile-dl",
    version,
    about = "GoFile.io CLI & Web Downloader (100% Safe Rust)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// GoFile share URL or bare content ID.
    #[arg(value_name = "URL")]
    url: Option<String>,

    /// Output directory for downloaded files.
    #[arg(short = 'd', long = "dir")]
    dir: Option<PathBuf>,

    /// Password for protected GoFile shares.
    #[arg(short = 'p', long = "password")]
    password: Option<String>,

    /// Optional bandwidth speed limit in KB/s.
    #[arg(long = "throttle")]
    throttle_kbps: Option<u64>,

    /// Retry attempts for failed file downloads (0-10).
    #[arg(long = "retries", default_value_t = 3)]
    retries: u32,

    /// Delay in seconds between transfer retry attempts.
    #[arg(long = "retry-delay", env = "RETRY_DELAY", default_value_t = 5)]
    retry_delay: u64,

    /// Strip emojis and pictographs from remote folder and file names.
    #[arg(long = "strip-emojis")]
    strip_emojis: bool,

    /// Enable incremental/sync mode using persistent `.gofile_tracker_{id}.json` files.
    #[arg(long = "incremental")]
    incremental: bool,

    /// Pipe-separated folder prefixes stripped during incremental folder matching.
    #[arg(long = "folder-pattern", default_value = DEFAULT_FOLDER_PATTERNS)]
    folder_pattern: String,

    /// Optional GoFile premium account token.
    #[arg(long = "premium-token", env = "GOFILE_PREMIUM_TOKEN")]
    premium_token: Option<String>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Launch the HTTP web dashboard and task server.
    Serve {
        /// Optional path to `config.yml`.
        #[arg(short = 'c', long = "config", default_value = "config.yml")]
        config: PathBuf,
        /// Override bind host.
        #[arg(long = "host")]
        host: Option<String>,
        /// Override TCP port.
        #[arg(long = "port")]
        port: Option<u16>,
    },
}

/// Terminal stderr progress reporter for interactive and scripted CLI downloads.
struct CliProgressLogger;

impl ProgressHooks for CliProgressLogger {
    fn on_name(&self, name: &str) {
        eprintln!("[gofile-dl] Task name: {name}");
    }

    fn on_overall_progress(&self, percent: u8, folder_name: &str) {
        eprintln!("[gofile-dl] Overall progress: {percent}% | {folder_name}");
    }

    fn on_file_progress(
        &self,
        file_path: &Path,
        progress: i32,
        _size: Option<u64>,
        retry_info: Option<&str>,
    ) {
        if let Some(info) = retry_info {
            eprintln!("[gofile-dl] File {}: {info}", file_path.display());
        } else if progress == 100 || progress == -2 {
            eprintln!(
                "[gofile-dl] File {} progress: {progress}%",
                file_path.display()
            );
        }
    }
}

/// Process entry point that maps top-level [`GoFileError`] failures to exit code `1`.
fn main() {
    if let Err(err) = try_main() {
        eprintln!("[gofile-dl] Error: {err}");
        std::process::exit(1);
    }
}

/// Parses CLI arguments and dispatches to `serve` or one-shot CLI download mode.
fn try_main() -> Result<(), GoFileError> {
    let mut cli = Cli::parse();
    match cli.command.take() {
        Some(Commands::Serve { config, host, port }) => run_server(&config, host, port),
        None => dispatch_default_mode(cli),
    }
}

/// Dispatches bare `gofile-dl` invocations: runs a CLI download if `URL` was supplied,
/// or launches the web server with `config.yml` when invoked with no arguments (Docker default).
fn dispatch_default_mode(cli: Cli) -> Result<(), GoFileError> {
    let Some(url) = cli.url.clone() else {
        return run_server(Path::new("config.yml"), None, None);
    };
    run_cli_download(&url, cli)
}

const MAX_PASSWORD_PROMPTS: usize = 3;

/// Executes a one-shot CLI download and emits final summary counters to stderr.
fn run_cli_download(url: &str, cli: Cli) -> Result<(), GoFileError> {
    let proxy = std::env::var("GOFILE_PROXY")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let transport = ReqwestTransport::new(proxy.as_deref(), 45)?;
    let mut client =
        GoFileClient::new(transport, cli.premium_token, WebsiteTokenConfig::from_env());
    let mut opts = DownloadOptions {
        output_dir: cli.dir.unwrap_or_else(|| PathBuf::from("./output")),
        password: cli.password,
        chunk_size: 8192,
        throttle_kbps: cli.throttle_kbps,
        retry_attempts: cli.retries.min(10),
        retry_delay_secs: cli.retry_delay,
        strip_emojis: cli.strip_emojis,
        incremental: cli.incremental,
        folder_pattern: cli.folder_pattern,
        config_dir: None,
    };
    let summary = execute_download_with_password_prompt(
        &mut client,
        url,
        &mut opts,
        &CliProgressLogger,
        prompt_cli_password,
    )?;
    eprintln!(
        "[gofile-dl] Completed '{}': {} downloaded, {} skipped, {} failed",
        summary.root_name, summary.files_downloaded, summary.files_skipped, summary.files_failed
    );
    Ok(())
}

fn execute_download_with_password_prompt<T, F>(
    client: &mut GoFileClient<T>,
    url: &str,
    opts: &mut DownloadOptions,
    hooks: &dyn ProgressHooks,
    mut prompt_password: F,
) -> Result<DownloadSummary, GoFileError>
where
    T: HttpTransport,
    F: FnMut(&str) -> Option<String>,
{
    let mut attempts = 0usize;
    loop {
        match execute_download(client, url, opts, hooks) {
            Ok(summary) => return Ok(summary),
            Err(GoFileError::Password(status)) if attempts < MAX_PASSWORD_PROMPTS => {
                attempts += 1;
                if let Some(pw) = prompt_password(&status).filter(|s| !s.is_empty()) {
                    opts.password = Some(pw);
                    continue;
                }
                return Err(GoFileError::Password(status));
            }
            Err(err) => return Err(err),
        }
    }
}

fn prompt_cli_password(status: &str) -> Option<String> {
    if status == "passwordWrong" {
        eprint!("[gofile-dl] Incorrect password. Enter password (empty to cancel): ");
    } else {
        eprint!("[gofile-dl] Password required ({status}). Enter password (empty to cancel): ");
    }
    let _ = io::stderr().flush();

    let mut line = String::new();
    let bytes = io::stdin().lock().read_line(&mut line).ok()?;
    if bytes == 0 {
        eprintln!();
        return None;
    }
    while line.ends_with(['\r', '\n']) {
        line.pop();
    }
    (!line.is_empty()).then_some(line)
}

fn run_server(
    config_path: &Path,
    host_override: Option<String>,
    port_override: Option<u16>,
) -> Result<(), GoFileError> {
    let mut cfg = AppConfig::load(Some(config_path))?;
    if let Some(h) = host_override {
        cfg.host = h;
    }
    if let Some(p) = port_override {
        cfg.port = p;
    }
    let bind_addr = format!("{}:{}", cfg.host, cfg.port);
    let cfg_arc = Arc::new(cfg);
    let tasks = TaskManager::new(Arc::clone(&cfg_arc));
    let template_path = PathBuf::from("templates/index.html");
    let state = WebAppState {
        config: cfg_arc,
        tasks,
        template_path: template_path.exists().then_some(template_path),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let router = build_router(state);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| GoFileError::Config(format!("Tokio runtime init failed: {e}")))?;

    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        eprintln!("[gofile-dl] Web server listening on http://{bind_addr}");
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        Ok::<(), GoFileError>(())
    })
}

async fn shutdown_signal() {
    #[cfg(unix)]
    wait_unix_signal().await;
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(unix)]
async fn wait_unix_signal() {
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = recv_sigterm(&mut sigterm) => {}
    }
}

#[cfg(unix)]
async fn recv_sigterm(sigterm: &mut Option<tokio::signal::unix::Signal>) {
    if let Some(s) = sigterm {
        s.recv().await;
    } else {
        std::future::pending::<()>().await;
    }
}
