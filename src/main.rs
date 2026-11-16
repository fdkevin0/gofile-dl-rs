#![forbid(unsafe_code)]
//! Command-line and web-server entry point for `gofile-dl`.
//!
//! Supports four execution modes:
//! 1. **Legacy-Compatible CLI Download**: `gofile-dl <URL_OR_ID> [-d DIR] [-p PASS] ...`
//! 2. **Web Dashboard Server**: `gofile-dl serve [--config config.yml] [--host H] [--port P]`
//! 3. **4-Stage Throughput Benchmark**: `gofile-dl bench --mode <safe|soa>`
//! 4. **A/B Differential Parity Runner**: `gofile-dl parity-seed --seed S --items N --work-dir W`

use clap::{Parser, Subcommand, ValueEnum};
use gofile_dl::client::{GoFileClient, ReqwestTransport};
use gofile_dl::config::{read_app_version, AppConfig};
use gofile_dl::downloader::{execute_download, DownloadOptions, ProgressHooks};
use gofile_dl::error::GoFileError;
use gofile_dl::sanitize::DEFAULT_FOLDER_PATTERNS;
use gofile_dl::soa::{run_seed_idiomatic, run_seed_soa, BatchArenaSoA};
use gofile_dl::tasks::TaskManager;
use gofile_dl::token::{encode_sha256_hex, WebsiteTokenConfig};
use gofile_dl::web::{build_router, WebAppState};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
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

    /// GoFile share URL or bare content ID (legacy CLI mode).
    #[arg(value_name = "URL")]
    url: Option<String>,

    /// Output directory for downloaded files (`-d` compatible with legacy `run.py`).
    #[arg(short = 'd', long = "dir")]
    dir: Option<PathBuf>,

    /// Password for protected GoFile shares (`-p` compatible with legacy `run.py`).
    #[arg(short = 'p', long = "password")]
    password: Option<String>,

    /// Optional bandwidth speed limit in KB/s.
    #[arg(long = "throttle")]
    throttle_kbps: Option<u64>,

    /// Retry attempts for failed file downloads (0-10).
    #[arg(long = "retries", default_value_t = 3)]
    retries: u32,

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
    /// Execute deterministic multi-seed throughput benchmark (`safe` vs `soa`).
    Bench {
        /// Execution kernel mode.
        #[arg(long = "mode", value_enum, default_value_t = BenchMode::Soa)]
        mode: BenchMode,
        /// Number of deterministic seeds to execute.
        #[arg(long = "seeds", default_value_t = 100)]
        seeds: u64,
        /// Pipeline items per seed.
        #[arg(long = "items-per-seed", default_value_t = 250)]
        items_per_seed: usize,
    },
    /// Execute a single deterministic seed and emit JSON for A/B differential parity.
    ParitySeed {
        /// Seed value.
        #[arg(long = "seed")]
        seed: u64,
        /// Number of items to synthesize for this seed.
        #[arg(long = "items", default_value_t = 64)]
        items: usize,
        /// Working directory for tracker and folder matching.
        #[arg(long = "work-dir")]
        work_dir: PathBuf,
    },
}

/// Selects which Rust kernel executes in `gofile-dl bench`.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum BenchMode {
    /// Stage 2 idiomatic Safe Rust (`run_seed_idiomatic`).
    Safe,
    /// Stage 3/4 Structure-of-Arrays + SIMD auto-vectorized arena (`run_seed_soa`).
    Soa,
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

/// Parses CLI arguments and dispatches to `serve`, `bench`, `parity-seed`, or legacy URL mode.
fn try_main() -> Result<(), GoFileError> {
    let mut cli = Cli::parse();
    match cli.command.take() {
        Some(Commands::Serve { config, host, port }) => run_server(&config, host, port),
        Some(Commands::Bench {
            mode,
            seeds,
            items_per_seed,
        }) => run_bench(mode, seeds, items_per_seed),
        Some(Commands::ParitySeed {
            seed,
            items,
            work_dir,
        }) => run_parity_seed(seed, items, &work_dir),
        None => dispatch_default_mode(cli),
    }
}

/// Runs a single deterministic seed via [`BatchArenaSoA`] and prints JSON for `legacy_bench_and_parity.py`.
fn run_parity_seed(seed: u64, items: usize, work_dir: &Path) -> Result<(), GoFileError> {
    let mut arena = BatchArenaSoA::with_capacity(items);
    let res = run_seed_soa(seed, items, work_dir, &mut arena)?;
    println!("{}", serde_json::to_string(&res)?);
    Ok(())
}

/// Dispatches bare `gofile-dl` invocations: runs a CLI download if `URL` was supplied,
/// or launches the web server with `config.yml` when invoked with no arguments (Docker default).
fn dispatch_default_mode(cli: Cli) -> Result<(), GoFileError> {
    let Some(url) = cli.url.clone() else {
        return run_server(Path::new("config.yml"), None, None);
    };
    run_cli_download(&url, cli)
}

/// Executes a one-shot CLI download and emits final summary counters to stderr.
fn run_cli_download(url: &str, cli: Cli) -> Result<(), GoFileError> {
    let proxy = std::env::var("GOFILE_PROXY")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let transport = ReqwestTransport::new(proxy.as_deref(), 45)?;
    let mut client =
        GoFileClient::new(transport, cli.premium_token, WebsiteTokenConfig::from_env());
    let opts = DownloadOptions {
        output_dir: cli.dir.unwrap_or_else(|| PathBuf::from("./output")),
        password: cli.password,
        chunk_size: 8192,
        throttle_kbps: cli.throttle_kbps,
        retry_attempts: cli.retries.min(10),
        retry_delay_secs: 5,
        strip_emojis: cli.strip_emojis,
        incremental: cli.incremental,
        folder_pattern: cli.folder_pattern,
        config_dir: None,
    };
    let summary = execute_download(&mut client, url, &opts, &CliProgressLogger)?;
    eprintln!(
        "[gofile-dl] Completed '{}': {} downloaded, {} skipped, {} failed",
        summary.root_name, summary.files_downloaded, summary.files_skipped, summary.files_failed
    );
    Ok(())
}

fn run_bench(mode: BenchMode, seeds: u64, items_per_seed: usize) -> Result<(), GoFileError> {
    let tmp_dir = std::env::temp_dir().join(format!("gofile_rs_bench_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir)?;

    let mut combined = Sha256::new();
    let mut total_sleep = 0.0_f64;
    let mut arena = BatchArenaSoA::with_capacity(items_per_seed);

    for s in 0..seeds {
        let seed_dir = tmp_dir.join(format!("seed_{s}"));
        let res = match mode {
            BenchMode::Safe => run_seed_idiomatic(s, items_per_seed, &seed_dir)?,
            BenchMode::Soa => run_seed_soa(s, items_per_seed, &seed_dir, &mut arena)?,
        };
        combined.update(res.digest.as_bytes());
        total_sleep += res.total_throttle_sleep;
    }

    let _ = fs::remove_dir_all(&tmp_dir);
    let digest_bytes: [u8; 32] = combined.finalize().into();
    let out = json!({
        "seeds": seeds,
        "items_per_seed": items_per_seed,
        "combined_digest": encode_sha256_hex(&digest_bytes),
        "total_throttle_sleep": (total_sleep * 1e12).round() / 1e12,
    });
    println!("{out}");
    Ok(())
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
        app_version: read_app_version(Path::new("version.txt")),
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
