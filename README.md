# GoFile Downloader (`gofile-dl`) — Safe Rust Edition

![Version](https://img.shields.io/badge/version-1.8.3-blue)
![Rust](https://img.shields.io/badge/rust-1.85%2B-orange)
![Safety](https://img.shields.io/badge/unsafe-forbid-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

A high-performance, **100% Safe Rust** (`#![forbid(unsafe_code)]`) CLI and Web application for downloading files and nested folder structures from [GoFile.io](https://gofile.io).

Migrated from the legacy Python/Flask codebase using the `migrate-to-rust` architecture workflow with Profile-Guided Optimization (PGO), Struct-of-Arrays (`BatchArenaSoA`) batch kernels, and bit-exact differential output parity.

---

## Highlights & Architectural Improvements

- **100% Memory & Concurrency Safe**: Enforces `#![forbid(unsafe_code)]` across library and binary crates, replacing unprotected Python global thread state with `RwLock`-synchronized task registries, `TASK_EXPIRY` terminal task eviction, `X-CSRF-Token` session rotation, and lock-free `AtomicBool` pause/cancel controls.
- **2026 GoFile Dynamic `X-Website-Token` Support**: Computes rotating 4-hour `wt` SHA-256 tokens (`sha256(ua::lang::token::window::salt)`), automatically retries `-1` bucket boundaries on `error-notPremium`, backs off on `error-rateLimit`, and falls back to web session HTML extraction.
- **Five Legacy Bugs Eliminated**:
  1. **Zero-Division Safe Transfers**: Handles chunked responses without `Content-Length` and `0`-byte files cleanly.
  2. **HTTP `206` vs `200` Resume Integrity**: Only appends `.part` files when storage servers honor `Range` with `206 Partial Content` (truncating cleanly on `200 OK`).
  3. **Honest Retry Failure Propagation**: Exhausted retries never mark missing files as `100%` or poison incremental `DownloadTracker` ledgers.
  4. **International Script Preservation**: `strip_emojis` removes Emoji/Dingbat/Pictograph codepoints without erasing CJK, Japanese Kana, or Korean Hangul characters.
  5. **Direct `POST /` Form Handling & Traversal Confinement**: Eliminates the broken `POST / -> 302 /start -> 405` redirect and blocks `..` traversal in remote item names and `/browse`.

---

## Quick Start

### Build from Source

```bash
cargo build --release
```

### CLI Usage

```bash
# Download a public GoFile share link or bare content ID
./target/release/gofile-dl "https://gofile.io/d/CONTENT_ID" -d ./downloads

# Password-protected share with bandwidth limit (KB/s), emoji stripping, and incremental sync
./target/release/gofile-dl "https://gofile.io/d/CONTENT_ID" \
  -d ./downloads \
  -p "my-secret-password" \
  --throttle 2048 \
  --retries 3 \
  --strip-emojis \
  --incremental
```

### Web Dashboard Server

```bash
# Starts the Bootstrap 5 dashboard & REST server (default: http://0.0.0.0:2355)
./target/release/gofile-dl serve --config config.yml
```

### Docker Deployment

```bash
docker build -t gofile-dl:latest .
docker run -d --name gofile-dl \
  -p 2355:2355 \
  -v "$(pwd)/downloads:/data" \
  -v "$(pwd)/config:/config" \
  gofile-dl:latest
```

---

## Configuration & Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PORT` | Web server TCP port | `2355` |
| `HOST` | Web server bind address | `0.0.0.0` |
| `BASE_DIR` | Root download & `/browse` directory | `./output` (`/data` in Docker) |
| `CONFIG_DIR` | Directory for `.gofile_tracker_{id}.json` sync files | `/config` |
| `SECRET_KEY` | HMAC-SHA256 signing secret for stateless CSRF tokens | Random UUID |
| `AUTH_ENABLED` | Enable HTTP Basic Authentication | `false` |
| `AUTH_USERNAME` | Basic Auth username | `admin` |
| `AUTH_PASSWORD` | Basic Auth password | `change-me-in-production` |
| `DEFAULT_RETRIES` | Default per-file retry count (`0-10`) | `3` |
| `RETRY_DELAY` | Seconds between transfer retries | `5` |
| `TASK_EXPIRY` | Seconds before completed/failed tasks are pruned (`0` = never) | `604800` |
| `GOFILE_PREMIUM_TOKEN` | Optional GoFile premium account token | unset |
| `GOFILE_WT_SALT` | Rotating `wt.obf.js` salt override | `12af056dacea0b` |
| `GOFILE_USER_AGENT` | User-Agent header & token hash input | Chrome 126 UA |
| `GOFILE_LANGUAGE` | `X-BL` header & token hash input | `en-US` |
| `GOFILE_PROXY` | Optional HTTP or `socks5://` proxy URL | unset |

---

## Verification, Parity & Benchmarks

| Stage | Architecture / Profile | Wall Time (25k items) | Peak RSS | Speedup |
| :--- | :--- | ---: | ---: | ---: |
| **1. Legacy Baseline** | Python 3.12 (`run.py` / `app.py`) | `3,153.52 ms` | `29.92 MB` | `1.00x` |
| **2. Safe Rust Port** | Idiomatic `#![forbid(unsafe_code)]` | `566.88 ms` | `6.96 MB` | `5.56x` |
| **3. SoA + Zero-Alloc** | `BatchArenaSoA` + SHA-256 midstate + SIMD `f64` | `73.77 ms` | `7.04 MB` | `42.75x` |
| **4. LLVM PGO + Fat LTO** | `-Cprofile-use` + `lto = "fat"` + `codegen-units = 1` | **`66.41 ms`** | **`6.21 MB`** | **`47.49x`** |

```bash
# Run unit, integration, proptest property fuzzing, and doc-tests (96.3% unfiltered LLVM line coverage)
cargo test --all-targets
cargo test --doc
cargo clippy --all-targets -- -D warnings

# Run deterministic 100-seed x 250-item SoA throughput benchmark
./target/release/gofile-dl bench --mode soa --seeds 100 --items-per-seed 250
```
