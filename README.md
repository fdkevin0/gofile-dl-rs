# GoFile Downloader (`gofile-dl`) — Safe Rust Edition

![Version](https://img.shields.io/github/v/release/fdkevin0/gofile-dl-rs?color=blue)
![Rust](https://img.shields.io/badge/rust-1.85%2B-orange)
![Safety](https://img.shields.io/badge/unsafe-forbid-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

A high-performance, **100% Safe Rust** (`#![forbid(unsafe_code)]`) CLI and Web application for downloading files and nested folder structures from [GoFile.io](https://gofile.io).

Originally ported from [martadams89/gofile-dl](https://github.com/martadams89/gofile-dl) to 100% Safe Rust.

---

## Highlights

- **100% Memory & Concurrency Safe**: Enforces `#![forbid(unsafe_code)]` across library and binary crates with `RwLock`-synchronized task registries, `CONFIG_DIR/tasks.json` persistence, `TASK_EXPIRY` terminal task eviction, `X-CSRF-Token` session rotation, and lock-free `AtomicBool` pause/cancel/retry controls.
- **2026 GoFile Dynamic `X-Website-Token` Support**: Computes rotating 4-hour `wt` SHA-256 tokens (`sha256(ua::lang::token::window::salt)`), automatically retries `-1` bucket boundaries on `error-notPremium`, backs off on `error-rateLimit`, and falls back to web session HTML extraction.
- **Resilient & Safe Transfers**:
  1. **Zero-Division Safe Transfers**: Handles chunked responses without `Content-Length` and `0`-byte files cleanly.
  2. **HTTP `206` vs `200` Resume Integrity**: Only appends `.part` files when storage servers honor `Range` with `206 Partial Content` (truncating cleanly on `200 OK`).
  3. **Honest Retry Failure Propagation**: Exhausted retries never mark missing files as `100%` or poison incremental `DownloadTracker` ledgers.
  4. **International Script Preservation**: `strip_emojis` removes Emoji/Dingbat/Pictograph codepoints without erasing CJK, Japanese Kana, or Korean Hangul characters.
  5. **Path Confinement**: Blocks `..` and symlink traversal escapes across downloads, `/browse`, and persisted task file deletion.

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
# Run pre-built multi-arch image from GHCR (amd64 / arm64)
# Use :latest for the latest stable release, or :main for rolling main builds
docker run -d --name gofile-dl \
  -p 2355:2355 \
  -v "$(pwd)/downloads:/data" \
  -v "$(pwd)/config:/config" \
  ghcr.io/fdkevin0/gofile-dl-rs:latest

# Or build locally from source
docker build -t gofile-dl:latest .
```

---

## Configuration & Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PORT` | Web server TCP port | `2355` |
| `HOST` | Web server bind address | `0.0.0.0` |
| `BASE_DIR` | Root download & `/browse` directory | `./output` (`/data` in Docker) |
| `CONFIG_DIR` | Directory for `tasks.json` persistence and `.gofile_tracker_{id}.json` sync files | unset (`/config` in Docker) |
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

## Development & Verification

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --doc --locked
```

---

## Community & Governance

- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
