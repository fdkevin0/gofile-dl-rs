#![forbid(unsafe_code)]
//! `gofile-dl` — High-performance, 100% Safe Rust GoFile.io CLI & Web Downloader.
//!
//! ## Architecture Overview
//!
//! - [`token`]: Rotating 4-hour `X-Website-Token` SHA-256 generator, password hashing,
//!   and zero-regex GoFile share URL / bare ID extraction.
//! - [`sanitize`]: Unicode emoji stripping (preserving CJK/Kana/Hangul), universal
//!   filename sanitization, `..` traversal hardening, and folder rename normalization.
//! - [`tracker`]: Atomic `.gofile_tracker_{id}.json` incremental sync persistence and
//!   renamed-folder matching.
//! - [`client`]: Isolated [`client::GoFileClient`] with trait-abstracted HTTP transport,
//!   guest rate-limit backoff, `-1` token-window boundary retry, and web HTML fallback.
//! - [`downloader`]: Resumable `.part` streaming downloader with HTTP `206` vs `200`
//!   integrity verification, zero-division-safe progress hooks, and KB/s throttling.
//! - [`soa`]: Cache-aligned Struct-of-Arrays (`BatchArenaSoA`) + SHA-256 midstate reuse
//!   for high-throughput batch processing.
//! - [`tasks`], [`security`], [`web`]: Thread-safe task manager, HMAC-SHA256 CSRF,
//!   Basic Auth, and `axum` dashboard server.

pub mod browse;
pub mod client;
pub mod config;
pub mod downloader;
pub mod error;
pub mod idiomatic;
pub mod prng;
pub mod sanitize;
pub mod security;
pub mod soa;
pub mod tasks;
pub mod token;
pub mod tracker;
pub mod transfer;
pub mod transport;
pub mod web;
