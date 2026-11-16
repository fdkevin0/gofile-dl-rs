//! Stage 2 (`safe_rust`) idiomatic Safe Rust deterministic seed runner and shared
//! [`ParitySeedResult`] schema.
//!
//! ## Overview
//!
//! [`run_seed_idiomatic`] serves as the straightforward, idiomatic Safe Rust reference
//! implementation of the 6-kernel workload (`X-Website-Token` SHA-256 generation, URL/ID
//! extraction, emoji stripping + Windows/POSIX sanitization, folder prefix normalization,
//! incremental [`DownloadTracker`] deduplication, and KB/s bandwidth throttle sleep math).
//!
//! It uses standard `String` formatting and immediate per-file JSON persistence to mirror
//! the control flow of `legacy/run.py` while eliminating Python's interpreter overhead.
//! Stage 3 ([`crate::soa::run_seed_soa`]) accelerates the exact same mathematical pipeline
//! via a reusable Structure-of-Arrays arena and SIMD auto-vectorized slice loops, and is
//! verified bit-for-bit against [`run_seed_idiomatic`] across 100 seeds.

use crate::error::GoFileError;
use crate::prng::parity_consts::{
    BAD_CHARS, CUSTOM_PATTERNS, EMOJIS, FOLDER_PREFIXES, RESERVED_STEMS,
};
use crate::prng::SplitMix64;
use crate::sanitize::{normalize_folder_name, sanitize_filename, strip_emojis};
use crate::token::{
    encode_sha256_hex, generate_website_token_at, parse_content_id, DEFAULT_USER_AGENT,
};
use crate::tracker::DownloadTracker;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Output record for one deterministic seed, compared directly against Python in A/B parity.
///
/// Every integer counter and the 64-char SHA-256 `digest` must match identically across
/// Stage 1 (`legacy_baseline`), Stage 2 (`safe_rust`), Stage 3 (`soa_simd`), and Stage 4
/// (`pgo_lto`), while `total_throttle_sleep` must agree within `1e-12` seconds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParitySeedResult {
    /// Deterministic seed index.
    pub seed: u64,
    /// Number of pipeline items processed for this seed.
    pub items: usize,
    /// 64-character lowercase SHA-256 hex digest of all item outputs.
    pub digest: String,
    /// Count of valid GoFile URLs / bare IDs extracted.
    pub parsed_valid_count: usize,
    /// Count of files skipped by incremental `DownloadTracker` deduplication.
    pub skipped_incremental_count: usize,
    /// Count of incoming folders matched to existing renamed folders on disk.
    pub matched_renamed_count: usize,
    /// Accumulated bandwidth-throttling sleep duration in seconds (`f64`).
    pub total_throttle_sleep: f64,
}

/// Stage 2 (`safe_rust`) idiomatic Safe Rust seed runner.
///
/// Synthesizes `items_per_seed` deterministic items from `SplitMix64::new(seed)`, runs
/// each item through all 6 GoFile domain kernels, persists incremental tracking records
/// under `seed_dir/config`, and returns the aggregated [`ParitySeedResult`].
///
/// # Examples
///
/// ```
/// use gofile_dl::idiomatic::run_seed_idiomatic;
///
/// let tmp = tempfile::tempdir().unwrap();
/// let res = run_seed_idiomatic(0, 8, tmp.path()).unwrap();
/// assert_eq!(res.items, 8);
/// assert_eq!(res.digest.len(), 64);
/// ```
///
/// # Errors
///
/// Returns [`GoFileError`] if directory creation or tracker persistence fails.
pub fn run_seed_idiomatic(
    seed: u64,
    items_per_seed: usize,
    seed_dir: &Path,
) -> Result<ParitySeedResult, GoFileError> {
    fs::create_dir_all(seed_dir)?;
    let existing_base_names: Vec<String> = (0..4)
        .map(|i| format!("Series_S{i:02}_Seed{seed}"))
        .collect();
    for bname in &existing_base_names {
        fs::create_dir_all(seed_dir.join(bname))?;
    }

    let cfg_dir = seed_dir.join("config");
    let mut tracker = DownloadTracker::with_config_dir(
        seed_dir,
        &cfg_dir,
        &format!("cid_{seed}"),
        Some("🔥HOT |⭐NEW FILES in |NEW FILES in |⭐"),
    )?;

    let mut rng = SplitMix64::new(seed);
    let mut digest_hasher = Sha256::new();
    let mut total_throttle_sleep = 0.0_f64;
    let mut parsed_valid_count = 0usize;
    let mut skipped_incremental_count = 0usize;
    let mut matched_renamed_count = 0usize;

    for idx in 0..items_per_seed {
        // Kernel 1: Time-windowed SHA-256 `X-Website-Token` synthesis.
        let token_str = rng.gen_alnum(24);
        let unix_ts = 1_770_000_000_i64 + (rng.next_range(86_400 * 30) as i64);
        let window_offset = (rng.next_range(3) as i64) - 1;
        let salt = format!("salt_{:04}", rng.next_range(1000));
        let lang = if rng.next_range(2) == 0 {
            "en-US"
        } else {
            "fr-FR"
        };
        let wt = generate_website_token_at(
            &token_str,
            unix_ts,
            window_offset,
            DEFAULT_USER_AGENT,
            lang,
            &salt,
        );

        // Kernel 2: GoFile URL & bare content-ID extraction across 6 URL shapes.
        let cid_len = 6 + (rng.next_range(8) as usize);
        let cid_core = rng.gen_alnum(cid_len);
        let raw_url = match rng.next_range(6) {
            0 => format!("https://gofile.io/d/{cid_core}"),
            1 => format!("  http://www.gofile.io/d/{cid_core}/?p=1#top "),
            2 => cid_core.clone(),
            3 => format!("HTTPS://GOFILE.IO/D/{cid_core}?filter=abc"),
            4 => format!("https://example.com/d/{cid_core}"),
            _ => "   not a valid url / bad   ".to_string(),
        };
        let parsed_cid = parse_content_id(&raw_url);
        if parsed_cid.is_some() {
            parsed_valid_count += 1;
        }

        // Kernel 3: Unicode emoji stripping + Windows/POSIX reserved-stem sanitization.
        let stem = RESERVED_STEMS[rng.next_range(RESERVED_STEMS.len() as u64) as usize];
        let em1 = EMOJIS[rng.next_range(EMOJIS.len() as u64) as usize];
        let em2 = EMOJIS[rng.next_range(EMOJIS.len() as u64) as usize];
        let bad = BAD_CHARS[rng.next_range(BAD_CHARS.len() as u64) as usize];
        let ext = if rng.next_range(2) == 0 {
            ".mkv"
        } else {
            ".zip"
        };
        let trail = if rng.next_range(3) == 0 { " . " } else { "" };
        let raw_fname = format!("  {em1} {stem}{bad}{idx} {em2}{ext}{trail}");
        let stripped_fname = strip_emojis(&raw_fname);
        let clean_fname = sanitize_filename(&stripped_fname);

        // Kernel 4: Folder prefix normalization & renamed-folder lookup on disk.
        let base_folder =
            &existing_base_names[rng.next_range(existing_base_names.len() as u64) as usize];
        let prefix = FOLDER_PREFIXES[rng.next_range(FOLDER_PREFIXES.len() as u64) as usize];
        let custom_pat = CUSTOM_PATTERNS[rng.next_range(CUSTOM_PATTERNS.len() as u64) as usize];
        let incoming_folder = format!("{prefix}{base_folder}");
        let norm_folder = normalize_folder_name(&incoming_folder, custom_pat);
        let found_folder = tracker.find_existing_folder(&incoming_folder, seed_dir);
        if found_folder.is_some() {
            matched_renamed_count += 1;
        }

        // Kernel 5: Incremental `DownloadTracker` deduplication with per-item JSON flush.
        let file_id = format!("f_{}", idx % 16);
        let logical_name = format!("part_{}.bin", idx % 16);
        if tracker.is_downloaded(&file_id, &logical_name) {
            skipped_incremental_count += 1;
        } else {
            tracker.mark_downloaded(&file_id, &logical_name)?;
        }

        // Kernel 6: KB/s bandwidth rate-limiting sleep accumulation (`f64`).
        let chunk_bytes = (8192 * (1 + rng.next_range(8))) as f64;
        let throttle_kbps = (256 + rng.next_range(2048)) as f64;
        let elapsed_s = 0.005 * ((1 + rng.next_range(10)) as f64);
        let rate = chunk_bytes / elapsed_s;
        let limit_bps = throttle_kbps * 1024.0;
        let mut sleep_s = if rate > limit_bps {
            (chunk_bytes / limit_bps) - elapsed_s
        } else {
            0.0
        };
        if sleep_s < 0.0 {
            sleep_s = 0.0;
        }
        total_throttle_sleep += sleep_s;

        let record = format!(
            "{wt}|{}|{stripped_fname}|{clean_fname}|{norm_folder}|{}",
            parsed_cid.as_deref().unwrap_or("NONE"),
            usize::from(found_folder.is_some())
        );
        digest_hasher.update(record.as_bytes());
    }

    let digest_bytes: [u8; 32] = digest_hasher.finalize().into();
    Ok(ParitySeedResult {
        seed,
        items: items_per_seed,
        digest: encode_sha256_hex(&digest_bytes),
        parsed_valid_count,
        skipped_incremental_count,
        matched_renamed_count,
        total_throttle_sleep,
    })
}
