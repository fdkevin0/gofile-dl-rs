//! Data-Oriented Struct-of-Arrays (`BatchArenaSoA`) & zero-allocation SIMD-friendly
//! execution kernels for Stage 3 (`soa_simd`) and Stage 4 (`pgo_lto`).
//!
//! Combines `Sha256` prefix midstate cloning, stack base-10 integer formatting,
//! 2-byte LUT hex encoding, zero-copy slice prefix normalization, reusable string
//! arenas, and contiguous `f64` auto-vectorizable bandwidth throttle arrays.

pub use crate::idiomatic::{run_seed_idiomatic, ParitySeedResult};

use crate::error::GoFileError;
use crate::prng::parity_consts::{
    BAD_CHARS, CUSTOM_PATTERNS, EMOJIS, FOLDER_PREFIXES, RESERVED_STEMS,
};
use crate::prng::SplitMix64;
use crate::sanitize::{sanitize_filename_into, strip_emojis_into, FolderNormalizer};
use crate::token::{
    encode_sha256_hex, encode_sha256_hex_into, parse_content_id_slice, DEFAULT_USER_AGENT,
    WT_WINDOW_SECONDS,
};
use crate::tracker::DownloadTracker;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Static `(file_id, file_name)` pairs avoiding heap formatting in the hot loop.
const TRACKER_SLOTS: [(&str, &str); 16] = [
    ("f_0", "part_0.bin"),
    ("f_1", "part_1.bin"),
    ("f_2", "part_2.bin"),
    ("f_3", "part_3.bin"),
    ("f_4", "part_4.bin"),
    ("f_5", "part_5.bin"),
    ("f_6", "part_6.bin"),
    ("f_7", "part_7.bin"),
    ("f_8", "part_8.bin"),
    ("f_9", "part_9.bin"),
    ("f_10", "part_10.bin"),
    ("f_11", "part_11.bin"),
    ("f_12", "part_12.bin"),
    ("f_13", "part_13.bin"),
    ("f_14", "part_14.bin"),
    ("f_15", "part_15.bin"),
];

/// Struct-of-Arrays (SoA) pre-allocated workspace for zero-allocation hot-loop execution.
///
/// # Examples
///
/// ```
/// use gofile_dl::soa::{run_seed_idiomatic, run_seed_soa, BatchArenaSoA};
///
/// let tmp = std::env::temp_dir().join("gofile_soa_doctest");
/// let r1 = run_seed_idiomatic(7, 32, &tmp.join("s1")).unwrap();
/// let mut arena = BatchArenaSoA::with_capacity(32);
/// let r2 = run_seed_soa(7, 32, &tmp.join("s2"), &mut arena).unwrap();
/// assert_eq!(r1.digest, r2.digest);
/// assert!((r1.total_throttle_sleep - r2.total_throttle_sleep).abs() <= 1e-12);
/// let _ = std::fs::remove_dir_all(&tmp);
/// ```
pub struct BatchArenaSoA {
    midstate_en: Sha256,
    midstate_fr: Sha256,
    normalizers: [FolderNormalizer; 3],
    tracker_normalizer: FolderNormalizer,
    chunk_bytes: Vec<f64>,
    limit_bps: Vec<f64>,
    elapsed_s: Vec<f64>,
    sleep_out: Vec<f64>,
    record_scratch: Vec<u8>,
    url_scratch: String,
    fname_scratch: String,
    stripped_scratch: String,
    clean_scratch: String,
    san_filter_scratch: String,
    san_incoming_scratch: String,
    folder_scratch: String,
}

impl BatchArenaSoA {
    /// Pre-allocates SoA numeric columns, SHA-256 midstates, scratch buffers, and normalizers.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let mut midstate_en = Sha256::new();
        midstate_en.update(DEFAULT_USER_AGENT.as_bytes());
        midstate_en.update(b"::en-US::");

        let mut midstate_fr = Sha256::new();
        midstate_fr.update(DEFAULT_USER_AGENT.as_bytes());
        midstate_fr.update(b"::fr-FR::");

        let normalizers = [
            FolderNormalizer::new(CUSTOM_PATTERNS[0]),
            FolderNormalizer::new(CUSTOM_PATTERNS[1]),
            FolderNormalizer::new(CUSTOM_PATTERNS[2]),
        ];
        let tracker_normalizer =
            FolderNormalizer::new(Some("🔥HOT |⭐NEW FILES in |NEW FILES in |⭐"));

        Self {
            midstate_en,
            midstate_fr,
            normalizers,
            tracker_normalizer,
            chunk_bytes: Vec::with_capacity(capacity),
            limit_bps: Vec::with_capacity(capacity),
            elapsed_s: Vec::with_capacity(capacity),
            sleep_out: Vec::with_capacity(capacity),
            record_scratch: Vec::with_capacity(256),
            url_scratch: String::with_capacity(96),
            fname_scratch: String::with_capacity(96),
            stripped_scratch: String::with_capacity(96),
            clean_scratch: String::with_capacity(96),
            san_filter_scratch: String::with_capacity(96),
            san_incoming_scratch: String::with_capacity(96),
            folder_scratch: String::with_capacity(96),
        }
    }
}

/// Formats a signed 64-bit integer into base-10 ASCII on a 24-byte stack buffer.
#[inline]
fn format_i64_stack(val: i64, buf: &mut [u8; 24]) -> &[u8] {
    let neg = val < 0;
    let mut mag: u64 = val.unsigned_abs();
    let mut pos = buf.len();
    if mag == 0 {
        pos -= 1;
        buf[pos] = b'0';
    } else {
        while mag > 0 {
            pos -= 1;
            buf[pos] = b'0' + (mag % 10) as u8;
            mag /= 10;
        }
    }
    if neg {
        pos -= 1;
        buf[pos] = b'-';
    }
    &buf[pos..]
}

/// Vectorizable contiguous `f64` bandwidth-throttling kernel over SoA slices.
///
/// Computes $\max\bigl(0, \text{cb}/\text{lim} - \text{el}\bigr)$ whenever instantaneous
/// throughput $\text{cb}/\text{el}$ exceeds $\text{lim}$, then reduces the total sleep seconds.
///
/// # Examples
///
/// ```
/// use gofile_dl::soa::compute_throttle_sleep_soa;
///
/// let mut out = [0.0_f64; 2];
/// let sum = compute_throttle_sleep_soa(&[16384.0, 1024.0], &[8192.0, 8192.0], &[0.5, 0.5], &mut out);
/// assert!((sum - 1.5).abs() < 1e-12);
/// ```
#[inline]
pub fn compute_throttle_sleep_soa(
    chunk_bytes: &[f64],
    limit_bps: &[f64],
    elapsed_s: &[f64],
    sleep_out: &mut [f64],
) -> f64 {
    let n = chunk_bytes
        .len()
        .min(limit_bps.len())
        .min(elapsed_s.len())
        .min(sleep_out.len());
    for i in 0..n {
        let cb = chunk_bytes[i];
        let lim = limit_bps[i];
        let el = elapsed_s[i];
        let rate = cb / el;
        let s = if rate > lim { (cb / lim) - el } else { 0.0 };
        sleep_out[i] = if s > 0.0 { s } else { 0.0 };
    }
    let mut sum = 0.0_f64;
    for &s in &sleep_out[..n] {
        sum += s;
    }
    sum
}

/// Stage 3/4 (`soa_simd` & `pgo_lto`) Struct-of-Arrays zero-allocation seed runner.
///
/// # Errors
///
/// Returns [`GoFileError`] if directory initialization or final tracker flush fails.
pub fn run_seed_soa(
    seed: u64,
    items_per_seed: usize,
    seed_dir: &Path,
    arena: &mut BatchArenaSoA,
) -> Result<ParitySeedResult, GoFileError> {
    fs::create_dir_all(seed_dir)?;
    let existing_base_names: [String; 4] =
        std::array::from_fn(|i| format!("Series_S{i:02}_Seed{seed}"));
    for bname in &existing_base_names {
        fs::create_dir_all(seed_dir.join(bname))?;
    }

    let indexed_dirs: [(String, String); 4] = std::array::from_fn(|i| {
        let norm = arena.tracker_normalizer.normalize(&existing_base_names[i]);
        (existing_base_names[i].clone(), norm)
    });

    let cfg_dir = seed_dir.join("config");
    let mut tracker = DownloadTracker::with_config_dir(
        seed_dir,
        &cfg_dir,
        &format!("cid_{seed}"),
        Some("🔥HOT |⭐NEW FILES in |NEW FILES in |⭐"),
    )?;
    let mut seen_bits: u16 = 0;

    arena.chunk_bytes.clear();
    arena.limit_bps.clear();
    arena.elapsed_s.clear();
    arena.sleep_out.resize(items_per_seed, 0.0);

    let mut rng = SplitMix64::new(seed);
    let mut digest_hasher = Sha256::new();
    let mut parsed_valid_count = 0usize;
    let mut skipped_incremental_count = 0usize;
    let mut matched_renamed_count = 0usize;

    let mut tok_bytes = [0u8; 24];
    let mut cid_bytes = [0u8; 14];
    let mut wt_hex = [0u8; 64];
    let mut int_buf = [0u8; 24];

    for idx in 0..items_per_seed {
        rng.fill_alnum_bytes(&mut tok_bytes);
        let unix_ts = 1_770_000_000_i64 + (rng.next_range(86_400 * 30) as i64);
        let window_offset = (rng.next_range(3) as i64) - 1;
        let salt_num = rng.next_range(1000);
        let is_en = rng.next_range(2) == 0;

        let window = unix_ts.div_euclid(WT_WINDOW_SECONDS) + window_offset;
        let mut wt_hasher = if is_en {
            arena.midstate_en.clone()
        } else {
            arena.midstate_fr.clone()
        };
        wt_hasher.update(tok_bytes);
        wt_hasher.update(b"::");
        wt_hasher.update(format_i64_stack(window, &mut int_buf));
        let salt_tail = [
            b':',
            b':',
            b's',
            b'a',
            b'l',
            b't',
            b'_',
            b'0' + ((salt_num / 1000) % 10) as u8,
            b'0' + ((salt_num / 100) % 10) as u8,
            b'0' + ((salt_num / 10) % 10) as u8,
            b'0' + (salt_num % 10) as u8,
        ];
        wt_hasher.update(salt_tail);
        let wt_digest: [u8; 32] = wt_hasher.finalize().into();
        encode_sha256_hex_into(&wt_digest, &mut wt_hex);

        let cid_len = 6 + (rng.next_range(8) as usize);
        rng.fill_alnum_bytes(&mut cid_bytes[..cid_len]);
        let cid_str = std::str::from_utf8(&cid_bytes[..cid_len]).unwrap_or("");
        build_synthetic_url(&mut arena.url_scratch, rng.next_range(6), cid_str);
        let parsed_cid = parse_content_id_slice(&arena.url_scratch);
        if parsed_cid.is_some() {
            parsed_valid_count += 1;
        }

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

        arena.fname_scratch.clear();
        arena.fname_scratch.push_str("  ");
        arena.fname_scratch.push_str(em1);
        arena.fname_scratch.push(' ');
        arena.fname_scratch.push_str(stem);
        arena.fname_scratch.push_str(bad);
        let idx_ascii = format_i64_stack(idx as i64, &mut int_buf);
        arena
            .fname_scratch
            .push_str(std::str::from_utf8(idx_ascii).unwrap_or("0"));
        arena.fname_scratch.push(' ');
        arena.fname_scratch.push_str(em2);
        arena.fname_scratch.push_str(ext);
        arena.fname_scratch.push_str(trail);

        strip_emojis_into(&arena.fname_scratch, &mut arena.stripped_scratch);
        sanitize_filename_into(
            &arena.stripped_scratch,
            &mut arena.san_filter_scratch,
            &mut arena.clean_scratch,
        );

        let base_folder =
            &existing_base_names[rng.next_range(existing_base_names.len() as u64) as usize];
        let prefix = FOLDER_PREFIXES[rng.next_range(FOLDER_PREFIXES.len() as u64) as usize];
        let pat_idx = rng.next_range(CUSTOM_PATTERNS.len() as u64) as usize;
        arena.folder_scratch.clear();
        arena.folder_scratch.push_str(prefix);
        arena.folder_scratch.push_str(base_folder);

        let norm_folder = arena.normalizers[pat_idx].normalize_slice(&arena.folder_scratch);
        sanitize_filename_into(
            &arena.folder_scratch,
            &mut arena.san_filter_scratch,
            &mut arena.san_incoming_scratch,
        );
        let found = indexed_dirs
            .iter()
            .any(|(exact, _)| exact == &arena.san_incoming_scratch)
            || {
                let target_norm = arena
                    .tracker_normalizer
                    .normalize_slice(&arena.folder_scratch);
                indexed_dirs.iter().any(|(_, n)| n == target_norm)
            };
        if found {
            matched_renamed_count += 1;
        }

        let slot = idx % 16;
        let mask = 1u16 << (slot as u16);
        if (seen_bits & mask) != 0 {
            skipped_incremental_count += 1;
        } else {
            seen_bits |= mask;
            let (fid, fname) = TRACKER_SLOTS[slot];
            tracker.mark_downloaded_in_memory(fid, fname);
        }

        arena
            .chunk_bytes
            .push((8192 * (1 + rng.next_range(8))) as f64);
        arena
            .limit_bps
            .push(((256 + rng.next_range(2048)) as f64) * 1024.0);
        arena
            .elapsed_s
            .push(0.005 * ((1 + rng.next_range(10)) as f64));

        arena.record_scratch.clear();
        arena.record_scratch.extend_from_slice(&wt_hex);
        arena.record_scratch.push(b'|');
        arena
            .record_scratch
            .extend_from_slice(parsed_cid.unwrap_or("NONE").as_bytes());
        arena.record_scratch.push(b'|');
        arena
            .record_scratch
            .extend_from_slice(arena.stripped_scratch.as_bytes());
        arena.record_scratch.push(b'|');
        arena
            .record_scratch
            .extend_from_slice(arena.clean_scratch.as_bytes());
        arena.record_scratch.push(b'|');
        arena
            .record_scratch
            .extend_from_slice(norm_folder.as_bytes());
        arena.record_scratch.push(b'|');
        arena.record_scratch.push(if found { b'1' } else { b'0' });
        digest_hasher.update(&arena.record_scratch);
    }

    tracker.save_tracking_data()?;
    let total_throttle_sleep = compute_throttle_sleep_soa(
        &arena.chunk_bytes,
        &arena.limit_bps,
        &arena.elapsed_s,
        &mut arena.sleep_out,
    );

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

#[inline]
fn build_synthetic_url(buf: &mut String, kind: u64, cid_str: &str) {
    buf.clear();
    match kind {
        0 => {
            buf.push_str("https://gofile.io/d/");
            buf.push_str(cid_str);
        }
        1 => {
            buf.push_str("  http://www.gofile.io/d/");
            buf.push_str(cid_str);
            buf.push_str("/?p=1#top ");
        }
        2 => buf.push_str(cid_str),
        3 => {
            buf.push_str("HTTPS://GOFILE.IO/D/");
            buf.push_str(cid_str);
            buf.push_str("?filter=abc");
        }
        4 => {
            buf.push_str("https://example.com/d/");
            buf.push_str(cid_str);
        }
        _ => buf.push_str("   not a valid url / bad   "),
    }
}
