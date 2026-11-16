//! Deterministic `SplitMix64` pseudo-random number generator and synthetic
//! workload item synthesizer for bit-exact Python vs. Rust A/B parity testing.
//!
//! Every arithmetic step uses explicit 64-bit wrapping semantics matching
//! `scripts/legacy_bench_and_parity.py`, guaranteeing identical pseudo-random
//! streams across platforms, optimization levels, and PGO passes.

/// Portable 64-bit `SplitMix64` PRNG with deterministic state progression.
///
/// # Examples
///
/// ```
/// use gofile_dl::prng::SplitMix64;
///
/// let mut rng_a = SplitMix64::new(42);
/// let mut rng_b = SplitMix64::new(42);
/// assert_eq!(rng_a.next_u64(), rng_b.next_u64());
/// assert!(rng_a.next_range(10) < 10);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Creates a new deterministic PRNG initialized with `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Advances the state and returns the next 64-bit unsigned integer.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Returns a deterministic value in `0..upper` matching `next_u64() % upper`.
    ///
    /// # Panics
    ///
    /// Panics if `upper == 0`.
    #[inline]
    pub fn next_range(&mut self, upper: u64) -> u64 {
        assert!(upper > 0, "upper bound must be non-zero");
        self.next_u64() % upper
    }

    /// Generates an ASCII alphanumeric + hyphen token of `len` bytes.
    #[must_use]
    pub fn gen_alnum(&mut self, len: usize) -> String {
        const ALPHANUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-";
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            let idx = self.next_range(ALPHANUM.len() as u64) as usize;
            out.push(ALPHANUM[idx] as char);
        }
        out
    }

    /// Writes `len` deterministic alphanumeric ASCII bytes directly into `buf`
    /// without heap allocation.
    #[inline]
    pub fn fill_alnum_bytes(&mut self, buf: &mut [u8]) {
        const ALPHANUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-";
        for slot in buf.iter_mut() {
            let idx = self.next_range(ALPHANUM.len() as u64) as usize;
            *slot = ALPHANUM[idx];
        }
    }
}

/// Constants shared between the Python parity harness and Rust synthetic generator.
pub mod parity_consts {
    /// Emoji palette used to synthesize Unicode filenames.
    pub const EMOJIS: [&str; 8] = ["⭐", "🎬", "🚀", "🔥", "✅", "🎵", "📦", "✨"];
    /// Forbidden filesystem characters injected into synthetic filenames.
    pub const BAD_CHARS: [&str; 11] = [
        "/", "\\", ":", "*", "?", "\"", "<", ">", "|", "\x00", "\x1f",
    ];
    /// Reserved and normal filename stems used in parity workloads.
    pub const RESERVED_STEMS: [&str; 10] = [
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "LPT1",
        "CLOCK$",
        "Episode01",
        "Archive",
        "Track_07",
    ];
    /// Folder prefixes simulating GoFile upload/rename conventions.
    pub const FOLDER_PREFIXES: [&str; 7] = [
        "",
        "⭐NEW FILES in ",
        "⭐ NEW FILES in ",
        "NEW FILES in ",
        "*** NEW FILES in ",
        "🔥HOT ",
        "⭐",
    ];
    /// Optional custom pipe-delimited pattern configurations.
    pub const CUSTOM_PATTERNS: [Option<&str>; 3] = [
        None,
        Some("⭐NEW FILES in |NEW FILES in |⭐"),
        Some("🔥HOT |⭐NEW FILES in |NEW FILES in |⭐"),
    ];
}
