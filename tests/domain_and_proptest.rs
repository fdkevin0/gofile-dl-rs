//! Domain unit tests, legacy `test_basic.py` parity tests, CJK & traversal regression
//! tests, and `proptest` property-based fuzzing suites.

use gofile_dl::client::{
    ByteStreamResponse, ContentChild, ContentNode, GoFileClient, HttpTransport,
};
use gofile_dl::error::{is_connection_reset_message, GoFileError};
use gofile_dl::sanitize::{
    normalize_folder_name, safe_child_path, sanitize_filename, strip_emojis,
};
use gofile_dl::soa::{run_seed_idiomatic, run_seed_soa, BatchArenaSoA};
use gofile_dl::token::{
    generate_website_token_at, hash_password, parse_content_id, WebsiteTokenConfig,
    DEFAULT_LANGUAGE, DEFAULT_USER_AGENT, DEFAULT_WT_SALT,
};
use gofile_dl::tracker::DownloadTracker;
use proptest::prelude::*;
use std::collections::BTreeMap;
use std::path::Path;
use tempfile::tempdir;

#[derive(Clone, Default)]
struct DummyTransport;

impl HttpTransport for DummyTransport {
    fn post_text(&self, _url: &str, _headers: &[(&str, &str)]) -> Result<String, GoFileError> {
        Ok(r#"{"status":"ok","data":{"token":"guest_abc"}}"#.to_string())
    }
    fn get_text(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
        _query: &[(&str, &str)],
    ) -> Result<String, GoFileError> {
        Ok(r#"{"status":"ok","data":{"type":"folder","name":"root"}}"#.to_string())
    }
    fn open_stream(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
    ) -> Result<ByteStreamResponse, GoFileError> {
        Err(GoFileError::Authentication("unused".to_string()))
    }
}

#[test]
fn test_errors_display_and_edge_detection() {
    let err = GoFileError::Authentication("bad token".to_string());
    assert!(err.to_string().contains("bad token"));

    let dl_err = GoFileError::Download {
        message: "timeout".to_string(),
        filename: "ep1.mkv".to_string(),
        url: "https://store1.gofile.io/ep1.mkv".to_string(),
    };
    assert_eq!(
        dl_err.to_string(),
        "timeout: ep1.mkv (https://store1.gofile.io/ep1.mkv)"
    );
    assert!(is_connection_reset_message("curl: (35) SSL connect error"));
    assert!(is_connection_reset_message("Connection reset by peer"));
    assert!(!is_connection_reset_message("404 not found"));
}

#[test]
fn test_gofile_client_isolated_instances() {
    let mut c1 = GoFileClient::new(
        DummyTransport,
        Some("premium_secret_1".to_string()),
        WebsiteTokenConfig::default(),
    );
    let mut c2 = GoFileClient::new(DummyTransport, None, WebsiteTokenConfig::default());

    assert!(c1.is_premium());
    assert!(!c2.is_premium());
    assert_eq!(c1.update_token().unwrap(), "premium_secret_1");
    assert_eq!(c2.update_token().unwrap(), "guest_abc");
    assert_ne!(c1.token(), c2.token());
}

#[test]
fn test_website_token_is_deterministic_sha256() {
    let tok = "exampletoken1234567890";
    let wt1 = generate_website_token_at(
        tok,
        1_775_000_000,
        0,
        DEFAULT_USER_AGENT,
        DEFAULT_LANGUAGE,
        DEFAULT_WT_SALT,
    );
    let wt2 = generate_website_token_at(
        tok,
        1_775_000_000,
        0,
        DEFAULT_USER_AGENT,
        DEFAULT_LANGUAGE,
        DEFAULT_WT_SALT,
    );
    let wt_prev = generate_website_token_at(
        tok,
        1_775_000_000,
        -1,
        DEFAULT_USER_AGENT,
        DEFAULT_LANGUAGE,
        DEFAULT_WT_SALT,
    );
    assert_eq!(wt1, wt2);
    assert_eq!(wt1.len(), 64);
    assert_ne!(wt1, wt_prev);
    assert_eq!(hash_password("hunter2").len(), 64);
}

#[test]
fn test_parse_content_id_cases() {
    assert_eq!(
        parse_content_id("https://gofile.io/d/abc123").as_deref(),
        Some("abc123")
    );
    assert_eq!(
        parse_content_id("http://www.gofile.io/d/XyZ9/").as_deref(),
        Some("XyZ9")
    );
    assert_eq!(
        parse_content_id("https://gofile.io/d/abc123?x=1#f").as_deref(),
        Some("abc123")
    );
    assert_eq!(parse_content_id("abc123").as_deref(), Some("abc123"));
    assert_eq!(parse_content_id("https://example.com/nope"), None);
    assert_eq!(parse_content_id("   "), None);
}

#[test]
fn test_strip_emojis_preserves_cjk_kana_hangul() {
    // Regression test for legacy Bug #4 (`\U000024C2-\U0001F251` CJK erasure).
    let input = "  ⭐ 日本語 テスト 한국어 中文 🎬 Episode 01 🚀.mkv  ";
    assert_eq!(
        strip_emojis(input),
        "日本語 テスト 한국어 中文 Episode 01 .mkv"
    );
    assert_eq!(strip_emojis("🎬🚀✨"), "");
}

#[test]
fn test_sanitize_and_safe_child_path_blocks_traversal() {
    assert_eq!(sanitize_filename("CON"), "CON_");
    assert_eq!(sanitize_filename("con.tar.gz"), "con_.tar.gz");
    assert_eq!(sanitize_filename("CLOCK$"), "CLOCK$_");
    assert_eq!(sanitize_filename("a/b\\c:d*e?f\"g<h>i|j"), "abcdefghij");
    assert_eq!(sanitize_filename("trailing. "), "trailing");

    let base = Path::new("/tmp/gofile_safe");
    let p_dotdot = safe_child_path(base, "..", false, "cid99999999").unwrap();
    assert_eq!(p_dotdot, base.join("item_cid99999"));

    let p_emoji_only = safe_child_path(base, "🎬🚀.mp4", true, "abcdef12345").unwrap();
    assert_eq!(p_emoji_only, base.join("item_abcdef12.mp4"));

    assert!(safe_child_path(base, "..", false, "///").is_err());
}

#[test]
fn test_content_node_children_and_legacy_contents_fallback() {
    let mut legacy_map = BTreeMap::new();
    legacy_map.insert(
        "k1".to_string(),
        ContentChild {
            item_type: "file".to_string(),
            name: "a.bin".to_string(),
            link: Some("https://store/a.bin".to_string()),
            size: Some(42),
        },
    );
    let node = ContentNode {
        node_type: "folder".to_string(),
        name: "Folder".to_string(),
        link: None,
        password_status: "passwordOk".to_string(),
        children_count: None,
        children: BTreeMap::new(),
        contents: legacy_map,
    };
    assert_eq!(node.count_files(), 1);
}

#[test]
fn test_tracker_persistence_and_renamed_folder_resolution() {
    let dir = tempdir().unwrap();
    let cfg_dir = dir.path().join("cfg");
    let dl_dir = dir.path().join("downloads");
    std::fs::create_dir_all(dl_dir.join("Show S01")).unwrap();

    let mut tracker = DownloadTracker::with_config_dir(
        &dl_dir,
        &cfg_dir,
        "content42",
        Some("🔥HOT |⭐NEW FILES in |NEW FILES in |⭐"),
    )
    .unwrap();
    assert!(tracker.is_empty());
    tracker.mark_downloaded("f10", "ep01.mkv").unwrap();
    assert_eq!(tracker.len(), 1);

    let matched = tracker
        .find_existing_folder("⭐NEW FILES in Show S01", &dl_dir)
        .unwrap();
    assert_eq!(matched, dl_dir.join("Show S01"));

    // Reload from persisted JSON file
    let reloaded = DownloadTracker::with_config_dir(
        &dl_dir,
        &cfg_dir,
        "content42",
        Some("🔥HOT |⭐NEW FILES in |NEW FILES in |⭐"),
    )
    .unwrap();
    assert!(reloaded.is_downloaded("f10", "ep01.mkv"));
    assert!(!reloaded.is_downloaded("f10", "ep02.mkv"));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn prop_sanitize_filename_invariants(s in "\\PC{0,320}") {
        let out = sanitize_filename(&s);
        prop_assert!(out.len() <= 255);
        for ch in out.chars() {
            let cp = ch as u32;
            prop_assert!(cp > 0x1F && cp != 0x7F);
            prop_assert!(!matches!(ch, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'));
        }
    }

    #[test]
    fn prop_safe_child_path_never_escapes_parent(
        raw_name in "\\PC{0,120}",
        strip_flag in any::<bool>(),
        id in "[A-Za-z0-9]{4,16}"
    ) {
        let parent = Path::new("/tmp/proptest_root");
        let joined = safe_child_path(parent, &raw_name, strip_flag, &id).unwrap();
        prop_assert_eq!(joined.parent(), Some(parent));
        let fname = joined.file_name().unwrap().to_string_lossy();
        prop_assert!(fname != "." && fname != ".." && !fname.is_empty());
    }

    #[test]
    fn prop_website_token_64_hex_and_window_sensitivity(
        tok in "[A-Za-z0-9]{8,32}",
        ts in 1_600_000_000_i64..2_000_000_000_i64,
        salt in "[a-f0-9]{6,16}"
    ) {
        let wt0 = generate_website_token_at(&tok, ts, 0, DEFAULT_USER_AGENT, DEFAULT_LANGUAGE, &salt);
        let wt1 = generate_website_token_at(&tok, ts, -1, DEFAULT_USER_AGENT, DEFAULT_LANGUAGE, &salt);
        prop_assert_eq!(wt0.len(), 64);
        prop_assert!(wt0.bytes().all(|b| b.is_ascii_hexdigit()));
        prop_assert_ne!(wt0, wt1);
    }

    #[test]
    fn prop_normalize_folder_idempotent_after_strip(base in "[A-Za-z0-9_]{3,24}") {
        let prefixed = format!("⭐NEW FILES in {base}");
        let once = normalize_folder_name(&prefixed, None);
        let twice = normalize_folder_name(&once, None);
        prop_assert_eq!(once.as_str(), base.as_str());
        prop_assert_eq!(twice.as_str(), base.as_str());
    }

    #[test]
    fn prop_soa_matches_idiomatic_exact(seed in 0_u64..500_u64) {
        let tmp = tempdir().unwrap();
        let r_safe = run_seed_idiomatic(seed, 24, &tmp.path().join("safe")).unwrap();
        let mut arena = BatchArenaSoA::with_capacity(24);
        let r_soa = run_seed_soa(seed, 24, &tmp.path().join("soa"), &mut arena).unwrap();
        prop_assert_eq!(r_safe.digest, r_soa.digest);
        prop_assert_eq!(r_safe.parsed_valid_count, r_soa.parsed_valid_count);
        prop_assert_eq!(r_safe.skipped_incremental_count, r_soa.skipped_incremental_count);
        prop_assert_eq!(r_safe.matched_renamed_count, r_soa.matched_renamed_count);
        prop_assert!((r_safe.total_throttle_sleep - r_soa.total_throttle_sleep).abs() <= 1e-12);
    }
}
