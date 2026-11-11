//! Offline deterministic tests for `GoFileClient` protocol fallbacks and
//! `downloader` streaming edge cases (HTTP 206 vs 200 resume, chunked 0-byte
//! transfers, retry exhaustion integrity, incremental sync, pause/cancel).

use gofile_dl::client::{
    extract_embedded_content_json, ByteStreamResponse, GoFileClient, HttpTransport,
};
use gofile_dl::downloader::{
    download_file, execute_download, DownloadOptions, NoopHooks, ProgressHooks,
};
use gofile_dl::error::GoFileError;
use gofile_dl::token::WebsiteTokenConfig;
use std::collections::VecDeque;
use std::io::Cursor;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;

struct ScriptedStream {
    status: u16,
    content_length: Option<u64>,
    body: Vec<u8>,
}

#[derive(Default)]
struct MockTransport {
    posts: Mutex<VecDeque<Result<String, GoFileError>>>,
    gets: Mutex<VecDeque<Result<String, GoFileError>>>,
    streams: Mutex<VecDeque<Result<ScriptedStream, GoFileError>>>,
    seen_ranges: Mutex<Vec<String>>,
    sleeps: AtomicUsize,
}

impl HttpTransport for MockTransport {
    fn post_text(&self, _url: &str, _headers: &[(&str, &str)]) -> Result<String, GoFileError> {
        self.posts
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Ok(r#"{"status":"ok","data":{"token":"tok_mock"}}"#.to_string()))
    }

    fn get_text(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
        _query: &[(&str, &str)],
    ) -> Result<String, GoFileError> {
        self.gets
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(GoFileError::ContentNotFound("empty queue".to_string())))
    }

    fn open_stream(
        &self,
        _url: &str,
        headers: &[(&str, &str)],
    ) -> Result<ByteStreamResponse, GoFileError> {
        for &(k, v) in headers {
            if k.eq_ignore_ascii_case("Range") {
                self.seen_ranges.lock().unwrap().push(v.to_string());
            }
        }
        let item = self
            .streams
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| {
                Err(GoFileError::Authentication(
                    "no scripted stream".to_string(),
                ))
            })?;
        Ok(ByteStreamResponse {
            status: item.status,
            content_length: item.content_length,
            reader: Box::new(Cursor::new(item.body)),
        })
    }

    fn backoff_sleep(&self, _duration: Duration) {
        self.sleeps.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn test_client_rate_limit_backoff_and_window_fallback() {
    let mock = MockTransport::default();
    mock.gets.lock().unwrap().extend([
        // Attempt 0: error-notPremium triggers immediate window_offset = -1 retry
        Ok(r#"{"status":"error-notPremium","data":{}}"#.to_string()),
        // Attempt 1: error-rateLimit triggers backoff sleep
        Ok(r#"{"status":"error-rateLimit","data":{}}"#.to_string()),
        // Attempt 2: succeeds!
        Ok(r#"{"status":"ok","data":{"type":"folder","name":"Recovered","passwordStatus":"passwordOk","children":{}}}"#.to_string()),
    ]);

    let mut client = GoFileClient::new(mock, None, WebsiteTokenConfig::default());
    let node = client.fetch_contents("cid_recover", Some("pw123")).unwrap();
    assert_eq!(node.name, "Recovered");
    assert_eq!(client.transport().sleeps.load(Ordering::Relaxed), 1);
}

#[test]
fn test_client_web_html_embedded_fallback_and_errors() {
    let html = r#"<html><script>window.contentData = {"type":"file","name":"fallback.bin","link":"https://store/fb.bin","passwordStatus":"passwordOk"};</script></html>"#;
    let parsed = extract_embedded_content_json(html).unwrap();
    assert_eq!(parsed.name, "fallback.bin");

    let mock = MockTransport::default();
    mock.gets.lock().unwrap().extend([
        Ok(r#"{"status":"error-notPremium"}"#.to_string()),
        Ok(r#"{"status":"error-notPremium"}"#.to_string()),
        // Web fallback Step 1: GET gofile.io/d/id HTML
        Ok(html.to_string()),
        // Web fallback Step 2: API still says error-notPremium, so HTML JSON extractor wins
        Ok(r#"{"status":"error-notPremium"}"#.to_string()),
    ]);
    let mut client = GoFileClient::new(mock, None, WebsiteTokenConfig::default());
    let node = client.fetch_contents("cid_web", None).unwrap();
    assert_eq!(node.name, "fallback.bin");

    // Password error check
    let mock_pw = MockTransport::default();
    mock_pw.gets.lock().unwrap().push_back(Ok(
        r#"{"status":"ok","data":{"type":"folder","name":"Locked","passwordStatus":"passwordRequired"}}"#
            .to_string(),
    ));
    let mut client_pw = GoFileClient::new(mock_pw, None, WebsiteTokenConfig::default());
    assert!(matches!(
        client_pw.fetch_contents("locked1", None),
        Err(GoFileError::Password(_))
    ));
}

#[test]
fn test_bugfix_zero_or_missing_content_length_never_divides_by_zero() {
    // Regression test for legacy Bug #1 (`ZeroDivisionError` in `run.py:989`).
    let tmp = tempdir().unwrap();
    let mock = MockTransport::default();
    mock.streams.lock().unwrap().extend([
        Ok(ScriptedStream {
            status: 200,
            content_length: None, // chunked transfer without Content-Length
            body: b"chunked-payload".to_vec(),
        }),
        Ok(ScriptedStream {
            status: 200,
            content_length: Some(0), // explicit 0-byte file
            body: Vec::new(),
        }),
    ]);

    let client = GoFileClient::new(mock, Some("tok".to_string()), WebsiteTokenConfig::default());
    let opts = DownloadOptions::new(tmp.path());

    let f1 = tmp.path().join("chunked.bin");
    download_file(&client, "https://store/1", &f1, &opts, &NoopHooks).unwrap();
    assert_eq!(std::fs::read(&f1).unwrap(), b"chunked-payload");

    let f2 = tmp.path().join("empty.bin");
    download_file(&client, "https://store/2", &f2, &opts, &NoopHooks).unwrap();
    assert!(std::fs::read(&f2).unwrap().is_empty());
}

#[test]
fn test_bugfix_http_206_append_vs_200_truncate_resume_integrity() {
    // Regression test for legacy Bug #2 (silent file corruption when server returns 200 OK).
    let tmp = tempdir().unwrap();
    let mock = MockTransport::default();
    mock.streams.lock().unwrap().extend([
        // Case A: server honors Range with 206 Partial Content
        Ok(ScriptedStream {
            status: 206,
            content_length: Some(6),
            body: b" world".to_vec(),
        }),
        // Case B: server ignores Range and returns 200 OK with full payload
        Ok(ScriptedStream {
            status: 200,
            content_length: Some(11),
            body: b"hello world".to_vec(),
        }),
    ]);

    let client = GoFileClient::new(mock, Some("tok".to_string()), WebsiteTokenConfig::default());
    let opts = DownloadOptions::new(tmp.path());

    let dest_206 = tmp.path().join("resumed_206.txt");
    std::fs::write(tmp.path().join("resumed_206.txt.part"), b"hello").unwrap();
    download_file(&client, "https://store/206", &dest_206, &opts, &NoopHooks).unwrap();
    assert_eq!(std::fs::read(&dest_206).unwrap(), b"hello world");

    let dest_200 = tmp.path().join("fallback_200.txt");
    std::fs::write(tmp.path().join("fallback_200.txt.part"), b"hello").unwrap();
    download_file(&client, "https://store/200", &dest_200, &opts, &NoopHooks).unwrap();
    assert_eq!(std::fs::read(&dest_200).unwrap(), b"hello world");
    assert_eq!(
        client.transport().seen_ranges.lock().unwrap().as_slice(),
        &["bytes=5-", "bytes=5-"]
    );
}

#[derive(Default)]
struct RecordingHooks {
    events: Mutex<Vec<(String, i32)>>,
    paused_once: AtomicBool,
    cancelled: AtomicBool,
}

impl ProgressHooks for RecordingHooks {
    fn on_file_progress(
        &self,
        file_path: &Path,
        progress: i32,
        _size: Option<u64>,
        _retry_info: Option<&str>,
    ) {
        let name = file_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        self.events.lock().unwrap().push((name, progress));
    }

    fn is_paused(&self) -> bool {
        // Return true once to exercise the pause polling loop, then unpause.
        self.paused_once.swap(false, Ordering::SeqCst)
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[test]
fn test_bugfix_failed_download_not_marked_complete_in_incremental_tracker() {
    // Regression test for legacy Bug #3 (`run.py:852-868` poisoning DownloadTracker on failure).
    let tmp = tempdir().unwrap();
    let cfg_dir = tmp.path().join("cfg");
    let out_dir = tmp.path().join("out");

    let mock = MockTransport::default();
    mock.gets.lock().unwrap().push_back(Ok(r#"{
        "status": "ok",
        "data": {
            "type": "folder",
            "name": "⭐ Batch",
            "children": {
                "good1": {"type": "file", "name": "ok.bin", "link": "https://store/ok.bin"},
                "bad1":  {"type": "file", "name": "broken.bin", "link": "https://store/broken.bin"}
            }
        }
    }"#
    .to_string()));
    mock.streams.lock().unwrap().extend([
        Err(GoFileError::Authentication("502 bad gateway".to_string())),
        Err(GoFileError::Authentication("502 bad gateway".to_string())),
        Ok(ScriptedStream {
            status: 200,
            content_length: Some(4),
            body: b"DATA".to_vec(),
        }),
    ]);

    let mut client = GoFileClient::new(mock, None, WebsiteTokenConfig::default());
    let mut opts = DownloadOptions::new(&out_dir);
    opts.retry_attempts = 1;
    opts.retry_delay_secs = 0;
    opts.strip_emojis = true;
    opts.incremental = true;
    opts.throttle_kbps = Some(100_000);
    opts.config_dir = Some(cfg_dir.clone());

    let hooks = Arc::new(RecordingHooks {
        events: Mutex::new(Vec::new()),
        paused_once: AtomicBool::new(true),
        cancelled: AtomicBool::new(false),
    });

    // Note: BTreeMap iterates keys alphabetically ("bad1" then "good1").
    let summary = execute_download(
        &mut client,
        "https://gofile.io/d/batch99",
        &opts,
        hooks.as_ref(),
    )
    .unwrap();
    assert_eq!(summary.files_downloaded, 1);
    assert_eq!(summary.files_failed, 1);
    assert_eq!(summary.root_name, "Batch");

    let recorded = hooks.events.lock().unwrap().clone();
    // `broken.bin` must end at `-2` (Failed), NEVER `100`!
    let broken_last = recorded
        .iter()
        .rfind(|(n, _)| n == "broken.bin")
        .map(|(_, p)| *p);
    assert_eq!(broken_last, Some(-2));

    // Second incremental run: `ok.bin` is skipped, `broken.bin` is retried and succeeds!
    client.transport().gets.lock().unwrap().push_back(Ok(r#"{
        "status": "ok",
        "data": {
            "type": "folder",
            "name": "⭐ Batch",
            "children": {
                "good1": {"type": "file", "name": "ok.bin", "link": "https://store/ok.bin"},
                "bad1":  {"type": "file", "name": "broken.bin", "link": "https://store/broken.bin"}
            }
        }
    }"#
    .to_string()));
    client
        .transport()
        .streams
        .lock()
        .unwrap()
        .push_back(Ok(ScriptedStream {
            status: 200,
            content_length: Some(7),
            body: b"RECOVER".to_vec(),
        }));

    let summary2 = execute_download(&mut client, "batch99", &opts, &NoopHooks).unwrap();
    assert_eq!(summary2.files_skipped, 1);
    assert_eq!(summary2.files_downloaded, 1);
    assert_eq!(summary2.files_failed, 0);
}
