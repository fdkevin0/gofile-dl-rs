//! Live loopback TCP transport, CLI binary, and reviewer regression integration tests.

use axum::body::Body;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use gofile_dl::browse::probe_existing_dir_writable;
use gofile_dl::client::{ContentChild, ContentNode, GoFileClient, HttpTransport, ReqwestTransport};
use gofile_dl::config::{AppConfig, CsrfConfig};
use gofile_dl::downloader::{execute_download, DownloadOptions, NoopHooks};
use gofile_dl::error::GoFileError;
use gofile_dl::sanitize::sanitize_filename;
use gofile_dl::security::{build_health_response, generate_csrf_token, verify_csrf_token};
use gofile_dl::tasks::{TaskManager, TaskWorkerFn};
use gofile_dl::token::{generate_website_token_at, parse_content_id, WebsiteTokenConfig};
use gofile_dl::tracker::DownloadTracker;
use gofile_dl::transfer::{download_file, part_file_path, remove_path_and_part};
use gofile_dl::transport::extract_embedded_content_json;
use gofile_dl::web::{build_router, WebAppState};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::net::TcpListener as StdTcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tower::ServiceExt;

#[derive(Clone)]
struct MockGoFileState {
    base_url: String,
    account_hits: Arc<AtomicUsize>,
    flaky_dl_hits: Arc<AtomicUsize>,
}

fn spawn_mock_gofile_server() -> (String, std::sync::mpsc::Sender<()>) {
    let std_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let addr = std_listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();

    let state = MockGoFileState {
        base_url: base_url.clone(),
        account_hits: Arc::new(AtomicUsize::new(0)),
        flaky_dl_hits: Arc::new(AtomicUsize::new(0)),
    };

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
            let router = Router::new()
                .route("/accounts", post(mock_accounts))
                .route("/contents/{id}", get(mock_contents))
                .route("/d/{id}", get(mock_web_page))
                .route("/download/{name}", get(mock_download))
                .with_state(state);

            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = tokio::task::spawn_blocking(move || stop_rx.recv()).await;
                })
                .await
                .unwrap();
        });
    });

    (base_url, stop_tx)
}

async fn mock_accounts(State(st): State<MockGoFileState>) -> Response {
    let n = st.account_hits.fetch_add(1, Ordering::SeqCst);
    if n == 0 {
        return (
            StatusCode::BAD_GATEWAY,
            "<html><body>502 Bad Gateway</body></html>",
        )
            .into_response();
    }
    (
        StatusCode::OK,
        axum::Json(json!({
            "status": "ok",
            "data": { "token": "mock-guest-token-123" }
        })),
    )
        .into_response()
}

async fn mock_contents(
    State(st): State<MockGoFileState>,
    AxumPath(id): AxumPath<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if id == "notfound404" {
        return (StatusCode::NOT_FOUND, "<html>404 not found</html>").into_response();
    }
    if id == "htmlfb" {
        return axum::Json(json!({ "status": "error-notPremium" })).into_response();
    }
    if id == "paged1" {
        let page = q
            .get("page")
            .and_then(|p| p.parse::<usize>().ok())
            .unwrap_or(1);
        let mut children = BTreeMap::new();
        if page == 1 {
            for i in 0..1000 {
                children.insert(
                    format!("f-{i:04}"),
                    ContentChild {
                        item_type: "file".to_string(),
                        name: format!("part-{i:04}.txt"),
                        link: Some(format!("{}/download/part-{i:04}.txt", st.base_url)),
                        size: Some(5),
                    },
                );
            }
        } else {
            for i in 1000..1002 {
                children.insert(
                    format!("f-{i:04}"),
                    ContentChild {
                        item_type: "file".to_string(),
                        name: format!("part-{i:04}.txt"),
                        link: Some(format!("{}/download/part-{i:04}.txt", st.base_url)),
                        size: Some(5),
                    },
                );
            }
        }
        return axum::Json(json!({
            "status": "ok",
            "data": {
                "type": "folder",
                "name": "PagedRoot",
                "passwordStatus": "passwordOk",
                "childrenCount": 1002,
                "children": children
            }
        }))
        .into_response();
    }

    // Default (`cli123` or `web123`): folder with 1 file
    let dl_name = if id == "cli123" {
        "flaky.bin"
    } else {
        "hello.bin"
    };
    axum::Json(json!({
        "status": "ok",
        "data": {
            "type": "folder",
            "name": format!("Share_{id}"),
            "passwordStatus": "passwordOk",
            "childrenCount": 1,
            "children": {
                "file-1": {
                    "type": "file",
                    "name": dl_name,
                    "link": format!("{}/download/{dl_name}", st.base_url),
                    "size": 10
                }
            }
        }
    }))
    .into_response()
}

async fn mock_web_page(
    State(st): State<MockGoFileState>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let html = format!(
        r#"<!doctype html><script>window.contentData = {{"type":"file","name":"{id}.txt","link":"{}/download/hello.bin","passwordStatus":"passwordOk"}};</script>"#,
        st.base_url
    );
    (StatusCode::OK, html).into_response()
}

async fn mock_download(
    State(st): State<MockGoFileState>,
    AxumPath(name): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if name == "flaky.bin" && st.flaky_dl_hits.fetch_add(1, Ordering::SeqCst) == 0 {
        return (StatusCode::INTERNAL_SERVER_ERROR, "upstream error").into_response();
    }
    let payload = b"0123456789";
    if let Some(range_val) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        if let Some(rest) = range_val.strip_prefix("bytes=") {
            if let Some(start_str) = rest.strip_suffix('-') {
                if let Ok(start) = start_str.parse::<usize>() {
                    if start < payload.len() {
                        let slice = &payload[start..];
                        return Response::builder()
                            .status(StatusCode::PARTIAL_CONTENT)
                            .header(header::CONTENT_LENGTH, slice.len().to_string())
                            .body(Body::from(slice.to_vec()))
                            .unwrap();
                    }
                }
            }
        }
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_LENGTH, payload.len().to_string())
        .body(Body::from(payload.to_vec()))
        .unwrap()
}

#[test]
fn test_regressions_url_filename_part_negative_window_csrf_and_config() {
    // 1. URL / Content ID host-boundary and character validation
    assert_eq!(parse_content_id("https://gofile.io/d/.."), None);
    assert_eq!(parse_content_id("https://gofile.io/d/."), None);
    assert_eq!(parse_content_id("https://gofile.io/d/a%2fb"), None);
    assert_eq!(parse_content_id("https://evilgofile.io/d/abc123"), None);
    assert_eq!(
        parse_content_id("https://sub.gofile.io/d/Abc_123-xyz?p=1#top"),
        Some("Abc_123-xyz".to_string())
    );
    assert_eq!(
        parse_content_id("Abc_123-xyz"),
        Some("Abc_123-xyz".to_string())
    );

    // 2. Reserved Windows stem near 255-byte boundary never exceeds 255 UTF-8 bytes
    let near_limit_reserved = format!("CON.{}", "a".repeat(251));
    let cleaned = sanitize_filename(&near_limit_reserved);
    assert!(cleaned.len() <= 255, "len was {}", cleaned.len());
    assert!(cleaned.starts_with("CON_."));

    // 3. 255-byte destination filename produces <= 255-byte `.part` filename
    let tmp = tempdir().unwrap();
    let max_name = format!("{}.bin", "x".repeat(251));
    assert_eq!(max_name.len(), 255);
    let dest = tmp.path().join(&max_name);
    let part = part_file_path(&dest);
    let part_fname = part.file_name().unwrap().to_str().unwrap();
    assert!(part_fname.len() <= 255, "part len was {}", part_fname.len());
    std::fs::write(&part, b"temp").unwrap();
    assert!(part.exists());
    assert!(remove_path_and_part(&dest).unwrap());
    assert!(!remove_path_and_part(&dest).unwrap());
    let sub_rm = tmp.path().join("rm_dir");
    std::fs::create_dir_all(&sub_rm).unwrap();
    assert!(remove_path_and_part(&sub_rm).unwrap());

    // Multi-byte UTF-8 boundary in `part_file_path`, root path fallback, and bare relative filename
    let utf8_long = format!("{}é.bin", "a".repeat(250));
    let utf8_part = part_file_path(Path::new(&utf8_long));
    assert!(utf8_part.to_str().unwrap().len() <= 255);
    assert!(part_file_path(Path::new("/"))
        .to_string_lossy()
        .ends_with(".part"));
    assert_eq!(extract_embedded_content_json("<html>empty</html>"), None);

    // 4. Negative timestamp window formatting works cleanly without overflow
    let neg_cfg = WebsiteTokenConfig::default();
    let tok = generate_website_token_at(
        "tok123",
        i64::MIN,
        0,
        &neg_cfg.user_agent,
        &neg_cfg.language,
        &neg_cfg.salt,
    );
    assert_eq!(tok.len(), 64);

    // 5. Future-dated CSRF token (`u64::MAX`) is rejected instead of accepted forever
    let secret = "reviewer-secret";
    let nonce = "deadbeefcafe1234deadbeefcafe1234";
    let payload = format!("{}.{nonce}", u64::MAX);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    let sig = gofile_dl::token::encode_sha256_hex(&mac.finalize().into_bytes().into());
    let forged_future = format!("{payload}.{sig}");
    assert!(!verify_csrf_token(
        &forged_future,
        secret,
        &CsrfConfig {
            enabled: true,
            time_limit: 3600,
        }
    ));

    // 6. Invalid YAML syntax in config file returns `Err(GoFileError::Config)`
    let bad_yaml = tmp.path().join("broken.yml");
    std::fs::write(&bad_yaml, "port: [unclosed\n").unwrap();
    let err = AppConfig::load(Some(&bad_yaml)).unwrap_err();
    assert!(matches!(err, GoFileError::Config(_)));

    // 7. Repository `config.yml` loads with `./output` (not `/app`)
    let repo_cfg = AppConfig::load(Some(Path::new("config.yml"))).unwrap();
    assert_ne!(repo_cfg.base_dir, Path::new("/app"));

    // 8. Read-only directory (`0555`) health check reports `writable: false` (when non-root)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let ro_dir = tmp.path().join("readonly_dir");
        std::fs::create_dir_all(&ro_dir).unwrap();
        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let writable = probe_existing_dir_writable(&ro_dir);
        if !writable {
            let health = build_health_response(&ro_dir, 0, "1.8.3");
            assert!(health.directories.exists);
            assert!(!health.directories.writable);
        }
        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

struct StubTransport {
    root: ContentNode,
    fail_files: bool,
}

impl HttpTransport for StubTransport {
    fn post_text(&self, _url: &str, _headers: &[(&str, &str)]) -> Result<String, GoFileError> {
        Ok(r#"{"status":"ok","data":{"token":"t"}}"#.to_string())
    }
    fn get_text(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
        _query: &[(&str, &str)],
    ) -> Result<String, GoFileError> {
        Ok(json!({"status": "ok", "data": self.root}).to_string())
    }
    fn open_stream(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
    ) -> Result<gofile_dl::client::ByteStreamResponse, GoFileError> {
        if self.fail_files {
            return Err(GoFileError::Authentication("simulated CDN failure".into()));
        }
        Ok(gofile_dl::client::ByteStreamResponse {
            status: 200,
            content_length: Some(4),
            reader: Box::new(std::io::Cursor::new(b"data".to_vec())),
        })
    }
    fn backoff_sleep(&self, _duration: Duration) {}
}

#[test]
fn test_regressions_incremental_single_file_emoji_pattern_and_new_failures() {
    let tmp = tempdir().unwrap();
    let cfg_dir = tmp.path().join("cfg");
    let out_dir = tmp.path().join("out");

    // 1. Single-file root share respects `--incremental` on second run
    let single_root = ContentNode {
        node_type: "file".to_string(),
        name: "movie.mkv".to_string(),
        link: Some("https://cdn/movie.mkv".to_string()),
        password_status: "passwordOk".to_string(),
        children_count: None,
        children: BTreeMap::new(),
        contents: BTreeMap::new(),
    };
    let mut client = GoFileClient::new(
        StubTransport {
            root: single_root,
            fail_files: false,
        },
        None,
        WebsiteTokenConfig::default(),
    );
    let mut opts = DownloadOptions::new(&out_dir);
    opts.incremental = true;
    opts.config_dir = Some(cfg_dir.clone());

    let s1 = execute_download(&mut client, "single42", &opts, &NoopHooks).unwrap();
    assert_eq!(s1.files_downloaded, 1);
    assert_eq!(s1.files_skipped, 0);

    let s2 = execute_download(&mut client, "single42", &opts, &NoopHooks).unwrap();
    assert_eq!(s2.files_downloaded, 0);
    assert_eq!(s2.files_skipped, 1);

    // 2. Emoji custom `folder_pattern` matches existing folder even when `strip_emojis = true`
    let show_dir = tmp.path().join("shows");
    std::fs::create_dir_all(show_dir.join("Drama S01")).unwrap();
    let mut children = BTreeMap::new();
    children.insert(
        "ep1".to_string(),
        ContentChild {
            item_type: "file".to_string(),
            name: "ep1.mp4".to_string(),
            link: Some("https://cdn/ep1.mp4".to_string()),
            size: Some(4),
        },
    );
    let folder_root = ContentNode {
        node_type: "folder".to_string(),
        name: "🔥HOT Drama S01".to_string(),
        link: None,
        password_status: "passwordOk".to_string(),
        children_count: Some(1),
        children: children.clone(),
        contents: BTreeMap::new(),
    };
    let mut client2 = GoFileClient::new(
        StubTransport {
            root: folder_root.clone(),
            fail_files: false,
        },
        None,
        WebsiteTokenConfig::default(),
    );
    let mut opts2 = DownloadOptions::new(&show_dir);
    opts2.incremental = true;
    opts2.strip_emojis = true;
    opts2.folder_pattern = "🔥HOT |NEW ".to_string();
    opts2.config_dir = Some(cfg_dir.clone());

    let s_emoji = execute_download(&mut client2, "show99", &opts2, &NoopHooks).unwrap();
    assert_eq!(s_emoji.files_downloaded, 1);
    assert!(show_dir.join("Drama S01").join("ep1.mp4").exists());
    assert!(!show_dir.join("HOT Drama S01").exists());

    // 3. Incremental sync with 1 already-downloaded file + 1 newly added failing file MUST error
    let mut children_with_new = children;
    children_with_new.insert(
        "ep2".to_string(),
        ContentChild {
            item_type: "file".to_string(),
            name: "ep2.mp4".to_string(),
            link: Some("https://cdn/ep2.mp4".to_string()),
            size: Some(4),
        },
    );
    let mut client_fail = GoFileClient::new(
        StubTransport {
            root: ContentNode {
                children: children_with_new,
                ..folder_root
            },
            fail_files: true,
        },
        None,
        WebsiteTokenConfig::default(),
    );
    opts2.retry_attempts = 0;
    let err = execute_download(&mut client_fail, "show99", &opts2, &NoopHooks).unwrap_err();
    assert!(matches!(err, GoFileError::Download { .. }));

    // Verify `ep2` was NOT marked downloaded in tracker
    let tracker = DownloadTracker::with_config_dir(&show_dir, &cfg_dir, "show99", None).unwrap();
    assert!(tracker.is_downloaded("ep1", "ep1.mp4"));
    assert!(!tracker.is_downloaded("ep2", "ep2.mp4"));
}

#[tokio::test]
async fn test_regressions_web_directory_confinement_xss_and_delete_race() {
    // 1. Verify DOM XSS escaping in `templates/index.html`
    let tpl = std::fs::read_to_string("templates/index.html").unwrap();
    assert!(tpl.contains("function escapeHtml("));
    assert!(tpl.contains("${escapeHtml(info.name)}"));
    assert!(tpl.contains("${escapeHtml(info.url)}"));
    assert!(tpl.contains("${escapeHtml(info.current_folder || \"N/A\")}"));
    assert!(tpl.contains("${escapeHtml(file.name)}"));

    // 2. Verify `/start` rejects directory traversal (`400`) and confines relative subdirs inside `base_dir`
    let tmp = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let cfg = Arc::new(AppConfig {
        base_dir: tmp.path().to_path_buf(),
        secret_key: "confinement-secret".to_string(),
        ..AppConfig::default()
    });

    let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
    let worker: TaskWorkerFn = Arc::new(move |req, wcfg, hooks| {
        let resolved = gofile_dl::browse::resolve_confined_output_dir(
            &wcfg.base_dir,
            req.directory.as_deref(),
        )?;
        std::fs::create_dir_all(&resolved)?;
        hooks.on_name("race.bin");
        let dest = resolved.join("race.bin");
        let part = part_file_path(&dest);
        std::fs::write(&part, b"in-flight-bytes")?;
        let _ = started_tx.send(());
        while !hooks.is_cancelled() {
            std::thread::sleep(Duration::from_millis(5));
        }
        Err(GoFileError::Cancelled)
    });

    let tasks = TaskManager::with_worker(Arc::clone(&cfg), worker);
    let app = build_router(WebAppState {
        config: Arc::clone(&cfg),
        tasks: tasks.clone(),
        template_path: None,
        app_version: "1.8.3".to_string(),
    });
    let csrf = generate_csrf_token(&cfg.secret_key);

    // Reject traversal `../../...` and absolute outside path
    for bad_dir in ["../escape", outside.path().to_str().unwrap()] {
        let body = format!(
            "url=https%3A%2F%2Fgofile.io%2Fd%2Fabc123&directory={}",
            bad_dir.replace('/', "%2F")
        );
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/start")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header("X-CSRFToken", &csrf)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let j: Value =
            serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(j["error"], "Invalid directory path");
    }

    // Accept relative subdirectory `sub/nested` inside `base_dir` and test `delete_task_files` race + `.part` cleanup
    let res_ok = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/start")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("X-CSRFToken", &csrf)
                .body(Body::from(
                    "url=https%3A%2F%2Fgofile.io%2Fd%2Fabc123&directory=sub%2Fnested",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_ok.status(), StatusCode::ACCEPTED);
    let ok_json: Value =
        serde_json::from_slice(&res_ok.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let tid = ok_json["task_id"].as_str().unwrap().to_string();

    tokio::task::spawn_blocking(move || {
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    })
    .await
    .unwrap();

    // Pause the active task, then call `delete_task_files` while paused + mid-stream!
    assert_eq!(tasks.toggle_pause(&tid), Some((true, "paused".to_string())));
    let canonical_base = std::fs::canonicalize(tmp.path()).unwrap();
    let expected_part = part_file_path(&canonical_base.join("sub/nested/race.bin"));
    assert!(expected_part.exists());

    let del_msg = tokio::task::spawn_blocking({
        let tasks = tasks.clone();
        let tid = tid.clone();
        move || tasks.delete_task_files(&tid).unwrap()
    })
    .await
    .unwrap();
    assert!(del_msg.unwrap().contains("files deleted"));
    assert!(!expected_part.exists());
    assert!(!tasks.cancel_task("missing-task-id"));
    assert_eq!(tasks.delete_task_files("missing-task-id").unwrap(), None);
}

#[test]
fn test_live_reqwest_transport_pagination_retries_resume_and_errors() {
    // 1. Valid SOCKS5/HTTP proxy builder & invalid proxy URL error
    assert!(ReqwestTransport::new(Some("socks5://127.0.0.1:1080"), 5).is_ok());
    let bad_proxy = ReqwestTransport::new(Some("http://[::1:bad"), 5);
    assert!(matches!(bad_proxy, Err(GoFileError::Config(_))));

    // 2. TCP reset / abrupt close handling on raw socket
    let rst_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let rst_addr = rst_listener.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = rst_listener.accept() {
            let mut one = [0u8; 1];
            let _ = stream.read(&mut one);
            // Drop immediately with unread request bytes in kernel buffer -> TCP RST
        }
    });
    let transport = ReqwestTransport::new(None, 5).unwrap();
    let big_hdr = "x".repeat(4096);
    let rst_err = transport
        .post_text(
            &format!("http://{rst_addr}/accounts"),
            &[("X-Pad", &big_hdr)],
        )
        .unwrap_err();
    assert!(matches!(
        rst_err,
        GoFileError::EdgeBlocked(_) | GoFileError::Authentication(_)
    ));

    // 3. Spin up loopback GoFile mock server
    let (base_url, stop_tx) = spawn_mock_gofile_server();

    // Direct 404 HTML response via `ReqwestTransport::get_text` returns `Err(Authentication)`
    let html_404 = transport
        .get_text(&format!("{base_url}/contents/notfound404"), &[], &[])
        .unwrap_err();
    assert!(matches!(html_404, GoFileError::Authentication(_)));

    let mut client = GoFileClient::new(transport, None, WebsiteTokenConfig::default())
        .with_base_urls(&base_url, &base_url);

    // First `/accounts` call hits 502 HTML -> retries -> succeeds on 2nd attempt;
    // `/contents/paged1` fetches page 1 (1,000 items) + page 2 (2 items) = 1,002 items!
    let paged = client.fetch_contents("paged1", None).unwrap();
    assert_eq!(paged.count_files(), 1002);

    // `/contents/htmlfb` hits `error-notPremium` -> falls back to `/d/htmlfb` embedded `window.contentData`!
    let html_node = client.fetch_contents("htmlfb", Some("pw123")).unwrap();
    assert_eq!(html_node.name, "htmlfb.txt");

    // `open_stream` + `download_file` 206 Partial Content resume from 4-byte `.part`
    let tmp = tempdir().unwrap();
    let dest = tmp.path().join("resumed.bin");
    let part = part_file_path(&dest);
    std::fs::write(&part, b"0123").unwrap();
    let opts = DownloadOptions::new(tmp.path());
    download_file(
        &client,
        &format!("{base_url}/download/hello.bin"),
        &dest,
        &opts,
        &NoopHooks,
    )
    .unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"0123456789");
    assert!(!part.exists());

    // Pre-cancelled `download_file` removes `.part` and returns `Err(Cancelled)` immediately
    struct AlwaysCancelled;
    impl gofile_dl::downloader::ProgressHooks for AlwaysCancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }
    std::fs::write(&part, b"stale").unwrap();
    let cancel_err = download_file(
        &client,
        &format!("{base_url}/download/hello.bin"),
        &dest,
        &opts,
        &AlwaysCancelled,
    )
    .unwrap_err();
    assert!(matches!(cancel_err, GoFileError::Cancelled));
    assert!(!part.exists());

    // Malformed JSON retries on `/accounts` and `/contents`
    struct MalformedJsonTransport;
    impl HttpTransport for MalformedJsonTransport {
        fn post_text(&self, _url: &str, _headers: &[(&str, &str)]) -> Result<String, GoFileError> {
            Ok("not-json".to_string())
        }
        fn get_text(
            &self,
            _url: &str,
            _headers: &[(&str, &str)],
            _query: &[(&str, &str)],
        ) -> Result<String, GoFileError> {
            Ok("not-json".to_string())
        }
        fn open_stream(
            &self,
            _url: &str,
            _headers: &[(&str, &str)],
        ) -> Result<gofile_dl::client::ByteStreamResponse, GoFileError> {
            Err(GoFileError::Cancelled)
        }
        fn backoff_sleep(&self, _duration: Duration) {}
    }
    let mut bad_acc =
        GoFileClient::new(MalformedJsonTransport, None, WebsiteTokenConfig::default());
    assert!(matches!(
        bad_acc.update_token(),
        Err(GoFileError::Authentication(_))
    ));
    let mut bad_cnt = GoFileClient::new(
        MalformedJsonTransport,
        Some("prem-tok".to_string()),
        WebsiteTokenConfig::default(),
    );
    assert!(matches!(
        bad_cnt.fetch_contents("abc", None),
        Err(GoFileError::Serialization(_))
    ));

    let _ = stop_tx.send(());
}

#[test]
fn test_cli_binary_download_bench_parity_and_graceful_serve() {
    let bin = env!("CARGO_BIN_EXE_gofile-dl");
    let (base_url, stop_tx) = spawn_mock_gofile_server();
    let tmp = tempdir().unwrap();

    // 1. `parity-seed` subcommand
    let parity_out = Command::new(bin)
        .args([
            "parity-seed",
            "--seed",
            "7",
            "--items",
            "16",
            "--work-dir",
            tmp.path().join("parity").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(parity_out.status.success());
    let parity_json: Value = serde_json::from_slice(&parity_out.stdout).unwrap();
    assert_eq!(parity_json["digest"].as_str().unwrap().len(), 64);

    // 2. `bench --mode safe` and `bench --mode soa` subcommands
    let bench_safe = Command::new(bin)
        .args([
            "bench",
            "--mode",
            "safe",
            "--seeds",
            "2",
            "--items-per-seed",
            "8",
        ])
        .output()
        .unwrap();
    assert!(bench_safe.status.success());
    let bench_soa = Command::new(bin)
        .args([
            "bench",
            "--mode",
            "soa",
            "--seeds",
            "2",
            "--items-per-seed",
            "8",
        ])
        .output()
        .unwrap();
    assert!(bench_soa.status.success());
    let j_safe: Value = serde_json::from_slice(&bench_safe.stdout).unwrap();
    let j_soa: Value = serde_json::from_slice(&bench_soa.stdout).unwrap();
    assert_eq!(j_safe["combined_digest"], j_soa["combined_digest"]);

    // 3. CLI download mode (with 1 retry on `flaky.bin` exercising `CliProgressLogger` retry & completion)
    let cli_dl_dir = tmp.path().join("cli_dl");
    let dl_out = Command::new(bin)
        .args([
            "https://gofile.io/d/cli123",
            "-d",
            cli_dl_dir.to_str().unwrap(),
            "--retries",
            "2",
            "--incremental",
        ])
        .env("CONFIG_DIR", tmp.path().join("cli_cfg"))
        .env("GOFILE_API_BASE_URL", &base_url)
        .env("GOFILE_WEB_BASE_URL", &base_url)
        .output()
        .unwrap();
    // Note: `retry_delay_secs` in CLI is 5s on first failure, which proves real retry succeeded
    assert!(
        dl_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&dl_out.stderr)
    );
    assert_eq!(
        std::fs::read(cli_dl_dir.join("Share_cli123").join("flaky.bin")).unwrap(),
        b"0123456789"
    );

    // 4. Invalid URL exits with code 1
    let bad_out = Command::new(bin)
        .arg("https://evil.example.com/not-gofile")
        .output()
        .unwrap();
    assert_eq!(bad_out.status.code(), Some(1));

    // 5. `serve` subcommand with repo `config.yml`, live `POST /start` (`TaskManager::new`), and graceful SIGTERM
    let probe = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let serve_base = tmp.path().join("serve_data");
    std::fs::create_dir_all(serve_base.join("movies")).unwrap();

    let mut child = Command::new(bin)
        .args([
            "serve",
            "--config",
            "config.yml",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ])
        .env("BASE_DIR", &serve_base)
        .env("SECRET_KEY", "live-serve-secret")
        .env("RETRY_DELAY", "0")
        .env("GOFILE_API_BASE_URL", &base_url)
        .env("GOFILE_WEB_BASE_URL", &base_url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let srv_url = format!("http://127.0.0.1:{port}");

    let mut ready = false;
    for _ in 0..40 {
        if let Ok(r) = http.get(format!("{srv_url}/health")).send() {
            if r.status() == StatusCode::OK {
                let h: Value = r.json().unwrap();
                assert_eq!(h["status"], "ok");
                assert_eq!(h["directories"]["writable"], true);
                ready = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "gofile-dl serve did not become ready in time");

    // Verify `/browse` returns 200 OK out of the box
    let browse_res = http.get(format!("{srv_url}/browse")).send().unwrap();
    assert_eq!(browse_res.status(), StatusCode::OK);
    let browse_json: Value = browse_res.json().unwrap();
    assert_eq!(browse_json["directories"], json!(["movies"]));

    // Start a real download task through `TaskManager::new` via `POST /start`
    let csrf = generate_csrf_token("live-serve-secret");
    let start_res = http
        .post(format!("{srv_url}/start"))
        .header("X-CSRFToken", &csrf)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("url=https%3A%2F%2Fgofile.io%2Fd%2Fweb123&directory=movies")
        .send()
        .unwrap();
    assert_eq!(start_res.status(), StatusCode::ACCEPTED);
    let tid = start_res.json::<Value>().unwrap()["task_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Poll `/tasks` until `tid` completes
    let mut completed = false;
    for _ in 0..40 {
        let tasks_json: Value = http
            .get(format!("{srv_url}/tasks"))
            .send()
            .unwrap()
            .json()
            .unwrap();
        if tasks_json[&tid]["status"] == "completed" {
            completed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(completed, "live web task did not complete");
    assert_eq!(
        std::fs::read(serve_base.join("movies/Share_web123/hello.bin")).unwrap(),
        b"0123456789"
    );

    // Send SIGTERM so `shutdown_signal()` exits cleanly (status 0) and flushes LLVM `.profraw`
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
    let exit_status = child.wait().unwrap();
    #[cfg(unix)]
    assert!(exit_status.success(), "serve exited with {exit_status}");

    let _ = stop_tx.send(());
}
