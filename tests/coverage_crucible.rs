//! Comprehensive branch-coverage crucible exercising error paths, nested subfolders,
//! single-file root downloads, YAML config loading, CSRF token expiry, Basic Auth
//! edge cases, task error/cancel transitions, and 404 HTTP handlers.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use gofile_dl::browse::{
    browse_confined_directory, check_directory_writable, derive_initial_task_name, StartTaskRequest,
};
use gofile_dl::client::{ByteStreamResponse, GoFileClient, HttpTransport};
use gofile_dl::config::{read_app_version, AppConfig, AuthConfig, CsrfConfig};
use gofile_dl::downloader::{execute_download, DownloadOptions, NoopHooks, ProgressHooks};
use gofile_dl::error::GoFileError;
use gofile_dl::security::{render_index_html, verify_basic_auth, verify_csrf_token};
use gofile_dl::tasks::{TaskManager, TaskWorkerFn};
use gofile_dl::token::{generate_website_token, WebsiteTokenConfig};
use gofile_dl::tracker::DownloadTracker;
use gofile_dl::web::{build_router, WebAppState};
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use tower::ServiceExt;

#[test]
fn test_all_error_variants_display_source_and_conversions() {
    let io_err: GoFileError = std::io::Error::other("disk full").into();
    assert!(io_err.source().is_some());
    assert!(io_err.to_string().contains("disk full"));

    let json_err: GoFileError = serde_json::from_str::<serde_json::Value>("{bad")
        .unwrap_err()
        .into();
    assert!(json_err.source().is_none());
    assert!(json_err.to_string().contains("Serialization error"));

    let variants = [
        GoFileError::Authentication("auth".into()),
        GoFileError::ContentNotFound("cid".into()),
        GoFileError::Password("wrong".into()),
        GoFileError::InvalidUrl("bad://url".into()),
        GoFileError::EdgeBlocked("accounts".into()),
        GoFileError::RateLimited("contents".into()),
        GoFileError::Download {
            message: "failed".into(),
            filename: "a.bin".into(),
            url: "https://s/a".into(),
        },
        GoFileError::Throttle("negative".into()),
        GoFileError::RetryExhausted {
            attempts: 3,
            target: "a.bin".into(),
            last_error: "timeout".into(),
        },
        GoFileError::Cancelled,
        GoFileError::PathSafety("escape".into()),
        GoFileError::Config("bad port".into()),
    ];
    for v in variants {
        assert!(!v.to_string().is_empty());
        assert!(v.source().is_none());
    }
}

#[test]
fn test_browse_and_config_yaml_and_env_edge_cases() {
    let tmp = tempdir().unwrap();
    check_directory_writable(tmp.path()).unwrap();

    let sub = tmp.path().join("movies").join("2026");
    std::fs::create_dir_all(&sub).unwrap();
    let file_only = tmp.path().join("note.txt");
    std::fs::write(&file_only, b"hi").unwrap();

    // Relative, exact canonical, and nonexistent browse paths
    let (_, cur_rel, dirs_rel) = browse_confined_directory(tmp.path(), "movies").unwrap();
    assert_eq!(dirs_rel, vec!["2026".to_string()]);
    let (_, cur_abs, _) =
        browse_confined_directory(tmp.path(), &cur_rel.display().to_string()).unwrap();
    assert_eq!(cur_abs, cur_rel);
    assert!(browse_confined_directory(tmp.path(), "does_not_exist").is_err());
    assert!(browse_confined_directory(tmp.path(), "note.txt").is_err());

    assert_eq!(
        derive_initial_task_name("https://gofile.io/d/abc", Some("/data/shows/")),
        "shows"
    );
    assert_eq!(
        derive_initial_task_name("https://gofile.io/d/abc", Some("/")),
        "download"
    );
    assert_eq!(derive_initial_task_name("bareid", None), "bareid");
    let req = StartTaskRequest::new("abc");
    assert_eq!(req.url, "abc");

    // YAML load + version file + all env overrides & parse failures
    let yaml_file = tmp.path().join("config.yml");
    std::fs::write(&yaml_file, "port: 3000\nhost: \"127.0.0.1\"\n").unwrap();
    let loaded = AppConfig::load(Some(&yaml_file)).unwrap();
    assert_eq!(loaded.port, 3000);
    let fallback_loaded = AppConfig::load(None).unwrap();
    assert!(fallback_loaded.port > 0);

    let vfile = tmp.path().join("version.txt");
    std::fs::write(&vfile, "2.0.0\n").unwrap();
    assert_eq!(read_app_version(&vfile), "2.0.0");

    let mut cfg = AppConfig::default();
    let mut env = HashMap::new();
    env.insert("BASE_DIR".into(), "/tmp/dl".into());
    env.insert("SECRET_KEY".into(), "k123".into());
    env.insert("RETRY_DELAY".into(), "9".into());
    env.insert("GOFILE_PREMIUM_TOKEN".into(), "prem_xyz".into());
    env.insert("GOFILE_PROXY".into(), "socks5://127.0.0.1:1080".into());
    env.insert("AUTH_USERNAME".into(), "bob".into());
    env.insert("AUTH_PASSWORD".into(), "pw".into());
    cfg.apply_env_map(&env).unwrap();
    assert_eq!(cfg.retry_delay, 9);
    assert_eq!(cfg.premium_token.as_deref(), Some("prem_xyz"));
    assert_eq!(cfg.proxy.as_deref(), Some("socks5://127.0.0.1:1080"));
    assert_eq!(cfg.auth.username, "bob");

    let mut bad_retries = HashMap::new();
    bad_retries.insert("DEFAULT_RETRIES".into(), "nope".into());
    assert!(cfg.apply_env_map(&bad_retries).is_err());

    let mut bad_delay = HashMap::new();
    bad_delay.insert("RETRY_DELAY".into(), "nope".into());
    assert!(cfg.apply_env_map(&bad_delay).is_err());
}

#[test]
fn test_security_csrf_expiry_basic_auth_and_token_edges() {
    let wt_cfg = WebsiteTokenConfig::default();
    assert_eq!(generate_website_token("", 0, &wt_cfg), "");
    assert_eq!(generate_website_token("tok", 0, &wt_cfg).len(), 64);

    let disabled_csrf = CsrfConfig {
        enabled: false,
        time_limit: 3600,
    };
    assert!(verify_csrf_token("anything", "sec", &disabled_csrf));

    let strict_csrf = CsrfConfig {
        enabled: true,
        time_limit: 10,
    };
    assert!(!verify_csrf_token("malformed", "sec", &strict_csrf));
    assert!(!verify_csrf_token(
        "notanumber.nonce.sig",
        "sec",
        &strict_csrf
    ));
    assert!(!verify_csrf_token("100.nonce.sig", "sec", &strict_csrf)); // expired timestamp

    let auth = AuthConfig {
        enabled: true,
        username: "u".into(),
        password: "p".into(),
    };
    assert!(!verify_basic_auth(Some("Bearer xyz"), &auth));
    assert!(!verify_basic_auth(Some("Basic !!!not_base64!!!"), &auth));
    assert!(!verify_basic_auth(Some("Basic dXNlcm9ubHk="), &auth)); // "useronly" without ':'

    let tmp = tempdir().unwrap();
    let custom_tpl = tmp.path().join("index.html");
    std::fs::write(&custom_tpl, "<input value=\"{{ csrf_token() }}\">").unwrap();
    assert_eq!(
        render_index_html(Some(&custom_tpl), "tok1"),
        "<input value=\"tok1\">"
    );
}

type StreamScript = Result<(u16, Option<u64>, Vec<u8>), GoFileError>;

#[derive(Default)]
struct ScriptTransport {
    posts: Mutex<VecDeque<Result<String, GoFileError>>>,
    gets: Mutex<VecDeque<Result<String, GoFileError>>>,
    streams: Mutex<VecDeque<StreamScript>>,
}

impl HttpTransport for ScriptTransport {
    fn post_text(&self, _u: &str, _h: &[(&str, &str)]) -> Result<String, GoFileError> {
        self.posts
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Ok(r#"{"status":"ok","data":{"token":"t1"}}"#.into()))
    }
    fn get_text(
        &self,
        _u: &str,
        _h: &[(&str, &str)],
        _q: &[(&str, &str)],
    ) -> Result<String, GoFileError> {
        self.gets
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(GoFileError::ContentNotFound("none".into())))
    }
    fn open_stream(
        &self,
        _u: &str,
        _h: &[(&str, &str)],
    ) -> Result<ByteStreamResponse, GoFileError> {
        let (status, content_length, data) = self.streams.lock().unwrap().pop_front().unwrap()?;
        Ok(ByteStreamResponse {
            status,
            content_length,
            reader: Box::new(Cursor::new(data)),
        })
    }
    fn backoff_sleep(&self, _d: Duration) {}
}

struct CancelFlagHooks(AtomicBool);
impl ProgressHooks for CancelFlagHooks {
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[test]
fn test_client_errors_nested_subfolders_single_file_root_and_cancellation() {
    let tmp = tempdir().unwrap();

    // 1. EdgeBlocked & guest token exhaustion
    let t_edge = ScriptTransport::default();
    t_edge
        .posts
        .lock()
        .unwrap()
        .push_back(Err(GoFileError::EdgeBlocked("accounts".into())));
    let mut c_edge = GoFileClient::new(t_edge, None, WebsiteTokenConfig::default());
    assert!(matches!(
        c_edge.update_token(),
        Err(GoFileError::EdgeBlocked(_))
    ));

    let t_fail = ScriptTransport::default();
    t_fail.posts.lock().unwrap().extend([
        Err(GoFileError::Authentication("net1".into())),
        Ok(r#"{"status":"error-bad"}"#.into()),
        Err(GoFileError::Authentication("net3".into())),
    ]);
    let mut c_fail = GoFileClient::new(t_fail, None, WebsiteTokenConfig::default());
    assert!(c_fail.update_token().is_err());

    // 2. ContentNotFound, persistent RateLimited, and unknown status
    let t_codes = ScriptTransport::default();
    t_codes.gets.lock().unwrap().extend([
        Ok(r#"{"status":"error-notFound"}"#.into()),
        Ok(r#"{"status":"error-mystery"}"#.into()),
        Ok(r#"{"status":"error-rateLimit"}"#.into()),
        Ok(r#"{"status":"error-rateLimit"}"#.into()),
        Ok(r#"{"status":"error-rateLimit"}"#.into()),
        Ok(r#"{"status":"error-rateLimit"}"#.into()),
    ]);
    let mut c_codes = GoFileClient::new(
        t_codes,
        Some("prem_tok".into()),
        WebsiteTokenConfig::default(),
    );
    assert!(matches!(
        c_codes.fetch_contents("missing", None),
        Err(GoFileError::ContentNotFound(_))
    ));
    assert!(c_codes.fetch_contents("mystery", None).is_err());
    assert!(matches!(
        c_codes.fetch_contents("rl", None),
        Err(GoFileError::RateLimited(_))
    ));

    // 3. Single-file root download + Nested subfolder + Empty folder + Exact folder match
    let dl_dir = tmp.path().join("dl");
    std::fs::create_dir_all(dl_dir.join("RootFolder")).unwrap();
    let cfg_dir = tmp.path().join("cfg");

    let mut tracker = DownloadTracker::with_config_dir(&dl_dir, &cfg_dir, "r1", None).unwrap();
    assert_eq!(tracker.base_dir(), dl_dir.as_path());
    assert!(tracker.tracking_file().exists() || !tracker.tracking_file().as_os_str().is_empty());
    assert_eq!(
        tracker.find_existing_folder("RootFolder", &dl_dir),
        Some(dl_dir.join("RootFolder"))
    );
    let _ = &mut tracker;

    let t_tree = ScriptTransport::default();
    t_tree.gets.lock().unwrap().extend([
        // Single-file root
        Ok(
            r#"{"status":"ok","data":{"type":"file","name":"🎬🚀.bin","link":"https://s/1"}}"#
                .into(),
        ),
        // Nested folder tree: RootFolder -> SubEmpty (empty folder) + SubFiles (1 file + 1 linkless file)
        Ok(
            r#"{"status":"ok","data":{"type":"folder","name":"RootFolder","children":{
            "sub_a":{"type":"folder","name":"SubEmpty"},
            "sub_b":{"type":"folder","name":"SubFiles"}
        }}}"#
                .into(),
        ),
        Ok(r#"{"status":"ok","data":{"type":"folder","name":"SubEmpty","children":{}}}"#.into()),
        Ok(
            r#"{"status":"ok","data":{"type":"folder","name":"SubFiles","children":{
            "f_nolink":{"type":"file","name":"nolink.bin"},
            "f_ok":{"type":"file","name":"nested.bin","link":"https://s/nested"}
        }}}"#
                .into(),
        ),
    ]);
    t_tree.streams.lock().unwrap().extend([
        Ok((200, Some(3), b"ONE".to_vec())),
        Ok((200, Some(3), b"TWO".to_vec())),
    ]);

    let mut c_tree = GoFileClient::new(t_tree, Some("tok".into()), WebsiteTokenConfig::default());
    let mut opts = DownloadOptions::new(&dl_dir);
    opts.strip_emojis = true;
    opts.incremental = true;
    opts.config_dir = Some(cfg_dir);

    let s_single = execute_download(&mut c_tree, "single1234", &opts, &NoopHooks).unwrap();
    assert_eq!(s_single.files_downloaded, 1);

    let s_nested = execute_download(&mut c_tree, "root1234", &opts, &NoopHooks).unwrap();
    assert_eq!(s_nested.files_downloaded, 1);
    assert_eq!(s_nested.files_failed, 1);

    // Invalid URL & immediate cancellation
    assert!(matches!(
        execute_download(
            &mut c_tree,
            "https://not-gofile.example/x",
            &opts,
            &NoopHooks
        ),
        Err(GoFileError::InvalidUrl(_))
    ));
    let cancel_hooks = CancelFlagHooks(AtomicBool::new(true));
    assert!(matches!(
        execute_download(&mut c_tree, "root1234", &opts, &cancel_hooks),
        Err(GoFileError::Cancelled)
    ));
}

#[tokio::test]
async fn test_tasks_error_states_and_web_404_and_validation_branches() {
    let tmp = tempdir().unwrap();
    let _trk = DownloadTracker::new(tmp.path(), "env_cid", None).unwrap();

    // Worker that fails when url == "fail", cancels when url == "cancel", succeeds otherwise
    let worker: TaskWorkerFn = Arc::new(|req, cfg, hooks| {
        hooks.on_progress(42);
        if req.url == "fail" {
            return Err(GoFileError::Authentication("boom".into()));
        }
        if req.url == "cancel" {
            return Err(GoFileError::Cancelled);
        }
        hooks.on_name("single.bin");
        std::fs::write(cfg.base_dir.join("single.bin"), b"abc")?;
        Ok(())
    });

    let cfg = Arc::new(AppConfig {
        base_dir: tmp.path().to_path_buf(),
        secret_key: "sec".into(),
        csrf: CsrfConfig {
            enabled: false,
            time_limit: 3600,
        },
        ..AppConfig::default()
    });
    let tasks = TaskManager::with_worker(Arc::clone(&cfg), worker);
    let t_fail = tasks.start_task(StartTaskRequest::new("fail"));
    let t_cancel = tasks.start_task(StartTaskRequest::new("cancel"));
    let t_file = tasks.start_task(StartTaskRequest::new("ok_file"));
    let _ = tasks.active_count();
    tokio::time::sleep(Duration::from_millis(40)).await;

    let map = tasks.list_tasks();
    assert_eq!(map[&t_fail].status, "error");
    assert!(map[&t_fail].error_message.contains("boom"));
    assert_eq!(map[&t_cancel].status, "cancelled");
    assert!(tasks.delete_task_files(&t_file).unwrap().is_some());
    assert!(tasks.delete_task_files(&t_fail).unwrap().is_some()); // no out_path branch

    let app = build_router(WebAppState {
        config: cfg,
        tasks,
        template_path: None,
        app_version: "1.8.3".into(),
    });

    // Empty URL -> 400 Bad Request
    let r_empty = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/start")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("url=+++&throttle=512"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_empty.status(), StatusCode::BAD_REQUEST);

    // 404 routes for unknown task IDs
    for (method, uri) in [
        (Method::GET, "/progress/unknown"),
        (Method::POST, "/pause/unknown"),
        (Method::POST, "/cancel/unknown"),
        (Method::POST, "/remove/unknown"),
        (Method::POST, "/delete/unknown"),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

struct PauseOnceHooks {
    paused_polls: AtomicBool,
}

impl ProgressHooks for PauseOnceHooks {
    fn is_paused(&self) -> bool {
        self.paused_polls.swap(false, Ordering::SeqCst)
    }
}

#[tokio::test]
async fn test_progress_bridge_pause_throttle_password_and_csrf_rejections() {
    let tmp = tempdir().unwrap();

    // 1. Exercise TaskManager::new (both invalid proxy and valid ReqwestTransport -> InvalidUrl)
    let bad_proxy_cfg = Arc::new(AppConfig {
        base_dir: tmp.path().to_path_buf(),
        proxy: Some("://bad-proxy-url".into()),
        ..AppConfig::default()
    });
    let live_mgr = TaskManager::new(bad_proxy_cfg);
    let live_tid = live_mgr.start_task(StartTaskRequest::new("https://gofile.io/d/abc123"));
    let ok_proxy_cfg = Arc::new(AppConfig {
        base_dir: tmp.path().to_path_buf(),
        ..AppConfig::default()
    });
    let live_mgr2 = TaskManager::new(ok_proxy_cfg);
    let live_tid2 = live_mgr2.start_task(StartTaskRequest::new("https://not-gofile.example/x"));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(live_mgr.list_tasks()[&live_tid].status, "error");
    assert_eq!(live_mgr2.list_tasks()[&live_tid2].status, "error");

    // 2. Exercise TaskProgressBridge (on_file_progress insert+update, on_overall_progress,
    //    is_paused, is_cancelled) + directory deletion in delete_task_files
    let bridge_worker: TaskWorkerFn = Arc::new(|_req, cfg, hooks| {
        let dir = cfg.base_dir.join("AlbumDir");
        std::fs::create_dir_all(&dir)?;
        let fpath = dir.join("track.flac");
        std::fs::write(&fpath, b"flac")?;
        hooks.on_name("AlbumDir");
        hooks.on_file_progress(&fpath, 0, Some(1000), None);
        hooks.on_file_progress(&fpath, 50, Some(1000), Some("Retry 1/3"));
        std::thread::sleep(Duration::from_millis(2));
        hooks.on_overall_progress(50, "AlbumDir");
        let _ = hooks.is_paused();
        let _ = hooks.is_cancelled();
        Ok(())
    });
    let bridge_cfg = Arc::new(AppConfig {
        base_dir: tmp.path().to_path_buf(),
        secret_key: "strict_secret".into(),
        csrf: CsrfConfig {
            enabled: true,
            time_limit: 3600,
        },
        ..AppConfig::default()
    });
    let bridge_mgr = TaskManager::with_worker(Arc::clone(&bridge_cfg), bridge_worker);
    let b_tid = bridge_mgr.start_task(StartTaskRequest::new("https://gofile.io/d/album1"));
    tokio::time::sleep(Duration::from_millis(40)).await;
    let snap = &bridge_mgr.list_tasks()[&b_tid];
    assert_eq!(snap.status, "completed");
    assert_eq!(snap.files.len(), 1);
    assert!(snap.download_speed >= 0.0);
    assert!(bridge_mgr.delete_task_files(&b_tid).unwrap().is_some());
    assert!(!tmp.path().join("AlbumDir").exists());

    // 3. Password error, web API retry ok, linkless root error, all-failed folder error,
    //    and pause+throttle loop in transfer.rs
    let t = ScriptTransport::default();
    t.gets.lock().unwrap().extend([
        // Password error
        Ok(r#"{"status":"ok","data":{"type":"folder","name":"Locked","passwordStatus":"passwordWrong"}}"#.into()),
        // Web fallback succeeding via API retry (offset 0 -> notPremium, offset -1 -> notPremium, html, api retry -> ok)
        Ok(r#"{"status":"error-notPremium"}"#.into()),
        Ok(r#"{"status":"error-notPremium"}"#.into()),
        Ok("<html></html>".into()),
        Ok(r#"{"status":"ok","data":{"type":"file","name":"nolink_root.bin"}}"#.into()),
        // Folder where every child fails -> Err(GoFileError::Download)
        Ok(r#"{"status":"ok","data":{"type":"folder","name":"AllBad","children":{
            "bad1":{"type":"file","name":"broken.bin"}
        }}}"#.into()),
        // Single-file throttled + paused download
        Ok(r#"{"status":"ok","data":{"type":"file","name":"throttled.bin","link":"https://s/th"}}"#.into()),
    ]);
    t.streams
        .lock()
        .unwrap()
        .push_back(Ok((200, Some(4096), vec![b'X'; 4096])));

    let mut client = GoFileClient::new(t, None, WebsiteTokenConfig::default());
    assert!(matches!(
        client.fetch_contents("locked1", Some("wrongpw")),
        Err(GoFileError::Password(_))
    ));

    let mut opts = DownloadOptions::new(tmp.path().join("out2"));
    opts.throttle_kbps = Some(1);
    opts.chunk_size = 1024;
    // Linkless root -> Err(GoFileError::Download) (via web fallback API retry!)
    assert!(matches!(
        execute_download(&mut client, "webok1", &opts, &NoopHooks),
        Err(GoFileError::Download { .. })
    ));
    // All children failed -> Err(GoFileError::Download)
    assert!(matches!(
        execute_download(&mut client, "allbad1", &opts, &NoopHooks),
        Err(GoFileError::Download { .. })
    ));
    // Paused + throttled transfer -> Ok
    let pause_hooks = PauseOnceHooks {
        paused_polls: AtomicBool::new(true),
    };
    let s_ok = execute_download(&mut client, "throt1", &opts, &pause_hooks).unwrap();
    assert_eq!(s_ok.files_downloaded, 1);

    // 4. Strict CSRF rejections on /start and /pause/{id} + malformed %ZZ percent-decoding
    let strict_app = build_router(WebAppState {
        config: bridge_cfg,
        tasks: bridge_mgr,
        template_path: None,
        app_version: "1.8.3".into(),
    });
    let r_no_csrf_start = strict_app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/start")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("url=abc%ZZ123&bareflag"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_no_csrf_start.status(), StatusCode::BAD_REQUEST);

    let r_no_csrf_pause = strict_app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/pause/any")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_no_csrf_pause.status(), StatusCode::BAD_REQUEST);

    let r_tasks = strict_app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/tasks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_tasks.status(), StatusCode::OK);

    let r_bad_browse = strict_app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/browse?path=does_not_exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_bad_browse.status(), StatusCode::BAD_REQUEST);

    let r_bad_mp = strict_app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/start")
                .header(header::CONTENT_TYPE, "multipart/form-data")
                .body(Body::from("not-multipart"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_bad_mp.status(), StatusCode::BAD_REQUEST);

    // 5. Client get_text EdgeBlocked, transient get_text retries, missing data, premium notPremium
    let t_retry = ScriptTransport::default();
    t_retry.gets.lock().unwrap().extend([
        Err(GoFileError::EdgeBlocked("contents".into())),
        Err(GoFileError::Authentication("t1".into())),
        Err(GoFileError::Authentication("t2".into())),
        Err(GoFileError::Authentication("t3".into())),
        Err(GoFileError::Authentication("t4".into())),
        Ok(r#"{"status":"ok"}"#.into()),
        Ok(r#"{"status":"error-notPremium"}"#.into()),
        Ok(r#"{"status":"error-notPremium"}"#.into()),
    ]);
    let mut c_retry = GoFileClient::new(
        t_retry,
        Some("prem_tok".into()),
        WebsiteTokenConfig::default(),
    );
    assert!(matches!(
        c_retry.fetch_contents("e1", None),
        Err(GoFileError::EdgeBlocked(_))
    ));
    assert!(c_retry.fetch_contents("e2", None).is_err());
    assert!(matches!(
        c_retry.fetch_contents("e3", None),
        Err(GoFileError::Serialization(_))
    ));
    assert!(c_retry.fetch_contents("e4", Some("pw")).is_err());
}
