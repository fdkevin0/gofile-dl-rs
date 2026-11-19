//! Behavioral edge-case tests for nested subfolders, single-file root downloads,
//! YAML config parsing, CSRF/Basic Auth rejections, task failure/cancel transitions,
//! and HTTP 400/404 validation paths.

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
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use tower::ServiceExt;

#[test]
fn test_browse_and_config_yaml_and_env_edge_cases() {
    let tmp = tempdir().unwrap();
    check_directory_writable(tmp.path()).unwrap();

    let sub = tmp.path().join("movies").join("2026");
    std::fs::create_dir_all(&sub).unwrap();
    let file_only = tmp.path().join("note.txt");
    std::fs::write(&file_only, b"hi").unwrap();

    // Relative, exact canonical, nonexistent, and file-as-directory browse paths
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

    // Version file override and env-map parsing & validation
    let vfile = tmp.path().join("version.txt");
    std::fs::write(&vfile, "2.0.0\n").unwrap();
    assert_eq!(read_app_version(&vfile), "2.0.0");

    let mut cfg = AppConfig::default();
    let env = HashMap::from([
        ("BASE_DIR".into(), "/tmp/dl".into()),
        ("SECRET_KEY".into(), "k123".into()),
        ("RETRY_DELAY".into(), "9".into()),
        ("GOFILE_PREMIUM_TOKEN".into(), "prem_xyz".into()),
        ("GOFILE_PROXY".into(), "socks5://127.0.0.1:1080".into()),
        ("AUTH_USERNAME".into(), "bob".into()),
        ("AUTH_PASSWORD".into(), "pw".into()),
    ]);
    cfg.apply_env_map(&env).unwrap();
    assert_eq!(cfg.retry_delay, 9);
    assert_eq!(cfg.premium_token.as_deref(), Some("prem_xyz"));
    assert_eq!(cfg.proxy.as_deref(), Some("socks5://127.0.0.1:1080"));
    assert_eq!(cfg.auth.username, "bob");

    let bad_retries = HashMap::from([("DEFAULT_RETRIES".into(), "nope".into())]);
    assert!(cfg.apply_env_map(&bad_retries).is_err());

    let bad_delay = HashMap::from([("RETRY_DELAY".into(), "nope".into())]);
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

    let tracker = DownloadTracker::with_config_dir(&dl_dir, &cfg_dir, "r1", None).unwrap();
    assert_eq!(
        tracker.find_existing_folder("RootFolder", &dl_dir),
        Some(dl_dir.join("RootFolder"))
    );

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
    type StepFn = Box<
        dyn FnOnce(
                StartTaskRequest,
                Arc<AppConfig>,
                Arc<dyn ProgressHooks>,
            ) -> Result<(), GoFileError>
            + Send,
    >;

    let tmp = tempdir().unwrap();

    let steps: Arc<Mutex<VecDeque<StepFn>>> = Arc::new(Mutex::new(VecDeque::from([
        Box::new(
            |_req: StartTaskRequest, _cfg: Arc<AppConfig>, hooks: Arc<dyn ProgressHooks>| {
                hooks.on_progress(42);
                Err(GoFileError::Authentication("boom".into()))
            },
        ) as StepFn,
        Box::new(
            |_req: StartTaskRequest, _cfg: Arc<AppConfig>, hooks: Arc<dyn ProgressHooks>| {
                hooks.on_progress(42);
                Err(GoFileError::Cancelled)
            },
        ) as StepFn,
        Box::new(
            |_req: StartTaskRequest, cfg: Arc<AppConfig>, hooks: Arc<dyn ProgressHooks>| {
                hooks.on_name("single.bin");
                std::fs::write(cfg.base_dir.join("single.bin"), b"abc")?;
                Ok(())
            },
        ) as StepFn,
    ])));
    let worker: TaskWorkerFn = Arc::new(move |req, cfg, hooks| {
        let step = steps.lock().unwrap().pop_front().unwrap();
        step(req, cfg, hooks)
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
    assert!(tasks.wait_for_task(&t_fail, Duration::from_secs(5)));
    let t_cancel = tasks.start_task(StartTaskRequest::new("cancel"));
    assert!(tasks.wait_for_task(&t_cancel, Duration::from_secs(5)));
    let t_file = tasks.start_task(StartTaskRequest::new("ok_file"));
    assert!(tasks.wait_for_task(&t_file, Duration::from_secs(5)));

    let map = tasks.list_tasks();
    assert_eq!(map[&t_fail].status, "error");
    assert!(map[&t_fail].error_message.contains("boom"));
    assert_eq!(map[&t_cancel].status, "cancelled");
    assert!(tasks.delete_task_files(&t_file).unwrap().is_some());
    assert!(!tmp.path().join("single.bin").exists());
    assert!(tasks.delete_task_files(&t_fail).unwrap().is_some());

    let app = build_router(WebAppState {
        config: cfg,
        tasks,
        template_path: None,
        app_version: "0.1.0-test".into(),
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
    let r_prog = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/progress/unknown")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_prog.status(), StatusCode::NOT_FOUND);

    let r_pause = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/pause/unknown")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_pause.status(), StatusCode::NOT_FOUND);

    let r_cancel = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/cancel/unknown")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_cancel.status(), StatusCode::NOT_FOUND);

    let r_remove = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/remove/unknown")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_remove.status(), StatusCode::NOT_FOUND);

    let r_delete = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/delete/unknown")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_delete.status(), StatusCode::NOT_FOUND);
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

    // 1. Live worker surfaces invalid proxy and invalid URL errors deterministically
    let bad_proxy_cfg = Arc::new(AppConfig {
        base_dir: tmp.path().to_path_buf(),
        proxy: Some("://bad-proxy-url".into()),
        ..AppConfig::default()
    });
    let live_mgr = TaskManager::new(bad_proxy_cfg);
    let live_tid = live_mgr.start_task(StartTaskRequest::new("https://gofile.io/d/abc123"));
    assert!(live_mgr.wait_for_task(&live_tid, Duration::from_secs(5)));
    assert_eq!(live_mgr.list_tasks()[&live_tid].status, "error");

    let ok_proxy_cfg = Arc::new(AppConfig {
        base_dir: tmp.path().to_path_buf(),
        ..AppConfig::default()
    });
    let live_mgr2 = TaskManager::new(ok_proxy_cfg);
    let live_tid2 = live_mgr2.start_task(StartTaskRequest::new("https://not-gofile.example/x"));
    assert!(live_mgr2.wait_for_task(&live_tid2, Duration::from_secs(5)));
    assert_eq!(live_mgr2.list_tasks()[&live_tid2].status, "error");

    // 2. TaskProgressBridge file upsert + directory deletion in delete_task_files
    let bridge_worker: TaskWorkerFn = Arc::new(|_req, cfg, hooks| {
        let dir = cfg.base_dir.join("AlbumDir");
        std::fs::create_dir_all(&dir)?;
        let fpath = dir.join("track.flac");
        std::fs::write(&fpath, b"flac")?;
        hooks.on_name("AlbumDir");
        hooks.on_file_progress(&fpath, 0, Some(1000), None);
        hooks.on_file_progress(&fpath, 50, Some(1000), Some("Retry 1/3"));
        hooks.on_overall_progress(50, "AlbumDir");
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
    assert!(bridge_mgr.wait_for_task(&b_tid, Duration::from_secs(5)));
    let snap = &bridge_mgr.list_tasks()[&b_tid];
    assert_eq!(snap.status, "completed");
    assert_eq!(snap.files.len(), 1);
    assert_eq!(snap.files[0].progress, 50);
    assert_eq!(snap.files[0].retry_info.as_deref(), Some("Retry 1/3"));
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

    // 4. Malformed %ZZ form payload, invalid /browse path, and malformed multipart rejections
    let strict_app = build_router(WebAppState {
        config: bridge_cfg,
        tasks: bridge_mgr,
        template_path: None,
        app_version: "0.1.0-test".into(),
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
