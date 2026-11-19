//! Integration tests for `AppConfig`, Basic Auth, stateless HMAC CSRF, path-confined
//! `/browse`, and the complete `axum` HTTP task lifecycle.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use gofile_dl::config::{read_app_version, AppConfig};
use gofile_dl::security::generate_csrf_token;
use gofile_dl::tasks::{TaskManager, TaskWorkerFn};
use gofile_dl::web::{build_router, WebAppState};
use http_body_util::BodyExt;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tower::ServiceExt;

fn build_test_app(
    base_dir: &Path,
    auth_enabled: bool,
    worker: TaskWorkerFn,
) -> (axum::Router, Arc<AppConfig>) {
    let (router, cfg, _) = build_test_app_with_tasks(base_dir, auth_enabled, worker);
    (router, cfg)
}

fn build_test_app_with_tasks(
    base_dir: &Path,
    auth_enabled: bool,
    worker: TaskWorkerFn,
) -> (axum::Router, Arc<AppConfig>, TaskManager) {
    let mut cfg = AppConfig {
        base_dir: base_dir.to_path_buf(),
        secret_key: "test-secret-key-999".to_string(),
        ..AppConfig::default()
    };
    cfg.auth.enabled = auth_enabled;
    cfg.auth.username = "admin".to_string();
    cfg.auth.password = "s3cr3t".to_string();
    let cfg_arc = Arc::new(cfg);
    let tasks = TaskManager::with_worker(Arc::clone(&cfg_arc), worker);
    let state = WebAppState {
        config: Arc::clone(&cfg_arc),
        tasks: tasks.clone(),
        template_path: None,
        app_version: "0.1.0-test".to_string(),
    };
    (build_router(state), cfg_arc, tasks)
}

async fn read_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn test_config_env_overrides_and_invalid_port() {
    let mut cfg = AppConfig::default();
    let mut env = HashMap::new();
    env.insert("PORT".to_string(), "9090".to_string());
    env.insert("HOST".to_string(), "127.0.0.1".to_string());
    env.insert("DEFAULT_RETRIES".to_string(), "99".to_string()); // clamped to 10
    env.insert("AUTH_ENABLED".to_string(), "true".to_string());
    cfg.apply_env_map(&env).unwrap();
    assert_eq!(cfg.port, 9090);
    assert_eq!(cfg.host, "127.0.0.1");
    assert_eq!(cfg.default_retries, 10);
    assert!(cfg.auth.enabled);

    env.insert("PORT".to_string(), "not-a-number".to_string());
    assert!(cfg.apply_env_map(&env).is_err());

    assert_eq!(
        read_app_version(Path::new("/nonexistent/version.txt")),
        env!("CARGO_PKG_VERSION")
    );
}

#[tokio::test]
async fn test_health_basic_auth_and_index_csrf_rendering() {
    let tmp = tempdir().unwrap();
    let worker: TaskWorkerFn = Arc::new(|_req, _cfg, _hooks| Ok(()));
    let (app, cfg) = build_test_app(tmp.path(), true, worker);

    // `/health` is unauthenticated for Docker container probes.
    let res_health = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_health.status(), StatusCode::OK);
    let h_json = read_json(res_health).await;
    assert_eq!(h_json["status"], "ok");
    assert_eq!(h_json["application"]["version"], "0.1.0-test");
    assert_eq!(h_json["directories"]["writable"], true);

    // Protected `/tasks` without credentials returns 401 + WWW-Authenticate
    let res_unauth = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/tasks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_unauth.status(), StatusCode::UNAUTHORIZED);
    assert!(res_unauth
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Basic"));

    // Valid Basic Auth renders `/` with injected CSRF token and stripped Jinja flash tags
    let creds = BASE64_STD.encode("admin:s3cr3t");
    let res_idx = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::AUTHORIZATION, format!("Basic {creds}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_idx.status(), StatusCode::OK);
    let html = String::from_utf8(
        res_idx
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(!html.contains("{{ csrf_token() }}"));
    assert!(!html.contains("{% with messages"));
    let _ = cfg;
}

#[tokio::test]
async fn test_web_task_lifecycle_multipart_post_root_and_browse_confinement() {
    use gofile_dl::downloader::ProgressHooks;
    use gofile_dl::error::GoFileError;
    use gofile_dl::tasks::StartTaskRequest;
    use std::collections::VecDeque;
    use std::sync::{mpsc, Mutex};

    type StepFn = Box<
        dyn FnOnce(
                StartTaskRequest,
                Arc<AppConfig>,
                Arc<dyn ProgressHooks>,
            ) -> Result<(), GoFileError>
            + Send,
    >;

    let tmp = tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("alpha")).unwrap();
    std::fs::create_dir_all(tmp.path().join("beta")).unwrap();

    let (t2_started_tx, t2_started_rx) = mpsc::channel::<()>();
    let (t2_release_tx, t2_release_rx) = mpsc::channel::<()>();
    let steps: Arc<Mutex<VecDeque<StepFn>>> = Arc::new(Mutex::new(VecDeque::from([
        Box::new(
            |_req: StartTaskRequest, cfg: Arc<AppConfig>, hooks: Arc<dyn ProgressHooks>| {
                hooks.on_name("dl_folder");
                let target_dir = cfg.base_dir.join("dl_folder");
                std::fs::create_dir_all(&target_dir)?;
                let fpath = target_dir.join("sample.bin");
                std::fs::write(&fpath, b"12345678")?;
                hooks.on_file_progress(&fpath, 50, Some(8), None);
                hooks.on_overall_progress(100, "dl_folder");
                Ok(())
            },
        ) as StepFn,
        Box::new(
            move |_req: StartTaskRequest, _cfg: Arc<AppConfig>, hooks: Arc<dyn ProgressHooks>| {
                hooks.on_name("active_folder");
                t2_started_tx.send(()).unwrap();
                let _ = t2_release_rx.recv();
                Err(GoFileError::Cancelled)
            },
        ) as StepFn,
    ])));
    let worker: TaskWorkerFn = Arc::new(move |req, cfg, hooks| {
        let step = steps.lock().unwrap().pop_front().unwrap();
        step(req, cfg, hooks)
    });

    let (app, cfg, tasks) = build_test_app_with_tasks(tmp.path(), false, worker);
    let csrf = generate_csrf_token(&cfg.secret_key);

    // 1. CSRF missing -> 400 Bad Request
    let bad_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/start")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("url=https%3A%2F%2Fgofile.io%2Fd%2Fabc123"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_csrf.status(), StatusCode::BAD_REQUEST);

    // 2. Regression test for Bug #5: `POST /` starts task directly (202) instead of 302 -> 405!
    let body_form = format!(
        "csrf_token={csrf}&url=https%3A%2F%2Fgofile.io%2Fd%2Fabc123&retries=2&incremental=true"
    );
    let res_post_root = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_post_root.status(), StatusCode::ACCEPTED);
    let tid1 = read_json(res_post_root).await["task_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(tasks.wait_for_task(&tid1, Duration::from_secs(5)));

    // 3. Multipart form-data on `/start` (matching browser `new FormData(form)`)
    let boundary = "----GoFileTestBoundary";
    let mp_body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"url\"\r\n\r\nhttps://gofile.io/d/xyz987\r\n--{boundary}--\r\n"
    );
    let res_mp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/start")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .header("X-CSRFToken", &csrf)
                .body(Body::from(mp_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_mp.status(), StatusCode::ACCEPTED);
    let tid2 = read_json(res_mp).await["task_id"]
        .as_str()
        .unwrap()
        .to_string();
    t2_started_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    // 4. Check `/progress/{id}`
    let res_prog = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/progress/{tid1}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_prog.status(), StatusCode::OK);

    // 5a. Completed task (`tid1`) must NOT resurrect into `paused` on `/pause/{tid1}`
    let res_pause_completed = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/pause/{tid1}"))
                .header("X-CSRFToken", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_pause_completed.status(), StatusCode::OK);
    let pause_completed_json = read_json(res_pause_completed).await;
    assert_eq!(pause_completed_json["paused"], false);
    assert_eq!(pause_completed_json["status"], "completed");

    // 5b. Toggle `/pause/{tid2}` on active task, `/cancel/{tid2}`, `/remove/{tid2}`, and `/delete/{tid1}`
    let res_pause = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/pause/{tid2}"))
                .header("X-CSRFToken", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_pause.status(), StatusCode::OK);
    assert_eq!(read_json(res_pause).await["paused"], true);

    let res_cancel = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/cancel/{tid2}"))
                .header("X-CSRFToken", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_cancel.status(), StatusCode::OK);
    let _ = t2_release_tx.send(());
    assert!(tasks.wait_for_task(&tid2, Duration::from_secs(5)));

    let res_remove = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/remove/{tid2}"))
                .header("X-CSRFToken", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_remove.status(), StatusCode::OK);

    let res_delete = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/delete/{tid1}"))
                .header("X-CSRFToken", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_delete.status(), StatusCode::OK);
    assert!(!tmp.path().join("dl_folder").exists());

    // 6. `/browse` directory confinement against `../../etc` escape attempt
    let res_browse_escape = app
        .oneshot(
            Request::builder()
                .uri("/browse?path=../../..")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_browse_escape.status(), StatusCode::OK);
    let b_json = read_json(res_browse_escape).await;
    assert_eq!(b_json["at_base"], true);
    assert_eq!(b_json["directories"], serde_json::json!(["alpha", "beta"]));
}

#[test]
fn task_expiry_env_and_pruning_evicts_expired_terminal_tasks() {
    let mut cfg = AppConfig::default();
    assert_eq!(cfg.task_expiry, 604_800);

    let env_ok = HashMap::from([("TASK_EXPIRY".to_string(), "60".to_string())]);
    cfg.apply_env_map(&env_ok).unwrap();
    assert_eq!(cfg.task_expiry, 60);

    let env_bad = HashMap::from([("TASK_EXPIRY".to_string(), "not_a_u64".to_string())]);
    assert!(cfg.apply_env_map(&env_bad).is_err());

    let tmp = tempdir().unwrap();
    let config_dir = tmp.path().join("cfg");
    std::fs::create_dir_all(&config_dir).unwrap();
    let seeded = serde_json::json!({
        "version": 1,
        "tasks": {
            "expired-task": {
                "snapshot": {
                    "progress": 100,
                    "overall_progress": 100,
                    "current_folder": "Old",
                    "download_speed": 0.0,
                    "status": "completed",
                    "error_message": "",
                    "url": "https://gofile.io/d/Old1",
                    "name": "Old",
                    "timestamp": 1.0,
                    "files": [],
                    "paused": false
                },
                "request": {
                    "url": "https://gofile.io/d/Old1",
                    "retries": 1,
                    "strip_emojis": false,
                    "incremental": false,
                    "folder_pattern": "NEW"
                }
            },
            "fresh-task": {
                "snapshot": {
                    "progress": 100,
                    "overall_progress": 100,
                    "current_folder": "Fresh",
                    "download_speed": 0.0,
                    "status": "completed",
                    "error_message": "",
                    "url": "https://gofile.io/d/Fresh1",
                    "name": "Fresh",
                    "timestamp": 9_999_999_999.0,
                    "files": [],
                    "paused": false
                },
                "request": {
                    "url": "https://gofile.io/d/Fresh1",
                    "retries": 1,
                    "strip_emojis": false,
                    "incremental": false,
                    "folder_pattern": "NEW"
                }
            }
        }
    });
    std::fs::write(
        config_dir.join("tasks.json"),
        serde_json::to_string(&seeded).unwrap(),
    )
    .unwrap();

    cfg.base_dir = tmp.path().to_path_buf();
    cfg.config_dir = Some(config_dir);
    let mgr = TaskManager::with_worker(Arc::new(cfg), Arc::new(|_, _, _| Ok(())));

    let remaining = mgr.list_tasks();
    assert!(!remaining.contains_key("expired-task"));
    assert!(remaining.contains_key("fresh-task"));
}

#[tokio::test]
async fn tasks_endpoint_rotates_x_csrf_token_header() {
    let tmp = tempdir().unwrap();
    let worker: TaskWorkerFn = Arc::new(|_req, _cfg, _hooks| Ok(()));
    let (app, _cfg) = build_test_app(tmp.path(), false, worker);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/tasks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let rotated = res
        .headers()
        .get("X-CSRF-Token")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(!rotated.is_empty());

    // Rotated header token must authorize a subsequent mutating request.
    let res_start = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/start")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("X-CSRF-Token", &rotated)
                .body(Body::from("url=https%3A%2F%2Fgofile.io%2Fd%2FRotate1"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_start.status(), StatusCode::ACCEPTED);
}

#[test]
fn zero_alloc_sanitize_and_folder_normalizer_slice_parity() {
    use gofile_dl::sanitize::{
        sanitize_filename, sanitize_filename_into, strip_emojis, strip_emojis_into,
        FolderNormalizer,
    };

    let mut stripped = String::new();
    let mut filtered = String::new();
    let mut out = String::new();

    let mut assert_parity = |sample: &str| {
        strip_emojis_into(sample, &mut stripped);
        assert_eq!(stripped, strip_emojis(sample));
        sanitize_filename_into(&stripped, &mut filtered, &mut out);
        assert_eq!(out, sanitize_filename(&stripped));
    };
    assert_parity("CON.mkv . ");
    assert_parity("  CON.mkv . ");
    assert_parity("COM\u{00b9}.zip");
    assert_parity("LPT\u{00b3}.tar");
    assert_parity("CLOCK$.bin");
    assert_parity("🔥 Episode <01>:Pilot?.mkv");
    assert_parity("...");

    let norm = FolderNormalizer::new(Some("🔥HOT |⭐NEW FILES in "));
    let folder_in = "🔥HOT ⭐ NEW FILES in Series_S01 ";
    assert_eq!(norm.normalize_slice(folder_in), "Series_S01");
    assert_eq!(norm.normalize_slice(folder_in), norm.normalize(folder_in));
}

#[tokio::test]
async fn retry_endpoint_restarts_failed_task_with_original_request_and_enforces_csrf() {
    use gofile_dl::downloader::ProgressHooks;
    use gofile_dl::error::GoFileError;
    use gofile_dl::tasks::StartTaskRequest;
    use std::collections::VecDeque;
    use std::sync::{mpsc, Mutex};

    type StepFn = Box<
        dyn FnOnce(
                StartTaskRequest,
                Arc<AppConfig>,
                Arc<dyn ProgressHooks>,
            ) -> Result<(), GoFileError>
            + Send,
    >;

    let tmp = tempdir().unwrap();
    let (req_tx, req_rx) = mpsc::channel::<StartTaskRequest>();
    let req_tx1 = req_tx.clone();
    let req_tx2 = req_tx;

    let steps: Arc<Mutex<VecDeque<StepFn>>> = Arc::new(Mutex::new(VecDeque::from([
        Box::new(
            move |req: StartTaskRequest, cfg: Arc<AppConfig>, hooks: Arc<dyn ProgressHooks>| {
                req_tx1.send(req).unwrap();
                hooks.on_name("RetryFolder");
                let failed_file = cfg.base_dir.join("RetryFolder").join("broken.bin");
                hooks.on_file_progress(&failed_file, -2, Some(1024), None);
                Err(GoFileError::Download {
                    message: "simulated drop".to_string(),
                    filename: "broken.bin".to_string(),
                    url: "https://gofile.io/d/retry01".to_string(),
                })
            },
        ) as StepFn,
        Box::new(
            move |req: StartTaskRequest, cfg: Arc<AppConfig>, hooks: Arc<dyn ProgressHooks>| {
                req_tx2.send(req).unwrap();
                hooks.on_name("RetryFolder");
                let ok_file = cfg.base_dir.join("RetryFolder").join("ok.bin");
                hooks.on_file_progress(&ok_file, 100, Some(2048), None);
                hooks.on_overall_progress(100, "RetryFolder");
                Ok(())
            },
        ) as StepFn,
    ])));

    let worker: TaskWorkerFn = Arc::new(move |req, cfg, hooks| {
        let step = steps.lock().unwrap().pop_front().unwrap();
        step(req, cfg, hooks)
    });

    let (app, cfg, tasks) = build_test_app_with_tasks(tmp.path(), false, worker);
    let csrf = generate_csrf_token(&cfg.secret_key);

    // Embedded WebUI template includes retry button and handler wiring.
    let res_idx = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let html = String::from_utf8(
        res_idx
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("function retryTask("));
    assert!(html.contains("/retry/"));

    // Start task with rich options that must survive retry.
    let form = format!(
        "csrf_token={csrf}&url=https%3A%2F%2Fgofile.io%2Fd%2Fretry01&directory=sub&password=pw123&throttle=500&retries=4&strip_emojis=true&incremental=true&folder_pattern=HOT%7CNEW&premium_token=prem-tok"
    );
    let res_start = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/start")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_start.status(), StatusCode::ACCEPTED);
    let tid = read_json(res_start).await["task_id"]
        .as_str()
        .unwrap()
        .to_string();

    assert!(tasks.wait_for_task(&tid, Duration::from_secs(5)));
    let first_req = req_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    let snapshot_failed = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/tasks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(snapshot_failed[&tid]["status"], "error");
    assert!(snapshot_failed[&tid]["error_message"]
        .as_str()
        .unwrap()
        .contains("simulated drop"));

    // Missing CSRF token on /retry/{id} returns 400.
    let res_no_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/retry/{tid}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_no_csrf.status(), StatusCode::BAD_REQUEST);

    // Unknown task ID returns 404.
    let res_missing = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/retry/does-not-exist")
                .header("X-CSRFToken", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_missing.status(), StatusCode::NOT_FOUND);

    // Retry failed task in place and verify original request fields are preserved.
    let res_retry = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/retry/{tid}"))
                .header("X-CSRFToken", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_retry.status(), StatusCode::ACCEPTED);
    let retry_json = read_json(res_retry).await;
    assert_eq!(retry_json["task_id"], tid);
    assert_eq!(retry_json["status"], "running");

    assert!(tasks.wait_for_task(&tid, Duration::from_secs(5)));
    let second_req = req_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(second_req.url, first_req.url);
    assert_eq!(second_req.directory, first_req.directory);
    assert_eq!(second_req.password, first_req.password);
    assert_eq!(second_req.throttle_kbps, first_req.throttle_kbps);
    assert_eq!(second_req.retries, first_req.retries);
    assert_eq!(second_req.strip_emojis, first_req.strip_emojis);
    assert_eq!(second_req.incremental, first_req.incremental);
    assert_eq!(second_req.folder_pattern, first_req.folder_pattern);
    assert_eq!(second_req.premium_token, first_req.premium_token);

    let snapshot_ok = read_json(
        app.oneshot(
            Request::builder()
                .uri("/tasks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(snapshot_ok[&tid]["status"], "completed");
    assert_eq!(snapshot_ok[&tid]["error_message"], "");
    assert_eq!(snapshot_ok[&tid]["files"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot_ok[&tid]["files"][0]["progress"], 100);
}

#[tokio::test]
async fn retry_endpoint_rejects_active_task_and_isolates_cancelled_stale_worker() {
    use gofile_dl::downloader::ProgressHooks;
    use gofile_dl::error::GoFileError;
    use gofile_dl::tasks::StartTaskRequest;
    use std::collections::VecDeque;
    use std::sync::{mpsc, Mutex};

    type StepFn = Box<
        dyn FnOnce(
                StartTaskRequest,
                Arc<AppConfig>,
                Arc<dyn ProgressHooks>,
            ) -> Result<(), GoFileError>
            + Send,
    >;

    let tmp = tempdir().unwrap();
    let (started1_tx, started1_rx) = mpsc::channel::<()>();
    let (release1_tx, release1_rx) = mpsc::channel::<()>();
    let (events_tx, events_rx) = mpsc::channel::<&'static str>();
    let events_tx1 = events_tx.clone();
    let events_tx2 = events_tx;

    let steps: Arc<Mutex<VecDeque<StepFn>>> = Arc::new(Mutex::new(VecDeque::from([
        Box::new(
            move |_req: StartTaskRequest, _cfg: Arc<AppConfig>, hooks: Arc<dyn ProgressHooks>| {
                started1_tx.send(()).unwrap();
                release1_rx.recv().unwrap();
                // Stale progress callback after retry must be ignored.
                hooks.on_name("StaleAttempt");
                events_tx1.send("attempt1_exited").unwrap();
                Err(GoFileError::Cancelled)
            },
        ) as StepFn,
        Box::new(
            move |_req: StartTaskRequest, _cfg: Arc<AppConfig>, hooks: Arc<dyn ProgressHooks>| {
                events_tx2.send("attempt2_started").unwrap();
                hooks.on_name("FreshAttempt");
                hooks.on_overall_progress(100, "FreshAttempt");
                Ok(())
            },
        ) as StepFn,
    ])));

    let worker: TaskWorkerFn = Arc::new(move |req, cfg, hooks| {
        let step = steps.lock().unwrap().pop_front().unwrap();
        step(req, cfg, hooks)
    });

    let (app, cfg, tasks) = build_test_app_with_tasks(tmp.path(), false, worker);
    let csrf = generate_csrf_token(&cfg.secret_key);

    let res_start = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/start")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("X-CSRFToken", &csrf)
                .body(Body::from("url=https%3A%2F%2Fgofile.io%2Fd%2Fcancelretry"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_start.status(), StatusCode::ACCEPTED);
    let tid = read_json(res_start).await["task_id"]
        .as_str()
        .unwrap()
        .to_string();

    started1_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    // Retrying while active must return 409 Conflict.
    let res_conflict = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/retry/{tid}"))
                .header("X-CSRFToken", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_conflict.status(), StatusCode::CONFLICT);

    // Cancel task while worker 1 is still unwinding, then immediately retry.
    let res_cancel = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/cancel/{tid}"))
                .header("X-CSRFToken", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_cancel.status(), StatusCode::OK);

    let res_retry = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/retry/{tid}"))
                .header("X-CSRFToken", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_retry.status(), StatusCode::ACCEPTED);

    // Release worker 1; worker 2 must only start after worker 1 exits, and stale finalization must not clobber attempt 2.
    release1_tx.send(()).unwrap();
    assert_eq!(
        events_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        "attempt1_exited"
    );
    assert_eq!(
        events_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        "attempt2_started"
    );
    assert!(tasks.wait_for_task(&tid, Duration::from_secs(5)));

    let tasks_json = read_json(
        app.oneshot(
            Request::builder()
                .uri("/tasks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(tasks_json[&tid]["status"], "completed");
    assert_eq!(tasks_json[&tid]["name"], "FreshAttempt");
}

#[tokio::test]
async fn task_persistence_survives_restart_recovers_interrupted_and_scrubs_secrets() {
    use gofile_dl::downloader::ProgressHooks;
    use gofile_dl::error::GoFileError;
    use gofile_dl::tasks::StartTaskRequest;
    use std::collections::VecDeque;
    use std::sync::{mpsc, Mutex};

    type StepFn = Box<
        dyn FnOnce(
                StartTaskRequest,
                Arc<AppConfig>,
                Arc<dyn ProgressHooks>,
            ) -> Result<(), GoFileError>
            + Send,
    >;

    let tmp = tempdir().unwrap();
    let base_dir = tmp.path().join("data");
    let config_dir = tmp.path().join("config");
    std::fs::create_dir_all(&base_dir).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();

    // Verify CONFIG_DIR env parsing.
    let mut cfg = AppConfig {
        base_dir: base_dir.clone(),
        secret_key: "persist-secret-key".to_string(),
        ..AppConfig::default()
    };
    let env = HashMap::from([(
        "CONFIG_DIR".to_string(),
        config_dir.to_string_lossy().into_owned(),
    )]);
    cfg.apply_env_map(&env).unwrap();
    assert_eq!(cfg.config_dir.as_deref(), Some(config_dir.as_path()));
    let cfg_arc = Arc::new(cfg);
    let csrf = generate_csrf_token(&cfg_arc.secret_key);

    // Instance 1: Task A completes (writing a file), Task B stays blocked to simulate mid-download restart.
    let (b_started_tx, b_started_rx) = mpsc::channel::<()>();
    let (b_release_tx, b_release_rx) = mpsc::channel::<()>();
    let steps1: Arc<Mutex<VecDeque<StepFn>>> = Arc::new(Mutex::new(VecDeque::from([
        Box::new(
            move |_req: StartTaskRequest, cfg: Arc<AppConfig>, hooks: Arc<dyn ProgressHooks>| {
                hooks.on_name("SavedFolder");
                let folder = cfg.base_dir.join("SavedFolder");
                std::fs::create_dir_all(&folder)?;
                let fpath = folder.join("clip.bin");
                std::fs::write(&fpath, b"payload")?;
                hooks.on_file_progress(&fpath, 100, Some(7), None);
                hooks.on_overall_progress(100, "SavedFolder");
                Ok(())
            },
        ) as StepFn,
        Box::new(
            move |_req: StartTaskRequest, _cfg: Arc<AppConfig>, hooks: Arc<dyn ProgressHooks>| {
                hooks.on_name("InFlightFolder");
                b_started_tx.send(()).unwrap();
                let _ = b_release_rx.recv();
                Err(GoFileError::Cancelled)
            },
        ) as StepFn,
    ])));
    let worker1: TaskWorkerFn = Arc::new(move |req, cfg, hooks| {
        let step = steps1.lock().unwrap().pop_front().unwrap();
        step(req, cfg, hooks)
    });

    let tasks1 = TaskManager::with_worker(Arc::clone(&cfg_arc), worker1);
    let app1 = build_router(WebAppState {
        config: Arc::clone(&cfg_arc),
        tasks: tasks1.clone(),
        template_path: None,
        app_version: "0.1.0-test".to_string(),
    });

    let res_a = app1
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/start")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("X-CSRFToken", &csrf)
                .body(Body::from(
                    "url=https%3A%2F%2Fgofile.io%2Fd%2Fdone01&password=super-secret-pw&premium_token=secret-prem-token&retries=5&incremental=true",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_a.status(), StatusCode::ACCEPTED);
    let tid_a = read_json(res_a).await["task_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(tasks1.wait_for_task(&tid_a, Duration::from_secs(5)));

    let res_b = app1
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/start")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("X-CSRFToken", &csrf)
                .body(Body::from(
                    "url=https%3A%2F%2Fgofile.io%2Fd%2Finflight02&retries=4&strip_emojis=true",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_b.status(), StatusCode::ACCEPTED);
    let tid_b = read_json(res_b).await["task_id"]
        .as_str()
        .unwrap()
        .to_string();
    b_started_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    // Verify tasks.json exists and does not persist plaintext secrets.
    let raw_store = std::fs::read_to_string(config_dir.join("tasks.json")).unwrap();
    assert!(!raw_store.contains("super-secret-pw"));
    assert!(!raw_store.contains("secret-prem-token"));

    // Release instance 1's blocked thread only after snapshotting tasks.json for instance 2.
    let store_copy = config_dir.join("tasks.json");
    let saved_before_release = std::fs::read(&store_copy).unwrap();
    let _ = b_release_tx.send(());
    assert!(tasks1.wait_for_task(&tid_b, Duration::from_secs(5)));
    std::fs::write(&store_copy, saved_before_release).unwrap();

    // Instance 2: simulates container restart reading CONFIG_DIR/tasks.json.
    let (retry_req_tx, retry_req_rx) = mpsc::channel::<StartTaskRequest>();
    let worker2: TaskWorkerFn = Arc::new(
        move |req: StartTaskRequest, _cfg: Arc<AppConfig>, hooks: Arc<dyn ProgressHooks>| {
            retry_req_tx.send(req).unwrap();
            hooks.on_name("RecoveredFolder");
            hooks.on_overall_progress(100, "RecoveredFolder");
            Ok(())
        },
    );
    let tasks2 = TaskManager::with_worker(Arc::clone(&cfg_arc), worker2);
    let app2 = build_router(WebAppState {
        config: Arc::clone(&cfg_arc),
        tasks: tasks2.clone(),
        template_path: None,
        app_version: "0.1.0-test".to_string(),
    });

    let restored = read_json(
        app2.clone()
            .oneshot(
                Request::builder()
                    .uri("/tasks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(restored[&tid_a]["status"], "completed");
    assert_eq!(restored[&tid_a]["name"], "SavedFolder");
    assert_eq!(restored[&tid_a]["files"].as_array().unwrap().len(), 1);
    assert_eq!(restored[&tid_b]["status"], "error");
    assert_eq!(restored[&tid_b]["name"], "InFlightFolder");
    assert_eq!(
        restored[&tid_b]["error_message"],
        "Interrupted by server restart"
    );

    // Retry recovered task B after restart.
    let res_retry_b = app2
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/retry/{tid_b}"))
                .header("X-CSRFToken", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_retry_b.status(), StatusCode::ACCEPTED);
    assert!(tasks2.wait_for_task(&tid_b, Duration::from_secs(5)));
    let retried_req = retry_req_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(retried_req.url, "https://gofile.io/d/inflight02");
    assert_eq!(retried_req.retries, 4);
    assert!(retried_req.strip_emojis);

    // Delete restored task A's files from disk using persisted out_path.
    assert!(base_dir.join("SavedFolder").exists());
    let res_del_a = app2
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/delete/{tid_a}"))
                .header("X-CSRFToken", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_del_a.status(), StatusCode::OK);
    assert!(!base_dir.join("SavedFolder").exists());

    // Instance 3: deleted task A stays gone, retried task B stays completed.
    let tasks3 = TaskManager::with_worker(Arc::clone(&cfg_arc), Arc::new(|_, _, _| Ok(())));
    let final_map = tasks3.list_tasks();
    assert!(!final_map.contains_key(&tid_a));
    assert_eq!(final_map[&tid_b].status, "completed");
    assert_eq!(final_map[&tid_b].name, "RecoveredFolder");
}

#[test]
fn task_persistence_ignores_corrupt_store_and_unconfined_out_path() {
    let tmp = tempdir().unwrap();
    let base_dir = tmp.path().join("data");
    let config_dir = tmp.path().join("config");
    let outside_file = tmp.path().join("outside_keep.txt");
    let inside_sentinel = base_dir.join("sentinel_keep.txt");
    std::fs::create_dir_all(&base_dir).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(&outside_file, b"must-not-delete").unwrap();
    std::fs::write(&inside_sentinel, b"base-dir-must-survive").unwrap();

    let cfg = Arc::new(AppConfig {
        base_dir: base_dir.clone(),
        config_dir: Some(config_dir.clone()),
        ..AppConfig::default()
    });

    // Corrupt JSON does not prevent startup.
    std::fs::write(config_dir.join("tasks.json"), "{not valid json").unwrap();
    let mgr_corrupt = TaskManager::with_worker(Arc::clone(&cfg), Arc::new(|_, _, _| Ok(())));
    assert!(mgr_corrupt.list_tasks().is_empty());

    // Tampered out_path outside base_dir OR equal to base_dir ("", ".", <base_dir>) must be stripped on load.
    let make_entry = |out_path: String| {
        serde_json::json!({
            "snapshot": {
                "progress": 100,
                "overall_progress": 100,
                "current_folder": "N/A",
                "download_speed": 0.0,
                "status": "completed",
                "error_message": "",
                "url": "https://gofile.io/d/safe01",
                "name": "safe01",
                "timestamp": 9_999_999_999.0,
                "files": [],
                "paused": false
            },
            "out_path": out_path,
            "request": {
                "url": "https://gofile.io/d/safe01",
                "retries": 3,
                "strip_emojis": false,
                "incremental": false,
                "folder_pattern": "NEW"
            }
        })
    };
    let tampered = serde_json::json!({
        "version": 1,
        "tasks": {
            "outside-id": make_entry(outside_file.to_string_lossy().into_owned()),
            "empty-out-path": make_entry(String::new()),
            "dot-out-path": make_entry(".".to_string()),
            "base-dir-out-path": make_entry(base_dir.to_string_lossy().into_owned())
        }
    });
    std::fs::write(
        config_dir.join("tasks.json"),
        serde_json::to_string(&tampered).unwrap(),
    )
    .unwrap();

    let mgr_tampered = TaskManager::with_worker(cfg, Arc::new(|_, _, _| Ok(())));
    let loaded = mgr_tampered.list_tasks();
    assert!(loaded.contains_key("outside-id"));
    assert!(loaded.contains_key("empty-out-path"));
    assert!(loaded.contains_key("dot-out-path"));
    assert!(loaded.contains_key("base-dir-out-path"));

    let _ = mgr_tampered.delete_task_files("outside-id").unwrap();
    let _ = mgr_tampered.delete_task_files("empty-out-path").unwrap();
    let _ = mgr_tampered.delete_task_files("dot-out-path").unwrap();
    let _ = mgr_tampered.delete_task_files("base-dir-out-path").unwrap();

    assert!(outside_file.exists());
    assert!(base_dir.exists());
    assert!(inside_sentinel.exists());
}

#[tokio::test]
async fn clear_completed_endpoint_removes_only_succeeded_tasks_keeps_files_and_persists() {
    use gofile_dl::downloader::ProgressHooks;
    use gofile_dl::error::GoFileError;
    use gofile_dl::tasks::StartTaskRequest;
    use std::collections::VecDeque;
    use std::sync::{mpsc, Mutex};

    type StepFn = Box<
        dyn FnOnce(
                StartTaskRequest,
                Arc<AppConfig>,
                Arc<dyn ProgressHooks>,
            ) -> Result<(), GoFileError>
            + Send,
    >;

    let tmp = tempdir().unwrap();
    let base_dir = tmp.path().join("data");
    let config_dir = tmp.path().join("config");
    std::fs::create_dir_all(&base_dir).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();

    let (active_started_tx, active_started_rx) = mpsc::channel::<()>();
    let (active_release_tx, active_release_rx) = mpsc::channel::<()>();

    let steps: Arc<Mutex<VecDeque<StepFn>>> = Arc::new(Mutex::new(VecDeque::from([
        Box::new(
            move |_req: StartTaskRequest, cfg: Arc<AppConfig>, hooks: Arc<dyn ProgressHooks>| {
                hooks.on_name("CleanDone");
                let dir = cfg.base_dir.join("CleanDone");
                std::fs::create_dir_all(&dir)?;
                let fpath = dir.join("file.bin");
                std::fs::write(&fpath, b"downloaded-content")?;
                hooks.on_file_progress(&fpath, 100, Some(18), None);
                hooks.on_overall_progress(100, "CleanDone");
                Ok(())
            },
        ) as StepFn,
        Box::new(
            move |_req: StartTaskRequest, cfg: Arc<AppConfig>, hooks: Arc<dyn ProgressHooks>| {
                hooks.on_name("PartialDone");
                let ok_path = cfg.base_dir.join("PartialDone").join("ok.bin");
                let fail_path = cfg.base_dir.join("PartialDone").join("bad.bin");
                hooks.on_file_progress(&ok_path, 100, Some(10), None);
                hooks.on_file_progress(&fail_path, -2, Some(10), None);
                hooks.on_overall_progress(100, "PartialDone");
                Ok(())
            },
        ) as StepFn,
        Box::new(
            move |_req: StartTaskRequest, _cfg: Arc<AppConfig>, hooks: Arc<dyn ProgressHooks>| {
                hooks.on_name("FailedTask");
                Err(GoFileError::Download {
                    message: "boom".to_string(),
                    filename: "a.bin".to_string(),
                    url: "https://gofile.io/d/fail03".to_string(),
                })
            },
        ) as StepFn,
        Box::new(
            move |_req: StartTaskRequest, _cfg: Arc<AppConfig>, hooks: Arc<dyn ProgressHooks>| {
                hooks.on_name("RunningTask");
                active_started_tx.send(()).unwrap();
                let _ = active_release_rx.recv();
                Ok(())
            },
        ) as StepFn,
    ])));

    let worker: TaskWorkerFn = Arc::new(move |req, cfg, hooks| {
        let step = steps.lock().unwrap().pop_front().unwrap();
        step(req, cfg, hooks)
    });

    let cfg = Arc::new(AppConfig {
        base_dir: base_dir.clone(),
        config_dir: Some(config_dir.clone()),
        secret_key: "clear-completed-secret".to_string(),
        ..AppConfig::default()
    });
    let tasks = TaskManager::with_worker(Arc::clone(&cfg), worker);
    let app = build_router(WebAppState {
        config: Arc::clone(&cfg),
        tasks: tasks.clone(),
        template_path: None,
        app_version: "0.1.0-test".to_string(),
    });
    let csrf = generate_csrf_token(&cfg.secret_key);

    // Embedded WebUI includes Clear Completed button & endpoint wiring.
    let res_idx = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let html = String::from_utf8(
        res_idx
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("id=\"clear-completed-btn\""));
    assert!(html.contains("/tasks/clear-completed"));

    // Start 4 tasks: clean completed, partially-failed completed, error, and active running.
    let tid_ok = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/start")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header("X-CSRFToken", &csrf)
                    .body(Body::from("url=https%3A%2F%2Fgofile.io%2Fd%2Fok01"))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await["task_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(tasks.wait_for_task(&tid_ok, Duration::from_secs(5)));

    let tid_partial = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/start")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header("X-CSRFToken", &csrf)
                    .body(Body::from("url=https%3A%2F%2Fgofile.io%2Fd%2Fpartial02"))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await["task_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(tasks.wait_for_task(&tid_partial, Duration::from_secs(5)));

    let tid_fail = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/start")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header("X-CSRFToken", &csrf)
                    .body(Body::from("url=https%3A%2F%2Fgofile.io%2Fd%2Ffail03"))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await["task_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(tasks.wait_for_task(&tid_fail, Duration::from_secs(5)));

    let tid_active = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/start")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header("X-CSRFToken", &csrf)
                    .body(Body::from("url=https%3A%2F%2Fgofile.io%2Fd%2Factive04"))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await["task_id"]
        .as_str()
        .unwrap()
        .to_string();
    active_started_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap();

    // Missing CSRF token returns 400.
    let res_no_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tasks/clear-completed")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_no_csrf.status(), StatusCode::BAD_REQUEST);

    // Clear completed removes only tid_ok (keeps partial, error, active, and downloaded files).
    let res_clear = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tasks/clear-completed")
                .header("X-CSRFToken", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_clear.status(), StatusCode::OK);
    let clear_json = read_json(res_clear).await;
    assert_eq!(clear_json["removed"], 1);
    assert_eq!(clear_json["message"], "Cleared 1 completed task.");

    // Second clear reports 0 removed.
    let res_clear_again = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/tasks/clear-completed")
                .header("X-CSRFToken", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_clear_again.status(), StatusCode::OK);
    let clear_again_json = read_json(res_clear_again).await;
    assert_eq!(clear_again_json["removed"], 0);
    assert_eq!(clear_again_json["message"], "Cleared 0 completed tasks.");

    let remaining = read_json(
        app.oneshot(
            Request::builder()
                .uri("/tasks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap(),
    )
    .await;
    let remaining_obj = remaining.as_object().unwrap();
    assert!(!remaining_obj.contains_key(&tid_ok));
    assert!(remaining_obj.contains_key(&tid_partial));
    assert!(remaining_obj.contains_key(&tid_fail));
    assert!(remaining_obj.contains_key(&tid_active));
    assert!(base_dir.join("CleanDone").join("file.bin").exists());

    // Finish active task and verify cleared state persists across restart.
    active_release_tx.send(()).unwrap();
    assert!(tasks.wait_for_task(&tid_active, Duration::from_secs(5)));

    let restarted = TaskManager::with_worker(cfg, Arc::new(|_, _, _| Ok(())));
    let persisted_map = restarted.list_tasks();
    assert!(!persisted_map.contains_key(&tid_ok));
    assert!(persisted_map.contains_key(&tid_partial));
    assert!(persisted_map.contains_key(&tid_fail));
    assert_eq!(persisted_map[&tid_active].status, "completed");
}
