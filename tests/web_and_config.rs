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
        tasks,
        template_path: None,
        app_version: "1.8.3-test".to_string(),
    };
    (build_router(state), cfg_arc)
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
        "1.8.3"
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
    assert_eq!(h_json["application"]["version"], "1.8.3-test");
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
    let tmp = tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("alpha")).unwrap();
    std::fs::create_dir_all(tmp.path().join("beta")).unwrap();

    let worker: TaskWorkerFn = Arc::new(|req, cfg, hooks| {
        hooks.on_name("dl_folder");
        let target_dir = cfg.base_dir.join("dl_folder");
        std::fs::create_dir_all(&target_dir)?;
        let fpath = target_dir.join("sample.bin");
        std::fs::write(&fpath, b"12345678")?;
        hooks.on_file_progress(&fpath, 50, Some(8), None);
        if req.url.contains("xyz987") {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !hooks.is_cancelled() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            if hooks.is_cancelled() {
                return Err(gofile_dl::error::GoFileError::Cancelled);
            }
        }
        while hooks.is_paused() && !hooks.is_cancelled() {
            std::thread::sleep(Duration::from_millis(10));
        }
        hooks.on_overall_progress(100, "dl_folder");
        Ok(())
    });

    let (app, cfg) = build_test_app(tmp.path(), false, worker);
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

    tokio::time::sleep(Duration::from_millis(40)).await;

    // 4. Check `/progress/{id}` and `/tasks`
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

    let env_ok = HashMap::from([("TASK_EXPIRY".to_string(), "1".to_string())]);
    cfg.apply_env_map(&env_ok).unwrap();
    assert_eq!(cfg.task_expiry, 1);

    let env_bad = HashMap::from([("TASK_EXPIRY".to_string(), "not_a_u64".to_string())]);
    assert!(cfg.apply_env_map(&env_bad).is_err());

    let tmp = tempdir().unwrap();
    cfg.base_dir = tmp.path().to_path_buf();
    let mgr = TaskManager::with_worker(
        Arc::new(cfg),
        Arc::new(|_req, _cfg, hooks| {
            hooks.on_name("QuickTask");
            Ok(())
        }),
    );

    let tid = mgr.start_task(gofile_dl::tasks::StartTaskRequest {
        url: "https://gofile.io/d/AbCdEf".to_string(),
        directory: None,
        password: None,
        throttle_kbps: None,
        retries: 1,
        strip_emojis: false,
        incremental: false,
        folder_pattern: "NEW|HOT".to_string(),
        premium_token: None,
    });

    std::thread::sleep(Duration::from_millis(50));
    assert!(mgr.list_tasks().contains_key(&tid));

    // Wait past `task_expiry = 1`s and verify terminal task is automatically pruned.
    std::thread::sleep(Duration::from_millis(1050));
    mgr.prune_expired_tasks();
    assert!(!mgr.list_tasks().contains_key(&tid));
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

    for sample in [
        "CON.mkv . ",
        "  CON.mkv . ",
        "COM\u{00b9}.zip",
        "LPT\u{00b3}.tar",
        "CLOCK$.bin",
        "🔥 Episode <01>:Pilot?.mkv",
        "...",
    ] {
        strip_emojis_into(sample, &mut stripped);
        assert_eq!(stripped, strip_emojis(sample));
        sanitize_filename_into(&stripped, &mut filtered, &mut out);
        assert_eq!(out, sanitize_filename(&stripped));
    }

    let norm = FolderNormalizer::new(Some("🔥HOT |⭐NEW FILES in "));
    let folder_in = "🔥HOT ⭐ NEW FILES in Series_S01 ";
    assert_eq!(norm.normalize_slice(folder_in), "Series_S01");
    assert_eq!(norm.normalize_slice(folder_in), norm.normalize(folder_in));
}
