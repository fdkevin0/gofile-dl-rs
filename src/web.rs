//! `axum` HTTP web application router implementing the GoFile Downloader dashboard
//! and REST endpoints (`/`, `/health`, `/tasks`, `/start`, `/progress/{id}`,
//! `/pause/{id}`, `/cancel/{id}`, `/remove/{id}`, `/delete/{id}`, `/browse`).
//!
//! Fixes the legacy `POST /` -> `302 /start` -> `405 Method Not Allowed` bug (`app.py:556`),
//! supports both `multipart/form-data` (browser `FormData`) and URL-encoded forms, and
//! rotates `X-CSRF-Token` on `GET /tasks` so long-lived dashboard tabs never expire mid-session.

use crate::config::AppConfig;
use crate::sanitize::DEFAULT_FOLDER_PATTERNS;
use crate::security::{
    build_health_response, generate_csrf_token, parse_urlencoded_fields, render_index_html,
    verify_basic_auth, verify_csrf_token,
};
use crate::tasks::{
    browse_confined_directory, resolve_confined_output_dir, StartTaskRequest, TaskManager,
};
use axum::body::Bytes;
use axum::extract::{FromRequest, Multipart, Path as AxumPath, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Shared state injected into every `axum` route handler.
#[derive(Clone)]
pub struct WebAppState {
    /// Application server configuration.
    pub config: Arc<AppConfig>,
    /// Thread-safe background download task manager.
    pub tasks: TaskManager,
    /// Optional path to `templates/index.html` on disk.
    pub template_path: Option<PathBuf>,
    /// Application version string reported by `/health`.
    pub app_version: String,
}

/// Builds the complete `axum::Router` with Basic Auth and CSRF middleware on protected routes.
pub fn build_router(state: WebAppState) -> Router {
    let protected = Router::new()
        .route("/", get(handle_index_get).post(handle_start))
        .route("/tasks", get(handle_tasks))
        .route("/browse", get(handle_browse))
        .route("/start", post(handle_start))
        .route("/progress/{task_id}", get(handle_progress))
        .route("/pause/{task_id}", post(handle_pause))
        .route("/cancel/{task_id}", post(handle_cancel))
        .route("/remove/{task_id}", post(handle_remove))
        .route("/delete/{task_id}", post(handle_delete))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_and_csrf_middleware,
        ));

    Router::new()
        .route("/health", get(handle_health))
        .merge(protected)
        .with_state(state)
}

/// Middleware enforcing HTTP Basic Authentication on all protected routes and HMAC CSRF
/// header verification on mutating routes (`/pause`, `/cancel`, `/remove`, `/delete`).
///
/// Form-bearing endpoints (`POST /` and `POST /start`) perform CSRF validation inside
/// [`handle_start`] so both `X-CSRFToken` headers and `csrf_token` form fields are accepted.
async fn auth_and_csrf_middleware(
    State(state): State<WebAppState>,
    req: Request,
    next: Next,
) -> Response {
    let auth_hdr = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if !verify_basic_auth(auth_hdr, &state.config.auth) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"gofile-dl\"")],
            "Authentication required\n",
        )
            .into_response();
    }

    let is_mutating = matches!(
        *req.method(),
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );
    let path = req.uri().path();
    let requires_header_csrf =
        is_mutating && state.config.csrf.enabled && path != "/start" && path != "/";
    if requires_header_csrf {
        let hdr_tok = extract_csrf_header(req.headers()).unwrap_or("");
        if !verify_csrf_token(hdr_tok, &state.config.secret_key, &state.config.csrf) {
            return csrf_error_response();
        }
    }

    next.run(req).await
}

/// Builds the standard `400 Bad Request` JSON response for rejected CSRF tokens.
fn csrf_error_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "Invalid or missing CSRF token"})),
    )
        .into_response()
}

/// Extracts `X-CSRFToken` or `X-CSRF-Token` from incoming HTTP request headers.
fn extract_csrf_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("X-CSRFToken")
        .or_else(|| headers.get("X-CSRF-Token"))
        .and_then(|v| v.to_str().ok())
}

/// `GET /health`: unauthenticated container readiness probe returning disk space and active task count.
async fn handle_health(State(state): State<WebAppState>) -> impl IntoResponse {
    let active = state.tasks.active_count();
    let payload = build_health_response(&state.config.base_dir, active, &state.app_version);
    Json(payload)
}

/// `GET /`: renders the dashboard HTML injected with a fresh HMAC-SHA256 CSRF token.
async fn handle_index_get(State(state): State<WebAppState>) -> impl IntoResponse {
    let _ = std::fs::create_dir_all(&state.config.base_dir);
    let csrf = generate_csrf_token(&state.config.secret_key);
    let html = render_index_html(state.template_path.as_deref(), &csrf);
    Html(html)
}

/// `GET /tasks`: returns active and historical task snapshots (pruning expired terminal tasks)
/// and rotates `X-CSRF-Token` so long-lived dashboard sessions never hit token TTL expiry.
async fn handle_tasks(State(state): State<WebAppState>) -> Response {
    let mut headers = HeaderMap::new();
    if state.config.csrf.enabled {
        let fresh = generate_csrf_token(&state.config.secret_key);
        if let Ok(val) = HeaderValue::from_str(&fresh) {
            headers.insert("X-CSRF-Token", val);
        }
    }
    (headers, Json(state.tasks.list_tasks())).into_response()
}

#[derive(Debug, Deserialize)]
struct BrowseQuery {
    #[serde(default)]
    path: String,
}

async fn handle_browse(
    State(state): State<WebAppState>,
    Query(query): Query<BrowseQuery>,
) -> Response {
    match browse_confined_directory(&state.config.base_dir, &query.path) {
        Ok((base, current, dirs)) => Json(json!({
            "directories": dirs,
            "current": current.display().to_string(),
            "base": base.display().to_string(),
            "at_base": current == base,
        }))
        .into_response(),
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid path"})),
        )
            .into_response(),
    }
}

async fn handle_start(
    State(state): State<WebAppState>,
    headers: HeaderMap,
    req: Request,
) -> Response {
    let fields = match decode_form_fields(&state, &headers, req).await {
        Ok(f) => f,
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response();
        }
    };

    if state.config.csrf.enabled {
        let token = extract_csrf_header(&headers)
            .map(str::to_owned)
            .or_else(|| fields.get("csrf_token").cloned())
            .unwrap_or_default();
        if !verify_csrf_token(&token, &state.config.secret_key, &state.config.csrf) {
            return csrf_error_response();
        }
    }

    let url = fields
        .get("url")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if url.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "URL is required"})),
        )
            .into_response();
    }

    let raw_directory = fields
        .get("directory")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let Ok(resolved_dir) =
        resolve_confined_output_dir(&state.config.base_dir, raw_directory.as_deref())
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid directory path"})),
        )
            .into_response();
    };

    let start_req = build_start_request(&state.config, &fields, url, resolved_dir);
    let task_id = state.tasks.start_task(start_req);
    (StatusCode::ACCEPTED, Json(json!({"task_id": task_id}))).into_response()
}

async fn decode_form_fields(
    state: &WebAppState,
    headers: &HeaderMap,
    req: Request,
) -> Result<HashMap<String, String>, &'static str> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    if content_type.starts_with("multipart/form-data") {
        let mp = Multipart::from_request(req, state)
            .await
            .map_err(|_| "Malformed multipart form")?;
        Ok(parse_multipart_fields(mp).await)
    } else {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|_| "Malformed request body")?;
        Ok(parse_urlencoded_fields(&bytes))
    }
}

fn build_start_request(
    cfg: &AppConfig,
    fields: &HashMap<String, String>,
    url: String,
    resolved_dir: PathBuf,
) -> StartTaskRequest {
    let throttle_kbps = fields
        .get("throttle")
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
        .or(cfg.default_throttle);

    let retries = fields
        .get("retries")
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map_or(cfg.default_retries, |r| r.min(10));

    let folder_pattern = fields
        .get("folder_pattern")
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| DEFAULT_FOLDER_PATTERNS.to_string());

    StartTaskRequest {
        url,
        directory: Some(resolved_dir.to_string_lossy().into_owned()),
        password: fields.get("password").cloned().filter(|s| !s.is_empty()),
        throttle_kbps,
        retries,
        strip_emojis: fields.get("strip_emojis").is_some_and(|v| v == "true"),
        incremental: fields.get("incremental").is_some_and(|v| v == "true"),
        folder_pattern,
        premium_token: fields
            .get("premium_token")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
    }
}

async fn parse_multipart_fields(mut mp: Multipart) -> HashMap<String, String> {
    let mut out = HashMap::new();
    while let Ok(Some(field)) = mp.next_field().await {
        let Some(name) = field.name().map(str::to_owned) else {
            continue;
        };
        if let Ok(val) = field.text().await {
            out.insert(name, val);
        }
    }
    out
}

async fn handle_progress(
    State(state): State<WebAppState>,
    AxumPath(task_id): AxumPath<String>,
) -> Response {
    match state.tasks.get_progress(&task_id) {
        Some(pct) => Json(json!({"task_id": task_id, "progress": pct})).into_response(),
        None => invalid_task_response(),
    }
}

async fn handle_pause(
    State(state): State<WebAppState>,
    AxumPath(task_id): AxumPath<String>,
) -> Response {
    match state.tasks.toggle_pause(&task_id) {
        Some((paused, status)) => Json(json!({
            "task_id": task_id,
            "paused": paused,
            "status": status,
        }))
        .into_response(),
        None => invalid_task_response(),
    }
}

async fn handle_cancel(
    State(state): State<WebAppState>,
    AxumPath(task_id): AxumPath<String>,
) -> Response {
    if state.tasks.cancel_task(&task_id) {
        Json(json!({"task_id": task_id, "status": "cancelled"})).into_response()
    } else {
        invalid_task_response()
    }
}

async fn handle_remove(
    State(state): State<WebAppState>,
    AxumPath(task_id): AxumPath<String>,
) -> Response {
    if state.tasks.remove_task(&task_id) {
        Json(json!({"message": format!("Task {task_id} removed.")})).into_response()
    } else {
        invalid_task_response()
    }
}

async fn handle_delete(
    State(state): State<WebAppState>,
    AxumPath(task_id): AxumPath<String>,
) -> Response {
    match state.tasks.delete_task_files(&task_id) {
        Ok(Some(msg)) => Json(json!({"message": msg})).into_response(),
        Ok(None) => invalid_task_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": err.to_string()})),
        )
            .into_response(),
    }
}

fn invalid_task_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": "Invalid task id"})),
    )
        .into_response()
}
