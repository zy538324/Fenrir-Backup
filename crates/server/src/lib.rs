//! fenrir-server: management server for Fenrir-Backup.
//!
//! Serves the web UI and its JSON API, the agent API, and per-platform
//! agent installers. State lives in one SQLite database. The server never
//! holds repository keys: secrets reach agents sealed by the browser.

pub mod agent_api;
pub mod anomaly;
pub mod auth;
pub mod db;
pub mod downloads;
pub mod extras;
pub mod gateway;
pub mod notify;
pub mod schedule;
pub mod selfservice;
pub mod tls;
pub mod ui_api;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::Connection;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
pub struct TlsInfo {
    /// SHA-256 of the certificate DER, hex. Agents pin this.
    pub cert_sha256: String,
    /// SHA-256 of the SubjectPublicKeyInfo, base64 (curl --pinnedpubkey).
    pub spki_sha256_b64: String,
    /// True for the server's own self-signed certificate: installers pin it.
    pub pinned: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// URL agents use to reach the server. If unset, derived from the
    /// request that generates an installer.
    pub public_url: Option<String>,
    pub agents_dir: PathBuf,
    pub ui_dir: Option<PathBuf>,
    pub tls: Option<TlsInfo>,
    pub poll_seconds: u32,
    /// Encrypted file downloads waiting for the browser (kept 24 hours).
    pub downloads_dir: PathBuf,
}

pub struct AppState {
    pub db: Mutex<Connection>,
    pub cfg: Config,
    pub login_failures: Mutex<HashMap<String, (u32, Instant)>>,
    /// NAS gateway relay (in memory).
    pub relay: gateway::Relay,
}

pub type Shared = Arc<AppState>;

impl AppState {
    pub fn new(conn: Connection, cfg: Config) -> anyhow::Result<Shared> {
        db::migrate(&conn)?;
        Ok(Arc::new(AppState {
            db: Mutex::new(conn),
            cfg,
            login_failures: Mutex::new(HashMap::new()),
            relay: gateway::Relay::default(),
        }))
    }

    pub fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// JSON error response.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, m: impl Into<String>) -> Self {
        ApiError {
            status,
            message: m.into(),
        }
    }
    pub fn bad(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, m)
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, m)
    }
    pub fn internal(m: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, m)
    }
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "not signed in")
    }
    pub fn forbidden(m: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, m)
    }
    pub fn conflict(m: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, m)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            tracing::error!(error = %self.message, "request failed");
        }
        (
            self.status,
            Json(protocol::ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        match e {
            rusqlite::Error::QueryReturnedNoRows => ApiError::not_found("not found"),
            e => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("database: {e}")),
        }
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("json: {e}"))
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 32 random bytes as URL-safe base64 (no padding).
pub fn random_token() -> String {
    use base64::Engine;
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS random source");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub fn sha256_hex(s: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s))
}

pub fn router(state: Shared) -> Router {
    let api = ui_api::routes()
        .merge(agent_api::routes())
        .merge(extras::routes())
        .merge(selfservice::routes())
        .merge(gateway::routes())
        .merge(downloads::routes());
    let mut app = Router::new()
        .merge(api)
        .route("/healthz", get(|| async { "ok" }));

    app = match &state.cfg.ui_dir {
        Some(dir) if dir.join("index.html").is_file() => {
            app.fallback_service(ServeDir::new(dir).fallback(ServeFile::new(dir.join("index.html"))))
        }
        _ => app.fallback(get(|| async {
            (
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                "<!doctype html><title>Fenrir-Backup</title><p>The web UI is not built. Run <code>npm run build</code> in <code>ui/</code> and start the server with <code>--ui-dir ui/dist</code>.",
            )
        })),
    };

    app.layer(SetResponseHeaderLayer::overriding(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    ))
    .layer(SetResponseHeaderLayer::overriding(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
    .layer(SetResponseHeaderLayer::overriding(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")))
    .layer(SetResponseHeaderLayer::overriding(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")))
    .with_state(state)
}
