//! Administrator sessions and agent bearer tokens.

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, Method};
use rusqlite::{params, OptionalExtension};

use crate::{now, sha256_hex, ApiError, Shared};

pub const SESSION_COOKIE: &str = "fenrir_session";
pub const SESSION_IDLE_SECS: i64 = 12 * 3600;
pub const CSRF_HEADER: &str = "x-fenrir-csrf";
pub const MIN_PASSWORD: usize = 10;

pub fn hash_password(pw: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| {
            ApiError::new(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("hashing: {e}"),
            )
        })
}

/// A real Argon2 hash of a random password, so failed logins for unknown
/// users cost the same as for known ones.
pub fn dummy_hash() -> &'static str {
    static H: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    H.get_or_init(|| hash_password(&crate::random_token()).unwrap_or_default())
}

pub fn verify_password(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

/// Create a session; returns the Set-Cookie header value.
pub fn new_session(state: &Shared, user_id: i64) -> Result<String, ApiError> {
    let token = crate::random_token();
    let t = now();
    state.db().execute(
        "INSERT INTO sessions (token_hash, user_id, created, last_seen) VALUES (?1, ?2, ?3, ?3)",
        params![sha256_hex(token.as_bytes()), user_id, t],
    )?;
    Ok(session_cookie(state, &token, SESSION_IDLE_SECS))
}

pub fn session_cookie(state: &Shared, value: &str, max_age: i64) -> String {
    let secure = if state.cfg.tls.is_some() {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{SESSION_COOKIE}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}"
    )
}

pub fn cookie_value(parts: &Parts, name: &str) -> Option<String> {
    parts
        .headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            (k == name).then(|| v.to_string())
        })
}

/// A signed-in administrator. Rejects state-changing requests that lack
/// the CSRF header (a cross-site form or image cannot set it).
#[derive(Debug, Clone)]
pub struct Admin {
    pub user_id: i64,
    pub username: String,
}

impl FromRequestParts<Shared> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Shared,
    ) -> Result<Self, Self::Rejection> {
        let token = cookie_value(parts, SESSION_COOKIE).ok_or_else(ApiError::unauthorized)?;
        if !matches!(parts.method, Method::GET | Method::HEAD)
            && parts.headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()) != Some("1")
        {
            return Err(ApiError::forbidden("missing CSRF header"));
        }
        let h = sha256_hex(token.as_bytes());
        let db = state.db();
        let row: Option<(i64, String, i64)> = db
            .query_row(
                "SELECT u.id, u.username, s.last_seen FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?1",
                params![h],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (user_id, username, last_seen) = row.ok_or_else(ApiError::unauthorized)?;
        let t = now();
        if t - last_seen > SESSION_IDLE_SECS {
            db.execute("DELETE FROM sessions WHERE token_hash = ?1", params![h])?;
            return Err(ApiError::unauthorized());
        }
        if t - last_seen > 60 {
            db.execute(
                "UPDATE sessions SET last_seen = ?1 WHERE token_hash = ?2",
                params![t, h],
            )?;
        }
        Ok(Admin { user_id, username })
    }
}

/// An enrolled, non-revoked agent authenticated by its bearer token.
#[derive(Debug, Clone)]
pub struct AgentAuth {
    pub agent_id: String,
    pub public_key: String,
}

impl FromRequestParts<Shared> for AgentAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Shared,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| {
                ApiError::new(axum::http::StatusCode::UNAUTHORIZED, "agent token required")
            })?;
        let row: Option<(String, String, i64)> = state
            .db()
            .query_row(
                "SELECT id, public_key, revoked FROM agents WHERE token_hash = ?1",
                params![sha256_hex(token.as_bytes())],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        match row {
            Some((agent_id, public_key, 0)) => Ok(AgentAuth {
                agent_id,
                public_key,
            }),
            Some(_) => Err(ApiError::forbidden(
                "this agent has been removed from the server",
            )),
            None => Err(ApiError::new(
                axum::http::StatusCode::UNAUTHORIZED,
                "unknown agent token",
            )),
        }
    }
}

/// Login throttling: 5 failures per username per 15 minutes.
pub fn login_allowed(state: &Shared, username: &str) -> bool {
    let mut m = state
        .login_failures
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let key = username.to_lowercase();
    match m.get(&key) {
        Some((n, since)) if since.elapsed().as_secs() < 900 => *n < 5,
        Some(_) => {
            m.remove(&key);
            true
        }
        None => true,
    }
}

pub fn record_login_failure(state: &Shared, username: &str) {
    let mut m = state
        .login_failures
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let e = m
        .entry(username.to_lowercase())
        .or_insert((0, std::time::Instant::now()));
    e.0 += 1;
}

pub fn clear_login_failures(state: &Shared, username: &str) {
    state
        .login_failures
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&username.to_lowercase());
}
