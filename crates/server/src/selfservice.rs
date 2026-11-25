//! Self-service restores: "restore" users (made by an administrator) see
//! only the backups of the machines they are given, browse them and download
//! files to their browser, encrypted for it as for administrators. They
//! cannot change anything else. Administrators manage the users here too.

use axum::extract::{Path, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::{self, Admin, SessionUser};
use crate::db::audit;
use crate::{now, ApiError, ApiResult, Shared};

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/{id}", delete(delete_user))
        .route("/api/self", get(me))
        .route("/api/self/images", get(my_images))
        .route("/api/self/images/{id}/browse", post(browse))
        .route("/api/self/images/{id}/download-files", post(download))
        .route("/api/self/jobs/{id}", get(job))
        .route("/api/self/jobs/{id}/download", get(job_download))
}

// ---------------------------------------------------------------- administrators

async fn list_users(State(st): State<Shared>, _a: Admin) -> ApiResult<Json<Vec<Value>>> {
    let db = st.db();
    let v = db
        .prepare("SELECT id, username, role, machines_json, created FROM users ORDER BY role, username")?
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "username": r.get::<_, String>(1)?, "role": r.get::<_, String>(2)?,
                "machines": r.get::<_, Option<String>>(3)?.and_then(|m| serde_json::from_str::<Value>(&m).ok()).unwrap_or(json!([])),
                "created": r.get::<_, i64>(4)?,
            }))
        })?
        .collect::<Result<_, _>>()?;
    Ok(Json(v))
}

#[derive(Deserialize)]
struct NewUser {
    username: String,
    password: String,
    /// The machines (agent IDs) whose backups the user may restore from.
    machines: Vec<String>,
}

/// A restore user: sees and downloads from the backups of `machines` only.
async fn create_user(
    State(st): State<Shared>,
    a: Admin,
    Json(u): Json<NewUser>,
) -> ApiResult<Json<Value>> {
    let name = u.username.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(ApiError::bad("choose a username (up to 64 characters)"));
    }
    if u.password.chars().count() < auth::MIN_PASSWORD {
        return Err(ApiError::bad(format!(
            "the password needs at least {} characters",
            auth::MIN_PASSWORD
        )));
    }
    let db = st.db();
    let mut machines = Vec::new();
    for m in &u.machines {
        let id = uuid::Uuid::parse_str(m)
            .map_err(|_| ApiError::bad("invalid machine id"))?
            .to_string();
        let ok: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM agents WHERE id = ?1 AND revoked = 0)",
            params![id],
            |r| r.get(0),
        )?;
        if !ok {
            return Err(ApiError::bad("no such machine"));
        }
        machines.push(id);
    }
    if machines.is_empty() {
        return Err(ApiError::bad(
            "choose the machines whose backups the user may restore from",
        ));
    }
    let hash = auth::hash_password(&u.password)?;
    db.execute(
        "INSERT INTO users (username, password_hash, created, role, machines_json) VALUES (?1, ?2, ?3, 'restore', ?4)",
        params![name, hash, now(), serde_json::to_string(&machines)?],
    )
    .map_err(|_| ApiError::conflict("that username is taken"))?;
    audit(
        &db,
        &a.username,
        "user.created",
        &format!("{name} (restore: {} machines)", machines.len()),
    );
    Ok(Json(json!({ "id": db.last_insert_rowid() })))
}

async fn delete_user(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    if id == a.user_id {
        return Err(ApiError::bad("you cannot remove yourself"));
    }
    let db = st.db();
    let (name, role): (String, String) = db
        .query_row(
            "SELECT username, role FROM users WHERE id = ?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .ok_or_else(|| ApiError::not_found("no such user"))?;
    db.execute("DELETE FROM sessions WHERE user_id = ?1", params![id])?;
    db.execute("DELETE FROM users WHERE id = ?1", params![id])?;
    audit(
        &db,
        &a.username,
        "user.removed",
        &format!("{name} ({role})"),
    );
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------- restore users

/// The identity jobs are queued under, so a restore user sees only theirs.
fn actor(u: &SessionUser) -> String {
    format!("self:{}", u.username)
}

fn as_admin(u: &SessionUser) -> Admin {
    Admin {
        user_id: u.user_id,
        username: actor(u),
    }
}

/// The image, if it is one of the user's machines' disk or folder backups.
fn allowed_image(st: &Shared, u: &SessionUser, image: &str) -> ApiResult<()> {
    if u.role == "admin" {
        return Ok(());
    }
    let agent: Option<Option<String>> = st
        .db()
        .query_row(
            "SELECT agent_id FROM images WHERE image_id = ?1",
            params![image],
            |r| r.get(0),
        )
        .optional()?;
    match agent.flatten() {
        Some(a) if u.machines.contains(&a) => Ok(()),
        _ => Err(ApiError::not_found("no such backup")),
    }
}

async fn me(State(st): State<Shared>, u: SessionUser) -> ApiResult<Json<Value>> {
    let db = st.db();
    let mut machines = Vec::new();
    for m in &u.machines {
        if let Some(n) = db
            .query_row(
                "SELECT COALESCE(display_name, hostname) FROM agents WHERE id = ?1",
                params![m],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            machines.push(json!({ "id": m, "name": n }));
        }
    }
    Ok(Json(
        json!({ "username": u.username, "role": u.role, "machines": machines }),
    ))
}

async fn my_images(State(st): State<Shared>, u: SessionUser) -> ApiResult<Json<Vec<Value>>> {
    let db = st.db();
    let mut out = Vec::new();
    for m in &u.machines {
        let rows: Vec<Value> = db
            .prepare(
                "SELECT i.image_id, i.created, i.machine_id, COALESCE(i.vm_name, i.hostname), i.label, i.captured_bytes
                 FROM images i WHERE i.agent_id = ?1
                   AND i.machine_id NOT LIKE 'saas:%' AND i.machine_id NOT LIKE 'k8s:%' AND i.machine_id NOT LIKE 'cdp:%'
                 ORDER BY i.created DESC LIMIT 200",
            )?
            .query_map(params![m], |r| {
                Ok(json!({
                    "image_id": r.get::<_, String>(0)?, "created": r.get::<_, i64>(1)?,
                    "source": if r.get::<_, String>(2)?.starts_with("files:") { "files" } else { "disks" },
                    "name": r.get::<_, String>(3)?, "label": r.get::<_, Option<String>>(4)?, "bytes": r.get::<_, i64>(5)?,
                    "agent_id": m,
                }))
            })?
            .collect::<Result<_, _>>()?;
        out.extend(rows);
    }
    Ok(Json(out))
}

async fn browse(
    State(st): State<Shared>,
    u: SessionUser,
    Path(id): Path<String>,
    Json(b): Json<Value>,
) -> ApiResult<Json<Value>> {
    allowed_image(&st, &u, &id)?;
    let mut b = b;
    // The machine that reads the backup is chosen by the server, not the user.
    b["agent_id"] = Value::Null;
    let r: crate::ui_api::BrowseReq =
        serde_json::from_value(b).map_err(|e| ApiError::bad(e.to_string()))?;
    crate::ui_api::browse_files(State(st), as_admin(&u), Path(id), Json(r)).await
}

async fn download(
    State(st): State<Shared>,
    u: SessionUser,
    Path(id): Path<String>,
    Json(b): Json<Value>,
) -> ApiResult<Json<Value>> {
    allowed_image(&st, &u, &id)?;
    let mut b = b;
    b["agent_id"] = Value::Null;
    let r: crate::ui_api::DownloadFilesReq =
        serde_json::from_value(b).map_err(|e| ApiError::bad(e.to_string()))?;
    crate::ui_api::download_files(State(st), as_admin(&u), Path(id), Json(r)).await
}

/// A job the user started (admins: any).
fn own_job(st: &Shared, u: &SessionUser, id: &str) -> ApiResult<()> {
    if u.role == "admin" {
        return Ok(());
    }
    let by: Option<String> = st
        .db()
        .query_row(
            "SELECT requested_by FROM jobs WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    if by.as_deref() == Some(actor(u).as_str()) {
        Ok(())
    } else {
        Err(ApiError::not_found("no such job"))
    }
}

async fn job(
    State(st): State<Shared>,
    u: SessionUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    own_job(&st, &u, &id)?;
    crate::ui_api::get_job(State(st), as_admin(&u), Path(id)).await
}

async fn job_download(
    State(st): State<Shared>,
    u: SessionUser,
    Path(id): Path<String>,
) -> ApiResult<axum::response::Response> {
    own_job(&st, &u, &id)?;
    crate::ui_api::get_download(State(st), as_admin(&u), Path(id)).await
}
