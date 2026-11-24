//! JSON API for the web UI. Every route except status, setup and login
//! requires a signed-in administrator.

use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use protocol::{AgentRole, Inventory, JobKind, JobProgress, OsSummary};
use rusqlite::{params, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::auth::{self, Admin};
use crate::db::audit;
use crate::schedule::Schedule;
use crate::{now, sha256_hex, ApiError, ApiResult, Shared};

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/status", get(status))
        .route("/api/setup", post(setup))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/overview", get(overview))
        .route("/api/agents", get(list_agents))
        .route(
            "/api/agents/{id}",
            get(get_agent).patch(rename_agent).delete(revoke_agent),
        )
        .route("/api/agents/{id}/jobs", post(create_job))
        .route("/api/jobs", get(list_jobs))
        .route("/api/jobs/{id}", get(get_job))
        .route("/api/jobs/{id}/cancel", post(cancel_job))
        .route(
            "/api/enrollment-tokens",
            get(list_tokens).post(create_token),
        )
        .route(
            "/api/enrollment-tokens/{id}",
            axum::routing::delete(revoke_token),
        )
        .route("/api/repositories", get(list_repos).post(create_repo))
        .route("/api/repositories/{id}", axum::routing::delete(forget_repo))
        .route("/api/repositories/{id}/access", post(grant_access))
        .route(
            "/api/repositories/{id}/access/{agent}",
            axum::routing::delete(revoke_access),
        )
        .route("/api/plans", get(list_plans).post(create_plan))
        .route(
            "/api/plans/{id}",
            axum::routing::patch(update_plan).delete(delete_plan),
        )
        .route("/api/plans/{id}/run", post(run_plan))
        .route("/api/images", get(list_images))
        .route("/api/audit", get(list_audit))
        .route("/api/repositories/{id}/hold", post(set_hold))
        .route("/api/repositories/{id}/maintenance", post(set_maintenance))
        .route("/api/repositories/{id}/prune", post(prune_now))
        .route("/api/repositories/{id}/copy", post(copy_now))
        .route("/api/restores", post(create_restore))
        .route("/api/images/{id}/boot-check", post(create_boot_check))
        .route("/api/images/{id}/boot-checks", get(list_boot_checks))
        .route("/api/boot-checks/{id}/screenshot.png", get(boot_screenshot))
        .route("/api/agents/{id}/vms/{session}/stop", post(stop_vm))
        .route(
            "/api/repositories/{id}/boot-verification",
            post(set_boot_verification),
        )
        .route("/api/repositories/{id}/share", post(set_share))
        .route("/api/agents/{id}/check-access", post(check_access))
        .route("/api/images/{id}/browse", post(browse_files))
        .route("/api/repositories/{id}/gateway", post(set_gateway))
        .route("/api/images/{id}/restore-files", post(restore_files))
        .route("/api/settings", get(get_settings).put(put_settings))
        .route("/api/export", get(export_config))
        .route("/api/settings/test-notification", post(test_notification))
        .route("/api/notifications", get(list_notifications))
}

fn uuid_param(s: &str) -> ApiResult<String> {
    Uuid::parse_str(s)
        .map(|u| u.to_string())
        .map_err(|_| ApiError::bad("invalid id"))
}

/// A repository's gateway: agent id, name, port, address, last seen.
type GatewayRow = (String, String, Option<i64>, Option<String>, Option<i64>);

// ---------- session ----------

async fn status(
    State(st): State<Shared>,
    parts: axum::http::request::Parts,
) -> ApiResult<Json<Value>> {
    let users: i64 = st
        .db()
        .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
    let mut p = parts;
    let user = Admin::from_request_parts_opt(&mut p, &st).await;
    Ok(Json(json!({
        "setup_required": users == 0,
        "version": crate::VERSION,
        "user": user.map(|u| json!({ "username": u.username })),
        "tls": st.cfg.tls.as_ref().map(|t| json!({ "pinned": t.pinned, "cert_sha256": t.cert_sha256 })),
        "server_time": now(),
    })))
}

impl Admin {
    async fn from_request_parts_opt(
        parts: &mut axum::http::request::Parts,
        st: &Shared,
    ) -> Option<Admin> {
        use axum::extract::FromRequestParts;
        Admin::from_request_parts(parts, st).await.ok()
    }
}

#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

async fn setup(
    State(st): State<Shared>,
    Json(c): Json<Credentials>,
) -> ApiResult<impl IntoResponse> {
    let username = c.username.trim().to_string();
    if username.is_empty() || username.len() > 64 {
        return Err(ApiError::bad("choose a username (up to 64 characters)"));
    }
    if c.password.chars().count() < auth::MIN_PASSWORD {
        return Err(ApiError::bad(format!(
            "the password needs at least {} characters",
            auth::MIN_PASSWORD
        )));
    }
    let hash = auth::hash_password(&c.password)?;
    let id = {
        let db = st.db();
        // Single statement: only succeeds while there are no users.
        let n = db.execute(
            "INSERT INTO users (username, password_hash, created) SELECT ?1, ?2, ?3 WHERE NOT EXISTS (SELECT 1 FROM users)",
            params![username, hash, now()],
        )?;
        if n == 0 {
            return Err(ApiError::conflict("setup has already been completed"));
        }
        audit(&db, &username, "setup.admin_created", "");
        db.last_insert_rowid()
    };
    let cookie = auth::new_session(&st, id)?;
    Ok((
        [(header::SET_COOKIE, cookie)],
        Json(json!({ "username": username })),
    ))
}

async fn login(
    State(st): State<Shared>,
    Json(c): Json<Credentials>,
) -> ApiResult<impl IntoResponse> {
    if !auth::login_allowed(&st, &c.username) {
        return Err(ApiError::new(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "too many failed attempts; try again in 15 minutes",
        ));
    }
    let row: Option<(i64, String, String)> = st
        .db()
        .query_row(
            "SELECT id, username, password_hash FROM users WHERE username = ?1",
            params![c.username.trim()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    // Verify against a dummy hash when the user is unknown so timing does
    // not reveal which usernames exist.
    let ok = match &row {
        Some((_, _, h)) => auth::verify_password(&c.password, h),
        None => {
            auth::verify_password(&c.password, auth::dummy_hash());
            false
        }
    };
    if !ok {
        auth::record_login_failure(&st, &c.username);
        audit(&st.db(), c.username.trim(), "login.failed", "");
        return Err(ApiError::new(
            axum::http::StatusCode::UNAUTHORIZED,
            "wrong username or password",
        ));
    }
    let (id, username, _) = row.expect("checked");
    auth::clear_login_failures(&st, &username);
    let cookie = auth::new_session(&st, id)?;
    audit(&st.db(), &username, "login", "");
    Ok((
        [(header::SET_COOKIE, cookie)],
        Json(json!({ "username": username })),
    ))
}

async fn logout(
    State(st): State<Shared>,
    parts: axum::http::request::Parts,
) -> ApiResult<impl IntoResponse> {
    if let Some(t) = auth::cookie_value(&parts, auth::SESSION_COOKIE) {
        st.db().execute(
            "DELETE FROM sessions WHERE token_hash = ?1",
            params![sha256_hex(t.as_bytes())],
        )?;
    }
    Ok((
        [(header::SET_COOKIE, auth::session_cookie(&st, "", 0))],
        Json(json!({ "ok": true })),
    ))
}

// ---------- agents ----------

#[derive(Serialize)]
pub struct AgentOut {
    id: String,
    name: String,
    hostname: String,
    role: String,
    os: OsSummary,
    agent_version: String,
    enrolled: i64,
    last_seen: Option<i64>,
    online: bool,
    revoked: bool,
    public_key: String,
    capabilities: Vec<String>,
    vm_count: usize,
    last_backup: Option<Value>,
    running_job: Option<Value>,
}

fn online(st: &Shared, last_seen: Option<i64>) -> bool {
    last_seen.is_some_and(|l| now() - l <= st.cfg.poll_seconds as i64 * 3 + 15)
}

const AGENT_COLS: &str = "id, hostname, display_name, role, os_json, agent_version, enrolled, last_seen, revoked, public_key, inventory_json";

fn agent_from_row(st: &Shared, db: &rusqlite::Connection, r: &Row) -> rusqlite::Result<AgentOut> {
    let id: String = r.get(0)?;
    let hostname: String = r.get(1)?;
    let display: Option<String> = r.get(2)?;
    let inv: Option<Inventory> = r
        .get::<_, Option<String>>(10)?
        .and_then(|s| serde_json::from_str(&s).ok());
    let last_seen: Option<i64> = r.get(7)?;
    let last_backup = db
        .query_row(
            "SELECT id, state, finished, error FROM jobs WHERE agent_id = ?1 AND kind_json LIKE '{\"type\":\"backup%' AND finished IS NOT NULL ORDER BY finished DESC LIMIT 1",
            params![id],
            |r| Ok(json!({ "job_id": r.get::<_, String>(0)?, "state": r.get::<_, String>(1)?, "at": r.get::<_, i64>(2)?, "error": r.get::<_, Option<String>>(3)? })),
        )
        .optional()?;
    let running_job = db
        .query_row(
            "SELECT id, kind_json, state, progress_json FROM jobs WHERE agent_id = ?1 AND state IN ('dispatched','running') LIMIT 1",
            params![id],
            |r| {
                let kind: Option<JobKind> = serde_json::from_str(&r.get::<_, String>(1)?).ok();
                let progress: Option<JobProgress> = r.get::<_, Option<String>>(3)?.and_then(|s| serde_json::from_str(&s).ok());
                Ok(json!({ "id": r.get::<_, String>(0)?, "label": kind.map(|k| k.label()), "state": r.get::<_, String>(2)?, "progress": progress }))
            },
        )
        .optional()?;
    Ok(AgentOut {
        name: display.unwrap_or_else(|| hostname.clone()),
        hostname,
        role: r.get(3)?,
        os: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or_default(),
        agent_version: r.get(5)?,
        enrolled: r.get(6)?,
        online: online(st, last_seen) && r.get::<_, i64>(8)? == 0,
        last_seen,
        revoked: r.get::<_, i64>(8)? != 0,
        public_key: r.get(9)?,
        capabilities: inv
            .as_ref()
            .map(|i| i.capabilities.clone())
            .unwrap_or_default(),
        vm_count: inv.as_ref().map(|i| i.vms.len()).unwrap_or(0),
        last_backup,
        running_job,
        id,
    })
}

fn all_agents(st: &Shared) -> ApiResult<Vec<AgentOut>> {
    let db = st.db();
    let mut stmt = db.prepare(&format!("SELECT {AGENT_COLS} FROM agents WHERE revoked = 0 ORDER BY lower(COALESCE(display_name, hostname))"))?;
    let rows = stmt
        .query_map([], |r| agent_from_row(st, &db, r))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

async fn list_agents(State(st): State<Shared>, _a: Admin) -> ApiResult<Json<Vec<AgentOut>>> {
    Ok(Json(all_agents(&st)?))
}

async fn get_agent(
    State(st): State<Shared>,
    _a: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    let agent = {
        let db = st.db();
        db.query_row(
            &format!("SELECT {AGENT_COLS} FROM agents WHERE id = ?1"),
            params![id],
            |r| agent_from_row(&st, &db, r),
        )?
    };
    let inventory: Option<Value> = st
        .db()
        .query_row(
            "SELECT inventory_json FROM agents WHERE id = ?1",
            params![id],
            |r| r.get::<_, Option<String>>(0),
        )?
        .and_then(|s| serde_json::from_str(&s).ok());
    let jobs = jobs_query(&st, Some(&id), 50)?;
    let images = images_query(&st, Some(&id), None)?;
    let plans = plans_query(&st, Some(&id))?;
    let repos: Vec<Value> = {
        let db = st.db();
        let mut s = db.prepare("SELECT r.id, r.name, r.status FROM repositories r JOIN repo_access a ON a.repository_id = r.id WHERE a.agent_id = ?1")?;
        let v = s
            .query_map(params![id], |r| Ok(json!({ "id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?, "status": r.get::<_, String>(2)? })))?
            .collect::<Result<_, _>>()?;
        v
    };
    Ok(Json(
        json!({ "agent": agent, "inventory": inventory, "jobs": jobs, "images": images, "plans": plans, "repositories": repos }),
    ))
}

#[derive(Deserialize)]
struct Rename {
    name: String,
}

async fn rename_agent(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(r): Json<Rename>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    let name = r.name.trim();
    let v = (!name.is_empty()).then_some(name.chars().take(80).collect::<String>());
    let db = st.db();
    if db.execute(
        "UPDATE agents SET display_name = ?1 WHERE id = ?2",
        params![v, id],
    )? == 0
    {
        return Err(ApiError::not_found("no such machine"));
    }
    audit(&db, &a.username, "agent.renamed", &format!("{id} {name}"));
    Ok(Json(json!({ "ok": true })))
}

async fn revoke_agent(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    let db = st.db();
    let t = now();
    db.execute("UPDATE agents SET revoked = 1 WHERE id = ?1", params![id])?;
    db.execute("DELETE FROM repo_access WHERE agent_id = ?1", params![id])?;
    db.execute(
        "UPDATE plans SET enabled = 0 WHERE agent_id = ?1",
        params![id],
    )?;
    db.execute(
        "UPDATE jobs SET state = 'cancelled', finished = ?1, error = 'machine removed' WHERE agent_id = ?2 AND state = 'queued'",
        params![t, id],
    )?;
    audit(&db, &a.username, "agent.removed", &id);
    Ok(Json(json!({ "ok": true })))
}

// ---------- jobs ----------

#[derive(Deserialize)]
struct NewJob {
    kind: JobKind,
    #[serde(default)]
    repository_id: Option<String>,
}

fn validate_job(
    st: &Shared,
    agent_id: &str,
    kind: &JobKind,
    repository_id: &Option<String>,
) -> ApiResult<()> {
    let db = st.db();
    let (role, inv): (String, Option<String>) = db.query_row(
        "SELECT role, inventory_json FROM agents WHERE id = ?1 AND revoked = 0",
        params![agent_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let caps: Vec<String> = inv
        .and_then(|s| serde_json::from_str::<Inventory>(&s).ok())
        .map(|i| i.capabilities)
        .unwrap_or_default();
    let need = match kind {
        JobKind::BackupSystem { .. } => Some("backup_system"),
        JobKind::BackupDisks { .. } => Some("backup_disks"),
        JobKind::BackupHyperv { .. } => Some("backup_hyperv"),
        JobKind::Verify { .. } => Some("verify"),
        _ => None,
    };
    if let Some(n) = need {
        if !caps.iter().any(|c| c == n) {
            return Err(ApiError::bad(format!(
                "this machine cannot run that job (it does not report {n}; role {role})"
            )));
        }
    }
    if let JobKind::Verify {
        level,
        sample_percent,
    } = kind
    {
        if !["quick", "sample", "full"].contains(&level.as_str())
            || sample_percent.is_some_and(|p| !(0.0..=100.0).contains(&p))
        {
            return Err(ApiError::bad("verify level must be quick, sample or full"));
        }
    }
    let needs_repo = !matches!(kind, JobKind::InitRepository);
    match repository_id {
        Some(rid) => {
            let ok: Option<String> = db
                .query_row(
                    "SELECT r.status FROM repositories r JOIN repo_access a ON a.repository_id = r.id WHERE r.id = ?1 AND a.agent_id = ?2",
                    params![rid, agent_id],
                    |r| r.get(0),
                )
                .optional()?;
            match ok.as_deref() {
                None => Err(ApiError::bad(
                    "this machine has no access to that repository",
                )),
                Some("ready") => Ok(()),
                Some(s) => Err(ApiError::bad(format!("the repository is not ready ({s})"))),
            }
        }
        None if needs_repo => Err(ApiError::bad("choose a repository")),
        None => Ok(()),
    }
}

pub fn insert_job(
    st: &Shared,
    agent_id: &str,
    kind: &JobKind,
    repository_id: Option<&str>,
    plan_id: Option<&str>,
    by: &str,
) -> ApiResult<String> {
    let id = Uuid::new_v4().to_string();
    st.db().execute(
        "INSERT INTO jobs (id, agent_id, repository_id, plan_id, kind_json, state, created, requested_by) VALUES (?1, ?2, ?3, ?4, ?5, 'queued', ?6, ?7)",
        params![id, agent_id, repository_id, plan_id, serde_json::to_string(kind)?, now(), by],
    )?;
    Ok(id)
}

async fn create_job(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(j): Json<NewJob>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    if !matches!(
        j.kind,
        JobKind::BackupSystem { .. }
            | JobKind::BackupDisks { .. }
            | JobKind::BackupHyperv { .. }
            | JobKind::Verify { .. }
            | JobKind::ListImages
    ) {
        return Err(ApiError::bad(
            "use the Repositories page (create, reclaim space) or the Restore dialog for that",
        ));
    }
    let repo = j.repository_id.as_deref().map(uuid_param).transpose()?;
    validate_job(&st, &id, &j.kind, &repo)?;
    let job_id = insert_job(&st, &id, &j.kind, repo.as_deref(), None, &a.username)?;
    audit(
        &st.db(),
        &a.username,
        "job.created",
        &format!("{} on {id}", j.kind.label()),
    );
    Ok(Json(json!({ "id": job_id })))
}

fn job_from_row(r: &Row) -> rusqlite::Result<Value> {
    let kind: Value = serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or(Value::Null);
    let label = serde_json::from_value::<JobKind>(kind.clone())
        .map(|k| k.label())
        .unwrap_or("Job");
    let parse = |s: Option<String>| s.and_then(|s| serde_json::from_str::<Value>(&s).ok());
    Ok(json!({
        "id": r.get::<_, String>(0)?,
        "agent_id": r.get::<_, String>(1)?,
        "agent_name": r.get::<_, String>(2)?,
        "repository_id": r.get::<_, Option<String>>(3)?,
        "kind": kind,
        "label": label,
        "state": r.get::<_, String>(5)?,
        "created": r.get::<_, i64>(6)?,
        "started": r.get::<_, Option<i64>>(7)?,
        "finished": r.get::<_, Option<i64>>(8)?,
        "progress": parse(r.get(9)?),
        "result": parse(r.get(10)?),
        "error": r.get::<_, Option<String>>(11)?,
        "warnings": parse(r.get(12)?).unwrap_or(json!([])),
        "requested_by": r.get::<_, Option<String>>(13)?,
        "plan_id": r.get::<_, Option<String>>(14)?,
        "repository_name": r.get::<_, Option<String>>(15)?,
    }))
}

const JOB_SELECT: &str = "SELECT j.id, j.agent_id, COALESCE(a.display_name, a.hostname), j.repository_id, j.kind_json, j.state, j.created, j.started, j.finished,
    j.progress_json, j.result_json, j.error, j.warnings_json, j.requested_by, j.plan_id, r.name
    FROM jobs j JOIN agents a ON a.id = j.agent_id LEFT JOIN repositories r ON r.id = j.repository_id";

fn jobs_query(st: &Shared, agent: Option<&str>, limit: i64) -> ApiResult<Vec<Value>> {
    let db = st.db();
    let (sql, p): (String, Vec<Box<dyn rusqlite::ToSql>>) = match agent {
        Some(a) => (
            format!("{JOB_SELECT} WHERE j.agent_id = ?1 ORDER BY j.created DESC LIMIT ?2"),
            vec![Box::new(a.to_string()), Box::new(limit)],
        ),
        None => (
            format!("{JOB_SELECT} ORDER BY j.created DESC LIMIT ?1"),
            vec![Box::new(limit)],
        ),
    };
    let mut s = db.prepare(&sql)?;
    let v = s
        .query_map(rusqlite::params_from_iter(p.iter()), job_from_row)?
        .collect::<Result<_, _>>()?;
    Ok(v)
}

#[derive(Deserialize)]
struct JobQuery {
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

async fn list_jobs(
    State(st): State<Shared>,
    _a: Admin,
    Query(q): Query<JobQuery>,
) -> ApiResult<Json<Vec<Value>>> {
    let agent = q.agent_id.as_deref().map(uuid_param).transpose()?;
    Ok(Json(jobs_query(
        &st,
        agent.as_deref(),
        q.limit.unwrap_or(100).clamp(1, 1000),
    )?))
}

async fn get_job(
    State(st): State<Shared>,
    _a: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    Ok(Json(st.db().query_row(
        &format!("{JOB_SELECT} WHERE j.id = ?1"),
        params![id],
        job_from_row,
    )?))
}

async fn cancel_job(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    let db = st.db();
    let n = db.execute(
        "UPDATE jobs SET state = 'cancelled', finished = ?1, error = 'cancelled before it started' WHERE id = ?2 AND state = 'queued'",
        params![now(), id],
    )?;
    if n == 0 {
        db.execute("UPDATE jobs SET cancel_requested = 1 WHERE id = ?1 AND state IN ('dispatched','running')", params![id])?;
    }
    audit(&db, &a.username, "job.cancel", &id);
    Ok(Json(json!({ "ok": true })))
}

// ---------- enrollment tokens ----------

#[derive(Deserialize)]
struct NewToken {
    #[serde(default)]
    label: String,
    #[serde(default = "default_role")]
    role: String,
    #[serde(default = "default_days")]
    expires_days: u32,
}
fn default_role() -> String {
    "server".into()
}
fn default_days() -> u32 {
    7
}

async fn create_token(
    State(st): State<Shared>,
    a: Admin,
    Json(n): Json<NewToken>,
) -> ApiResult<Json<Value>> {
    let role = AgentRole::parse(&n.role)
        .ok_or_else(|| ApiError::bad("role must be workstation, server, hyperv or recovery"))?;
    if !(1..=90).contains(&n.expires_days) {
        return Err(ApiError::bad("expiry must be 1 to 90 days"));
    }
    let token = crate::random_token();
    let id = Uuid::new_v4().to_string();
    let t = now();
    let expires = t + n.expires_days as i64 * 86_400;
    let label = if n.label.trim().is_empty() {
        format!("Created by {}", a.username)
    } else {
        n.label.trim().to_string()
    };
    let db = st.db();
    db.execute(
        "INSERT INTO enrollment_tokens (id, token_hash, label, role, created, expires) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, sha256_hex(token.as_bytes()), label, role.as_str(), t, expires],
    )?;
    audit(&db, &a.username, "enrollment_token.created", &label);
    // The token itself is returned once and never stored.
    Ok(Json(
        json!({ "id": id, "token": token, "label": label, "role": role.as_str(), "expires": expires }),
    ))
}

async fn list_tokens(State(st): State<Shared>, _a: Admin) -> ApiResult<Json<Vec<Value>>> {
    let db = st.db();
    let mut s = db.prepare("SELECT id, label, role, created, expires, revoked, uses FROM enrollment_tokens ORDER BY created DESC LIMIT 100")?;
    let t = now();
    let v = s
        .query_map([], |r| {
            let expires: i64 = r.get(4)?;
            let revoked: i64 = r.get(5)?;
            Ok(json!({
                "id": r.get::<_, String>(0)?, "label": r.get::<_, String>(1)?, "role": r.get::<_, String>(2)?,
                "created": r.get::<_, i64>(3)?, "expires": expires, "uses": r.get::<_, i64>(6)?,
                "active": revoked == 0 && expires > t,
            }))
        })?
        .collect::<Result<_, _>>()?;
    Ok(Json(v))
}

async fn revoke_token(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    let db = st.db();
    db.execute(
        "UPDATE enrollment_tokens SET revoked = 1 WHERE id = ?1",
        params![id],
    )?;
    audit(&db, &a.username, "enrollment_token.revoked", &id);
    Ok(Json(json!({ "ok": true })))
}

// ---------- repositories ----------

#[derive(Deserialize)]
struct SealedFor {
    agent_id: String,
    sealed: protocol::seal::Sealed,
    /// Network share sign-in sealed to this agent (share_auth = password).
    #[serde(default)]
    sealed_share: Option<protocol::seal::Sealed>,
    /// Reach the repository through its gateway (NAS gateway).
    #[serde(default)]
    via_gateway: bool,
}

/// How agents sign in to a repository on a network share.
#[derive(Deserialize, Default, Clone)]
struct ShareAuth {
    /// "none" (local path, or the share needs no sign-in), "machine"
    /// (Windows computer account) or "password".
    #[serde(default)]
    share_auth: Option<String>,
    /// Shown in the UI, e.g. "CORP\\backup-svc"; never the password.
    #[serde(default)]
    share_user: Option<String>,
}

impl ShareAuth {
    fn mode(&self) -> ApiResult<&'static str> {
        match self.share_auth.as_deref().unwrap_or("none") {
            "none" => Ok("none"),
            "machine" => Ok("machine"),
            "password" => Ok("password"),
            _ => Err(ApiError::bad(
                "share sign-in must be none, machine or password",
            )),
        }
    }
    fn user(&self) -> Option<String> {
        self.share_user
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .map(|u| u.chars().take(200).collect())
    }
}

/// Object storage: S3-compatible (`s3://bucket/prefix`) or Azure Blob
/// (`azure://container/prefix`). Both use the same settings.
fn is_s3_path(p: &str) -> bool {
    let p = p.trim();
    p.starts_with("s3://") || p.starts_with("azure://")
}

/// Check S3 settings for `path`; the repository's maintenance interval
/// must be shorter than its lock so that locks are extended in time.
fn check_s3(path: &str, s3: Option<&protocol::S3Settings>, prune_every_days: i64) -> ApiResult<()> {
    match (is_s3_path(path), s3) {
        (false, None) => Ok(()),
        (false, Some(_)) => Err(ApiError::bad(
            "object storage settings need an s3://bucket/prefix or azure://container/prefix location",
        )),
        (true, None) => Err(ApiError::bad(
            "an s3:// or azure:// location needs its endpoint",
        )),
        (true, Some(s)) => {
            let azure = path.trim().starts_with("azure://");
            let ep = s.endpoint.trim();
            let host = ep
                .strip_prefix("https://")
                .or_else(|| ep.strip_prefix("http://"));
            // Azure endpoints may carry the account in the path (the Azurite
            // emulator); S3 endpoints are a host only.
            if host.is_none_or(|h| {
                h.trim_end_matches('/').is_empty() || (!azure && h.trim_end_matches('/').contains('/'))
            }) {
                return Err(ApiError::bad(
                    "the endpoint is https://host (or http://host:port), without a path",
                ));
            }
            if azure {
                let c = path.trim()["azure://".len()..].split('/').next().unwrap_or("");
                let ok = (3..=63).contains(&c.len())
                    && c.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    && !c.starts_with('-')
                    && !c.ends_with('-')
                    && !c.contains("--");
                if !ok {
                    return Err(ApiError::bad(
                        "the container name is 3 to 63 lower-case letters, digits or single hyphens",
                    ));
                }
            } else {
                let bucket = path.trim()["s3://".len()..].split('/').next().unwrap_or("");
                let bucket_ok = (3..=63).contains(&bucket.len())
                    && bucket.bytes().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.'
                    });
                if !bucket_ok {
                    return Err(ApiError::bad(
                        "the bucket name is 3 to 63 lower-case letters, digits, dots or hyphens",
                    ));
                }
            }
            match s.lock_mode.as_deref() {
                None | Some("") | Some("none") => Ok(()),
                Some("governance") | Some("compliance") => {
                    if s.lock_days == 0 || s.lock_days > 36_500 {
                        return Err(ApiError::bad("Object Lock needs 1 to 36500 days"));
                    }
                    if prune_every_days == 0 || prune_every_days >= s.lock_days as i64 {
                        return Err(ApiError::bad(format!(
                            "with an Object Lock of {} days, maintenance must run more often than that (it extends the locks of backups in use); it runs every {} days",
                            s.lock_days,
                            if prune_every_days == 0 { "0 (never)".to_string() } else { prune_every_days.to_string() }
                        )));
                    }
                    Ok(())
                }
                Some(_) => Err(ApiError::bad(
                    "Object Lock mode must be none, governance or compliance",
                )),
            }
        }
    }
}

fn is_share_path(p: &str) -> bool {
    let p = p.trim();
    p.starts_with(r"\\") || p.starts_with("//") || p.starts_with("smb://")
}

#[derive(Deserialize)]
struct NewRepo {
    name: String,
    path: String,
    /// Chosen by the browser, matching the recovery key it generated. Not
    /// given for an existing repository (the machine reports it).
    #[serde(default)]
    repo_uuid: Option<Uuid>,
    /// Add a repository that already exists (moved from another server, or
    /// re-added): its images are listed instead of a new one being created.
    #[serde(default)]
    existing: bool,
    init_agent_id: String,
    access: Vec<SealedFor>,
    #[serde(flatten)]
    share: ShareAuth,
    #[serde(default)]
    s3: Option<protocol::S3Settings>,
}

async fn create_repo(
    State(st): State<Shared>,
    a: Admin,
    Json(n): Json<NewRepo>,
) -> ApiResult<Json<Value>> {
    let name = n.name.trim();
    let path = n.path.trim();
    if name.is_empty() || path.is_empty() {
        return Err(ApiError::bad("name and path are required"));
    }
    let init = uuid_param(&n.init_agent_id)?;
    if !n.access.iter().any(|x| x.agent_id == init) {
        return Err(ApiError::bad(
            "the machine that creates the repository needs its sealed secret",
        ));
    }
    let mode = n.share.mode()?;
    check_s3(path, n.s3.as_ref(), 7)?;
    if is_s3_path(path) && mode != "password" {
        return Err(ApiError::bad(
            "an S3 repository needs an access key and secret for every machine",
        ));
    }
    if mode != "none" && !is_share_path(path) && !is_s3_path(path) {
        return Err(ApiError::bad(
            r"a share sign-in needs a network path like \\server\share\folder",
        ));
    }
    if mode == "password" && n.access.iter().any(|x| x.sealed_share.is_none()) {
        return Err(ApiError::bad("enter the share password for every machine"));
    }
    let repo_uuid = match (n.existing, n.repo_uuid) {
        (true, _) => String::new(), // reported by the machine that lists it
        (false, Some(u)) => u.to_string(),
        (false, None) => return Err(ApiError::bad("repo_uuid is required for a new repository")),
    };
    let id = Uuid::new_v4().to_string();
    let t = now();
    {
        let db = st.db();
        let tx = db.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO repositories (id, name, path, repo_uuid, status, created, maintenance_agent_id, share_auth, share_user, s3_json) VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6, ?7, ?8, ?9)",
            params![id, name, path, repo_uuid, t, init, mode, n.share.user(), n.s3.as_ref().map(serde_json::to_string).transpose()?],
        )?;
        for x in &n.access {
            let agent = uuid_param(&x.agent_id)?;
            let share = match mode {
                "password" => x
                    .sealed_share
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
                _ => None,
            };
            tx.execute(
                "INSERT INTO repo_access (repository_id, agent_id, sealed, granted, sealed_share) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, agent, serde_json::to_string(&x.sealed)?, t, share],
            )
            .map_err(|_| ApiError::bad("unknown machine in access list"))?;
        }
        tx.commit()?;
        audit(
            &db,
            &a.username,
            "repository.created",
            &format!("{name} at {path}"),
        );
    }
    let job = insert_job(
        &st,
        &init,
        if n.existing {
            &JobKind::ListImages
        } else {
            &JobKind::InitRepository
        },
        Some(&id),
        None,
        &a.username,
    )?;
    Ok(Json(json!({ "id": id, "init_job_id": job })))
}

/// Repositories and plans, for moving to Fenrir Cloud (or another server):
/// no secrets (repository passphrases and share sign-ins are only ever sealed
/// to machines). Machines are named by their machine ID, repositories by
/// their repository ID, which the importing side matches.
async fn export_config(State(st): State<Shared>, a: Admin) -> ApiResult<Json<Value>> {
    let db = st.db();
    let repos: Vec<Value> = db
        .prepare(
            "SELECT name, path, repo_uuid, share_auth, share_user, s3_json, prune_every_days FROM repositories
             WHERE status = 'ready' ORDER BY created",
        )?
        .query_map([], |r| {
            Ok(json!({
                "name": r.get::<_, String>(0)?, "path": r.get::<_, String>(1)?, "repo_uuid": r.get::<_, String>(2)?,
                "share_auth": r.get::<_, Option<String>>(3)?, "share_user": r.get::<_, Option<String>>(4)?,
                "s3": r.get::<_, Option<String>>(5)?.and_then(|s| serde_json::from_str::<Value>(&s).ok()),
                "prune_every_days": r.get::<_, Option<i64>>(6)?,
            }))
        })?
        .collect::<Result<_, _>>()?;
    let plans: Vec<Value> = db
        .prepare(
            "SELECT p.name, a.machine_id, a.hostname, r.repo_uuid, p.job_json, p.schedule_json, p.retention_json, p.enabled, c.repo_uuid
             FROM plans p JOIN agents a ON a.id = p.agent_id JOIN repositories r ON r.id = p.repository_id
             LEFT JOIN repositories c ON c.id = p.copy_to_repository_id ORDER BY p.name",
        )?
        .query_map([], |r| {
            let parse = |s: Option<String>| s.and_then(|s| serde_json::from_str::<Value>(&s).ok());
            Ok(json!({
                "name": r.get::<_, String>(0)?, "machine_id": r.get::<_, String>(1)?, "hostname": r.get::<_, String>(2)?,
                "repo_uuid": r.get::<_, String>(3)?, "job": parse(r.get(4)?), "schedule": parse(r.get(5)?),
                "retention": parse(r.get(6)?), "enabled": r.get::<_, i64>(7)? != 0,
                "copy_to_repo_uuid": r.get::<_, Option<String>>(8)?,
            }))
        })?
        .collect::<Result<_, _>>()?;
    audit(&db, &a.username, "config.exported", "");
    Ok(Json(json!({
        "format": "fenrir-backup-export", "version": 1, "exported": now(),
        "repositories": repos, "plans": plans,
    })))
}

async fn list_repos(State(st): State<Shared>, _a: Admin) -> ApiResult<Json<Vec<Value>>> {
    let db = st.db();
    let mut s = db.prepare(
        "SELECT r.id, r.name, r.path, r.repo_uuid, r.status, r.status_message, r.created,
            (SELECT COUNT(*) FROM images i WHERE i.repository_id = r.id),
            (SELECT COALESCE(SUM(stored_new_bytes),0) FROM images i WHERE i.repository_id = r.id),
            (SELECT MAX(created) FROM images i WHERE i.repository_id = r.id),
            r.hold, r.hold_reason, r.hold_since, r.maintenance_agent_id, r.prune_every_days, r.last_prune,
            (SELECT COUNT(*) FROM images i WHERE i.repository_id = r.id AND i.anomaly IS NOT NULL),
            r.boot_agent_id, r.boot_every_days,
            (SELECT MAX(at) FROM boot_checks b WHERE b.repository_id = r.id AND b.outcome = 'verified'),
            r.share_auth, r.share_user, r.s3_json
         FROM repositories r ORDER BY r.created",
    )?;
    let mut repos: Vec<Value> = s
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?, "path": r.get::<_, String>(2)?,
                "repo_uuid": r.get::<_, String>(3)?, "status": r.get::<_, String>(4)?, "status_message": r.get::<_, Option<String>>(5)?,
                "created": r.get::<_, i64>(6)?, "images": r.get::<_, i64>(7)?, "stored_bytes": r.get::<_, i64>(8)?,
                "last_image": r.get::<_, Option<i64>>(9)?,
                "hold": r.get::<_, i64>(10)? != 0, "hold_reason": r.get::<_, Option<String>>(11)?, "hold_since": r.get::<_, Option<i64>>(12)?,
                "maintenance_agent_id": r.get::<_, Option<String>>(13)?, "prune_every_days": r.get::<_, i64>(14)?,
                "last_prune": r.get::<_, Option<i64>>(15)?, "anomalies": r.get::<_, i64>(16)?,
                "boot_agent_id": r.get::<_, Option<String>>(17)?, "boot_every_days": r.get::<_, i64>(18)?,
                "last_verified_boot": r.get::<_, Option<i64>>(19)?,
                "share_auth": r.get::<_, String>(20)?, "share_user": r.get::<_, Option<String>>(21)?,
                "s3": r.get::<_, Option<String>>(22)?.and_then(|s| serde_json::from_str::<Value>(&s).ok()),
            }))
        })?
        .collect::<Result<_, _>>()?;
    for r in &mut repos {
        let rid = r["id"].as_str().unwrap_or_default().to_string();
        let mut a = db.prepare(
            "SELECT a.id, COALESCE(a.display_name, a.hostname), x.via_gateway FROM repo_access x JOIN agents a ON a.id = x.agent_id WHERE x.repository_id = ?1 AND a.revoked = 0",
        )?;
        let agents: Vec<Value> = a
            .query_map(params![rid], |r| {
                Ok(json!({ "id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?, "via_gateway": r.get::<_, i64>(2)? != 0 }))
            })?
            .collect::<Result<_, _>>()?;
        r["agents"] = json!(agents);
        drop(a);
        let gw: Option<GatewayRow> = db
            .query_row(
                "SELECT a.id, COALESCE(a.display_name, a.hostname), a.gateway_port, a.gateway_address, a.last_seen
                 FROM repositories r JOIN agents a ON a.id = r.gateway_agent_id WHERE r.id = ?1",
                params![rid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        r["gateway"] = match gw {
            Some((gid, name, port, address, seen)) => json!({
                "agent_id": gid, "name": name, "online": online(&st, seen), "port": port.unwrap_or(0),
                "address": address, "addresses": crate::gateway::addresses(&db, &gid)?,
            }),
            None => Value::Null,
        };
    }
    Ok(Json(repos))
}

async fn grant_access(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(x): Json<SealedFor>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    let agent = uuid_param(&x.agent_id)?;
    let db = st.db();
    let mode: Option<String> = db
        .query_row(
            "SELECT share_auth FROM repositories WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )
        .optional()?;
    let mode = mode.ok_or_else(|| ApiError::not_found("no such repository"))?;
    if x.via_gateway {
        let gw: Option<String> = db.query_row(
            "SELECT gateway_agent_id FROM repositories WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )?;
        if gw.is_none() || gw.as_deref() == Some(agent.as_str()) {
            return Err(ApiError::bad(
                "set up a gateway for this repository first (and choose another machine than the gateway)",
            ));
        }
    }
    // Through the gateway, only the gateway signs in to the share.
    let mode = if x.via_gateway {
        "none".to_string()
    } else {
        mode
    };
    if mode == "password" && x.sealed_share.is_none() {
        return Err(ApiError::bad(
            "this repository is on a network share: enter the share password for the machine too",
        ));
    }
    let share = match mode.as_str() {
        "password" => x
            .sealed_share
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?,
        _ => None,
    };
    db.execute(
        "INSERT INTO repo_access (repository_id, agent_id, sealed, granted, sealed_share, via_gateway) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(repository_id, agent_id) DO UPDATE SET sealed = excluded.sealed, granted = excluded.granted, sealed_share = excluded.sealed_share, via_gateway = excluded.via_gateway",
        params![id, agent, serde_json::to_string(&x.sealed)?, now(), share, x.via_gateway],
    )
    .map_err(|_| ApiError::bad("unknown repository or machine"))?;
    audit(
        &db,
        &a.username,
        "repository.access_granted",
        &format!("{id} -> {agent}"),
    );
    Ok(Json(json!({ "ok": true })))
}

async fn revoke_access(
    State(st): State<Shared>,
    a: Admin,
    Path((id, agent)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let (id, agent) = (uuid_param(&id)?, uuid_param(&agent)?);
    let db = st.db();
    let gw: Option<String> = db
        .query_row(
            "SELECT gateway_agent_id FROM repositories WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    if gw.as_deref() == Some(agent.as_str()) {
        return Err(ApiError::bad(
            "that machine is this repository's gateway: stop serving through it first",
        ));
    }
    db.execute(
        "DELETE FROM repo_access WHERE repository_id = ?1 AND agent_id = ?2",
        params![id, agent],
    )?;
    db.execute(
        "UPDATE plans SET enabled = 0 WHERE repository_id = ?1 AND agent_id = ?2",
        params![id, agent],
    )?;
    audit(
        &db,
        &a.username,
        "repository.access_revoked",
        &format!("{id} -> {agent}"),
    );
    Ok(Json(json!({ "ok": true })))
}

async fn forget_repo(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    let db = st.db();
    let plans: i64 = db.query_row(
        "SELECT COUNT(*) FROM plans WHERE repository_id = ?1",
        params![id],
        |r| r.get(0),
    )?;
    if plans > 0 {
        return Err(ApiError::conflict(
            "delete the backup plans that use this repository first",
        ));
    }
    db.execute("DELETE FROM repositories WHERE id = ?1", params![id])?;
    audit(&db, &a.username, "repository.forgotten", &id);
    Ok(Json(
        json!({ "ok": true, "note": "The server forgot this repository. Its data was not touched." }),
    ))
}

// ---------- plans ----------

#[derive(Deserialize)]
struct NewPlan {
    name: String,
    agent_id: String,
    repository_id: String,
    job: JobKind,
    schedule: Schedule,
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    retention: Option<protocol::Retention>,
    /// Off-site copy: copy each backup to this repository too.
    #[serde(default)]
    copy_to_repository_id: Option<String>,
}
fn yes() -> bool {
    true
}

fn plan_from_row(r: &Row) -> rusqlite::Result<Value> {
    Ok(json!({
        "id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?, "agent_id": r.get::<_, String>(2)?,
        "agent_name": r.get::<_, String>(3)?, "repository_id": r.get::<_, String>(4)?, "repository_name": r.get::<_, String>(5)?,
        "job": serde_json::from_str::<Value>(&r.get::<_, String>(6)?).unwrap_or(Value::Null),
        "schedule": serde_json::from_str::<Value>(&r.get::<_, String>(7)?).unwrap_or(Value::Null),
        "enabled": r.get::<_, i64>(8)? != 0, "last_run": r.get::<_, Option<i64>>(9)?, "next_run": r.get::<_, Option<i64>>(10)?,
        "retention": r.get::<_, Option<String>>(11)?.and_then(|s| serde_json::from_str::<Value>(&s).ok()),
        "copy_to_repository_id": r.get::<_, Option<String>>(12)?, "copy_to_repository_name": r.get::<_, Option<String>>(13)?,
    }))
}

fn plans_query(st: &Shared, agent: Option<&str>) -> ApiResult<Vec<Value>> {
    let db = st.db();
    let base = "SELECT p.id, p.name, p.agent_id, COALESCE(a.display_name, a.hostname), p.repository_id, r.name, p.job_json, p.schedule_json, p.enabled,
        COALESCE((SELECT MAX(j.created) FROM jobs j WHERE j.plan_id = p.id AND j.kind_json NOT LIKE '{\"type\":\"apply_retention%'), p.last_run),
        p.next_run, p.retention_json, p.copy_to_repository_id, c.name
        FROM plans p JOIN agents a ON a.id = p.agent_id JOIN repositories r ON r.id = p.repository_id
        LEFT JOIN repositories c ON c.id = p.copy_to_repository_id";
    let v = match agent {
        Some(id) => db
            .prepare(&format!("{base} WHERE p.agent_id = ?1 ORDER BY p.name"))?
            .query_map(params![id], plan_from_row)?
            .collect::<Result<_, _>>()?,
        None => db
            .prepare(&format!("{base} ORDER BY p.name"))?
            .query_map([], plan_from_row)?
            .collect::<Result<_, _>>()?,
    };
    Ok(v)
}

async fn list_plans(State(st): State<Shared>, _a: Admin) -> ApiResult<Json<Vec<Value>>> {
    Ok(Json(plans_query(&st, None)?))
}

async fn create_plan(
    State(st): State<Shared>,
    a: Admin,
    Json(p): Json<NewPlan>,
) -> ApiResult<Json<Value>> {
    let agent = uuid_param(&p.agent_id)?;
    let repo = uuid_param(&p.repository_id)?;
    if p.name.trim().is_empty() {
        return Err(ApiError::bad("give the plan a name"));
    }
    if !matches!(
        p.job,
        JobKind::BackupSystem { .. }
            | JobKind::BackupDisks { .. }
            | JobKind::BackupHyperv { .. }
            | JobKind::Verify { .. }
    ) {
        return Err(ApiError::bad("plans run backups or verification"));
    }
    p.schedule.validate().map_err(ApiError::bad)?;
    validate_job(&st, &agent, &p.job, &Some(repo.clone()))?;
    let copy_to = check_copy_target(&st, &agent, &repo, p.copy_to_repository_id.as_deref())?;
    let id = Uuid::new_v4().to_string();
    let t = now();
    let db = st.db();
    db.execute(
        "INSERT INTO plans (id, name, agent_id, repository_id, job_json, schedule_json, enabled, next_run, created, retention_json, copy_to_repository_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![id, p.name.trim(), agent, repo, serde_json::to_string(&p.job)?, serde_json::to_string(&p.schedule)?, p.enabled, p.schedule.next_after(t), t,
                p.retention.map(|r| serde_json::to_string(&r)).transpose()?, copy_to],
    )?;
    audit(&db, &a.username, "plan.created", p.name.trim());
    Ok(Json(json!({ "id": id })))
}

#[derive(Deserialize)]
struct PlanPatch {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    schedule: Option<Schedule>,
    #[serde(default)]
    job: Option<JobKind>,
    /// Present (even null) to change retention; null = keep everything.
    #[serde(default, deserialize_with = "some_value")]
    retention: Option<Option<protocol::Retention>>,
    /// Present (even null) to change the off-site copy; null = none.
    #[serde(default, deserialize_with = "some_value")]
    copy_to_repository_id: Option<Option<String>>,
}

/// An off-site copy destination for `agent`'s backups in `repo`: another
/// repository the machine has access to.
fn check_copy_target(
    st: &Shared,
    agent: &str,
    repo: &str,
    target: Option<&str>,
) -> ApiResult<Option<String>> {
    let Some(t) = target.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    let t = uuid_param(t)?;
    if t == repo {
        return Err(ApiError::bad(
            "the copy must go to another repository than the backup",
        ));
    }
    let has: i64 = st.db().query_row(
        "SELECT COUNT(*) FROM repo_access WHERE repository_id = ?1 AND agent_id = ?2",
        params![t, agent],
        |r| r.get(0),
    )?;
    if has == 0 {
        return Err(ApiError::bad(
            "the machine has no access to the copy's repository; grant it access there first",
        ));
    }
    Ok(Some(t))
}

fn some_value<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

async fn update_plan(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(p): Json<PlanPatch>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    if let Some(s) = &p.schedule {
        s.validate().map_err(ApiError::bad)?;
    }
    let (agent, repo): (String, String) = st.db().query_row(
        "SELECT agent_id, repository_id FROM plans WHERE id = ?1",
        params![id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if let Some(j) = &p.job {
        validate_job(&st, &agent, j, &Some(repo.clone()))?;
    }
    let db = st.db();
    if let Some(n) = p.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
        db.execute("UPDATE plans SET name = ?1 WHERE id = ?2", params![n, id])?;
    }
    if let Some(e) = p.enabled {
        db.execute(
            "UPDATE plans SET enabled = ?1 WHERE id = ?2",
            params![e, id],
        )?;
    }
    if let Some(s) = &p.schedule {
        db.execute(
            "UPDATE plans SET schedule_json = ?1, next_run = ?2 WHERE id = ?3",
            params![serde_json::to_string(s)?, s.next_after(now()), id],
        )?;
    }
    if let Some(j) = &p.job {
        db.execute(
            "UPDATE plans SET job_json = ?1 WHERE id = ?2",
            params![serde_json::to_string(j)?, id],
        )?;
    }
    if let Some(r) = &p.retention {
        db.execute(
            "UPDATE plans SET retention_json = ?1 WHERE id = ?2",
            params![r.map(|r| serde_json::to_string(&r)).transpose()?, id],
        )?;
    }
    if let Some(c) = &p.copy_to_repository_id {
        drop(db);
        let c = check_copy_target(&st, &agent, &repo, c.as_deref())?;
        st.db().execute(
            "UPDATE plans SET copy_to_repository_id = ?1 WHERE id = ?2",
            params![c, id],
        )?;
    }
    let db = st.db();
    audit(&db, &a.username, "plan.updated", &id);
    Ok(Json(json!({ "ok": true })))
}

async fn delete_plan(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    let db = st.db();
    db.execute("DELETE FROM plans WHERE id = ?1", params![id])?;
    audit(&db, &a.username, "plan.deleted", &id);
    Ok(Json(json!({ "ok": true })))
}

async fn run_plan(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    let (agent, repo, job_json): (String, String, String) = st.db().query_row(
        "SELECT agent_id, repository_id, job_json FROM plans WHERE id = ?1",
        params![id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let kind: JobKind = serde_json::from_str(&job_json)?;
    validate_job(&st, &agent, &kind, &Some(repo.clone()))?;
    let job = insert_job(&st, &agent, &kind, Some(&repo), Some(&id), &a.username)?;
    Ok(Json(json!({ "id": job })))
}

// ---------- images, overview, audit ----------

fn images_query(st: &Shared, agent: Option<&str>, repo: Option<&str>) -> ApiResult<Vec<Value>> {
    let db = st.db();
    let mut s = db.prepare(
        "SELECT i.image_id, i.repository_id, r.name, i.agent_id, i.machine_id, i.hostname, i.created, i.kind, i.consistency,
            i.captured_bytes, i.stored_new_bytes, i.disks_json, i.label, i.vm_name, i.anomaly, i.chunks_total, i.chunks_new,
            i.applications_json,
            (SELECT json_object('id', b.id, 'at', b.at, 'outcome', b.outcome, 'method', b.method, 'seconds', b.seconds,
                    'firmware', b.firmware, 'accel', b.accel, 'message', b.message, 'has_screenshot', b.screenshot IS NOT NULL)
               FROM boot_checks b WHERE b.image_id = i.image_id ORDER BY b.at DESC, b.id DESC LIMIT 1)
         FROM images i JOIN repositories r ON r.id = i.repository_id
         WHERE (?1 IS NULL OR i.agent_id = ?1) AND (?2 IS NULL OR i.repository_id = ?2)
         ORDER BY i.created DESC LIMIT 500",
    )?;
    let v = s
        .query_map(params![agent, repo], |r| {
            Ok(json!({
                "image_id": r.get::<_, String>(0)?, "repository_id": r.get::<_, String>(1)?, "repository_name": r.get::<_, String>(2)?,
                "agent_id": r.get::<_, Option<String>>(3)?, "machine_id": r.get::<_, String>(4)?, "hostname": r.get::<_, String>(5)?,
                "created": r.get::<_, i64>(6)?, "kind": r.get::<_, String>(7)?, "consistency": r.get::<_, String>(8)?,
                "captured_bytes": r.get::<_, i64>(9)?, "stored_new_bytes": r.get::<_, i64>(10)?,
                "disks": serde_json::from_str::<Value>(&r.get::<_, String>(11)?).unwrap_or(json!([])),
                "label": r.get::<_, Option<String>>(12)?, "vm_name": r.get::<_, Option<String>>(13)?,
                "anomaly": r.get::<_, Option<String>>(14)?, "chunks_total": r.get::<_, i64>(15)?, "chunks_new": r.get::<_, i64>(16)?,
                "applications": r.get::<_, Option<String>>(17)?
                    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                    .unwrap_or(json!([])),
                "boot_check": boot_json(r.get::<_, Option<String>>(18)?),
            }))
        })?
        .collect::<Result<_, _>>()?;
    Ok(v)
}

#[derive(Deserialize)]
struct ImageQuery {
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    repository_id: Option<String>,
}

async fn list_images(
    State(st): State<Shared>,
    _a: Admin,
    Query(q): Query<ImageQuery>,
) -> ApiResult<Json<Vec<Value>>> {
    let agent = q.agent_id.as_deref().map(uuid_param).transpose()?;
    let repo = q.repository_id.as_deref().map(uuid_param).transpose()?;
    Ok(Json(images_query(&st, agent.as_deref(), repo.as_deref())?))
}

async fn overview(State(st): State<Shared>, _a: Admin) -> ApiResult<Json<Value>> {
    let agents = all_agents(&st)?;
    let t = now();
    let (ok, warn, failed, running, images, stored, protected_bytes): (i64, i64, i64, i64, i64, i64, i64) = st.db().query_row(
        "SELECT
            (SELECT COUNT(*) FROM jobs WHERE state = 'succeeded' AND finished > ?1 AND kind_json LIKE '{\"type\":\"backup%'),
            (SELECT COUNT(*) FROM jobs WHERE state = 'warning' AND finished > ?1 AND kind_json LIKE '{\"type\":\"backup%'),
            (SELECT COUNT(*) FROM jobs WHERE state = 'failed' AND finished > ?1 AND kind_json LIKE '{\"type\":\"backup%'),
            (SELECT COUNT(*) FROM jobs WHERE state IN ('queued','dispatched','running')),
            (SELECT COUNT(*) FROM images),
            (SELECT COALESCE(SUM(stored_new_bytes),0) FROM images),
            (SELECT COALESCE(SUM(captured_bytes),0) FROM images i WHERE created = (SELECT MAX(created) FROM images j WHERE j.machine_id = i.machine_id))",
        params![t - 86_400],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
    )?;
    let repos: i64 = st
        .db()
        .query_row("SELECT COUNT(*) FROM repositories", [], |r| r.get(0))?;
    let plans: i64 =
        st.db()
            .query_row("SELECT COUNT(*) FROM plans WHERE enabled = 1", [], |r| {
                r.get(0)
            })?;
    let attention = agents
        .iter()
        .filter(|a| {
            !a.online
                || a.last_backup.as_ref().is_none_or(|b| {
                    b["state"] == "failed" || b["at"].as_i64().is_some_and(|at| t - at > 3 * 86_400)
                })
        })
        .count();
    let boot: Value = st.db().query_row(
        "SELECT
            (SELECT COUNT(*) FROM boot_checks WHERE outcome = 'verified' AND at > ?1),
            (SELECT COUNT(*) FROM boot_checks WHERE outcome = 'screen' AND at > ?1),
            (SELECT COUNT(*) FROM boot_checks WHERE outcome = 'failed' AND at > ?1),
            (SELECT json_object('at', b.at, 'image_id', b.image_id, 'hostname', i.hostname, 'vm_name', i.vm_name, 'id', b.id, 'seconds', b.seconds)
               FROM boot_checks b LEFT JOIN images i ON i.image_id = b.image_id WHERE b.outcome = 'verified' ORDER BY b.at DESC LIMIT 1)",
        params![t - 30 * 86_400],
        |r| {
            Ok(json!({
                "verified_30d": r.get::<_, i64>(0)?, "screen_30d": r.get::<_, i64>(1)?, "failed_30d": r.get::<_, i64>(2)?,
                "last_verified": boot_json(r.get::<_, Option<String>>(3)?),
            }))
        },
    )?;
    Ok(Json(json!({
        "boot": boot,
        "machines": { "total": agents.len(), "online": agents.iter().filter(|a| a.online).count(), "attention": attention },
        "last_24h": { "succeeded": ok, "warning": warn, "failed": failed },
        "running": running,
        "storage": { "images": images, "stored_bytes": stored, "protected_bytes": protected_bytes },
        "repositories": repos,
        "plans": plans,
        "agents": agents,
        "recent_jobs": jobs_query(&st, None, 12)?,
    })))
}

async fn list_audit(State(st): State<Shared>, _a: Admin) -> ApiResult<Json<Vec<Value>>> {
    let db = st.db();
    let mut s =
        db.prepare("SELECT at, actor, action, detail FROM audit ORDER BY id DESC LIMIT 300")?;
    let v = s
        .query_map([], |r| {
            Ok(json!({ "at": r.get::<_, i64>(0)?, "actor": r.get::<_, String>(1)?, "action": r.get::<_, String>(2)?, "detail": r.get::<_, String>(3)? }))
        })?
        .collect::<Result<_, _>>()?;
    Ok(Json(v))
}

// ---------- holds, maintenance ----------

#[derive(Deserialize)]
struct HoldReq {
    hold: bool,
    #[serde(default)]
    reason: String,
}

async fn set_hold(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(h): Json<HoldReq>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    let db = st.db();
    let n = if h.hold {
        let reason = if h.reason.trim().is_empty() {
            format!("Placed on hold by {}", a.username)
        } else {
            h.reason.trim().to_string()
        };
        db.execute(
            "UPDATE repositories SET hold = 1, hold_since = ?1, hold_reason = ?2 WHERE id = ?3",
            params![now(), reason, id],
        )?
    } else {
        db.execute(
            "UPDATE repositories SET hold = 0, hold_since = NULL, hold_reason = NULL WHERE id = ?1",
            params![id],
        )?
    };
    if n == 0 {
        return Err(ApiError::not_found("no such repository"));
    }
    audit(
        &db,
        &a.username,
        if h.hold {
            "repository.hold"
        } else {
            "repository.hold_released"
        },
        &id,
    );
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct MaintenanceReq {
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    prune_every_days: Option<u32>,
}

async fn set_maintenance(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(m): Json<MaintenanceReq>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    let db = st.db();
    if let Some(agent) = m.agent_id.as_deref().map(uuid_param).transpose()? {
        let ok: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM repo_access WHERE repository_id = ?1 AND agent_id = ?2)",
            params![id, agent],
            |r| r.get(0),
        )?;
        if !ok {
            return Err(ApiError::bad(
                "that machine has no access to this repository",
            ));
        }
        let gw: Option<String> = db.query_row(
            "SELECT gateway_agent_id FROM repositories WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )?;
        if gw.as_ref().is_some_and(|g| g != &agent) {
            return Err(ApiError::bad(
                "this repository is served through a gateway: its maintenance runs on the gateway",
            ));
        }
        db.execute(
            "UPDATE repositories SET maintenance_agent_id = ?1 WHERE id = ?2",
            params![agent, id],
        )?;
    }
    if let Some(d) = m.prune_every_days {
        if d > 365 {
            return Err(ApiError::bad(
                "prune interval must be 0 (never) to 365 days",
            ));
        }
        let (path, s3): (String, Option<String>) = db.query_row(
            "SELECT path, s3_json FROM repositories WHERE id = ?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let s3: Option<protocol::S3Settings> =
            s3.as_deref().and_then(|s| serde_json::from_str(s).ok());
        check_s3(&path, s3.as_ref(), d as i64)?;
        db.execute(
            "UPDATE repositories SET prune_every_days = ?1 WHERE id = ?2",
            params![d, id],
        )?;
    }
    audit(&db, &a.username, "repository.maintenance_changed", &id);
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct PruneReq {
    #[serde(default)]
    dry_run: bool,
}

async fn prune_now(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(p): Json<PruneReq>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    let (agent, hold): (Option<String>, i64) = st.db().query_row(
        "SELECT maintenance_agent_id, hold FROM repositories WHERE id = ?1",
        params![id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if hold != 0 && !p.dry_run {
        return Err(ApiError::conflict(
            "the repository is on hold; release the hold before reclaiming space",
        ));
    }
    let agent = agent.ok_or_else(|| ApiError::bad("choose a maintenance machine first"))?;
    let job = insert_job(
        &st,
        &agent,
        &JobKind::Prune { dry_run: p.dry_run },
        Some(&id),
        None,
        &a.username,
    )?;
    Ok(Json(json!({ "id": job })))
}

#[derive(Deserialize)]
struct CopyReq {
    /// Machine that copies (it needs access to both repositories).
    agent_id: String,
    target_repository_id: String,
    /// Empty: every image the destination does not have.
    #[serde(default)]
    images: Vec<Uuid>,
    #[serde(default)]
    full_verify: bool,
}

/// Copy images to another repository now (off-site copy).
async fn copy_now(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(c): Json<CopyReq>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    let agent = uuid_param(&c.agent_id)?;
    let has: i64 = st.db().query_row(
        "SELECT COUNT(*) FROM repo_access WHERE repository_id = ?1 AND agent_id = ?2",
        params![id, agent],
        |r| r.get(0),
    )?;
    if has == 0 {
        return Err(ApiError::bad(
            "the machine has no access to this repository",
        ));
    }
    let target = check_copy_target(&st, &agent, &id, Some(&c.target_repository_id))?
        .ok_or_else(|| ApiError::bad("choose the repository to copy to"))?;
    let kind = JobKind::CopyImages {
        target_repository_id: Uuid::parse_str(&target).map_err(|_| ApiError::bad("bad id"))?,
        images: c.images,
        full_verify: c.full_verify,
    };
    let job = insert_job(&st, &agent, &kind, Some(&id), None, &a.username)?;
    Ok(Json(json!({ "id": job })))
}

// ---------- restore ----------

#[derive(Deserialize)]
struct RestoreReq {
    image_id: Uuid,
    /// Machine that performs the restore (needs access to the repository).
    agent_id: String,
    target: protocol::RestoreTarget,
    #[serde(default)]
    disks: Vec<u32>,
}

async fn create_restore(
    State(st): State<Shared>,
    a: Admin,
    Json(r): Json<RestoreReq>,
) -> ApiResult<Json<Value>> {
    let agent = uuid_param(&r.agent_id)?;
    let repo: String = st
        .db()
        .query_row(
            "SELECT repository_id FROM images WHERE image_id = ?1",
            params![r.image_id.to_string()],
            |x| x.get(0),
        )
        .map_err(|_| ApiError::not_found("no such image"))?;
    let need = match &r.target {
        protocol::RestoreTarget::Vhdx { directory } => {
            if directory.trim().is_empty() {
                return Err(ApiError::bad("choose a folder on the target machine"));
            }
            "restore_vhdx"
        }
        protocol::RestoreTarget::HypervVm {
            name, directory, ..
        } => {
            if name.trim().is_empty() || directory.trim().is_empty() {
                return Err(ApiError::bad("choose a VM name and a folder on the host"));
            }
            "restore_hyperv"
        }
        protocol::RestoreTarget::Disk {
            device, confirm, ..
        } => {
            if device.trim().is_empty() || confirm != device {
                return Err(ApiError::bad(
                    "type the target device exactly to confirm that it will be overwritten",
                ));
            }
            "restore_disk"
        }
    };
    let target = r.target.clone();
    let kind = JobKind::Restore {
        image_id: r.image_id,
        disks: r.disks,
        target: r.target,
    };
    {
        let db = st.db();
        let (caps, revoked): (Option<String>, i64) = db.query_row(
            "SELECT inventory_json, revoked FROM agents WHERE id = ?1",
            params![agent],
            |x| Ok((x.get(0)?, x.get(1)?)),
        )?;
        let inv = caps.and_then(|s| serde_json::from_str::<Inventory>(&s).ok());
        let caps: Vec<String> = inv
            .as_ref()
            .map(|i| i.capabilities.clone())
            .unwrap_or_default();
        if revoked != 0 || !caps.iter().any(|c| c == need) {
            return Err(ApiError::bad(
                "that machine cannot perform this kind of restore",
            ));
        }
        // A disk device must be one the machine reported, and not its system
        // disk or a disk in use (e.g. the recovery medium). Image files are
        // checked by the agent.
        let is_device = |p: &str| p.starts_with("/dev/") || p.starts_with(r"\\.\");
        if let protocol::RestoreTarget::Disk { device, .. } = &target {
            if is_device(device) {
                let d = inv
                    .as_ref()
                    .and_then(|i| i.disks.iter().find(|d| &d.path == device))
                    .ok_or_else(|| ApiError::bad("that disk is not one the machine reported"))?;
                if d.system || d.in_use {
                    return Err(ApiError::bad(
                    "that disk is in use on the machine (its system disk, the recovery medium, or mounted)",
                ));
                }
            }
        }
        let access: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM repo_access WHERE repository_id = ?1 AND agent_id = ?2)",
            params![repo, agent],
            |x| x.get(0),
        )?;
        if !access {
            return Err(ApiError::bad(
                "that machine has no access to the image's repository; give it access first",
            ));
        }
    }
    let job = insert_job(&st, &agent, &kind, Some(&repo), None, &a.username)?;
    audit(
        &st.db(),
        &a.username,
        "restore.requested",
        &format!("image {} on {agent}", r.image_id),
    );
    Ok(Json(json!({ "id": job })))
}

// ---------- settings ----------

fn redact(mut n: crate::notify::NotifySettings) -> Value {
    let has_pw = n.email.as_ref().is_some_and(|e| !e.password.is_empty());
    if let Some(e) = &mut n.email {
        e.password.clear();
    }
    let mut v = serde_json::to_value(n).unwrap_or(Value::Null);
    if let Some(e) = v.get_mut("email").filter(|e| e.is_object()) {
        e["has_password"] = json!(has_pw);
    }
    v
}

async fn get_settings(State(st): State<Shared>, _a: Admin) -> ApiResult<Json<Value>> {
    let db = st.db();
    let n: crate::notify::NotifySettings = crate::db::get_setting(&db, crate::notify::KEY);
    let u: crate::agent_api::UpdateSettings =
        crate::db::get_setting(&db, crate::agent_api::UPDATE_KEY);
    Ok(Json(
        json!({ "notifications": redact(n), "auto_update": u.enabled() }),
    ))
}

#[derive(Deserialize)]
struct SettingsReq {
    #[serde(default)]
    notifications: Option<crate::notify::NotifySettings>,
    #[serde(default)]
    auto_update: Option<bool>,
}

async fn put_settings(
    State(st): State<Shared>,
    a: Admin,
    Json(r): Json<SettingsReq>,
) -> ApiResult<Json<Value>> {
    let db = st.db();
    if let Some(mut n) = r.notifications {
        if let Some(e) = &mut n.email {
            if e.host.trim().is_empty() || e.from.trim().is_empty() || e.to.is_empty() {
                return Err(ApiError::bad(
                    "email needs a server, a sender and at least one recipient",
                ));
            }
            // Empty password = keep the stored one.
            if e.password.is_empty() {
                let old: crate::notify::NotifySettings =
                    crate::db::get_setting(&db, crate::notify::KEY);
                if let Some(o) = old.email {
                    e.password = o.password;
                }
            }
        }
        if let Some(w) = &n.webhook {
            if !(w.url.starts_with("https://") || w.url.starts_with("http://")) {
                return Err(ApiError::bad(
                    "webhook URL must start with https:// or http://",
                ));
            }
        }
        crate::db::set_setting(&db, crate::notify::KEY, &n)?;
    }
    if let Some(u) = r.auto_update {
        crate::db::set_setting(
            &db,
            crate::agent_api::UPDATE_KEY,
            &crate::agent_api::UpdateSettings {
                auto_update: Some(u),
            },
        )?;
    }
    audit(&db, &a.username, "settings.updated", "");
    Ok(Json(json!({ "ok": true })))
}

async fn test_notification(State(st): State<Shared>, a: Admin) -> ApiResult<Json<Value>> {
    let cfg: crate::notify::NotifySettings = crate::db::get_setting(&st.db(), crate::notify::KEY);
    if cfg.email.is_none() && cfg.webhook.is_none() {
        return Err(ApiError::bad("configure email or a webhook first"));
    }
    let ev = crate::notify::Event {
        severity: crate::notify::Severity::Info,
        subject: "Test notification".into(),
        body: format!(
            "{} sent this test from the Fenrir-Backup settings page. Alerts will arrive like this.",
            a.username
        ),
        link: Some("/".into()),
    };
    let base = st.cfg.public_url.clone();
    let st2 = st.clone();
    let results = tokio::task::spawn_blocking(move || {
        crate::notify::deliver(&st2, &cfg, &ev, base.as_deref())
    })
    .await
    .map_err(|e| ApiError::new(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({
        "results": results.into_iter().map(|(ch, r)| json!({ "channel": ch, "ok": r.is_ok(), "error": r.err() })).collect::<Vec<_>>()
    })))
}

async fn list_notifications(State(st): State<Shared>, _a: Admin) -> ApiResult<Json<Vec<Value>>> {
    let db = st.db();
    let mut s = db.prepare(
        "SELECT at, channel, subject, ok, error FROM notifications ORDER BY id DESC LIMIT 100",
    )?;
    let v = s
        .query_map([], |r| {
            Ok(json!({ "at": r.get::<_, i64>(0)?, "channel": r.get::<_, String>(1)?, "subject": r.get::<_, String>(2)?,
                       "ok": r.get::<_, i64>(3)? != 0, "error": r.get::<_, Option<String>>(4)? }))
        })?
        .collect::<Result<_, _>>()?;
    Ok(Json(v))
}

// ---------- boot checks ----------

fn boot_json(s: Option<String>) -> Value {
    let mut v = s
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .unwrap_or(Value::Null);
    if let Some(h) = v.get_mut("has_screenshot") {
        *h = json!(h.as_i64().map(|x| x != 0).or(h.as_bool()).unwrap_or(false));
    }
    v
}

fn agent_caps(db: &rusqlite::Connection, agent: &str) -> ApiResult<Vec<String>> {
    let (inv, revoked): (Option<String>, i64) = db
        .query_row(
            "SELECT inventory_json, revoked FROM agents WHERE id = ?1",
            params![agent],
            |x| Ok((x.get(0)?, x.get(1)?)),
        )
        .optional()?
        .ok_or_else(|| ApiError::not_found("no such machine"))?;
    if revoked != 0 {
        return Err(ApiError::bad("that machine has been removed"));
    }
    Ok(inv
        .and_then(|s| serde_json::from_str::<Inventory>(&s).ok())
        .map(|i| i.capabilities)
        .unwrap_or_default())
}

#[derive(Deserialize)]
struct BootCheckReq {
    agent_id: String,
    #[serde(default)]
    keep_running: bool,
    #[serde(default)]
    memory_mb: Option<u64>,
    #[serde(default)]
    cpus: Option<u32>,
    /// Hyper-V: folder on the host for the VM's disks.
    #[serde(default)]
    directory: Option<String>,
}

async fn create_boot_check(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(r): Json<BootCheckReq>,
) -> ApiResult<Json<Value>> {
    let image_id: Uuid = id.parse().map_err(|_| ApiError::bad("invalid image id"))?;
    let agent = uuid_param(&r.agent_id)?;
    if r.memory_mb.is_some_and(|m| !(256..=65536).contains(&m))
        || r.cpus.is_some_and(|c| !(1..=16).contains(&c))
    {
        return Err(ApiError::bad(
            "memory must be 256 MB to 64 GB, CPUs 1 to 16",
        ));
    }
    let repo: String = {
        let db = st.db();
        let repo: String = db
            .query_row(
                "SELECT repository_id FROM images WHERE image_id = ?1",
                params![image_id.to_string()],
                |x| x.get(0),
            )
            .optional()?
            .ok_or_else(|| ApiError::not_found("no such image"))?;
        let caps = agent_caps(&db, &agent)?;
        let kvm = caps.iter().any(|c| c == "boot_kvm");
        if !kvm && !caps.iter().any(|c| c == "boot_hyperv") {
            return Err(ApiError::bad(
                "that machine cannot boot VMs (it needs QEMU on Linux, or Hyper-V on Windows)",
            ));
        }
        if let Some(d) = r
            .directory
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty())
        {
            let windows_path = d.len() >= 3 && d.as_bytes()[1] == b':' && d.as_bytes()[2] == b'\\'
                || d.starts_with("\\\\");
            if kvm || d.len() > 500 || !windows_path {
                return Err(ApiError::bad(
                    "the folder for the VM is for Hyper-V hosts and must be a full Windows path, e.g. D:\\Fenrir checks",
                ));
            }
        }
        let access: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM repo_access WHERE repository_id = ?1 AND agent_id = ?2)",
            params![repo, agent],
            |x| x.get(0),
        )?;
        if !access {
            return Err(ApiError::bad(
                "that machine has no access to the image's repository; give it access first",
            ));
        }
        repo
    };
    let kind = JobKind::BootCheck {
        image_id,
        keep_running: r.keep_running,
        memory_mb: r.memory_mb,
        cpus: r.cpus,
        directory: r
            .directory
            .map(|d| d.trim().to_string())
            .filter(|d| !d.is_empty()),
    };
    let job = insert_job(&st, &agent, &kind, Some(&repo), None, &a.username)?;
    audit(
        &st.db(),
        &a.username,
        "boot_check.requested",
        &format!("image {image_id} on {agent}"),
    );
    Ok(Json(json!({ "id": job })))
}

async fn list_boot_checks(
    State(st): State<Shared>,
    _a: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<Value>>> {
    let id = uuid_param(&id)?;
    let db = st.db();
    let mut s = db.prepare(
        "SELECT b.id, b.at, b.outcome, b.method, b.seconds, b.firmware, b.accel, b.message, b.screenshot IS NOT NULL,
                b.agent_id, COALESCE(a.display_name, a.hostname), b.job_id
         FROM boot_checks b LEFT JOIN agents a ON a.id = b.agent_id WHERE b.image_id = ?1 ORDER BY b.at DESC, b.id DESC LIMIT 50",
    )?;
    let v = s
        .query_map(params![id], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "at": r.get::<_, i64>(1)?, "outcome": r.get::<_, String>(2)?,
                "method": r.get::<_, String>(3)?, "seconds": r.get::<_, i64>(4)?, "firmware": r.get::<_, String>(5)?,
                "accel": r.get::<_, String>(6)?, "message": r.get::<_, String>(7)?, "has_screenshot": r.get::<_, bool>(8)?,
                "agent_id": r.get::<_, String>(9)?, "agent_name": r.get::<_, Option<String>>(10)?, "job_id": r.get::<_, Option<String>>(11)?,
            }))
        })?
        .collect::<Result<_, _>>()?;
    Ok(Json(v))
}

async fn boot_screenshot(
    State(st): State<Shared>,
    _a: Admin,
    Path(id): Path<i64>,
) -> ApiResult<impl IntoResponse> {
    let png: Option<Vec<u8>> = st
        .db()
        .query_row(
            "SELECT screenshot FROM boot_checks WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    let png = png.ok_or_else(|| ApiError::not_found("no screenshot"))?;
    Ok((
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "private, max-age=86400"),
        ],
        png,
    ))
}

async fn stop_vm(
    State(st): State<Shared>,
    a: Admin,
    Path((id, session)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let agent = uuid_param(&id)?;
    let session_id: Uuid = session
        .parse()
        .map_err(|_| ApiError::bad("invalid session id"))?;
    {
        let db = st.db();
        agent_caps(&db, &agent)?;
    }
    let job = insert_job(
        &st,
        &agent,
        &JobKind::StopVm { session_id },
        None,
        None,
        &a.username,
    )?;
    audit(
        &st.db(),
        &a.username,
        "vm.stop_requested",
        &format!("session {session_id} on {agent}"),
    );
    Ok(Json(json!({ "id": job })))
}

#[derive(Deserialize)]
struct BootVerificationReq {
    /// Boot host; null = turn boot verification off.
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    every_days: u32,
}

async fn set_boot_verification(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(r): Json<BootVerificationReq>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    let db = st.db();
    let agent = r.agent_id.as_deref().map(uuid_param).transpose()?;
    if let Some(agent) = &agent {
        if !(1..=90).contains(&r.every_days) {
            return Err(ApiError::bad("the interval must be 1 to 90 days"));
        }
        let caps = agent_caps(&db, agent)?;
        if !caps.iter().any(|c| c == "boot_kvm" || c == "boot_hyperv") {
            return Err(ApiError::bad("that machine cannot boot VMs"));
        }
        let ok: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM repo_access WHERE repository_id = ?1 AND agent_id = ?2)",
            params![id, agent],
            |r| r.get(0),
        )?;
        if !ok {
            return Err(ApiError::bad(
                "that machine has no access to this repository",
            ));
        }
    }
    let n = db.execute(
        "UPDATE repositories SET boot_agent_id = ?1, boot_every_days = ?2 WHERE id = ?3",
        params![agent, if agent.is_some() { r.every_days } else { 0 }, id],
    )?;
    if n == 0 {
        return Err(ApiError::not_found("no such repository"));
    }
    audit(
        &db,
        &a.username,
        "repository.boot_verification_changed",
        &id,
    );
    Ok(Json(json!({ "ok": true })))
}

// ---------- network shares ----------

#[derive(Deserialize)]
struct ShareUpdate {
    #[serde(flatten)]
    share: ShareAuth,
    /// For "password": the sign-in sealed to every machine with access.
    #[serde(default)]
    access: Vec<ShareFor>,
}

#[derive(Deserialize)]
struct ShareFor {
    agent_id: String,
    sealed_share: protocol::seal::Sealed,
}

/// Change how machines sign in to a share repository (new password,
/// another account, computer account).
async fn set_share(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(u): Json<ShareUpdate>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    let mode = u.share.mode()?;
    let db = st.db();
    let path: String = db
        .query_row(
            "SELECT path FROM repositories WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| ApiError::not_found("no such repository"))?;
    if mode != "none" && !is_share_path(&path) && !is_s3_path(&path) {
        return Err(ApiError::bad("this repository is not on a network share"));
    }
    let agents: Vec<String> = db
        .prepare("SELECT agent_id FROM repo_access WHERE repository_id = ?1")?
        .query_map(params![id], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut sealed: std::collections::BTreeMap<String, String> = Default::default();
    if mode == "password" {
        for x in &u.access {
            sealed.insert(
                uuid_param(&x.agent_id)?,
                serde_json::to_string(&x.sealed_share)?,
            );
        }
        if let Some(missing) = agents.iter().find(|a| !sealed.contains_key(*a)) {
            return Err(ApiError::bad(format!(
                "the sign-in must be sealed for every machine with access (missing {missing})"
            )));
        }
    }
    let tx = db.unchecked_transaction()?;
    tx.execute(
        "UPDATE repositories SET share_auth = ?1, share_user = ?2 WHERE id = ?3",
        params![
            mode,
            if mode == "password" {
                u.share.user()
            } else {
                None
            },
            id
        ],
    )?;
    for agent in &agents {
        tx.execute(
            "UPDATE repo_access SET sealed_share = ?1 WHERE repository_id = ?2 AND agent_id = ?3",
            params![sealed.get(agent), id, agent],
        )?;
    }
    tx.commit()?;
    audit(
        &db,
        &a.username,
        "repository.share_signin_changed",
        &format!("{id}: {mode}"),
    );
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct CheckAccessReq {
    path: String,
    #[serde(default)]
    sealed_share: Option<protocol::seal::Sealed>,
    #[serde(default)]
    s3: Option<protocol::S3Settings>,
}

/// Queue a connection test on a machine; poll the job for the result.
async fn check_access(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(r): Json<CheckAccessReq>,
) -> ApiResult<Json<Value>> {
    let agent = uuid_param(&id)?;
    let path = r.path.trim();
    if path.is_empty() || path.len() > 1000 {
        return Err(ApiError::bad("enter a folder path"));
    }
    agent_caps(&st.db(), &agent)?;
    check_s3(path, r.s3.as_ref(), 7)?;
    let kind = JobKind::CheckAccess {
        path: path.to_string(),
        sealed_share: r.sealed_share,
        s3: r.s3,
    };
    let job = insert_job(&st, &agent, &kind, None, None, &a.username)?;
    Ok(Json(json!({ "id": job })))
}

// ---------- file-level restore ----------

/// The machine that reads an image for browsing or file restore: the one
/// asked for, else the machine the image came from, else any online machine
/// with access. Returns (agent id, name, online).
fn file_agent(
    st: &Shared,
    image_id: &str,
    want: Option<&str>,
) -> ApiResult<(String, String, String, bool)> {
    let db = st.db();
    let (repo, owner): (String, Option<String>) = db
        .query_row(
            "SELECT repository_id, agent_id FROM images WHERE image_id = ?1",
            params![image_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .ok_or_else(|| ApiError::not_found("no such image"))?;
    let mut s = db.prepare(
        "SELECT a.id, COALESCE(a.display_name, a.hostname), a.last_seen FROM agents a
         JOIN repo_access x ON x.agent_id = a.id AND x.repository_id = ?1 WHERE a.revoked = 0",
    )?;
    let mut candidates: Vec<(String, String, bool)> = s
        .query_map(params![repo], |r| {
            Ok((r.get(0)?, r.get(1)?, online(st, r.get(2)?)))
        })?
        .collect::<Result<_, _>>()?;
    drop(s);
    let chosen = match want {
        Some(w) => {
            let w = uuid_param(w)?;
            candidates.into_iter().find(|c| c.0 == w).ok_or_else(|| {
                ApiError::bad(
                    "that machine has no access to the image's repository; give it access first",
                )
            })?
        }
        None => {
            candidates.sort_by_key(|c| (Some(&c.0) != owner.as_ref(), !c.2));
            candidates
                .into_iter()
                .next()
                .ok_or_else(|| ApiError::bad("no machine has access to this image's repository"))?
        }
    };
    let caps = agent_caps(&db, &chosen.0)?;
    if !caps.iter().any(|c| c == "restore_files") {
        return Err(ApiError::bad(format!(
            "the backup agent on {} is too old to browse files; it updates itself shortly",
            chosen.1
        )));
    }
    Ok((chosen.0, chosen.1, repo, chosen.2))
}

fn volume_of(disk: Option<u32>, partition: Option<u32>) -> ApiResult<Option<protocol::VolumeRef>> {
    match (disk, partition) {
        (None, None) => Ok(None),
        (Some(disk), Some(partition)) if partition >= 1 => {
            Ok(Some(protocol::VolumeRef { disk, partition }))
        }
        _ => Err(ApiError::bad("choose a volume")),
    }
}

#[derive(Deserialize)]
struct BrowseReq {
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    disk: Option<u32>,
    #[serde(default)]
    partition: Option<u32>,
    #[serde(default)]
    path: Option<String>,
}

/// List an image's volumes (no volume given) or one folder; poll the job for the listing.
async fn browse_files(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(r): Json<BrowseReq>,
) -> ApiResult<Json<Value>> {
    let image_id: Uuid = id.parse().map_err(|_| ApiError::bad("invalid image id"))?;
    let (agent, name, repo, is_online) =
        file_agent(&st, &image_id.to_string(), r.agent_id.as_deref())?;
    let path = r.path.unwrap_or_else(|| "/".into());
    if path.len() > 4000 || path.split(['/', '\\']).any(|c| c == "..") {
        return Err(ApiError::bad("invalid folder"));
    }
    let volume = volume_of(r.disk, r.partition)?;
    let kind = JobKind::BrowseFiles {
        image_id,
        volume,
        path,
    };
    let job = insert_job(&st, &agent, &kind, Some(&repo), None, &a.username)?;
    if volume.is_none() {
        audit(
            &st.db(),
            &a.username,
            "files.browsed",
            &format!("image {image_id} on {name}"),
        );
    }
    Ok(Json(
        json!({ "id": job, "agent_id": agent, "agent_name": name, "agent_online": is_online }),
    ))
}

#[derive(Deserialize)]
struct RestoreFilesReq {
    #[serde(default)]
    agent_id: Option<String>,
    disk: u32,
    partition: u32,
    paths: Vec<String>,
    target: String,
    #[serde(default = "yes")]
    keep_structure: bool,
    #[serde(default)]
    conflict: Option<String>,
}

/// Copy chosen files and folders out of a backup into a folder on a machine.
async fn restore_files(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(r): Json<RestoreFilesReq>,
) -> ApiResult<Json<Value>> {
    let image_id: Uuid = id.parse().map_err(|_| ApiError::bad("invalid image id"))?;
    let (agent, name, repo, _) = file_agent(&st, &image_id.to_string(), r.agent_id.as_deref())?;
    let volume = volume_of(Some(r.disk), Some(r.partition))?.expect("both given");
    let paths: Vec<String> = r
        .paths
        .into_iter()
        .filter(|p| !p.trim_matches('/').is_empty())
        .collect();
    if paths.is_empty() || paths.len() > 1000 || paths.iter().any(|p| p.len() > 4000) {
        return Err(ApiError::bad("choose 1 to 1000 files or folders"));
    }
    let target = r.target.trim().to_string();
    if target.is_empty() || target.len() > 1000 {
        return Err(ApiError::bad("choose the folder to restore into"));
    }
    let conflict = r.conflict.unwrap_or_else(|| "rename".into());
    if !["rename", "skip", "overwrite"].contains(&conflict.as_str()) {
        return Err(ApiError::bad("existing files: rename, skip or overwrite"));
    }
    let kind = JobKind::RestoreFiles {
        image_id,
        volume,
        paths: paths.clone(),
        target: target.clone(),
        keep_structure: r.keep_structure,
        conflict: conflict.clone(),
    };
    let job = insert_job(&st, &agent, &kind, Some(&repo), None, &a.username)?;
    audit(
        &st.db(),
        &a.username,
        "files.restore_requested",
        &format!(
            "{} item(s) of image {image_id} on {name} to {target} ({conflict})",
            paths.len()
        ),
    );
    Ok(Json(json!({ "id": job })))
}

// ---------- NAS gateway ----------

#[derive(Deserialize)]
struct GatewayReq {
    /// The gateway machine; None stops serving through a gateway.
    #[serde(default)]
    agent_id: Option<String>,
    /// Port for direct connections; 0 = relay only.
    #[serde(default)]
    port: Option<u16>,
    /// "host:port" reachable from outside the gateway's network.
    #[serde(default)]
    address: Option<String>,
}

/// Serve a repository through a gateway agent, or stop.
async fn set_gateway(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(r): Json<GatewayReq>,
) -> ApiResult<Json<Value>> {
    let id = uuid_param(&id)?;
    let db = st.db();
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM repositories WHERE id = ?1)",
        params![id],
        |x| x.get(0),
    )?;
    if !exists {
        return Err(ApiError::not_found("no such repository"));
    }
    let path: String = db.query_row(
        "SELECT path FROM repositories WHERE id = ?1",
        params![id],
        |r| r.get(0),
    )?;
    if is_s3_path(&path) {
        return Err(ApiError::bad(
            "a repository on object storage is reached directly by every machine; a gateway is for folders on a NAS",
        ));
    }
    let Some(gw) = r.agent_id.as_deref().map(uuid_param).transpose()? else {
        let users: i64 = db.query_row(
            "SELECT COUNT(*) FROM repo_access WHERE repository_id = ?1 AND via_gateway = 1",
            params![id],
            |x| x.get(0),
        )?;
        if users > 0 {
            return Err(ApiError::bad(format!(
                "{users} machine(s) reach this repository through the gateway; remove their access first"
            )));
        }
        db.execute(
            "UPDATE repositories SET gateway_agent_id = NULL WHERE id = ?1",
            params![id],
        )?;
        audit(&db, &a.username, "repository.gateway_removed", &id);
        return Ok(Json(json!({ "ok": true })));
    };
    let direct: Option<i64> = db
        .query_row(
            "SELECT via_gateway FROM repo_access WHERE repository_id = ?1 AND agent_id = ?2",
            params![id, gw],
            |x| x.get(0),
        )
        .optional()?;
    if direct != Some(0) {
        return Err(ApiError::bad(
            "the gateway must be a machine with direct access to the repository (give it access first)",
        ));
    }
    let caps = agent_caps(&db, &gw)?;
    if !caps.iter().any(|c| c == "gateway") {
        return Err(ApiError::bad(
            "that machine's backup agent is too old to be a gateway; it updates itself shortly",
        ));
    }
    let port = r.port.unwrap_or(crate::gateway::DEFAULT_PORT);
    if port != 0 && port < 1024 {
        return Err(ApiError::bad(
            "the port must be 1024 to 65535, or 0 to use the relay only",
        ));
    }
    let address = r
        .address
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(addr) = &address {
        let ok = addr.len() <= 255
            && addr.rsplit_once(':').is_some_and(|(h, p)| {
                !h.is_empty()
                    && p.parse::<u16>().is_ok_and(|p| p > 0)
                    && h.chars()
                        .all(|c| c.is_ascii_alphanumeric() || ".-[]:".contains(c))
            });
        if !ok {
            return Err(ApiError::bad(
                "the extra address must look like host:port, e.g. nas-gw.example.com:8475",
            ));
        }
    }
    // Retention and space reclamation run on the gateway.
    db.execute(
        "UPDATE repositories SET gateway_agent_id = ?1, maintenance_agent_id = ?1 WHERE id = ?2",
        params![gw, id],
    )?;
    db.execute(
        "UPDATE agents SET gateway_port = ?1, gateway_address = ?2 WHERE id = ?3",
        params![
            if port == 0 { None } else { Some(port as i64) },
            address,
            gw
        ],
    )?;
    audit(
        &db,
        &a.username,
        "repository.gateway_set",
        &format!("{id} via {gw} port {port}"),
    );
    Ok(Json(json!({ "ok": true })))
}
