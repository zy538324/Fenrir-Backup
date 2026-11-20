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
        .route("/api/restores", post(create_restore))
        .route("/api/settings", get(get_settings).put(put_settings))
        .route("/api/settings/test-notification", post(test_notification))
        .route("/api/notifications", get(list_notifications))
}

fn uuid_param(s: &str) -> ApiResult<String> {
    Uuid::parse_str(s)
        .map(|u| u.to_string())
        .map_err(|_| ApiError::bad("invalid id"))
}

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
        .ok_or_else(|| ApiError::bad("role must be workstation, server or hyperv"))?;
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
}

#[derive(Deserialize)]
struct NewRepo {
    name: String,
    path: String,
    /// Chosen by the browser, matching the recovery key it generated.
    repo_uuid: Uuid,
    init_agent_id: String,
    access: Vec<SealedFor>,
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
    let id = Uuid::new_v4().to_string();
    let t = now();
    {
        let db = st.db();
        let tx = db.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO repositories (id, name, path, repo_uuid, status, created, maintenance_agent_id) VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6)",
            params![id, name, path, n.repo_uuid.to_string(), t, init],
        )?;
        for x in &n.access {
            let agent = uuid_param(&x.agent_id)?;
            tx.execute(
                "INSERT INTO repo_access (repository_id, agent_id, sealed, granted) VALUES (?1, ?2, ?3, ?4)",
                params![id, agent, serde_json::to_string(&x.sealed)?, t],
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
        &JobKind::InitRepository,
        Some(&id),
        None,
        &a.username,
    )?;
    Ok(Json(json!({ "id": id, "init_job_id": job })))
}

async fn list_repos(State(st): State<Shared>, _a: Admin) -> ApiResult<Json<Vec<Value>>> {
    let db = st.db();
    let mut s = db.prepare(
        "SELECT r.id, r.name, r.path, r.repo_uuid, r.status, r.status_message, r.created,
            (SELECT COUNT(*) FROM images i WHERE i.repository_id = r.id),
            (SELECT COALESCE(SUM(stored_new_bytes),0) FROM images i WHERE i.repository_id = r.id),
            (SELECT MAX(created) FROM images i WHERE i.repository_id = r.id),
            r.hold, r.hold_reason, r.hold_since, r.maintenance_agent_id, r.prune_every_days, r.last_prune,
            (SELECT COUNT(*) FROM images i WHERE i.repository_id = r.id AND i.anomaly IS NOT NULL)
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
            }))
        })?
        .collect::<Result<_, _>>()?;
    for r in &mut repos {
        let rid = r["id"].as_str().unwrap_or_default().to_string();
        let mut a = db.prepare(
            "SELECT a.id, COALESCE(a.display_name, a.hostname) FROM repo_access x JOIN agents a ON a.id = x.agent_id WHERE x.repository_id = ?1 AND a.revoked = 0",
        )?;
        let agents: Vec<Value> = a
            .query_map(params![rid], |r| {
                Ok(json!({ "id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)? }))
            })?
            .collect::<Result<_, _>>()?;
        r["agents"] = json!(agents);
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
    db.execute(
        "INSERT INTO repo_access (repository_id, agent_id, sealed, granted) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(repository_id, agent_id) DO UPDATE SET sealed = excluded.sealed, granted = excluded.granted",
        params![id, agent, serde_json::to_string(&x.sealed)?, now()],
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
    }))
}

fn plans_query(st: &Shared, agent: Option<&str>) -> ApiResult<Vec<Value>> {
    let db = st.db();
    let base = "SELECT p.id, p.name, p.agent_id, COALESCE(a.display_name, a.hostname), p.repository_id, r.name, p.job_json, p.schedule_json, p.enabled, p.last_run, p.next_run, p.retention_json
        FROM plans p JOIN agents a ON a.id = p.agent_id JOIN repositories r ON r.id = p.repository_id";
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
    let id = Uuid::new_v4().to_string();
    let t = now();
    let db = st.db();
    db.execute(
        "INSERT INTO plans (id, name, agent_id, repository_id, job_json, schedule_json, enabled, next_run, created, retention_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![id, p.name.trim(), agent, repo, serde_json::to_string(&p.job)?, serde_json::to_string(&p.schedule)?, p.enabled, p.schedule.next_after(t), t,
                p.retention.map(|r| serde_json::to_string(&r)).transpose()?],
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
        validate_job(&st, &agent, j, &Some(repo))?;
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
            i.captured_bytes, i.stored_new_bytes, i.disks_json, i.label, i.vm_name, i.anomaly, i.chunks_total, i.chunks_new
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
    Ok(Json(json!({
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
        let caps: Vec<String> = caps
            .and_then(|s| serde_json::from_str::<Inventory>(&s).ok())
            .map(|i| i.capabilities)
            .unwrap_or_default();
        if revoked != 0 || !caps.iter().any(|c| c == need) {
            return Err(ApiError::bad(
                "that machine cannot perform this kind of restore",
            ));
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
