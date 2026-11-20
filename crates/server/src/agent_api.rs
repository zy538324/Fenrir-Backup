//! Endpoints the agents call. Agents always initiate; the server never
//! connects to them.

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use protocol::*;
use rusqlite::{params, OptionalExtension};
use uuid::Uuid;

use crate::auth::AgentAuth;
use crate::db::audit;
use crate::{now, sha256_hex, ApiError, ApiResult, Shared};

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/agent/enroll", post(enroll))
        .route("/api/agent/heartbeat", post(heartbeat))
        .route("/api/agent/jobs/{id}/update", post(update_job))
}

/// A dispatched job the agent stopped mentioning for this long is
/// considered lost (agent restarted mid-job).
const LOST_AFTER_SECS: i64 = 180;

async fn enroll(
    State(st): State<Shared>,
    Json(req): Json<EnrollRequest>,
) -> ApiResult<Json<EnrollResponse>> {
    if req.protocol != PROTOCOL_VERSION {
        return Err(ApiError::bad(format!(
            "server speaks protocol {PROTOCOL_VERSION}, agent sent {}",
            req.protocol
        )));
    }
    if req.machine_id.trim().is_empty()
        || req.hostname.trim().is_empty()
        || req.public_key.len() != 44
    {
        return Err(ApiError::bad(
            "hostname, machine_id and a 32-byte public key are required",
        ));
    }
    let t = now();
    let db = st.db();
    let tok: Option<(String, i64, i64)> = db
        .query_row(
            "SELECT id, expires, revoked FROM enrollment_tokens WHERE token_hash = ?1",
            params![sha256_hex(req.token.as_bytes())],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (tok_id, expires, revoked) =
        tok.ok_or_else(|| ApiError::forbidden("enrollment token not recognised"))?;
    if revoked != 0 || expires < t {
        return Err(ApiError::forbidden(
            "enrollment token has expired or was revoked; create a new download",
        ));
    }
    // The installer chose the role (the Hyper-V installer says "hyperv").
    let role = req.role.as_str();

    let agent_token = crate::random_token();
    let token_hash = sha256_hex(agent_token.as_bytes());
    let os_json = serde_json::to_string(&req.os)?;

    // Reinstall on the same machine keeps the agent's identity and history.
    // If its key pair changed, secrets sealed to the old key are useless and
    // are dropped; the administrator re-grants repository access.
    let existing: Option<(String, String)> = db
        .query_row(
            "SELECT id, public_key FROM agents WHERE machine_id = ?1 AND revoked = 0 ORDER BY enrolled DESC LIMIT 1",
            params![req.machine_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let agent_id = match existing {
        Some((id, old_pk)) => {
            db.execute(
                "UPDATE agents SET token_hash = ?1, hostname = ?2, role = ?3, os_json = ?4, public_key = ?5, agent_version = ?6, last_seen = ?7 WHERE id = ?8",
                params![token_hash, req.hostname, role, os_json, req.public_key, req.agent_version, t, id],
            )?;
            if old_pk != req.public_key {
                db.execute("DELETE FROM repo_access WHERE agent_id = ?1", params![id])?;
                audit(
                    &db,
                    &format!("agent:{id}"),
                    "agent.reenrolled_new_key",
                    "repository access must be granted again",
                );
            } else {
                audit(
                    &db,
                    &format!("agent:{id}"),
                    "agent.reenrolled",
                    &req.hostname,
                );
            }
            id
        }
        None => {
            let id = Uuid::new_v4().to_string();
            db.execute(
                "INSERT INTO agents (id, token_hash, hostname, machine_id, role, os_json, public_key, agent_version, enrolled, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
                params![id, token_hash, req.hostname, req.machine_id, role, os_json, req.public_key, req.agent_version, t],
            )?;
            audit(&db, &format!("agent:{id}"), "agent.enrolled", &req.hostname);
            id
        }
    };
    db.execute(
        "UPDATE enrollment_tokens SET uses = uses + 1 WHERE id = ?1",
        params![tok_id],
    )?;
    Ok(Json(EnrollResponse {
        agent_id: Uuid::parse_str(&agent_id).expect("stored uuid"),
        agent_token,
        poll_seconds: st.cfg.poll_seconds,
    }))
}

async fn heartbeat(
    State(st): State<Shared>,
    agent: AgentAuth,
    Json(req): Json<HeartbeatRequest>,
) -> ApiResult<Json<HeartbeatResponse>> {
    let t = now();
    let db = st.db();
    db.execute(
        "UPDATE agents SET last_seen = ?1, inventory_json = ?2, hostname = ?3, agent_version = ?4 WHERE id = ?5",
        params![t, serde_json::to_string(&req.inventory)?, req.inventory.hostname, req.inventory.agent_version, agent.agent_id],
    )?;

    // Jobs this agent was given but no longer reports: it restarted.
    let running = req.running_job.map(|u| u.to_string()).unwrap_or_default();
    db.execute(
        "UPDATE jobs SET state = 'failed', finished = ?1, error = 'The agent stopped before finishing this job (restart or crash). It will run again at the next scheduled time.'
         WHERE agent_id = ?2 AND state IN ('dispatched','running') AND id != ?3 AND dispatched < ?4",
        params![t, agent.agent_id, running, t - LOST_AFTER_SECS],
    )?;

    let mut jobs = Vec::new();
    let busy: i64 = db.query_row(
        "SELECT COUNT(*) FROM jobs WHERE agent_id = ?1 AND state IN ('dispatched','running')",
        params![agent.agent_id],
        |r| r.get(0),
    )?;
    if busy == 0 && req.running_job.is_none() {
        let next: Option<(String, Option<String>, String)> = db
            .query_row(
                "SELECT id, repository_id, kind_json FROM jobs WHERE agent_id = ?1 AND state = 'queued' ORDER BY created LIMIT 1",
                params![agent.agent_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((id, repo_id, kind_json)) = next {
            let kind: JobKind = serde_json::from_str(&kind_json)?;
            let repository = match &repo_id {
                None => Ok(None),
                Some(rid) => db
                    .query_row(
                        "SELECT r.path, a.sealed FROM repositories r JOIN repo_access a ON a.repository_id = r.id
                         WHERE r.id = ?1 AND a.agent_id = ?2",
                        params![rid, agent.agent_id],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                    )
                    .optional()?
                    .map(|(path, sealed)| {
                        Ok::<_, ApiError>(Some(RepoAccess {
                            repository_id: Uuid::parse_str(rid).map_err(|_| ApiError::bad("bad repository id"))?,
                            path,
                            sealed_secret: serde_json::from_str(&sealed)?,
                        }))
                    })
                    .unwrap_or(Err(ApiError::forbidden("no access"))),
            };
            match repository {
                Ok(repository) => {
                    db.execute(
                        "UPDATE jobs SET state = 'dispatched', dispatched = ?1 WHERE id = ?2",
                        params![t, id],
                    )?;
                    jobs.push(JobSpec {
                        id: Uuid::parse_str(&id).expect("stored uuid"),
                        kind,
                        repository,
                    });
                }
                Err(_) => {
                    db.execute(
                        "UPDATE jobs SET state = 'failed', finished = ?1, error = 'This machine has not been given access to the repository. Grant access on the Repositories page.' WHERE id = ?2",
                        params![t, id],
                    )?;
                }
            }
        }
    }

    let mut stmt = db.prepare("SELECT id FROM jobs WHERE agent_id = ?1 AND cancel_requested = 1 AND state IN ('dispatched','running')")?;
    let cancel = stmt
        .query_map(params![agent.agent_id], |r| r.get::<_, String>(0))?
        .filter_map(|r| r.ok().and_then(|s| Uuid::parse_str(&s).ok()))
        .collect();
    Ok(Json(HeartbeatResponse {
        jobs,
        poll_seconds: st.cfg.poll_seconds,
        cancel,
    }))
}

async fn update_job(
    State(st): State<Shared>,
    agent: AgentAuth,
    Path(id): Path<Uuid>,
    Json(u): Json<JobUpdate>,
) -> ApiResult<Json<serde_json::Value>> {
    let t = now();
    let db = st.db();
    let (owner, repo_id, cur_state, kind_json): (String, Option<String>, String, String) = db
        .query_row(
            "SELECT agent_id, repository_id, state, kind_json FROM jobs WHERE id = ?1",
            params![id.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
    if owner != agent.agent_id {
        return Err(ApiError::forbidden("job belongs to another agent"));
    }
    if JobState::parse(&cur_state).is_some_and(|s| s.is_final()) {
        return Err(ApiError::conflict("job already finished"));
    }
    let progress = u.progress.as_ref().map(serde_json::to_string).transpose()?;
    db.execute(
        "UPDATE jobs SET state = ?1, progress_json = COALESCE(?2, progress_json),
            started = COALESCE(started, CASE WHEN ?1 = 'running' THEN ?3 END),
            finished = CASE WHEN ?4 THEN ?3 ELSE finished END,
            result_json = COALESCE(?5, result_json), error = COALESCE(?6, error),
            warnings_json = CASE WHEN ?7 = '[]' THEN warnings_json ELSE ?7 END
         WHERE id = ?8",
        params![
            u.state.as_str(),
            progress,
            t,
            u.state.is_final(),
            u.result.as_ref().map(serde_json::to_string).transpose()?,
            u.error,
            serde_json::to_string(&u.warnings)?,
            id.to_string()
        ],
    )?;

    if let (Some(rid), Some(images)) = (&repo_id, &u.images) {
        for im in images {
            db.execute(
                "INSERT INTO images (image_id, repository_id, agent_id, machine_id, hostname, created, kind, consistency, captured_bytes, stored_new_bytes, disks_json, label, vm_name)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                 ON CONFLICT(image_id) DO UPDATE SET label = excluded.label",
                params![
                    im.image_id.to_string(),
                    rid,
                    agent.agent_id,
                    im.machine_id,
                    im.hostname,
                    im.created_unix,
                    im.kind,
                    im.consistency,
                    im.captured_bytes as i64,
                    im.stored_new_bytes as i64,
                    serde_json::to_string(&im.disks)?,
                    im.label,
                    im.vm_name
                ],
            )?;
        }
    }

    if matches!(
        serde_json::from_str::<JobKind>(&kind_json),
        Ok(JobKind::InitRepository)
    ) && u.state.is_final()
    {
        if let Some(rid) = &repo_id {
            let expected: String = db.query_row(
                "SELECT repo_uuid FROM repositories WHERE id = ?1",
                params![rid],
                |r| r.get(0),
            )?;
            let (status, msg) = match (u.state, u.repo_uuid) {
                (JobState::Succeeded | JobState::Warning, Some(got))
                    if got.to_string() == expected =>
                {
                    ("ready", None)
                }
                (JobState::Succeeded | JobState::Warning, _) => (
                    "failed",
                    Some("agent reported a different repository ID".to_string()),
                ),
                _ => ("failed", u.error.clone()),
            };
            db.execute(
                "UPDATE repositories SET status = ?1, status_message = ?2 WHERE id = ?3",
                params![status, msg, rid],
            )?;
        }
    }
    if u.state.is_final() {
        audit(
            &db,
            &format!("agent:{}", agent.agent_id),
            &format!("job.{}", u.state.as_str()),
            &id.to_string(),
        );
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}
