//! Endpoints the agents call. Agents always initiate; the server never
//! connects to them.

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use protocol::*;
use rusqlite::{params, OptionalExtension};

/// How long a local recovery partition's enrolment code works (it is
/// renewed whenever the partition is rebuilt).
pub const LOCAL_RECOVERY_DAYS: i64 = 365;
use uuid::Uuid;

use crate::auth::AgentAuth;
use crate::db::audit;
use crate::{anomaly, notify};
use crate::{now, sha256_hex, ApiError, ApiResult, Shared};

/// Most bytes one encrypted download may hold (the agent's limit, framed).
pub const DOWNLOAD_MAX: u64 = (4 << 30) + (64 << 20);

#[derive(serde::Deserialize)]
struct UploadAt {
    offset: u64,
}

/// The agent appends to the encrypted stream of its `download_files` job.
/// Uploads carry their offset so a retried request is harmless.
async fn upload_download(
    State(st): State<Shared>,
    agent: AgentAuth,
    Path(id): Path<Uuid>,
    axum::extract::Query(q): axum::extract::Query<UploadAt>,
    body: axum::body::Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    let (owner, state, kind_json): (String, String, String) = st.db().query_row(
        "SELECT agent_id, state, kind_json FROM jobs WHERE id = ?1",
        params![id.to_string()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if owner != agent.agent_id {
        return Err(ApiError::forbidden("job belongs to another agent"));
    }
    if !matches!(
        serde_json::from_str::<JobKind>(&kind_json),
        Ok(JobKind::DownloadFiles { .. } | JobKind::ExportSaas { .. })
    ) || JobState::parse(&state).is_some_and(|s| s.is_final())
    {
        return Err(ApiError::conflict("not a running download"));
    }
    let dir = &st.cfg.downloads_dir;
    std::fs::create_dir_all(dir).map_err(|e| ApiError::internal(e.to_string()))?;
    let path = dir.join(format!("{id}.bin"));
    let have = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let end = q.offset + body.len() as u64;
    if end > DOWNLOAD_MAX {
        return Err(ApiError::bad("the download is too large"));
    }
    if q.offset > have {
        return Err(ApiError::conflict(format!("expected offset {have}")));
    }
    if end > have {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        f.seek(SeekFrom::Start(q.offset))
            .and_then(|_| f.write_all(&body))
            .map_err(|e| ApiError::internal(e.to_string()))?;
    }
    Ok(Json(serde_json::json!({ "have": end.max(have) })))
}

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/agent/enroll", post(enroll))
        .route("/api/agent/heartbeat", post(heartbeat))
        .route("/api/agent/jobs/{id}/update", post(update_job))
        .route(
            "/api/agent/jobs/{id}/download",
            post(upload_download).layer(axum::extract::DefaultBodyLimit::max(16 << 20)),
        )
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
    let tok: Option<(String, i64, i64, String)> = db
        .query_row(
            "SELECT id, expires, revoked, role FROM enrollment_tokens WHERE token_hash = ?1",
            params![sha256_hex(req.token.as_bytes())],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let (tok_id, expires, revoked, tok_role) =
        tok.ok_or_else(|| ApiError::forbidden("enrollment token not recognised"))?;
    // Recovery tokens (on recovery media) enrol recovery sessions only, and
    // recovery sessions need one.
    if (tok_role == "recovery") != (req.role == protocol::AgentRole::Recovery) {
        return Err(ApiError::forbidden(
            "this enrollment token is for recovery media only, or this agent needs one",
        ));
    }
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
                "SELECT j.id, j.repository_id, j.kind_json FROM jobs j LEFT JOIN repositories r ON r.id = j.repository_id
                 WHERE j.agent_id = ?1 AND j.state = 'queued'
                   AND NOT (COALESCE(r.hold, 0) = 1 AND (j.kind_json LIKE '{\"type\":\"apply_retention%' OR j.kind_json LIKE '{\"type\":\"prune%'))
                 ORDER BY j.created LIMIT 1",
                params![agent.agent_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((id, repo_id, kind_json)) = next {
            let kind: JobKind = serde_json::from_str(&kind_json)?;
            let access_to = |rid: &str| -> Result<RepoAccess, ApiError> {
                db.query_row(
                    "SELECT r.path, a.sealed, a.sealed_share, r.s3_json FROM repositories r JOIN repo_access a ON a.repository_id = r.id
                     WHERE r.id = ?1 AND a.agent_id = ?2",
                    params![rid, agent.agent_id],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, Option<String>>(3)?)),
                )
                .optional()?
                .map(|(path, sealed, share, s3)| {
                    Ok::<_, ApiError>(RepoAccess {
                        repository_id: Uuid::parse_str(rid).map_err(|_| ApiError::bad("bad repository id"))?,
                        path,
                        sealed_secret: serde_json::from_str(&sealed)?,
                        sealed_share: share.as_deref().map(serde_json::from_str).transpose()?,
                        gateway: crate::gateway::route(&db, rid, &agent.agent_id)?,
                        s3: s3.as_deref().map(serde_json::from_str).transpose()?,
                    })
                })
                .unwrap_or(Err(ApiError::forbidden("no access")))
            };
            let repository = match &repo_id {
                None => Ok(None),
                Some(rid) => access_to(rid).map(Some),
            };
            // A copy also needs the destination, sealed to this machine.
            let copy_target = match &kind {
                JobKind::CopyImages { target_repository_id, .. } => {
                    match access_to(&target_repository_id.to_string()) {
                        Ok(a) => Ok(Some(a)),
                        Err(_) => Err("This machine has not been given access to the destination repository. Grant access on the Repositories page."),
                    }
                }
                _ => Ok(None),
            };
            // A repository joining a dedup group: the member it takes the
            // group's key from, which this machine must be able to open.
            let group_source = match (&kind, &repo_id) {
                (JobKind::InitRepository, Some(rid)) => {
                    let src: Option<String> = db
                        .query_row(
                            "SELECT dedup_source_id FROM repositories WHERE id = ?1",
                            params![rid],
                            |r| r.get(0),
                        )
                        .optional()?
                        .flatten();
                    match src {
                        None => Ok(None),
                        Some(s) => access_to(&s).map(Some).map_err(|_| "This machine has no access to the repository whose dedup group the new one joins. Grant it access there first."),
                    }
                }
                _ => Ok(None),
            };
            // An offline media set: the other drives of the set this machine
            // can write to, tried when the first is not attached.
            let copy_alternatives: Vec<RepoAccess> = match &kind {
                JobKind::CopyImages {
                    target_repository_id,
                    ..
                } => {
                    let others: Vec<String> = db
                        .prepare(
                            "SELECT o.id FROM repositories t JOIN repositories o ON o.media_set = t.media_set AND o.id != t.id
                             WHERE t.id = ?1 AND t.media_set IS NOT NULL AND o.status = 'ready' ORDER BY o.name",
                        )?
                        .query_map(params![target_repository_id.to_string()], |r| r.get(0))?
                        .collect::<Result<_, _>>()?;
                    others.iter().filter_map(|o| access_to(o).ok()).collect()
                }
                _ => vec![],
            };
            let repository = match (repository, copy_target, group_source) {
                (Ok(r), Ok(c), Ok(g)) => Ok((r, c, g)),
                (Err(_), _, _) => Err("This machine has not been given access to the repository. Grant access on the Repositories page."),
                (_, Err(e), _) | (_, _, Err(e)) => Err(e),
            };
            // Local recovery: a long-lived enrolment code for recovery
            // sessions (replacing this machine's earlier one; the agent adds
            // its own server address and pin).
            let recovery_settings = match &kind {
                JobKind::LocalRecovery { action, .. } => {
                    let label = format!("local-recovery:{}", agent.agent_id);
                    db.execute(
                        "UPDATE enrollment_tokens SET revoked = 1 WHERE label = ?1",
                        params![label],
                    )?;
                    if *action == protocol::LocalRecoveryAction::Remove {
                        None
                    } else {
                        let token = crate::random_token();
                        let expires = t + LOCAL_RECOVERY_DAYS * 86_400;
                        db.execute(
                            "INSERT INTO enrollment_tokens (id, token_hash, label, role, created, expires) VALUES (?1, ?2, ?3, 'recovery', ?4, ?5)",
                            params![Uuid::new_v4().to_string(), crate::sha256_hex(token.as_bytes()), label, t, expires],
                        )?;
                        Some(protocol::recovery::RecoveryConfig {
                            server: String::new(),
                            pin: String::new(),
                            token,
                            expires: expires as u64,
                        })
                    }
                }
                _ => None,
            };
            match repository {
                Ok((repository, copy_target, group_source)) => {
                    db.execute(
                        "UPDATE jobs SET state = 'dispatched', dispatched = ?1 WHERE id = ?2",
                        params![t, id],
                    )?;
                    jobs.push(JobSpec {
                        id: Uuid::parse_str(&id).expect("stored uuid"),
                        kind,
                        repository,
                        copy_target,
                        copy_alternatives,
                        group_source,
                        recovery_settings,
                    });
                }
                Err(why) => {
                    db.execute(
                        "UPDATE jobs SET state = 'failed', finished = ?1, error = ?2 WHERE id = ?3",
                        params![t, why, id],
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
    drop(stmt);
    let auto_update = crate::db::get_setting::<UpdateSettings>(&db, UPDATE_KEY).enabled();
    let gateway = crate::gateway::config(&db, &agent.agent_id)?;
    // Someone is browsing this machine's backups: poll every second for three minutes.
    let browsing: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM jobs WHERE agent_id = ?1 AND created > ?2 AND kind_json LIKE '{\"type\":\"browse_files%')",
        params![agent.agent_id, t - 180],
        |r| r.get(0),
    )?;
    drop(db);
    let update = if auto_update {
        crate::downloads::update_offer(&st, &req.inventory)
    } else {
        None
    };
    Ok(Json(HeartbeatResponse {
        jobs,
        poll_seconds: if browsing { 1 } else { st.cfg.poll_seconds },
        cancel,
        update,
        gateway,
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
    let (owner, repo_id, cur_state, kind_json, plan_id): (
        String,
        Option<String>,
        String,
        String,
        Option<String>,
    ) = db.query_row(
        "SELECT agent_id, repository_id, state, kind_json, plan_id FROM jobs WHERE id = ?1",
        params![id.to_string()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )?;
    let kind: Option<JobKind> = serde_json::from_str(&kind_json).ok();
    // Disk images: checked for mass encryption.
    let is_disk_backup = matches!(
        kind,
        Some(
            JobKind::BackupSystem { .. }
                | JobKind::BackupDisks { .. }
                | JobKind::BackupHyperv { .. }
        )
    );
    // Every backup: retention, copies and the work after it.
    let is_backup = is_disk_backup
        || matches!(
            kind,
            Some(
                JobKind::BackupFiles { .. }
                    | JobKind::BackupKubernetes { .. }
                    | JobKind::BackupSaas { .. }
            )
        );
    let mut events: Vec<notify::Event> = Vec::new();
    let agent_name: String = db
        .query_row(
            "SELECT COALESCE(display_name, hostname) FROM agents WHERE id = ?1",
            params![agent.agent_id],
            |r| r.get(0),
        )
        .unwrap_or_default();
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

    // Restore evidence (BDR-03): recovery point, times, RPO/RTO and what was written.
    if u.state.is_final()
        && kind
            .as_ref()
            .and_then(crate::evidence::restore_image)
            .is_some()
    {
        crate::evidence::record(&db, &id.to_string())?;
    }

    // A copy reports the images it put in the destination repository.
    let images_repo = match &kind {
        // (an offline media set: the drive that was attached)
        Some(JobKind::CopyImages {
            target_repository_id,
            ..
        }) => Some(
            u.result
                .as_ref()
                .and_then(|r| r["target_repository_id"].as_str())
                .and_then(|s| Uuid::parse_str(s).ok())
                .unwrap_or(*target_repository_id)
                .to_string(),
        ),
        _ => repo_id.clone(),
    };
    if let (Some(rid), Some(images)) = (&images_repo, &u.images) {
        for im in images {
            let inserted = db.execute(
                "INSERT INTO images (image_id, repository_id, agent_id, machine_id, hostname, created, kind, consistency, captured_bytes, stored_new_bytes, disks_json, label, vm_name, chunks_total, chunks_new, bytes_new_raw, applications_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
                 ON CONFLICT(image_id) DO NOTHING",
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
                    im.vm_name,
                    im.chunks_total as i64,
                    im.chunks_new as i64,
                    im.bytes_new_raw as i64,
                    (!im.applications.is_empty())
                        .then(|| serde_json::to_string(&im.applications))
                        .transpose()?
                ],
            )?;
            if inserted == 1 {
                crate::cases::hold_new_image(&db, &im.image_id.to_string(), &im.machine_id)?;
            }
            if inserted == 1 && is_disk_backup {
                if let Some(reason) = check_anomaly(&db, rid, im)? {
                    let what = im.vm_name.clone().unwrap_or_else(|| im.hostname.clone());
                    db.execute(
                        "UPDATE images SET anomaly = ?1 WHERE image_id = ?2",
                        params![reason, im.image_id.to_string()],
                    )?;
                    db.execute(
                        "UPDATE repositories SET hold = 1, hold_since = ?1, hold_reason = ?2 WHERE id = ?3",
                        params![t, format!("Possible ransomware on {what}: {reason}"), rid],
                    )?;
                    audit(
                        &db,
                        &format!("agent:{}", agent.agent_id),
                        "repository.hold.anomaly",
                        &format!("{what}: {reason}"),
                    );
                    events.push(notify::Event {
                        severity: notify::Severity::Error,
                        subject: format!("Possible ransomware detected on {what}"),
                        body: format!(
                            "The latest backup of {what} looks like mass encryption: {reason}.\n\nDeletion of old backups in this repository is on hold, so earlier images are kept. Check the machine, then release the hold in Repositories."
                        ),
                        link: Some("/repositories".into()),
                    });
                }
            }
        }
    }
    if let (Some(rid), Some(b), Some(JobKind::BootCheck { image_id, .. })) =
        (&repo_id, &u.boot_check, &kind)
    {
        if u.state.is_final() && b.image_id == *image_id {
            record_boot_check(&db, rid, &agent.agent_id, &id.to_string(), b)?;
            if b.outcome == "failed" {
                events.push(notify::Event {
                    severity: notify::Severity::Error,
                    subject: format!("Backup of {agent_name}'s image did not boot"),
                    body: format!("A boot check of image {image_id} failed: {}", b.message),
                    link: Some("/machines".into()),
                });
            }
        }
    }
    if let Some(rid) = &repo_id {
        for removed in &u.removed_images {
            db.execute(
                "DELETE FROM images WHERE image_id = ?1 AND repository_id = ?2",
                params![removed.to_string(), rid],
            )?;
            db.execute(
                "DELETE FROM boot_checks WHERE image_id = ?1",
                params![removed.to_string()],
            )?;
            db.execute(
                "DELETE FROM scans WHERE image_id = ?1",
                params![removed.to_string()],
            )?;
        }
        if matches!(kind, Some(JobKind::Prune { dry_run: false })) && u.state == JobState::Succeeded
        {
            db.execute(
                "UPDATE repositories SET last_prune = ?1 WHERE id = ?2",
                params![t, rid],
            )?;
        }
    }
    // Retention runs after each successful plan backup, unless on hold; the
    // off-site copy, if the plan has one, before it.
    if is_backup && matches!(u.state, JobState::Succeeded | JobState::Warning) {
        if let (Some(pid), Some(rid)) = (&plan_id, &repo_id) {
            queue_copy(
                &db,
                pid,
                rid,
                &agent.agent_id,
                u.images.as_deref().unwrap_or(&[]),
            )?;
            queue_retention(
                &db,
                pid,
                rid,
                &agent.agent_id,
                u.images.as_deref().unwrap_or(&[]),
            )?;
            if let Some((subject, body)) = crate::extras::after_backup(
                &db,
                pid,
                rid,
                &agent.agent_id,
                u.images.as_deref().unwrap_or(&[]),
            )? {
                events.push(notify::Event {
                    severity: notify::Severity::Error,
                    subject,
                    body,
                    link: Some("/plans".into()),
                });
            }
        }
    }
    if let Some(JobKind::ScanImage { image_id, .. }) = &kind {
        if u.state.is_final() {
            if let Some((subject, body)) = crate::extras::record_scan(
                &db,
                &id.to_string(),
                &agent.agent_id,
                &image_id.to_string(),
                matches!(u.state, JobState::Succeeded | JobState::Warning),
                u.error.as_deref(),
                u.result.as_ref(),
            )? {
                events.push(notify::Event {
                    severity: notify::Severity::Error,
                    subject,
                    body,
                    link: Some("/restore".into()),
                });
            }
        }
    }
    if u.state.is_final() {
        let label = kind.as_ref().map(|k| k.label()).unwrap_or("Job");
        let settings: notify::NotifySettings = crate::db::get_setting(&db, notify::KEY);
        let link = Some(format!("/machines/{}", agent.agent_id));
        match u.state {
            // Browsing and connection tests show their errors where they were started.
            JobState::Failed
                if !matches!(
                    kind,
                    Some(JobKind::BrowseFiles { .. } | JobKind::CheckAccess { .. })
                ) =>
            {
                events.push(notify::Event {
                    severity: notify::Severity::Error,
                    subject: format!("{label} failed: {agent_name}"),
                    body: format!(
                        "{label} on {agent_name} failed.\n\n{}",
                        u.error.clone().unwrap_or_default()
                    ),
                    link,
                })
            }
            JobState::Warning if settings.on_warning && is_backup => events.push(notify::Event {
                severity: notify::Severity::Warning,
                subject: format!("{label} completed with warnings: {agent_name}"),
                body: u.warnings.join("\n"),
                link,
            }),
            _ => {}
        }
    }

    // eDiscovery: a case's search or export finished.
    if u.state.is_final() {
        let by: Option<String> = db
            .query_row(
                "SELECT requested_by FROM jobs WHERE id = ?1",
                params![id.to_string()],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        if let Some(by) = by.filter(|b| b.starts_with("case:")) {
            crate::cases::record_job(
                &db,
                &st,
                &id.to_string(),
                &by,
                u.state.as_str(),
                u.result.as_ref(),
                u.error.as_deref(),
            )?;
        }
    }
    // Storage health checks: the result goes on the repository; a newly
    // failing check raises an alert.
    if let (Some(JobKind::CheckAccess { .. }), Some(rid), true) =
        (&kind, &repo_id, u.state.is_final())
    {
        let by: Option<String> = db
            .query_row(
                "SELECT requested_by FROM jobs WHERE id = ?1",
                params![id.to_string()],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        if by.as_deref() == Some("storage check") {
            let error = match u.state {
                JobState::Succeeded | JobState::Warning => None,
                _ => Some(
                    u.error
                        .clone()
                        .unwrap_or_else(|| "the storage could not be reached".into()),
                ),
            };
            let (name, was): (String, Option<String>) = db.query_row(
                "SELECT name, storage_error FROM repositories WHERE id = ?1",
                params![rid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            db.execute(
                "UPDATE repositories SET storage_checked_at = ?1, storage_error = ?2 WHERE id = ?3",
                params![t, error, rid],
            )?;
            if let (Some(e), None) = (&error, &was) {
                events.push(notify::Event {
                    severity: notify::Severity::Error,
                    subject: format!("Storage of {name} cannot be reached"),
                    body: format!(
                        "The daily check of the repository {name}'s storage from {agent_name} failed: {e}\n\nBackups into it will fail until this is fixed (an expired key or password, a full disk, or a share or bucket that moved)."
                    ),
                    link: Some("/repositories".into()),
                });
            }
        }
    }
    // Adopting an existing repository: its first listing names it.
    if matches!(kind, Some(JobKind::ListImages)) && u.state.is_final() {
        if let Some(rid) = &repo_id {
            let (status, uuid): (String, String) = db.query_row(
                "SELECT status, repo_uuid FROM repositories WHERE id = ?1",
                params![rid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if status == "pending" && uuid.is_empty() {
                let (status, msg, got) = match (u.state, u.repo_uuid) {
                    (JobState::Succeeded | JobState::Warning, Some(got)) => {
                        let other: Option<String> = db
                            .query_row(
                                "SELECT name FROM repositories WHERE repo_uuid = ?1 AND id != ?2",
                                params![got.to_string(), rid],
                                |r| r.get(0),
                            )
                            .optional()?;
                        match other {
                            Some(n) => (
                                "failed",
                                Some(format!("this repository is already registered here as {n}")),
                                String::new(),
                            ),
                            None => ("ready", None, got.to_string()),
                        }
                    }
                    (JobState::Succeeded | JobState::Warning, None) => (
                        "failed",
                        Some(
                            "the machine did not report the repository's ID; update its agent"
                                .to_string(),
                        ),
                        String::new(),
                    ),
                    _ => ("failed", u.error.clone(), String::new()),
                };
                db.execute(
                    "UPDATE repositories SET status = ?1, status_message = ?2, repo_uuid = ?3 WHERE id = ?4",
                    params![status, msg, got, rid],
                )?;
            }
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
    drop(db);
    for ev in events {
        notify::send(&st, ev);
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}

fn check_anomaly(
    db: &rusqlite::Connection,
    repo: &str,
    im: &ImageReport,
) -> rusqlite::Result<Option<String>> {
    let mut stmt = db.prepare(
        "SELECT chunks_total, chunks_new, bytes_new_raw, stored_new_bytes FROM images
         WHERE machine_id = ?1 AND repository_id = ?2 AND image_id != ?3 AND chunks_total > 0
         ORDER BY created DESC LIMIT 10",
    )?;
    let hist: Vec<anomaly::Stats> = stmt
        .query_map(params![im.machine_id, repo, im.image_id.to_string()], |r| {
            Ok(anomaly::Stats {
                chunks_total: r.get::<_, i64>(0)? as u64,
                chunks_new: r.get::<_, i64>(1)? as u64,
                bytes_new_raw: r.get::<_, i64>(2)? as u64,
                bytes_new_stored: r.get::<_, i64>(3)? as u64,
            })
        })?
        .collect::<Result<_, _>>()?;
    let cur = anomaly::Stats {
        chunks_total: im.chunks_total,
        chunks_new: im.chunks_new,
        bytes_new_raw: im.bytes_new_raw,
        bytes_new_stored: im.stored_new_bytes,
    };
    Ok(anomaly::evaluate(&hist, &cur))
}

/// Queue retention for the machines a plan backup just imaged.
/// The plan's off-site copy of the images just taken, on the same machine.
fn queue_copy(
    db: &rusqlite::Connection,
    plan: &str,
    repo: &str,
    agent: &str,
    images: &[ImageReport],
) -> rusqlite::Result<()> {
    let target: Option<String> = db
        .query_row(
            "SELECT copy_to_repository_id FROM plans WHERE id = ?1",
            params![plan],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    let (Some(target), false) = (target, images.is_empty()) else {
        return Ok(());
    };
    let Ok(target_repository_id) = Uuid::parse_str(&target) else {
        return Ok(());
    };
    // A drive of an offline media set gets everything it does not have
    // yet (it may have been away for a while), not just this backup.
    let media: bool = db.query_row(
        "SELECT media_set IS NOT NULL FROM repositories WHERE id = ?1",
        params![target],
        |r| r.get(0),
    )?;
    let kind = JobKind::CopyImages {
        target_repository_id,
        images: if media {
            vec![]
        } else {
            images.iter().map(|i| i.image_id).collect()
        },
        full_verify: false,
    };
    db.execute(
        "INSERT INTO jobs (id, agent_id, repository_id, plan_id, kind_json, state, created, requested_by)
         VALUES (?1, ?2, ?3, ?4, ?5, 'queued', ?6, 'copy')",
        params![Uuid::new_v4().to_string(), agent, repo, plan, serde_json::to_string(&kind).unwrap_or_default(), now()],
    )?;
    Ok(())
}

fn queue_retention(
    db: &rusqlite::Connection,
    plan: &str,
    repo: &str,
    agent: &str,
    images: &[ImageReport],
) -> rusqlite::Result<()> {
    let ret: Option<Retention> = db
        .query_row(
            "SELECT retention_json FROM plans WHERE id = ?1",
            params![plan],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok());
    let Some(retention) = ret.filter(|r| !r.keeps_everything()) else {
        return Ok(());
    };
    let mut machine_ids: Vec<String> = images.iter().map(|i| i.machine_id.clone()).collect();
    machine_ids.sort();
    machine_ids.dedup();
    if machine_ids.is_empty() {
        return Ok(());
    }
    let held: Vec<Uuid> = {
        let mut q = db.prepare(
            "SELECT image_id FROM images WHERE repository_id = ?1 AND legal_hold_json IS NOT NULL ORDER BY image_id",
        )?;
        let rows: Vec<String> = q
            .query_map(params![repo], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        rows.iter()
            .filter_map(|s| Uuid::parse_str(s).ok())
            .collect()
    };
    let kind = JobKind::ApplyRetention {
        machine_ids,
        retention,
        dry_run: false,
        held: held.clone(),
    };
    // Served append-only through a gateway: only the gateway deletes old images.
    let agent: String = db
        .query_row(
            "SELECT COALESCE((SELECT r.gateway_agent_id FROM repositories r JOIN agents g ON g.id = r.gateway_agent_id
                              WHERE r.id = ?1 AND g.revoked = 0), ?2)",
            params![repo, agent],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| agent.to_string());
    let agent = agent.as_str();
    if !held.is_empty() {
        // An agent too old to know about legal hold would delete held images:
        // no retention until it is updated.
        let caps: Vec<String> = db
            .query_row(
                "SELECT inventory_json FROM agents WHERE id = ?1",
                params![agent],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .and_then(|s| serde_json::from_str::<protocol::Inventory>(&s).ok())
            .map(|i| i.capabilities)
            .unwrap_or_default();
        if !caps.iter().any(|c| c == "legal_hold") {
            crate::db::audit(
                db,
                "retention",
                "retention.skipped",
                &format!("repository {repo}: backups are on legal hold and the agent that applies retention needs an update"),
            );
            return Ok(());
        }
    }
    db.execute(
        "INSERT INTO jobs (id, agent_id, repository_id, plan_id, kind_json, state, created, requested_by)
         VALUES (?1, ?2, ?3, ?4, ?5, 'queued', ?6, 'retention')",
        params![Uuid::new_v4().to_string(), agent, repo, plan, serde_json::to_string(&kind).unwrap_or_default(), now()],
    )?;
    Ok(())
}

pub const UPDATE_KEY: &str = "updates";

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct UpdateSettings {
    /// None = default (on).
    #[serde(default)]
    pub auto_update: Option<bool>,
}

impl UpdateSettings {
    pub fn enabled(&self) -> bool {
        self.auto_update.unwrap_or(true)
    }
}

/// Largest screenshot stored per boot check.
const MAX_SCREENSHOT: usize = 4 << 20;

fn record_boot_check(
    db: &rusqlite::Connection,
    repo_id: &str,
    agent_id: &str,
    job_id: &str,
    b: &protocol::BootCheckResult,
) -> rusqlite::Result<()> {
    use base64::Engine;
    let shot = b
        .screenshot_png
        .as_deref()
        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
        .filter(|p| p.len() <= MAX_SCREENSHOT && p.starts_with(b"\x89PNG"));
    let outcome = match b.outcome.as_str() {
        "verified" | "screen" => b.outcome.as_str(),
        _ => "failed",
    };
    let clip = |s: &str, n: usize| s.chars().take(n).collect::<String>();
    db.execute(
        "INSERT INTO boot_checks (image_id, repository_id, agent_id, job_id, at, outcome, method, seconds, firmware, accel, message, screenshot, restore_test_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            b.image_id.to_string(),
            repo_id,
            agent_id,
            job_id,
            now(),
            outcome,
            clip(&b.method, 40),
            b.seconds as i64,
            clip(&b.firmware, 10),
            clip(&b.accel, 10),
            clip(&b.message, 1000),
            shot,
            b.restore_test
                .as_ref()
                .and_then(|t| serde_json::to_string(t).ok())
        ],
    )?;
    Ok(())
}
