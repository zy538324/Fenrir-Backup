//! Malware scans of backups (docs/design/malware-scan.md), search across a
//! machine's backups (search.md), restoring one SQL Server or Exchange
//! database (app-restore.md), legal hold of all of a machine's backups,
//! and the work queued after each plan backup: the file catalogue for
//! search, a scan when the plan asks for one, and the plan's standby VM
//! (cloud-restore.md §4).

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use protocol::{Inventory, JobKind};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::auth::Admin;
use crate::db::audit;
use crate::{now, ApiError, ApiResult, Shared};

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/images/{id}/scan", post(create_scan))
        .route("/api/images/{id}/scans", get(list_scans))
        .route("/api/images/{id}/restore-app", post(restore_app))
        .route(
            "/api/scan-content",
            get(get_scan_content).put(put_scan_content),
        )
        .route("/api/search", post(search))
        .route("/api/legal-hold/machine", post(hold_machine))
}

const FOLDER_PREFIX: &str = "files:";
const MAX_INDICATORS: usize = 500_000;
const MAX_FINDINGS: usize = 1000;
const SEARCH_MAX_IMAGES: usize = 500;
pub const VM_FILE_FORMATS: &[&str] = &["qcow2", "vdi", "vmdk"];

fn uuid(s: &str) -> ApiResult<String> {
    Uuid::parse_str(s)
        .map(|u| u.to_string())
        .map_err(|_| ApiError::bad("invalid id"))
}

pub fn caps(db: &Connection, agent: &str) -> Vec<String> {
    db.query_row(
        "SELECT inventory_json FROM agents WHERE id = ?1 AND revoked = 0",
        params![agent],
        |r| r.get::<_, Option<String>>(0),
    )
    .optional()
    .ok()
    .flatten()
    .flatten()
    .and_then(|s| serde_json::from_str::<Inventory>(&s).ok())
    .map(|i| i.capabilities)
    .unwrap_or_default()
}

fn has_access(db: &Connection, repo: &str, agent: &str) -> bool {
    db.query_row(
        "SELECT COUNT(*) FROM repo_access WHERE repository_id = ?1 AND agent_id = ?2",
        params![repo, agent],
        |r| r.get::<_, i64>(0),
    )
    .unwrap_or(0)
        > 0
}

fn online(db: &Connection, agent: &str) -> bool {
    db.query_row(
        "SELECT last_seen FROM agents WHERE id = ?1",
        params![agent],
        |r| r.get::<_, Option<i64>>(0),
    )
    .ok()
    .flatten()
    .is_some_and(|t| now() - t < 180)
}

fn queue(
    db: &Connection,
    agent: &str,
    kind: &JobKind,
    repo: Option<&str>,
    plan: Option<&str>,
    by: &str,
) -> ApiResult<String> {
    let id = Uuid::new_v4().to_string();
    db.execute(
        "INSERT INTO jobs (id, agent_id, repository_id, plan_id, kind_json, state, created, requested_by)
         VALUES (?1, ?2, ?3, ?4, ?5, 'queued', ?6, ?7)",
        params![id, agent, repo, plan, serde_json::to_string(kind)?, now(), by],
    )?;
    Ok(id)
}

struct ImageRow {
    repository_id: String,
    agent_id: Option<String>,
    what: String,
    applications: Value,
}

fn image(db: &Connection, id: &str) -> ApiResult<ImageRow> {
    db.query_row(
        "SELECT repository_id, agent_id, machine_id, COALESCE(vm_name, hostname), applications_json FROM images WHERE image_id = ?1",
        params![id],
        |r| {
            Ok(ImageRow {
                repository_id: r.get(0)?,
                agent_id: r.get(1)?,
                what: r.get(3)?,
                applications: r
                    .get::<_, Option<String>>(4)?
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or(json!([])),
            })
        },
    )
    .optional()?
    .ok_or_else(|| ApiError::not_found("no such image"))
}

pub fn is_folder_backup(machine_id: &str) -> bool {
    machine_id.starts_with(FOLDER_PREFIX)
}

// ---------------------------------------------------------------- scan content

/// The detection content scans use, kept by the administrator: YARA rules
/// and SHA-256 hashes of known malicious files.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanContent {
    #[serde(default)]
    pub rules: Vec<ScanRuleRow>,
    #[serde(default)]
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRuleRow {
    pub name: String,
    pub source: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

fn scan_content(db: &Connection) -> ApiResult<ScanContent> {
    let rules = db
        .prepare("SELECT name, source, enabled FROM scan_rules ORDER BY name")?
        .query_map([], |r| {
            Ok(ScanRuleRow {
                name: r.get(0)?,
                source: r.get(1)?,
                enabled: r.get::<_, i64>(2)? != 0,
            })
        })?
        .collect::<Result<_, _>>()?;
    let indicators = db
        .prepare("SELECT sha256 FROM scan_indicators ORDER BY sha256")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(ScanContent { rules, indicators })
}

async fn get_scan_content(State(st): State<Shared>, _a: Admin) -> ApiResult<Json<Value>> {
    let c = scan_content(&st.db())?;
    Ok(Json(
        json!({ "rules": c.rules, "indicators": c.indicators }),
    ))
}

async fn put_scan_content(
    State(st): State<Shared>,
    a: Admin,
    Json(c): Json<ScanContent>,
) -> ApiResult<Json<Value>> {
    let mut seen = std::collections::HashSet::new();
    for r in &c.rules {
        let n = r.name.trim();
        if n.is_empty() || n.len() > 200 || !seen.insert(n.to_string()) {
            return Err(ApiError::bad(
                "each rule needs a unique name of up to 200 characters",
            ));
        }
        if r.source.trim().is_empty() || r.source.len() > 1_000_000 {
            return Err(ApiError::bad(format!(
                "rule {n}: the source is empty or larger than 1 MB"
            )));
        }
    }
    let mut hashes: Vec<String> = c
        .indicators
        .iter()
        .map(|h| h.trim().to_lowercase())
        .filter(|h| !h.is_empty())
        .collect();
    if let Some(bad) = hashes
        .iter()
        .find(|h| h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(ApiError::bad(format!(
            "{bad} is not a SHA-256 hash (64 hex digits)"
        )));
    }
    hashes.sort();
    hashes.dedup();
    if hashes.len() > MAX_INDICATORS {
        return Err(ApiError::bad(format!("at most {MAX_INDICATORS} hashes")));
    }
    let mut db = st.db();
    let tx = db.transaction()?;
    tx.execute("DELETE FROM scan_rules", [])?;
    tx.execute("DELETE FROM scan_indicators", [])?;
    for r in &c.rules {
        tx.execute(
            "INSERT INTO scan_rules (name, source, enabled) VALUES (?1, ?2, ?3)",
            params![r.name.trim(), r.source, r.enabled],
        )?;
    }
    for h in &hashes {
        tx.execute(
            "INSERT INTO scan_indicators (sha256) VALUES (?1)",
            params![h],
        )?;
    }
    tx.commit()?;
    audit(
        &db,
        &a.username,
        "scan.content.updated",
        &format!("{} rules, {} hashes", c.rules.len(), hashes.len()),
    );
    Ok(Json(
        json!({ "rules": c.rules.len(), "indicators": hashes.len() }),
    ))
}

// ---------------------------------------------------------------- scans

fn scan_kind(db: &Connection, image_id: &str, selection: &str) -> ApiResult<JobKind> {
    let c = scan_content(db)?;
    Ok(JobKind::ScanImage {
        image_id: Uuid::parse_str(image_id).map_err(|_| ApiError::bad("invalid image id"))?,
        indicators: c.indicators,
        rules: c
            .rules
            .into_iter()
            .filter(|r| r.enabled)
            .map(|r| protocol::ScanRule {
                name: r.name,
                source: r.source,
            })
            .collect(),
        selection: selection.into(),
        max_file_mib: 64,
    })
}

/// The machine that scans: the one asked for, else the one the backup came
/// from, else any (online first) with access that can scan.
fn scan_agent(db: &Connection, im: &ImageRow, asked: Option<&str>) -> ApiResult<String> {
    let able = |a: &str| {
        caps(db, a).iter().any(|c| c == "scan_images") && has_access(db, &im.repository_id, a)
    };
    if let Some(a) = asked {
        let a = uuid(a)?;
        return if able(&a) {
            Ok(a)
        } else {
            Err(ApiError::bad(
                "that machine cannot scan this backup (it needs access to the repository and an up-to-date agent)",
            ))
        };
    }
    let mut c: Vec<String> = db
        .prepare("SELECT agent_id FROM repo_access WHERE repository_id = ?1")?
        .query_map(params![im.repository_id], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    c.retain(|a| able(a));
    c.sort_by_key(|a| (!online(db, a), Some(a) != im.agent_id.as_ref()));
    c.into_iter().next().ok_or_else(|| {
        ApiError::bad("no machine with access to this repository can scan backups yet: update its backup agent")
    })
}

#[derive(Deserialize)]
struct ScanReq {
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    all_files: bool,
}

async fn create_scan(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(r): Json<ScanReq>,
) -> ApiResult<Json<Value>> {
    let id = uuid(&id)?;
    let db = st.db();
    let im = image(&db, &id)?;
    let agent = scan_agent(&db, &im, r.agent_id.as_deref())?;
    let selection = if r.all_files { "all" } else { "executables" };
    let job = queue(
        &db,
        &agent,
        &scan_kind(&db, &id, selection)?,
        Some(&im.repository_id),
        None,
        &a.username,
    )?;
    audit(
        &db,
        &a.username,
        "scan.requested",
        &format!("{} {id} ({selection})", im.what),
    );
    Ok(Json(json!({ "id": job, "agent_id": agent })))
}

async fn list_scans(
    State(st): State<Shared>,
    _a: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<Value>>> {
    let id = uuid(&id)?;
    let db = st.db();
    let v = db
        .prepare(
            "SELECT s.id, s.at, s.state, s.files_scanned, s.bytes_scanned, s.findings_json, s.summary_json, s.agent_id,
                    COALESCE(a.display_name, a.hostname), s.job_id
             FROM scans s LEFT JOIN agents a ON a.id = s.agent_id WHERE s.image_id = ?1 ORDER BY s.at DESC, s.id DESC LIMIT 20",
        )?
        .query_map(params![id], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "at": r.get::<_, i64>(1)?, "state": r.get::<_, String>(2)?,
                "files_scanned": r.get::<_, i64>(3)?, "bytes_scanned": r.get::<_, i64>(4)?,
                "findings": r.get::<_, Option<String>>(5)?.and_then(|s| serde_json::from_str::<Value>(&s).ok()).unwrap_or(json!([])),
                "summary": r.get::<_, Option<String>>(6)?.and_then(|s| serde_json::from_str::<Value>(&s).ok()).unwrap_or(json!({})),
                "agent_id": r.get::<_, Option<String>>(7)?, "agent_name": r.get::<_, Option<String>>(8)?,
                "job_id": r.get::<_, Option<String>>(9)?,
            }))
        })?
        .collect::<Result<_, _>>()?;
    Ok(Json(v))
}

/// The latest scan of an image: (state, number of findings, files scanned, at).
pub fn latest_scan(db: &Connection, image_id: &str) -> Option<Value> {
    db.query_row(
        "SELECT state, findings_json, files_scanned, at FROM scans WHERE image_id = ?1 ORDER BY at DESC, id DESC LIMIT 1",
        params![image_id],
        |r| {
            let findings = r
                .get::<_, Option<String>>(1)?
                .and_then(|s| serde_json::from_str::<Vec<Value>>(&s).ok())
                .map(|v| v.len())
                .unwrap_or(0);
            Ok(json!({ "state": r.get::<_, String>(0)?, "findings": findings,
                       "files_scanned": r.get::<_, i64>(2)?, "at": r.get::<_, i64>(3)? }))
        },
    )
    .optional()
    .ok()
    .flatten()
}

fn cut(v: &Value, n: usize) -> String {
    v.as_str().unwrap_or("").chars().take(n).collect()
}

/// Store what a finished scan job found (paths and names only, bounded).
/// Returns a notification when malware was found.
pub fn record_scan(
    db: &Connection,
    job_id: &str,
    agent: &str,
    image_id: &str,
    succeeded: bool,
    error: Option<&str>,
    result: Option<&Value>,
) -> rusqlite::Result<Option<(String, String)>> {
    let Some((repo, what, created)): Option<(String, String, i64)> = db
        .query_row(
            "SELECT repository_id, COALESCE(vm_name, hostname), created FROM images WHERE image_id = ?1",
            params![image_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?
    else {
        return Ok(None);
    };
    let rep = result.and_then(|r| r.get("scan")).filter(|v| v.is_object());
    let insert = |state: &str, files: i64, bytes: i64, findings: &Value, summary: &Value| {
        db.execute(
            "INSERT INTO scans (image_id, repository_id, agent_id, job_id, at, state, files_scanned, bytes_scanned, findings_json, summary_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![image_id, repo, agent, job_id, now(), state, files, bytes, findings.to_string(), summary.to_string()],
        )
    };
    let Some(rep) = rep.filter(|_| succeeded) else {
        insert(
            "incomplete",
            0,
            0,
            &json!([]),
            &json!({ "error": error.unwrap_or("").chars().take(1000).collect::<String>() }),
        )?;
        return Ok(None);
    };
    let findings: Vec<Value> = rep["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .take(MAX_FINDINGS)
        .filter(|f| f.is_object())
        .map(|f| {
            json!({
                "volume": cut(&f["volume"], 200), "path": cut(&f["path"], 2000),
                "size": f["size"].as_u64().unwrap_or(0), "sha256": cut(&f["sha256"], 64).to_lowercase(),
                "detections": f["detections"].as_array().into_iter().flatten().take(20)
                    .map(|d| json!({ "kind": cut(&d["kind"], 10), "name": cut(&d["name"], 300) })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let scanned: Vec<String> = rep["volumes_scanned"]
        .as_array()
        .into_iter()
        .flatten()
        .take(50)
        .map(|v| cut(v, 200))
        .collect();
    let list = |k: &str| -> Vec<String> {
        rep[k]
            .as_array()
            .into_iter()
            .flatten()
            .take(50)
            .map(|v| cut(v, 500))
            .collect()
    };
    let summary = json!({
        "volumes_scanned": scanned, "volumes_skipped": list("volumes_skipped"), "rule_errors": list("rule_errors"),
        "truncated": rep["truncated"].as_bool().unwrap_or(false),
        "files_cached": rep["files_cached"].as_u64().unwrap_or(0),
        "files_skipped_large": rep["files_skipped_large"].as_u64().unwrap_or(0),
        "files_unreadable": rep["files_unreadable"].as_u64().unwrap_or(0),
        "rules_used": rep["rules_used"].as_u64().unwrap_or(0),
        "indicators_used": rep["indicators_used"].as_u64().unwrap_or(0),
    });
    let state = if !findings.is_empty() {
        "infected"
    } else if !scanned.is_empty() {
        "clean"
    } else {
        "incomplete"
    };
    insert(
        state,
        rep["files_scanned"].as_i64().unwrap_or(0),
        rep["bytes_scanned"].as_i64().unwrap_or(0),
        &json!(findings),
        &summary,
    )?;
    audit(
        db,
        &format!("agent:{agent}"),
        &format!("scan.{state}"),
        &format!("{what} {image_id}: {} findings", findings.len()),
    );
    if findings.is_empty() {
        return Ok(None);
    }
    let mut names: Vec<String> = findings
        .iter()
        .flat_map(|f| f["detections"].as_array().cloned().unwrap_or_default())
        .filter_map(|d| d["name"].as_str().map(str::to_string))
        .collect();
    names.sort();
    names.dedup();
    Ok(Some((
        format!("Malware found in a backup of {what}"),
        format!(
            "A scan of the backup of {what} taken at unix time {created} found {} infected file{} ({}). Restoring it brings them back: restore from a clean backup (the Restore page shows the last clean one), or restore and clean the files.",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" },
            names.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
        ),
    )))
}

/// Restoring what the latest scan found infected needs `allow_infected`: a
/// whole image when it has findings, chosen files when they are (or
/// contain) an infected file.
pub fn malware_guard(
    db: &Connection,
    image_id: &str,
    allow_infected: bool,
    paths: Option<&[String]>,
) -> ApiResult<()> {
    if allow_infected {
        return Ok(());
    }
    let row: Option<(String, Option<String>)> = db
        .query_row(
            "SELECT state, findings_json FROM scans WHERE image_id = ?1 ORDER BY at DESC, id DESC LIMIT 1",
            params![image_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((state, findings)) = row else {
        return Ok(());
    };
    if state != "infected" {
        return Ok(());
    }
    let hits: Vec<String> = findings
        .and_then(|s| serde_json::from_str::<Vec<Value>>(&s).ok())
        .unwrap_or_default()
        .iter()
        .filter_map(|f| f["path"].as_str().map(str::to_string))
        .filter(|h| {
            paths.is_none_or(|ps| {
                ps.iter().any(|sel| {
                    let a = sel.trim_end_matches('/').to_lowercase();
                    let b = h.to_lowercase();
                    a.is_empty() || b == a || b.starts_with(&format!("{a}/"))
                })
            })
        })
        .collect();
    if hits.is_empty() {
        return Ok(());
    }
    let n = hits.len();
    Err(ApiError::conflict(format!(
        "infected: the latest malware scan found {n} infected file{} in what you are restoring: {}{}. Restore anyway only if you will clean them.",
        if n == 1 { "" } else { "s" },
        hits.iter().take(10).cloned().collect::<Vec<_>>().join(", "),
        if n > 10 { ", ..." } else { "" }
    )))
}

/// Disk restores and boot checks need an image of disks.
pub fn disks_only(db: &Connection, image_id: &str, what: &str) -> ApiResult<()> {
    let m: Option<String> = db
        .query_row(
            "SELECT machine_id FROM images WHERE image_id = ?1",
            params![image_id],
            |r| r.get(0),
        )
        .optional()?;
    if m.as_deref().is_some_and(is_folder_backup) {
        return Err(ApiError::bad(format!(
            "this is a backup of files and folders: {what}; restore its files with Browse files"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------- one application database

#[derive(Deserialize)]
struct RestoreAppReq {
    agent_id: String,
    component: String,
    directory: String,
    #[serde(default)]
    attach_as: Option<String>,
    #[serde(default)]
    sql_instance: String,
    #[serde(default)]
    allow_infected: bool,
    /// Exchange: restore this mailbox from a recovery database, unattended.
    #[serde(default)]
    mailbox: Option<MailboxReq>,
}

#[derive(Deserialize)]
struct MailboxReq {
    source: String,
    target: String,
    #[serde(default)]
    folder: String,
    /// The target mailbox typed again: it writes into a live mailbox.
    #[serde(default)]
    confirm: String,
}

/// Checks an Exchange mailbox restore request (the agent checks it again).
fn mailbox_restore(
    writer: &str,
    m: Option<&MailboxReq>,
) -> ApiResult<Option<protocol::MailboxRestore>> {
    let Some(m) = m else { return Ok(None) };
    if !writer.to_ascii_lowercase().contains("exchange") {
        return Err(ApiError::bad(
            "a mailbox can only be restored from an Exchange database",
        ));
    }
    let (source, target, folder) = (m.source.trim(), m.target.trim(), m.folder.trim());
    let line =
        |s: &str, max: usize| !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control);
    if !line(source, 256)
        || !line(target, 320)
        || folder.len() > 255
        || folder.chars().any(char::is_control)
    {
        return Err(ApiError::bad(
            "give the mailbox in the backup and the mailbox to restore into, each on one line",
        ));
    }
    if !m.confirm.trim().eq_ignore_ascii_case(target) {
        return Err(ApiError::bad(
            "type the target mailbox again to confirm: items are written into that live mailbox",
        ));
    }
    Ok(Some(protocol::MailboxRestore {
        source: source.into(),
        target: target.into(),
        folder: folder.into(),
    }))
}

async fn restore_app(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(r): Json<RestoreAppReq>,
) -> ApiResult<Json<Value>> {
    let id = uuid(&id)?;
    let db = st.db();
    let im = image(&db, &id)?;
    malware_guard(&db, &id, r.allow_infected, None)?;
    let app = im
        .applications
        .as_array()
        .into_iter()
        .flatten()
        .find(|x| x["component"] == r.component.as_str())
        .cloned()
        .ok_or_else(|| ApiError::bad("this backup has no such application component"))?;
    if app["file_sets"].as_u64().unwrap_or(0) == 0 {
        return Err(ApiError::bad(
                "this backup does not list that component's files (taken by an older agent): restore the volume instead",
            ));
    }
    let agent = uuid(&r.agent_id)?;
    if !caps(&db, &agent).iter().any(|c| c == "restore_apps") {
        return Err(ApiError::bad(
                "that machine cannot restore application data (it must be a Windows machine with an up-to-date agent)",
            ));
    }
    if !has_access(&db, &im.repository_id, &agent) {
        return Err(ApiError::bad(
            "that machine has no access to the image's repository; give it access first",
        ));
    }
    let dir = r.directory.trim();
    let full = dir.len() >= 3 && dir.as_bytes()[0].is_ascii_alphabetic() && &dir[1..3] == ":\\"
        || dir.starts_with("\\\\");
    if !full || dir.len() > 500 {
        return Err(ApiError::bad(
            "choose a full folder path on that machine, e.g. D:\\Restores",
        ));
    }
    let attach = r
        .attach_as
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let mailbox = mailbox_restore(app["writer"].as_str().unwrap_or(""), r.mailbox.as_ref())?;
    let instance = r.sql_instance.trim().to_string();
    if let Some(n) = &attach {
        if app["writer"] != "SqlServerWriter" {
            return Err(ApiError::bad("only SQL Server databases can be attached"));
        }
        if n.chars().count() > 128 || n.chars().any(|c| (c as u32) < 32) {
            return Err(ApiError::bad("database names are up to 128 characters"));
        }
        let ok_inst = instance.len() <= 200
            && instance.split_once('\\').map_or(
                instance
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c)),
                |(h, i)| {
                    h.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
                        && !i.is_empty()
                        && i.chars()
                            .all(|c| c.is_ascii_alphanumeric() || "_$-".contains(c))
                },
            );
        if !ok_inst {
            return Err(ApiError::bad(
                "SQL Server instance: blank for the default, or SERVER\\INSTANCE",
            ));
        }
    }
    let kind = JobKind::RestoreApplication {
        image_id: Uuid::parse_str(&id).expect("checked"),
        component: r.component.clone(),
        directory: dir.to_string(),
        attach_as: attach.clone(),
        sql_instance: instance,
        mailbox: mailbox.clone(),
    };
    let job = queue(
        &db,
        &agent,
        &kind,
        Some(&im.repository_id),
        None,
        &a.username,
    )?;
    audit(
        &db,
        &a.username,
        "restore.application",
        &format!(
            "{} {id}: {} to {dir}{}{}{}",
            im.what,
            r.component,
            attach.map(|n| format!(" as {n}")).unwrap_or_default(),
            mailbox
                .map(|m| format!(", mailbox {} into {}", m.source, m.target))
                .unwrap_or_default(),
            if r.allow_infected {
                " (infected files acknowledged)"
            } else {
                ""
            }
        ),
    );
    Ok(Json(json!({ "id": job })))
}

// ---------------------------------------------------------------- search across backups

#[derive(Deserialize)]
struct SearchReq {
    query: String,
    /// One machine's backups (its machine ID); empty: every backup.
    #[serde(default)]
    machine_id: Option<String>,
}

async fn search(
    State(st): State<Shared>,
    a: Admin,
    Json(r): Json<SearchReq>,
) -> ApiResult<Json<Value>> {
    let q = r.query.trim();
    if q.is_empty() || q.chars().count() > 200 {
        return Err(ApiError::bad(
            "type part of a file or folder name (up to 200 characters)",
        ));
    }
    let db = st.db();
    let rows: Vec<(String, String, Option<String>)> = db
        .prepare(
            "SELECT image_id, repository_id, agent_id FROM images
             WHERE (?1 IS NULL OR machine_id = ?1) ORDER BY created DESC",
        )?
        .query_map(
            params![r.machine_id.as_deref().filter(|m| !m.is_empty())],
            |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?)),
        )?
        .collect::<Result<_, _>>()?;
    if rows.is_empty() {
        return Err(ApiError::bad("no backups to search"));
    }
    // Per repository: its images (newest first) and the machine each came from.
    type Images = Vec<(String, Option<String>)>;
    let mut by_repo: Vec<(String, Images)> = Vec::new();
    for (img, repo, agent) in rows {
        match by_repo.iter_mut().find(|(r, _)| *r == repo) {
            Some((_, v)) => v.push((img, agent)),
            None => by_repo.push((repo, vec![(img, agent)])),
        }
    }
    let mut jobs = Vec::new();
    for (repo, images) in by_repo {
        let mut c: Vec<String> = db
            .prepare("SELECT agent_id FROM repo_access WHERE repository_id = ?1")?
            .query_map(params![repo], |x| x.get(0))?
            .collect::<Result<_, _>>()?;
        c.retain(|ag| caps(&db, ag).iter().any(|x| x == "search_files"));
        c.sort_by_key(|ag| (!online(&db, ag), Some(ag) != images[0].1.as_ref()));
        let Some(agent) = c.into_iter().next() else {
            continue;
        };
        let ids: Vec<Uuid> = images
            .iter()
            .take(SEARCH_MAX_IMAGES)
            .filter_map(|(i, _)| Uuid::parse_str(i).ok())
            .collect();
        let n = ids.len();
        let job = queue(
            &db,
            &agent,
            &JobKind::SearchFiles {
                query: q.to_string(),
                images: ids,
                limit: 500,
                budget_secs: 120,
            },
            Some(&repo),
            None,
            &a.username,
        )?;
        let name: String = db.query_row(
            "SELECT COALESCE(display_name, hostname) FROM agents WHERE id = ?1",
            params![agent],
            |x| x.get(0),
        )?;
        jobs.push(
            json!({ "id": job, "repository_id": repo, "agent_id": agent, "agent_name": name,
                          "agent_online": online(&db, &agent), "images": n }),
        );
    }
    if jobs.is_empty() {
        return Err(ApiError::bad(
            "no machine with access to these backups can search them yet: update its backup agent",
        ));
    }
    audit(
        &db,
        &a.username,
        "search",
        &format!("{q:?} in {} repositories", jobs.len()),
    );
    Ok(Json(json!({ "jobs": jobs })))
}

// ---------------------------------------------------------------- legal hold of a machine

#[derive(Deserialize)]
struct HoldMachineReq {
    machine_id: String,
    reason: String,
}

/// Hold every current backup of a machine (later backups are not held).
async fn hold_machine(
    State(st): State<Shared>,
    a: Admin,
    Json(r): Json<HoldMachineReq>,
) -> ApiResult<Json<Value>> {
    let reason = r.reason.trim();
    if !(3..=500).contains(&reason.chars().count()) {
        return Err(ApiError::bad(
            "say why the backups are held (a case or matter reference), 3 to 500 characters",
        ));
    }
    let db = st.db();
    let v = json!({ "reason": reason, "by": a.username, "at": now() }).to_string();
    let mut n = db.execute(
        "UPDATE images SET legal_hold_json = ?1 WHERE machine_id = ?2 AND legal_hold_json IS NULL",
        params![v, r.machine_id],
    )?;
    // Backups an eDiscovery case holds get this hold too (kept when the case closes).
    let case_held: Vec<(String, String)> = db
        .prepare("SELECT image_id, legal_hold_json FROM images WHERE machine_id = ?1 AND legal_hold_json IS NOT NULL")?
        .query_map(params![r.machine_id], |x| Ok((x.get(0)?, x.get(1)?)))?
        .collect::<Result<_, _>>()?;
    for (img, cur) in case_held {
        let cur: Value = serde_json::from_str(&cur).unwrap_or_default();
        if cur["case_only"] == true {
            let mut nv = json!({ "reason": reason, "by": a.username, "at": now() });
            nv["cases"] = cur["cases"].clone();
            db.execute(
                "UPDATE images SET legal_hold_json = ?1 WHERE image_id = ?2",
                params![nv.to_string(), img],
            )?;
            n += 1;
        }
    }
    let total: i64 = db.query_row(
        "SELECT COUNT(*) FROM images WHERE machine_id = ?1",
        params![r.machine_id],
        |x| x.get(0),
    )?;
    if total == 0 {
        return Err(ApiError::not_found("no backups of that machine"));
    }
    audit(
        &db,
        &a.username,
        "image.legal_hold.placed",
        &format!("{}: {n} backups: {reason}", r.machine_id),
    );
    Ok(Json(json!({ "held": n })))
}

// ---------------------------------------------------------------- after each plan backup

/// A plan's standby VM, as stored with the plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Standby {
    pub agent_id: String,
    /// "hyperv_vm" or "vm_files".
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub format: Option<String>,
    pub name: String,
    pub directory: String,
}

/// Check a standby: a host with access to the repository that can make that kind of VM.
pub fn check_standby(db: &Connection, s: &Standby, repo: &str) -> ApiResult<Standby> {
    let host = uuid(&s.agent_id)?;
    let c = caps(db, &host);
    match s.kind.as_str() {
        "hyperv_vm" if c.iter().any(|x| x == "restore_hyperv") => {}
        "hyperv_vm" => return Err(ApiError::bad("the standby host must be a Hyper-V host")),
        "vm_files"
            if c.iter().any(|x| x == "restore_vm_files")
                && s.format.as_deref().is_some_and(|f| VM_FILE_FORMATS.contains(&f)) => {}
        "vm_files" => {
            return Err(ApiError::bad(
                "choose QEMU (qcow2), VirtualBox (vdi) or VMware (vmdk) files on a machine with an up-to-date agent",
            ))
        }
        _ => return Err(ApiError::bad("a standby is a Hyper-V VM or VM files")),
    }
    if !vm_name_ok(&s.name) || s.directory.trim().is_empty() || s.directory.len() > 500 {
        return Err(ApiError::bad(
            "choose a standby VM name (letters, digits, spaces, dots, hyphens, underscores) and a folder on the host",
        ));
    }
    if !has_access(db, repo, &host) {
        return Err(ApiError::bad(
            "the standby host has no access to the plan's repository; give it access first",
        ));
    }
    Ok(Standby {
        agent_id: host,
        kind: s.kind.clone(),
        format: (s.kind == "vm_files").then(|| s.format.clone()).flatten(),
        name: s.name.clone(),
        directory: s.directory.trim().to_string(),
    })
}

pub fn vm_name_ok(n: &str) -> bool {
    let ok = |c: char| c.is_ascii_alphanumeric() || "._-".contains(c);
    !n.is_empty()
        && n.len() <= 80
        && n.chars().all(|c| ok(c) || c == ' ')
        && n.chars().next().is_some_and(ok)
        && n.chars().last().is_some_and(ok)
}

/// After a successful plan backup: the file catalogue of each new image (for
/// search), a malware scan when the plan asks for one, and the standby VM.
pub fn after_backup(
    db: &Connection,
    plan: &str,
    repo: &str,
    agent: &str,
    images: &[protocol::ImageReport],
) -> ApiResult<Option<(String, String)>> {
    let c = caps(db, agent);
    let who = format!("agent:{agent}");
    if c.iter().any(|x| x == "search_files") {
        // Disk images and folder backups have file catalogues; SaaS backups
        // carry their own index, and Kubernetes and CDP images have none.
        for im in images.iter().filter(|i| {
            !["saas:", "k8s:", "cdp:"]
                .iter()
                .any(|p| i.machine_id.starts_with(p))
        }) {
            queue(
                db,
                agent,
                &JobKind::IndexImage {
                    image_id: im.image_id,
                },
                Some(repo),
                Some(plan),
                &who,
            )?;
        }
    }
    let (scan, standby): (i64, Option<String>) = db
        .query_row(
            "SELECT scan_after_backup, standby_json FROM plans WHERE id = ?1",
            params![plan],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .unwrap_or((0, None));
    if scan != 0 && c.iter().any(|x| x == "scan_images") {
        for im in images {
            let k = scan_kind(db, &im.image_id.to_string(), "executables")?;
            queue(db, agent, &k, Some(repo), Some(plan), &who)?;
        }
    }
    let Some(sb) = standby.and_then(|s| serde_json::from_str::<Standby>(&s).ok()) else {
        return Ok(None);
    };
    let Some(newest) = images.last() else {
        return Ok(None);
    };
    if !has_access(db, repo, &sb.agent_id) {
        return Ok(Some((
            format!("Standby VM not updated: {}", sb.name),
            format!("The standby host has no access to the plan's repository, so the standby VM {} was not updated. Give it access on the Repositories page.", sb.name),
        )));
    }
    let target = if sb.kind == "vm_files" {
        protocol::RestoreTarget::VmFiles {
            format: sb.format.clone().unwrap_or_else(|| "qcow2".into()),
            name: sb.name.clone(),
            directory: sb.directory.clone(),
            replace: true,
        }
    } else {
        protocol::RestoreTarget::HypervVm {
            name: sb.name.clone(),
            directory: sb.directory.clone(),
            switch: None,
            start: false,
            replace: true,
        }
    };
    queue(
        db,
        &sb.agent_id,
        &JobKind::Restore {
            image_id: newest.image_id,
            disks: vec![],
            target,
        },
        Some(repo),
        Some(plan),
        "standby",
    )?;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(source: &str, target: &str, confirm: &str) -> MailboxReq {
        MailboxReq {
            source: source.into(),
            target: target.into(),
            folder: "Restored".into(),
            confirm: confirm.into(),
        }
    }

    #[test]
    fn mailbox_restore_needs_exchange_both_mailboxes_and_a_typed_confirmation() {
        let w = "Microsoft Exchange Writer";
        assert_eq!(mailbox_restore(w, None).unwrap(), None);
        let ok = mailbox_restore(
            w,
            Some(&req(" Anna Smith ", "anna@example.com", "ANNA@example.com")),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            (ok.source.as_str(), ok.target.as_str(), ok.folder.as_str()),
            ("Anna Smith", "anna@example.com", "Restored")
        );
        assert!(mailbox_restore("SqlServerWriter", Some(&req("a", "b", "b"))).is_err());
        assert!(mailbox_restore(w, Some(&req("a", "b", ""))).is_err());
        assert!(mailbox_restore(w, Some(&req("", "b", "b"))).is_err());
        assert!(mailbox_restore(w, Some(&req("a\nb", "b", "b"))).is_err());
    }
}
