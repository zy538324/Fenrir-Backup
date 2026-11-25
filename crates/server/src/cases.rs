//! eDiscovery cases over backups (docs/design/ediscovery.md): custodians'
//! backups held while the case is open (and later ones when asked),
//! searches kept with the case, exports made on a machine with access and
//! encrypted for the browser with a SHA-256 manifest, and the case's
//! chain-of-custody manifest.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use protocol::{JobKind, VolumeRef};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::Admin;
use crate::db::audit;
use crate::extras::caps;
use crate::{now, ApiError, ApiResult, Shared};

const MAX_HITS: usize = 5000;
const KINDS: &[&str] = &[
    "mail",
    "file",
    "site-file",
    "record",
    "teams-message",
    "directory",
];

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/cases", get(list).post(create))
        .route("/api/cases/{id}", get(get_case).patch(update))
        .route("/api/cases/{id}/close", post(close))
        .route("/api/cases/{id}/search", post(search))
        .route("/api/cases/{id}/export", post(export))
        .route("/api/cases/{id}/exports/{eid}/receipt", post(receipt))
        .route("/api/cases/{id}/manifest", get(manifest))
}

#[derive(Debug, Clone, serde::Serialize, Deserialize, PartialEq)]
pub struct Custodian {
    /// The machine ID images carry (`saas:m365:contoso` for a tenant).
    pub machine_id: String,
    #[serde(default)]
    pub label: String,
    /// SaaS custodians: only these accounts (empty: the whole tenant).
    #[serde(default)]
    pub accounts: Vec<String>,
}

struct Case {
    id: String,
    name: String,
    matter: String,
    description: String,
    status: String,
    custodians: Vec<Custodian>,
    hold_new: bool,
    searches: Vec<Value>,
    exports: Vec<Value>,
    created_by: String,
    created: i64,
    closed_by: Option<String>,
    closed: Option<i64>,
}

fn load(db: &Connection, id: &str) -> ApiResult<Case> {
    db.query_row(
        "SELECT id, name, matter, description, status, custodians_json, hold_new, searches_json, exports_json,
                created_by, created, closed_by, closed FROM cases WHERE id = ?1",
        params![id],
        |r| {
            let js = |i: usize| -> rusqlite::Result<Vec<Value>> {
                Ok(serde_json::from_str(&r.get::<_, String>(i)?).unwrap_or_default())
            };
            Ok(Case {
                id: r.get(0)?,
                name: r.get(1)?,
                matter: r.get(2)?,
                description: r.get(3)?,
                status: r.get(4)?,
                custodians: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
                hold_new: r.get::<_, i64>(6)? != 0,
                searches: js(7)?,
                exports: js(8)?,
                created_by: r.get(9)?,
                created: r.get(10)?,
                closed_by: r.get(11)?,
                closed: r.get(12)?,
            })
        },
    )
    .optional()?
    .ok_or_else(|| ApiError::not_found("no such case"))
}

fn save(db: &Connection, c: &Case) -> ApiResult<()> {
    db.execute(
        "UPDATE cases SET description = ?2, status = ?3, custodians_json = ?4, hold_new = ?5, searches_json = ?6,
                exports_json = ?7, closed_by = ?8, closed = ?9 WHERE id = ?1",
        params![
            c.id,
            c.description,
            c.status,
            serde_json::to_string(&c.custodians)?,
            c.hold_new as i64,
            serde_json::to_string(&c.searches)?,
            serde_json::to_string(&c.exports)?,
            c.closed_by,
            c.closed
        ],
    )?;
    Ok(())
}

fn held_count(db: &Connection, id: &str) -> ApiResult<usize> {
    Ok(holds_of(db, id)?.len())
}

fn holds_of(db: &Connection, id: &str) -> ApiResult<Vec<(String, String, i64, String)>> {
    let mut s = db.prepare(
        "SELECT image_id, COALESCE(vm_name, hostname), created, repository_id, legal_hold_json FROM images
         WHERE legal_hold_json IS NOT NULL ORDER BY created",
    )?;
    let rows = s.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (img, what, created, repo, hold) = row?;
        let v: Value = serde_json::from_str(&hold).unwrap_or_default();
        if v["cases"]
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x == id))
        {
            out.push((img, what, created, repo));
        }
    }
    Ok(out)
}

fn out(db: &Connection, c: &Case, full: bool) -> ApiResult<Value> {
    let mut v = json!({
        "id": c.id, "name": c.name, "matter": c.matter, "description": c.description, "status": c.status,
        "custodians": c.custodians, "hold_new": c.hold_new, "held_backups": held_count(db, &c.id)?,
        "created_by": c.created_by, "created": c.created, "closed_by": c.closed_by, "closed": c.closed,
        "search_count": c.searches.len(), "export_count": c.exports.len(),
    });
    if full {
        v["searches"] = json!(c.searches);
        v["exports"] = json!(c.exports);
    }
    Ok(v)
}

/// Put an image on hold for `case`, or add the case to its hold.
fn hold(
    db: &Connection,
    image: &str,
    current: Option<String>,
    c: &Case,
    by: &str,
) -> ApiResult<bool> {
    let mut v: Value = current
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(Value::Null);
    let mut cases: Vec<Value> = v["cases"].as_array().cloned().unwrap_or_default();
    if cases.iter().any(|x| x == &c.id) {
        return Ok(false);
    }
    if v.is_null() {
        let reason = if c.matter.is_empty() {
            format!("eDiscovery case {}", c.name)
        } else {
            format!("eDiscovery case {} ({})", c.name, c.matter)
        };
        v = json!({ "reason": reason, "by": by, "at": now(), "case_only": true });
    }
    cases.push(json!(c.id));
    v["cases"] = json!(cases);
    db.execute(
        "UPDATE images SET legal_hold_json = ?1 WHERE image_id = ?2",
        params![v.to_string(), image],
    )?;
    Ok(true)
}

fn release(db: &Connection, image: &str, current: &str, case: &str) -> ApiResult<bool> {
    let mut v: Value = serde_json::from_str(current).unwrap_or_default();
    let before = v["cases"].as_array().cloned().unwrap_or_default();
    let cases: Vec<Value> = before.iter().filter(|x| *x != case).cloned().collect();
    if cases.len() == before.len() {
        return Ok(false);
    }
    let new = if cases.is_empty() && v["case_only"] == true {
        None
    } else {
        v["cases"] = json!(cases);
        Some(v.to_string())
    };
    db.execute(
        "UPDATE images SET legal_hold_json = ?1 WHERE image_id = ?2",
        params![new, image],
    )?;
    Ok(true)
}

/// Hold the custodians' backups while the case is open; release the
/// others this case holds (all of them once it is closed).
fn apply_holds(db: &Connection, c: &Case, by: &str) -> ApiResult<(usize, usize)> {
    let open = c.status == "open";
    let rows: Vec<(String, String, Option<String>)> = db
        .prepare("SELECT image_id, machine_id, legal_hold_json FROM images")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let (mut held, mut released) = (0, 0);
    for (img, machine, current) in rows {
        if open && c.custodians.iter().any(|x| x.machine_id == machine) {
            held += hold(db, &img, current, c, by)? as usize;
        } else if let Some(cur) = current {
            released += release(db, &img, &cur, &c.id)? as usize;
        }
    }
    Ok((held, released))
}

/// A new backup recorded: held by every open case that holds its
/// machine's later backups.
pub fn hold_new_image(db: &Connection, image: &str, machine: &str) -> ApiResult<()> {
    let ids: Vec<String> = db
        .prepare("SELECT id FROM cases WHERE status = 'open' AND hold_new = 1")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    for id in ids {
        let c = load(db, &id)?;
        if c.custodians.iter().any(|x| x.machine_id == machine) {
            let current: Option<String> = db.query_row(
                "SELECT legal_hold_json FROM images WHERE image_id = ?1",
                params![image],
                |r| r.get(0),
            )?;
            hold(db, image, current, &c, &format!("case:{id}"))?;
        }
    }
    Ok(())
}

/// A case's search or export finished (requested_by `case:ID:search:SID`
/// or `case:ID:export:EID`): keep the matches, or the export's hashes.
pub fn record_job(
    db: &Connection,
    st: &Shared,
    job: &str,
    requested_by: &str,
    state: &str,
    result: Option<&Value>,
    error: Option<&str>,
) -> ApiResult<()> {
    let parts: Vec<&str> = requested_by.split(':').collect();
    let [_, id, what, entry] = parts[..] else {
        return Ok(());
    };
    let Ok(mut c) = load(db, id) else {
        return Ok(());
    };
    let empty = json!({});
    let result = result.unwrap_or(&empty);
    if what == "search" {
        let machines: Vec<(String, String)> = db
            .prepare("SELECT image_id, machine_id FROM images")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        for s in c.searches.iter_mut().filter(|s| s["id"] == entry) {
            let mut hits = s["hits"].as_array().cloned().unwrap_or_default();
            for h in result["hits"].as_array().into_iter().flatten() {
                if hits.len() >= MAX_HITS {
                    s["truncated"] = json!(true);
                    break;
                }
                if let Some(acc) = h["account"].as_str() {
                    let machine = machines
                        .iter()
                        .find(|(i, _)| Some(i.as_str()) == h["image_id"].as_str())
                        .map(|(_, m)| m.as_str());
                    let allowed = c
                        .custodians
                        .iter()
                        .find(|x| Some(x.machine_id.as_str()) == machine)
                        .map(|x| x.accounts.clone())
                        .unwrap_or_default();
                    if !allowed.is_empty() && !allowed.iter().any(|a| a.eq_ignore_ascii_case(acc)) {
                        continue;
                    }
                }
                hits.push(h.clone());
            }
            s["hits"] = json!(hits);
            if result["truncated"] == true {
                s["truncated"] = json!(true);
            }
            let mut done: Vec<Value> = s["done"].as_array().cloned().unwrap_or_default();
            done.push(json!(job));
            let all = s["jobs"].as_array().cloned().unwrap_or_default();
            if all.iter().all(|j| done.contains(j)) {
                s["state"] = json!("done");
            }
            s["done"] = json!(done);
            if let Some(e) = error {
                s["error"] = json!(e);
            }
        }
    } else if what == "export" {
        let path = st.cfg.downloads_dir.join(format!("{job}.bin"));
        let cipher = std::fs::read(&path)
            .ok()
            .map(|b| (hex::encode(Sha256::digest(&b)), b.len()));
        for e in c.exports.iter_mut().filter(|e| e["id"] == entry) {
            e["state"] = json!(state);
            e["finished"] = json!(now());
            e["manifest_sha256"] = result["manifest_sha256"].clone();
            e["manifest_entries"] = result["manifest_files"].clone();
            e["error"] = json!(error);
            if let Some((h, n)) = &cipher {
                e["ciphertext_sha256"] = json!(h);
                e["ciphertext_bytes"] = json!(n);
            }
        }
    } else {
        return Ok(());
    }
    save(db, &c)?;
    audit(
        db,
        "agent",
        &format!("case.{what}_finished"),
        &format!("case {id}: job {job} {state}"),
    );
    Ok(())
}

fn custodians(db: &Connection, raw: Vec<Custodian>) -> ApiResult<Vec<Custodian>> {
    if raw.len() > 200 {
        return Err(ApiError::bad("up to 200 custodians"));
    }
    raw.into_iter()
        .map(|mut c| {
            let label: Option<String> = db
                .query_row(
                    "SELECT COALESCE(vm_name, hostname) FROM images WHERE machine_id = ?1 ORDER BY created DESC LIMIT 1",
                    params![c.machine_id],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(label) = label else {
                return Err(ApiError::bad("each custodian must be a machine or cloud tenant with backups"));
            };
            if !c.accounts.is_empty() && !c.machine_id.starts_with("saas:") {
                return Err(ApiError::bad("accounts can be chosen only for cloud-service custodians"));
            }
            c.accounts.retain(|a| !a.trim().is_empty());
            c.accounts.truncate(500);
            if c.label.trim().is_empty() {
                c.label = label;
            }
            Ok(c)
        })
        .collect()
}

async fn list(State(st): State<Shared>, _a: Admin) -> ApiResult<Json<Value>> {
    let db = st.db();
    let ids: Vec<String> = db
        .prepare("SELECT id FROM cases ORDER BY created DESC")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut v = Vec::new();
    for id in ids {
        v.push(out(&db, &load(&db, &id)?, false)?);
    }
    Ok(Json(json!(v)))
}

#[derive(Deserialize)]
struct CreateReq {
    name: String,
    #[serde(default)]
    matter: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    custodians: Vec<Custodian>,
    #[serde(default = "yes")]
    hold_new: bool,
}

fn yes() -> bool {
    true
}

async fn create(
    State(st): State<Shared>,
    a: Admin,
    Json(r): Json<CreateReq>,
) -> ApiResult<Json<Value>> {
    let name = r.name.trim();
    if !(3..=200).contains(&name.chars().count()) {
        return Err(ApiError::bad("name the case (3 to 200 characters)"));
    }
    let db = st.db();
    let id = Uuid::new_v4().to_string();
    let cust = custodians(&db, r.custodians)?;
    db.execute(
        "INSERT INTO cases (id, name, matter, description, status, custodians_json, hold_new, searches_json, exports_json, created_by, created)
         VALUES (?1, ?2, ?3, ?4, 'open', ?5, ?6, '[]', '[]', ?7, ?8)",
        params![id, name, r.matter.trim().chars().take(200).collect::<String>(),
                r.description.chars().take(5000).collect::<String>(), serde_json::to_string(&cust)?,
                r.hold_new as i64, a.username, now()],
    )?;
    let c = load(&db, &id)?;
    let (held, _) = apply_holds(&db, &c, &a.username)?;
    audit(
        &db,
        &a.username,
        "case.created",
        &format!(
            "case {id} {name}: {} custodians, {held} backups held",
            cust.len()
        ),
    );
    Ok(Json(out(&db, &c, true)?))
}

async fn get_case(
    State(st): State<Shared>,
    _a: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let db = st.db();
    Ok(Json(out(&db, &load(&db, &id)?, true)?))
}

#[derive(Deserialize)]
struct UpdateReq {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    hold_new: Option<bool>,
    #[serde(default)]
    custodians: Option<Vec<Custodian>>,
}

async fn update(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(r): Json<UpdateReq>,
) -> ApiResult<Json<Value>> {
    let db = st.db();
    let mut c = load(&db, &id)?;
    if c.status != "open" {
        return Err(ApiError::bad("the case is closed"));
    }
    if let Some(d) = r.description {
        c.description = d.chars().take(5000).collect();
    }
    if let Some(h) = r.hold_new {
        c.hold_new = h;
    }
    let mut changed = (0, 0);
    if let Some(cs) = r.custodians {
        c.custodians = custodians(&db, cs)?;
        save(&db, &c)?;
        changed = apply_holds(&db, &c, &a.username)?;
    }
    save(&db, &c)?;
    audit(
        &db,
        &a.username,
        "case.updated",
        &format!(
            "case {id}: {} custodians, {} held, {} released",
            c.custodians.len(),
            changed.0,
            changed.1
        ),
    );
    Ok(Json(out(&db, &c, true)?))
}

#[derive(Deserialize)]
struct CloseReq {
    password: String,
}

async fn close(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(r): Json<CloseReq>,
) -> ApiResult<Json<Value>> {
    let db = st.db();
    let hash: String = db.query_row(
        "SELECT password_hash FROM users WHERE id = ?1",
        params![a.user_id],
        |x| x.get(0),
    )?;
    if !crate::auth::verify_password(&r.password, &hash) {
        return Err(ApiError::bad("enter your password to close the case"));
    }
    let mut c = load(&db, &id)?;
    if c.status != "open" {
        return Err(ApiError::bad("the case is already closed"));
    }
    c.status = "closed".into();
    c.closed_by = Some(a.username.clone());
    c.closed = Some(now());
    save(&db, &c)?;
    let (_, released) = apply_holds(&db, &c, &a.username)?;
    audit(
        &db,
        &a.username,
        "case.closed",
        &format!("case {id}: {released} holds released"),
    );
    Ok(Json(out(&db, &c, true)?))
}

/// An image of a custodian: (image, repository, agent, machine).
type CustodianImage = (String, String, Option<String>, String);

fn custodian_images(db: &Connection, c: &Case) -> ApiResult<Vec<CustodianImage>> {
    let rows: Vec<CustodianImage> = db
        .prepare("SELECT image_id, repository_id, agent_id, machine_id FROM images ORDER BY created DESC")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<Result<_, _>>()?;
    Ok(rows
        .into_iter()
        .filter(|(_, _, _, m)| c.custodians.iter().any(|x| &x.machine_id == m))
        .collect())
}

/// The machine with access to `repo` that has `cap`: the one the backup
/// came from first, then online ones.
fn pick(db: &Connection, repo: &str, cap: &str, prefer: Option<&str>) -> ApiResult<Option<String>> {
    let mut c: Vec<(String, Option<i64>)> = db
        .prepare("SELECT x.agent_id, a.last_seen FROM repo_access x JOIN agents a ON a.id = x.agent_id WHERE x.repository_id = ?1 AND a.revoked = 0")?
        .query_map(params![repo], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    c.retain(|(ag, _)| caps(db, ag).iter().any(|x| x == cap));
    c.sort_by_key(|(ag, seen)| {
        (
            Some(ag.as_str()) != prefer,
            !seen.is_some_and(|t| now() - t < 180),
        )
    });
    Ok(c.into_iter().next().map(|(a, _)| a))
}

fn queue(db: &Connection, agent: &str, kind: &JobKind, repo: &str, by: &str) -> ApiResult<String> {
    let id = Uuid::new_v4().to_string();
    db.execute(
        "INSERT INTO jobs (id, agent_id, repository_id, kind_json, state, created, requested_by) VALUES (?1, ?2, ?3, ?4, 'queued', ?5, ?6)",
        params![id, agent, repo, serde_json::to_string(kind)?, now(), by],
    )?;
    Ok(id)
}

#[derive(Deserialize)]
struct SearchReq {
    query: String,
}

async fn search(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(r): Json<SearchReq>,
) -> ApiResult<Json<Value>> {
    let q = r.query.trim();
    if q.is_empty() || q.chars().count() > 200 {
        return Err(ApiError::bad(
            "type what to search for (up to 200 characters)",
        ));
    }
    let db = st.db();
    let mut c = load(&db, &id)?;
    let images = custodian_images(&db, &c)?;
    if images.is_empty() {
        return Err(ApiError::bad("the custodians have no backups"));
    }
    let sid = Uuid::new_v4().simple().to_string()[..12].to_string();
    let mut repos: Vec<String> = images.iter().map(|i| i.1.clone()).collect();
    repos.sort();
    repos.dedup();
    let mut jobs = Vec::new();
    for repo in repos {
        let ids: Vec<Uuid> = images
            .iter()
            .filter(|i| i.1 == repo)
            .filter_map(|i| Uuid::parse_str(&i.0).ok())
            .take(2000)
            .collect();
        let Some(agent) = pick(&db, &repo, "search_files", None)? else {
            continue;
        };
        let kind = JobKind::SearchFiles {
            query: q.to_string(),
            images: ids,
            limit: 2000,
            budget_secs: 600,
        };
        jobs.push(queue(
            &db,
            &agent,
            &kind,
            &repo,
            &format!("case:{id}:search:{sid}"),
        )?);
    }
    if jobs.is_empty() {
        return Err(ApiError::bad(
            "no machine with access to these backups can search them: update its backup agent",
        ));
    }
    c.searches.push(json!({ "id": sid, "query": q, "by": a.username, "at": now(), "jobs": jobs, "done": [], "hits": [], "state": "running" }));
    save(&db, &c)?;
    audit(
        &db,
        &a.username,
        "case.search",
        &format!("case {id}: {q:?}"),
    );
    Ok(Json(json!({ "id": sid, "jobs": jobs })))
}

#[derive(Deserialize)]
struct ExportReq {
    image_id: String,
    recipient: String,
    #[serde(default)]
    disk: Option<u32>,
    #[serde(default)]
    partition: Option<u32>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    accounts: Vec<String>,
    #[serde(default)]
    kinds: Vec<String>,
    #[serde(default)]
    items: Vec<String>,
}

async fn export(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
    Json(r): Json<ExportReq>,
) -> ApiResult<Json<Value>> {
    let db = st.db();
    let mut c = load(&db, &id)?;
    if c.status != "open" {
        return Err(ApiError::bad("the case is closed"));
    }
    let Some((img, repo, from, machine)) = custodian_images(&db, &c)?
        .into_iter()
        .find(|i| i.0 == r.image_id)
    else {
        return Err(ApiError::bad(
            "choose a backup of one of the case's custodians",
        ));
    };
    use base64::Engine as _;
    if base64::engine::general_purpose::STANDARD
        .decode(r.recipient.trim())
        .map(|k| k.len())
        != Ok(32)
    {
        return Err(ApiError::bad(
            "recipient must be a 32-byte X25519 public key (base64)",
        ));
    }
    let Some(agent) = pick(&db, &repo, "ediscovery", from.as_deref())? else {
        return Err(ApiError::bad("no machine with access to this backup can make eDiscovery exports yet: update its backup agent"));
    };
    let image_id = Uuid::parse_str(&img).map_err(|_| ApiError::bad("invalid image"))?;
    let (kind, what) = if machine.starts_with("saas:") {
        let cust = c
            .custodians
            .iter()
            .find(|x| x.machine_id == machine)
            .cloned()
            .expect("custodian");
        let accounts = if r.accounts.is_empty() {
            cust.accounts.clone()
        } else {
            r.accounts.clone()
        };
        if !cust.accounts.is_empty()
            && accounts
                .iter()
                .any(|x| !cust.accounts.iter().any(|y| y.eq_ignore_ascii_case(x)))
        {
            return Err(ApiError::bad(
                "only the case's accounts of this tenant can be exported",
            ));
        }
        let kinds: Vec<String> = r
            .kinds
            .into_iter()
            .filter(|k| KINDS.contains(&k.as_str()))
            .collect();
        let what = if r.items.is_empty() {
            "all matching items".to_string()
        } else {
            format!("{} items", r.items.len())
        };
        (
            JobKind::ExportSaas {
                image_id,
                accounts,
                kinds,
                items: r.items.into_iter().take(5000).collect(),
                recipient: r.recipient.trim().into(),
            },
            what,
        )
    } else {
        let (Some(disk), Some(partition)) = (r.disk, r.partition) else {
            return Err(ApiError::bad("choose a volume"));
        };
        let paths: Vec<String> = r
            .paths
            .into_iter()
            .filter(|p| !p.trim_matches('/').is_empty())
            .collect();
        if paths.is_empty() || paths.len() > 1000 {
            return Err(ApiError::bad("choose 1 to 1000 files or folders"));
        }
        let what = format!("{} files or folders", paths.len());
        (
            JobKind::DownloadFiles {
                image_id,
                volume: VolumeRef { disk, partition },
                paths,
                recipient: r.recipient.trim().into(),
                manifest: true,
            },
            what,
        )
    };
    let eid = Uuid::new_v4().simple().to_string()[..12].to_string();
    let job = queue(
        &db,
        &agent,
        &kind,
        &repo,
        &format!("case:{id}:export:{eid}"),
    )?;
    let host: String = db.query_row(
        "SELECT COALESCE(vm_name, hostname) FROM images WHERE image_id = ?1",
        params![img],
        |x| x.get(0),
    )?;
    c.exports.push(json!({ "id": eid, "image_id": img, "machine": host, "what": what, "by": a.username, "at": now(), "job_id": job, "state": "queued" }));
    save(&db, &c)?;
    audit(
        &db,
        &a.username,
        "case.export",
        &format!("case {id}: {what} of {host} ({img}), job {job}"),
    );
    Ok(Json(json!({ "id": eid, "job_id": job })))
}

#[derive(Deserialize)]
struct ReceiptReq {
    sha256: String,
    #[serde(default)]
    bytes: u64,
}

async fn receipt(
    State(st): State<Shared>,
    a: Admin,
    Path((id, eid)): Path<(String, String)>,
    Json(r): Json<ReceiptReq>,
) -> ApiResult<Json<Value>> {
    let sha = r.sha256.to_lowercase();
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::bad("sha256: 64 hex characters"));
    }
    let db = st.db();
    let mut c = load(&db, &id)?;
    let Some(e) = c.exports.iter_mut().find(|e| e["id"] == eid.as_str()) else {
        return Err(ApiError::not_found("no such export"));
    };
    let mut rs = e["receipts"].as_array().cloned().unwrap_or_default();
    rs.push(json!({ "by": a.username, "at": now(), "sha256": sha, "bytes": r.bytes }));
    e["receipts"] = json!(rs);
    let e = e.clone();
    save(&db, &c)?;
    audit(
        &db,
        &a.username,
        "case.export_received",
        &format!("case {id}: export {eid} saved, SHA-256 {sha}"),
    );
    Ok(Json(e))
}

async fn manifest(
    State(st): State<Shared>,
    a: Admin,
    Path(id): Path<String>,
) -> ApiResult<axum::response::Response> {
    let db = st.db();
    let c = load(&db, &id)?;
    let holds: Vec<Value> = holds_of(&db, &id)?
        .into_iter()
        .map(|(img, what, created, repo)| json!({ "image_id": img, "machine": what, "created": created, "repository_id": repo }))
        .collect();
    let needle = format!("case {id}");
    let trail: Vec<Value> = db
        .prepare("SELECT at, actor, action, detail FROM audit WHERE action LIKE 'case.%' ORDER BY id")?
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?)))?
        .filter_map(Result::ok)
        .filter(|x| x.3.starts_with(&needle))
        .map(|(at, actor, action, detail)| json!({ "at": at, "actor": actor, "action": action, "detail": detail }))
        .collect();
    let mut doc = json!({
        "format": "fenrir-ediscovery-case", "version": 1, "generated": now(),
        "case": { "id": c.id, "name": c.name, "matter": c.matter, "description": c.description, "status": c.status,
                  "created_by": c.created_by, "created": c.created, "closed_by": c.closed_by, "closed": c.closed,
                  "hold_new_backups": c.hold_new },
        "custodians": c.custodians,
        "holds": holds,
        "searches": c.searches.iter().map(|s| json!({ "id": s["id"], "query": s["query"], "by": s["by"], "at": s["at"],
            "state": s["state"], "truncated": s["truncated"], "hits": s["hits"].as_array().map_or(0, |h| h.len()) })).collect::<Vec<_>>(),
        "exports": c.exports,
        "audit_trail": trail,
    });
    // serde_json's map is ordered by key, so this is the canonical form.
    let sha = hex::encode(Sha256::digest(serde_json::to_vec(&doc)?));
    doc["sha256"] = json!(sha);
    audit(
        &db,
        &a.username,
        "case.manifest",
        &format!("case {id}: manifest {sha}"),
    );
    axum::response::Response::builder()
        .header("Content-Type", "application/json")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"case-{}-manifest.json\"", &id[..8]),
        )
        .body(axum::body::Body::from(serde_json::to_vec_pretty(&doc)?))
        .map_err(|e| ApiError::internal(e.to_string()))
}
