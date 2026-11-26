//! Restore evidence (BDR-03). When a restore finishes, the server keeps one
//! record of it: which backup (and its recovery point) was restored, when the
//! restore was asked for, started and finished, how long it took, the RTO
//! (request to finished) and the age of the recovery point at the request
//! (the data a failure at that moment would have lost, the RPO), together with
//! what the agent reported writing: each output's SHA-256 read back from where
//! it was written and the read-back check of restored disks. The record is
//! stored as canonical JSON with its SHA-256, so a copy handed to an auditor
//! can be checked against the server.

use protocol::JobKind;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The image a restore job restores from; None for jobs that are not restores.
pub fn restore_image(kind: &JobKind) -> Option<Uuid> {
    match kind {
        JobKind::Restore { image_id, .. }
        | JobKind::RestoreFiles { image_id, .. }
        | JobKind::RestoreApplication { image_id, .. }
        | JobKind::RestoreKubernetes { image_id, .. }
        | JobKind::RestoreSaas { image_id, .. } => Some(*image_id),
        _ => None,
    }
}

fn rfc3339(t: Option<i64>) -> Value {
    t.map(|s| json!(core_format::timefmt::rfc3339_utc(s)))
        .unwrap_or(Value::Null)
}

/// SHA-256 of the record's canonical JSON (object keys sorted).
pub fn digest(record: &Value) -> String {
    let text = serde_json::to_string(record).unwrap_or_default();
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// kind, state, agent, created, started, finished, result, warnings, requested by, agent name
type JobRow = (
    String,
    String,
    String,
    i64,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Build and store the evidence of one finished restore job.
pub fn record(db: &Connection, job_id: &str) -> rusqlite::Result<Option<Value>> {
    let row: Option<JobRow> = db
        .query_row(
            "SELECT j.kind_json, j.state, j.agent_id, j.created, j.started, j.finished, j.result_json, j.warnings_json, j.requested_by,
                    COALESCE(a.display_name, a.hostname)
             FROM jobs j LEFT JOIN agents a ON a.id = j.agent_id WHERE j.id = ?1",
            params![job_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?)),
        )
        .optional()?;
    let Some((
        kind_json,
        state,
        agent_id,
        created,
        started,
        finished,
        result_json,
        warnings_json,
        requested_by,
        agent_name,
    )) = row
    else {
        return Ok(None);
    };
    let Ok(kind) = serde_json::from_str::<JobKind>(&kind_json) else {
        return Ok(None);
    };
    let Some(image_id) = restore_image(&kind) else {
        return Ok(None);
    };
    let image: Option<(i64, String, String)> = db
        .query_row(
            "SELECT created, hostname, kind FROM images WHERE image_id = ?1",
            params![image_id.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let result: Value = result_json
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);
    let ev = &result["evidence"];
    let warnings: Value = warnings_json
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(json!([]));
    let recovery_point = image.as_ref().map(|i| i.0);
    let record = json!({
        "format": "fenrir-restore-evidence-v1",
        "jobId": job_id,
        "kind": kind.label(),
        "state": state,
        "agentId": agent_id,
        "agent": agent_name,
        "requestedBy": requested_by,
        "imageId": image_id.to_string(),
        "imageKind": image.as_ref().map(|i| i.2.clone()),
        "sourceMachine": image.as_ref().map(|i| i.1.clone()),
        "recoveryPoint": rfc3339(recovery_point),
        "requestedAt": rfc3339(Some(created)),
        "startedAt": rfc3339(started),
        "finishedAt": rfc3339(finished),
        "durationSeconds": started.zip(finished).map(|(s, f)| f - s),
        "rtoSeconds": finished.map(|f| f - created),
        "rpoSeconds": recovery_point.map(|p| created - p),
        "outputs": ev.get("outputs").cloned().unwrap_or(json!([])),
        "verification": ev.get("verification").cloned().unwrap_or(json!([])),
        "checks": ev.get("checks").cloned().unwrap_or(json!([])),
        "verified": ev.get("verified").cloned().unwrap_or(Value::Bool(false)),
        "agentReportedEvidence": !ev.is_null(),
        "warnings": warnings,
    });
    let sha = digest(&record);
    db.execute(
        "INSERT INTO restore_evidence (job_id, image_id, record_json, sha256, created) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(job_id) DO UPDATE SET record_json = excluded.record_json, sha256 = excluded.sha256, created = excluded.created",
        params![job_id, image_id.to_string(), serde_json::to_string(&record).unwrap_or_default(), sha, crate::now()],
    )?;
    Ok(Some(json!({ "evidence": record, "sha256": sha })))
}

/// The stored evidence of a job, with its digest checked again.
pub fn load(db: &Connection, job_id: &str) -> rusqlite::Result<Option<Value>> {
    let row: Option<(String, String)> = db
        .query_row(
            "SELECT record_json, sha256 FROM restore_evidence WHERE job_id = ?1",
            params![job_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(row.map(|(text, sha)| {
        let record: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let intact = digest(&record) == sha;
        json!({ "evidence": record, "sha256": sha, "intact": intact })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_evidence_has_rpo_rto_outputs_and_detects_tampering() {
        let db = Connection::open_in_memory().unwrap();
        crate::db::migrate(&db).unwrap();
        db.execute_batch(
            "INSERT INTO agents (id, token_hash, hostname, machine_id, role, os_json, public_key, agent_version, enrolled)
               VALUES ('a1', 'h', 'srv-01', 'm1', 'agent', '{}', 'k', '1', 1);
             INSERT INTO repositories (id, name, path, repo_uuid, status, created) VALUES ('r1', 'NAS', '/srv/r', 'u', 'ok', 1);",
        )
        .unwrap();
        let image = Uuid::from_u128(9);
        db.execute(
            "INSERT INTO images (image_id, repository_id, agent_id, machine_id, hostname, created, kind, consistency, captured_bytes, stored_new_bytes, disks_json)
             VALUES (?1, 'r1', 'a1', 'm1', 'srv-01', 1000, 'full', 'crash', 0, 0, '[]')",
            params![image.to_string()],
        )
        .unwrap();
        let kind = JobKind::RestoreFiles {
            image_id: image,
            volume: protocol::VolumeRef {
                disk: 0,
                partition: 1,
            },
            paths: vec!["/Users/anna/report.docx".into()],
            target: "C:\\\\Restored".into(),
            keep_structure: false,
            conflict: "rename".into(),
        };
        let result = json!({ "files": 1, "evidence": { "outputs": [{ "path": "C:\\\\Restored\\\\report.docx", "bytes": 3, "sha256": "ab" }],
                                                         "verification": [{ "method": "file-sha256", "supported": true }], "checks": [], "verified": true } });
        db.execute(
            "INSERT INTO jobs (id, agent_id, kind_json, state, created, started, finished, result_json, warnings_json, requested_by)
             VALUES ('j1', 'a1', ?1, 'succeeded', 4600, 4630, 4690, ?2, '[]', 'admin')",
            params![serde_json::to_string(&kind).unwrap(), result.to_string()],
        )
        .unwrap();
        let out = record(&db, "j1").unwrap().unwrap();
        let ev = &out["evidence"];
        assert_eq!(ev["rpoSeconds"], 3600);
        assert_eq!(ev["rtoSeconds"], 90);
        assert_eq!(ev["durationSeconds"], 60);
        assert_eq!(ev["recoveryPoint"], "1970-01-01T00:16:40Z");
        assert_eq!(ev["outputs"][0]["sha256"], "ab");
        assert_eq!(ev["verified"], true);
        let loaded = load(&db, "j1").unwrap().unwrap();
        assert_eq!(loaded["intact"], true);
        assert_eq!(loaded["sha256"], out["sha256"]);
        db.execute("UPDATE restore_evidence SET record_json = replace(record_json, '\"rtoSeconds\":90', '\"rtoSeconds\":5')", []).unwrap();
        assert_eq!(load(&db, "j1").unwrap().unwrap()["intact"], false);
        // Not a restore: no evidence.
        db.execute("INSERT INTO jobs (id, agent_id, kind_json, state, created) VALUES ('j2', 'a1', '{\"type\":\"list_images\"}', 'succeeded', 1)", []).unwrap();
        assert!(record(&db, "j2").unwrap().is_none());
    }
}
