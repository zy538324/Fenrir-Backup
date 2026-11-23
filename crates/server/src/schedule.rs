//! Backup plan schedules and the background task that turns them into jobs.

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::{now, Shared};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Schedule {
    /// Every `hours` hours and `minutes` minutes (at least 5 minutes in all,
    /// for frequent backups; at most 31 days).
    Interval {
        #[serde(default)]
        hours: u32,
        #[serde(default)]
        minutes: u32,
    },
    /// At `time` ("HH:MM") local time on the given weekdays (0 = Monday;
    /// empty = every day). `utc_offset_minutes` is the administrator's
    /// offset when the plan was saved (e.g. 60 for UTC+1).
    Daily {
        time: String,
        #[serde(default)]
        days: Vec<u8>,
        #[serde(default)]
        utc_offset_minutes: i32,
    },
    /// Only when started by hand.
    Manual,
}

impl Schedule {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Schedule::Interval { hours, minutes } => {
                let total = *hours as u64 * 60 + *minutes as u64;
                if *minutes < 60 && (5..=31 * 24 * 60).contains(&total) {
                    Ok(())
                } else {
                    Err("interval must be 5 minutes to 31 days".into())
                }
            }
            Schedule::Daily {
                time,
                days,
                utc_offset_minutes,
            } => {
                parse_hm(time).ok_or("time must be HH:MM")?;
                if days.iter().any(|d| *d > 6) {
                    return Err("days are 0 (Monday) to 6 (Sunday)".into());
                }
                if utc_offset_minutes.abs() > 14 * 60 {
                    return Err("UTC offset out of range".into());
                }
                Ok(())
            }
            Schedule::Manual => Ok(()),
        }
    }

    /// First run time strictly after `after` (Unix seconds).
    pub fn next_after(&self, after: i64) -> Option<i64> {
        match self {
            Schedule::Interval { hours, minutes } => {
                Some(after + *hours as i64 * 3600 + *minutes as i64 * 60)
            }
            Schedule::Manual => None,
            Schedule::Daily {
                time,
                days,
                utc_offset_minutes,
            } => {
                let (h, m) = parse_hm(time)?;
                let off = *utc_offset_minutes as i64 * 60;
                let local = after + off;
                let day_start = local.div_euclid(86_400) * 86_400;
                for d in 0..8 {
                    let cand_local = day_start + d * 86_400 + h as i64 * 3600 + m as i64 * 60;
                    if cand_local <= local {
                        continue;
                    }
                    // 1970-01-01 was a Thursday (weekday 3 with Monday = 0).
                    let weekday = ((cand_local.div_euclid(86_400) + 3).rem_euclid(7)) as u8;
                    if days.is_empty() || days.contains(&weekday) {
                        return Some(cand_local - off);
                    }
                }
                None
            }
        }
    }
}

fn parse_hm(s: &str) -> Option<(u32, u32)> {
    let (h, m) = s.split_once(':')?;
    let (h, m) = (h.parse::<u32>().ok()?, m.parse::<u32>().ok()?);
    (h < 24 && m < 60).then_some((h, m))
}

/// Create jobs for plans that are due. A plan never has more than one
/// unfinished job, so a machine that was offline catches up with a single
/// run rather than one per missed slot.
pub fn run_due(state: &Shared) -> rusqlite::Result<usize> {
    let t = now();
    let db = state.db();
    let mut stmt = db.prepare(
        "SELECT id, agent_id, repository_id, job_json, schedule_json FROM plans
         WHERE enabled = 1 AND next_run IS NOT NULL AND next_run <= ?1",
    )?;
    let due: Vec<(String, String, String, String, String)> = stmt
        .query_map(params![t], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<Result<_, _>>()?;
    drop(stmt);
    let mut created = 0;
    for (plan_id, agent_id, repo_id, job_json, sched_json) in due {
        let busy: i64 = db.query_row(
            "SELECT COUNT(*) FROM jobs WHERE plan_id = ?1 AND state IN ('queued','dispatched','running')",
            params![plan_id],
            |r| r.get(0),
        )?;
        if busy == 0 {
            db.execute(
                "INSERT INTO jobs (id, agent_id, repository_id, plan_id, kind_json, state, created, requested_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'queued', ?6, 'schedule')",
                params![uuid::Uuid::new_v4().to_string(), agent_id, repo_id, plan_id, job_json, t],
            )?;
            created += 1;
        }
        let next = serde_json::from_str::<Schedule>(&sched_json)
            .ok()
            .and_then(|s| s.next_after(t));
        db.execute(
            "UPDATE plans SET last_run = ?1, next_run = ?2 WHERE id = ?3",
            params![t, next, plan_id],
        )?;
    }
    Ok(created)
}

/// Recovery sessions (machines booted from recovery media) not seen for a
/// week are removed, with any access given to them.
pub fn expire_recovery_sessions(state: &Shared) -> rusqlite::Result<usize> {
    let db = state.db();
    let old: Vec<String> = db
        .prepare(
            "SELECT id FROM agents WHERE role = 'recovery' AND revoked = 0 AND last_seen < ?1",
        )?
        .query_map(params![now() - 7 * 86_400], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    for id in &old {
        db.execute("UPDATE agents SET revoked = 1 WHERE id = ?1", params![id])?;
        db.execute("DELETE FROM repo_access WHERE agent_id = ?1", params![id])?;
        db.execute(
            "UPDATE jobs SET state = 'cancelled', finished = ?1, error = 'recovery session ended' WHERE agent_id = ?2 AND state = 'queued'",
            params![now(), id],
        )?;
    }
    Ok(old.len())
}

/// Queue a prune for repositories whose maintenance interval has passed.
/// Skipped while a repository is on hold, and while one is already queued.
pub fn run_maintenance(state: &Shared) -> rusqlite::Result<usize> {
    let t = now();
    let db = state.db();
    // Folder listings name files: keep them a day.
    db.execute(
        "UPDATE jobs SET result_json = NULL WHERE finished < ?1 AND result_json IS NOT NULL
           AND kind_json LIKE '{\"type\":\"browse_files%'",
        params![t - 86_400],
    )?;
    let mut stmt = db.prepare(
        "SELECT r.id, r.maintenance_agent_id FROM repositories r JOIN agents a ON a.id = r.maintenance_agent_id
         JOIN repo_access x ON x.repository_id = r.id AND x.agent_id = a.id
         WHERE r.status = 'ready' AND r.hold = 0 AND a.revoked = 0 AND r.prune_every_days > 0
           AND COALESCE(r.last_prune, r.created) < ?1 - r.prune_every_days * 86400
           AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.repository_id = r.id AND j.state IN ('queued','dispatched','running')
                           AND j.kind_json LIKE '{\"type\":\"prune%')",
    )?;
    let due: Vec<(String, String)> = stmt
        .query_map(params![t], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    drop(stmt);
    for (repo, agent) in &due {
        let kind =
            serde_json::to_string(&protocol::JobKind::Prune { dry_run: false }).unwrap_or_default();
        db.execute(
            "INSERT INTO jobs (id, agent_id, repository_id, kind_json, state, created, requested_by) VALUES (?1, ?2, ?3, ?4, 'queued', ?5, 'maintenance')",
            params![uuid::Uuid::new_v4().to_string(), agent, repo, kind, t],
        )?;
    }
    Ok(due.len())
}

/// Boot verification: per repository with a boot host and an interval,
/// queue a boot check of the newest image of each machine that has not
/// been checked within the interval. One check per repository at a time.
pub fn run_boot_checks(state: &Shared) -> rusqlite::Result<usize> {
    let t = now();
    let db = state.db();
    let due: Vec<(String, String, String)> = db
        .prepare(
            "SELECT r.id, r.boot_agent_id, i.image_id FROM repositories r
             JOIN agents a ON a.id = r.boot_agent_id AND a.revoked = 0
             JOIN repo_access x ON x.repository_id = r.id AND x.agent_id = a.id
             JOIN images i ON i.repository_id = r.id
             WHERE r.status = 'ready' AND r.boot_every_days > 0
               AND i.created = (SELECT MAX(created) FROM images j WHERE j.repository_id = r.id AND j.machine_id = i.machine_id)
               AND NOT EXISTS (SELECT 1 FROM boot_checks b WHERE b.repository_id = r.id AND b.image_id IN
                    (SELECT image_id FROM images k WHERE k.repository_id = r.id AND k.machine_id = i.machine_id)
                    AND b.at > ?1 - r.boot_every_days * 86400)
               AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.repository_id = r.id AND j.state IN ('queued','dispatched','running')
                    AND j.kind_json LIKE '{\"type\":\"boot_check%')
               AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.repository_id = r.id AND j.kind_json LIKE '{\"type\":\"boot_check%'
                    AND j.requested_by = 'boot verification'
                    AND j.kind_json LIKE '%' || i.image_id || '%' AND j.created > ?1 - 86400)
             ORDER BY i.created",
        )?
        .query_map(params![t], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let mut queued = std::collections::BTreeSet::new();
    for (repo, agent, image) in &due {
        if !queued.insert(repo.clone()) {
            continue;
        }
        let Ok(image_id) = image.parse() else {
            continue;
        };
        let kind = serde_json::to_string(&protocol::JobKind::BootCheck {
            image_id,
            keep_running: false,
            memory_mb: None,
            cpus: None,
            directory: None,
        })
        .unwrap_or_default();
        db.execute(
            "INSERT INTO jobs (id, agent_id, repository_id, kind_json, state, created, requested_by) VALUES (?1, ?2, ?3, ?4, 'queued', ?5, 'boot verification')",
            params![uuid::Uuid::new_v4().to_string(), agent, repo, kind, t],
        )?;
    }
    Ok(queued.len())
}

/// Offline and overdue machines. Each alert fires once per episode
/// (offline) or once a day (overdue); `alert_state` remembers.
pub fn check_alerts(state: &Shared) -> rusqlite::Result<()> {
    use crate::notify::{self, Event, NotifySettings, Severity};
    let t = now();
    let mut events = vec![];
    {
        let db = state.db();
        let cfg: NotifySettings = crate::db::get_setting(&db, notify::KEY);
        if cfg.email.is_none() && cfg.webhook.is_none() {
            return Ok(());
        }
        let agents: Vec<(String, String, Option<i64>)> = db
            .prepare("SELECT id, COALESCE(display_name, hostname), last_seen FROM agents WHERE revoked = 0 AND role != 'recovery'")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        for (id, name, seen) in agents {
            let key = format!("offline:{id}");
            let offline = cfg.offline_hours > 0
                && seen.is_some_and(|s| t - s > cfg.offline_hours as i64 * 3600);
            let alerted: Option<i64> = db
                .query_row(
                    "SELECT at FROM alert_state WHERE key = ?1",
                    params![key],
                    |r| r.get(0),
                )
                .optional()?;
            match (offline, alerted) {
                (true, None) => {
                    db.execute(
                        "INSERT INTO alert_state (key, at) VALUES (?1, ?2)",
                        params![key, t],
                    )?;
                    events.push(Event {
                        severity: Severity::Warning,
                        subject: format!("{name} is offline"),
                        body: format!("{name} has not checked in for more than {} hours. It will not be backed up until it is back.", cfg.offline_hours),
                        link: Some(format!("/machines/{id}")),
                    });
                }
                (false, Some(_)) => {
                    db.execute("DELETE FROM alert_state WHERE key = ?1", params![key])?;
                }
                _ => {}
            }
            if cfg.overdue_days > 0 {
                let has_plan: bool = db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM plans WHERE agent_id = ?1 AND enabled = 1)",
                    params![id],
                    |r| r.get(0),
                )?;
                let last_good: Option<i64> = db.query_row(
                    "SELECT MAX(finished) FROM jobs WHERE agent_id = ?1 AND state IN ('succeeded','warning') AND kind_json LIKE '{\"type\":\"backup%'",
                    params![id],
                    |r| r.get(0),
                )?;
                let enrolled: i64 = db.query_row(
                    "SELECT enrolled FROM agents WHERE id = ?1",
                    params![id],
                    |r| r.get(0),
                )?;
                let since = last_good.unwrap_or(enrolled);
                let okey = format!("overdue:{id}");
                let last_alert: Option<i64> = db
                    .query_row(
                        "SELECT at FROM alert_state WHERE key = ?1",
                        params![okey],
                        |r| r.get(0),
                    )
                    .optional()?;
                if has_plan
                    && t - since > cfg.overdue_days as i64 * 86_400
                    && last_alert.is_none_or(|a| t - a > 86_400)
                {
                    db.execute(
                        "INSERT INTO alert_state (key, at) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET at = excluded.at",
                        params![okey, t],
                    )?;
                    events.push(Event {
                        severity: Severity::Error,
                        subject: format!("{name} has no recent backup"),
                        body: match last_good {
                            Some(_) => format!("The last successful backup of {name} is more than {} days old.", cfg.overdue_days),
                            None => format!("{name} has a backup plan but has never been backed up successfully."),
                        },
                        link: Some(format!("/machines/{id}")),
                    });
                }
            }
        }
    }
    for e in events {
        notify::send(state, e);
    }
    Ok(())
}

pub async fn scheduler_loop(state: Shared) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(20));
    loop {
        tick.tick().await;
        let s = state.clone();
        let r = tokio::task::spawn_blocking(move || {
            let a = run_due(&s);
            let b = run_maintenance(&s);
            let c = check_alerts(&s);
            if let Err(e) = run_boot_checks(&s) {
                tracing::error!(error = %e, "boot verification scheduler");
            }
            if let Err(e) = expire_recovery_sessions(&s) {
                tracing::error!(error = %e, "recovery session cleanup");
            }
            (a, b, c)
        })
        .await;
        if let Ok((a, b, c)) = r {
            match a {
                Ok(n) if n > 0 => tracing::info!(jobs = n, "scheduled jobs created"),
                Err(e) => tracing::error!(error = %e, "scheduler"),
                _ => {}
            }
            if let Err(e) = b {
                tracing::error!(error = %e, "maintenance scheduler");
            }
            if let Err(e) = c {
                tracing::error!(error = %e, "alert checks");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2026-11-20 (a Friday) 10:00:00 UTC.
    const FRI_10UTC: i64 = 1_795_168_800;

    #[test]
    fn weekday_reference() {
        assert_eq!(core_time(FRI_10UTC), "2026-11-20T10:00:00Z");
    }

    fn core_time(t: i64) -> String {
        // Local helper to keep the test readable without a date crate.
        let days = t.div_euclid(86_400);
        let (y, m, d) = {
            let z = days + 719_468;
            let era = z.div_euclid(146_097);
            let doe = z.rem_euclid(146_097);
            let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
            let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            let mp = (5 * doy + 2) / 153;
            let d = doy - (153 * mp + 2) / 5 + 1;
            let m = if mp < 10 { mp + 3 } else { mp - 9 };
            (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
        };
        let s = t.rem_euclid(86_400);
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            s / 3600,
            s % 3600 / 60,
            s % 60
        )
    }

    #[test]
    fn daily_same_day_and_next_day() {
        let s = Schedule::Daily {
            time: "22:30".into(),
            days: vec![],
            utc_offset_minutes: 0,
        };
        assert_eq!(
            core_time(s.next_after(FRI_10UTC).unwrap()),
            "2026-11-20T22:30:00Z"
        );
        let s = Schedule::Daily {
            time: "09:00".into(),
            days: vec![],
            utc_offset_minutes: 0,
        };
        assert_eq!(
            core_time(s.next_after(FRI_10UTC).unwrap()),
            "2026-11-21T09:00:00Z"
        );
    }

    #[test]
    fn daily_weekdays_only_skips_weekend() {
        let s = Schedule::Daily {
            time: "09:00".into(),
            days: vec![0, 1, 2, 3, 4],
            utc_offset_minutes: 0,
        };
        assert_eq!(
            core_time(s.next_after(FRI_10UTC).unwrap()),
            "2026-11-23T09:00:00Z"
        ); // Monday
    }

    #[test]
    fn daily_respects_utc_offset() {
        // 23:00 at UTC+2 is 21:00 UTC.
        let s = Schedule::Daily {
            time: "23:00".into(),
            days: vec![],
            utc_offset_minutes: 120,
        };
        assert_eq!(
            core_time(s.next_after(FRI_10UTC).unwrap()),
            "2026-11-20T21:00:00Z"
        );
        // 01:00 at UTC-5 is 06:00 UTC the next day.
        let s = Schedule::Daily {
            time: "01:00".into(),
            days: vec![],
            utc_offset_minutes: -300,
        };
        assert_eq!(
            core_time(s.next_after(FRI_10UTC).unwrap()),
            "2026-11-21T06:00:00Z"
        );
    }

    #[test]
    fn interval_and_validation() {
        assert_eq!(
            Schedule::Interval {
                hours: 6,
                minutes: 0
            }
            .next_after(100),
            Some(100 + 6 * 3600)
        );
        assert_eq!(Schedule::Manual.next_after(100), None);
        assert!(Schedule::Interval {
            hours: 0,
            minutes: 0
        }
        .validate()
        .is_err());
        // Frequent backups: down to every 5 minutes, and hours still work alone.
        assert!(Schedule::Interval {
            hours: 0,
            minutes: 4
        }
        .validate()
        .is_err());
        assert!(Schedule::Interval {
            hours: 0,
            minutes: 5
        }
        .validate()
        .is_ok());
        assert!(Schedule::Interval {
            hours: 1,
            minutes: 60
        }
        .validate()
        .is_err());
        assert_eq!(
            Schedule::Interval {
                hours: 0,
                minutes: 15
            }
            .next_after(100),
            Some(100 + 900)
        );
        let old: Schedule = serde_json::from_str(r#"{"type":"interval","hours":6}"#).unwrap();
        assert_eq!(
            old,
            Schedule::Interval {
                hours: 6,
                minutes: 0
            }
        );
        assert!(Schedule::Daily {
            time: "25:00".into(),
            days: vec![],
            utc_offset_minutes: 0
        }
        .validate()
        .is_err());
        assert!(Schedule::Daily {
            time: "10:00".into(),
            days: vec![7],
            utc_offset_minutes: 0
        }
        .validate()
        .is_err());
    }
}
