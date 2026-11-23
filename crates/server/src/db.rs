//! SQLite schema. Migrations are append-only: never edit a shipped step.

use rusqlite::Connection;

const MIGRATIONS: &[&str] = &[
    // 1: initial schema
    r#"
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        created INTEGER NOT NULL
    );
    CREATE TABLE sessions (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created INTEGER NOT NULL,
        last_seen INTEGER NOT NULL
    );
    CREATE TABLE enrollment_tokens (
        id TEXT PRIMARY KEY,
        token_hash TEXT NOT NULL UNIQUE,
        label TEXT NOT NULL,
        role TEXT NOT NULL,
        created INTEGER NOT NULL,
        expires INTEGER NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0,
        uses INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE agents (
        id TEXT PRIMARY KEY,
        token_hash TEXT NOT NULL UNIQUE,
        hostname TEXT NOT NULL,
        display_name TEXT,
        machine_id TEXT NOT NULL,
        role TEXT NOT NULL,
        os_json TEXT NOT NULL,
        public_key TEXT NOT NULL,
        agent_version TEXT NOT NULL,
        enrolled INTEGER NOT NULL,
        last_seen INTEGER,
        inventory_json TEXT,
        revoked INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX agents_machine ON agents(machine_id);
    CREATE TABLE repositories (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        path TEXT NOT NULL,
        repo_uuid TEXT NOT NULL,
        status TEXT NOT NULL,
        status_message TEXT,
        created INTEGER NOT NULL
    );
    CREATE TABLE repo_access (
        repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
        agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
        sealed TEXT NOT NULL,
        granted INTEGER NOT NULL,
        PRIMARY KEY (repository_id, agent_id)
    );
    CREATE TABLE plans (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
        repository_id TEXT NOT NULL REFERENCES repositories(id),
        job_json TEXT NOT NULL,
        schedule_json TEXT NOT NULL,
        enabled INTEGER NOT NULL,
        last_run INTEGER,
        next_run INTEGER,
        created INTEGER NOT NULL
    );
    CREATE TABLE jobs (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
        repository_id TEXT,
        plan_id TEXT,
        kind_json TEXT NOT NULL,
        state TEXT NOT NULL,
        cancel_requested INTEGER NOT NULL DEFAULT 0,
        created INTEGER NOT NULL,
        dispatched INTEGER,
        started INTEGER,
        finished INTEGER,
        progress_json TEXT,
        result_json TEXT,
        error TEXT,
        warnings_json TEXT,
        requested_by TEXT
    );
    CREATE INDEX jobs_agent_state ON jobs(agent_id, state);
    CREATE INDEX jobs_created ON jobs(created);
    CREATE TABLE images (
        image_id TEXT PRIMARY KEY,
        repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
        agent_id TEXT,
        machine_id TEXT NOT NULL,
        hostname TEXT NOT NULL,
        created INTEGER NOT NULL,
        kind TEXT NOT NULL,
        consistency TEXT NOT NULL,
        captured_bytes INTEGER NOT NULL,
        stored_new_bytes INTEGER NOT NULL,
        disks_json TEXT NOT NULL,
        label TEXT,
        vm_name TEXT
    );
    CREATE INDEX images_agent ON images(agent_id);
    CREATE TABLE audit (
        id INTEGER PRIMARY KEY,
        at INTEGER NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        detail TEXT NOT NULL
    );
    "#,
    // 2: retention, maintenance, anomaly hold, settings, notifications
    r#"
    ALTER TABLE plans ADD COLUMN retention_json TEXT;
    ALTER TABLE repositories ADD COLUMN hold INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE repositories ADD COLUMN hold_reason TEXT;
    ALTER TABLE repositories ADD COLUMN hold_since INTEGER;
    ALTER TABLE repositories ADD COLUMN maintenance_agent_id TEXT;
    ALTER TABLE repositories ADD COLUMN prune_every_days INTEGER NOT NULL DEFAULT 7;
    ALTER TABLE repositories ADD COLUMN last_prune INTEGER;
    ALTER TABLE images ADD COLUMN chunks_total INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE images ADD COLUMN chunks_new INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE images ADD COLUMN bytes_new_raw INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE images ADD COLUMN anomaly TEXT;
    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE notifications (
        id INTEGER PRIMARY KEY,
        at INTEGER NOT NULL,
        channel TEXT NOT NULL,
        subject TEXT NOT NULL,
        ok INTEGER NOT NULL,
        error TEXT
    );
    CREATE TABLE alert_state (key TEXT PRIMARY KEY, at INTEGER NOT NULL);
    UPDATE repositories SET maintenance_agent_id =
        (SELECT agent_id FROM jobs WHERE jobs.repository_id = repositories.id AND kind_json LIKE '{"type":"init_repository"%' LIMIT 1);
    "#,
    // 3: boot checks
    r#"
    CREATE TABLE boot_checks (
        id INTEGER PRIMARY KEY,
        image_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        job_id TEXT,
        at INTEGER NOT NULL,
        outcome TEXT NOT NULL,
        method TEXT NOT NULL,
        seconds INTEGER NOT NULL,
        firmware TEXT NOT NULL,
        accel TEXT NOT NULL,
        message TEXT NOT NULL,
        screenshot BLOB
    );
    CREATE INDEX boot_checks_image ON boot_checks(image_id, at);
    ALTER TABLE repositories ADD COLUMN boot_agent_id TEXT;
    ALTER TABLE repositories ADD COLUMN boot_every_days INTEGER NOT NULL DEFAULT 0;
    "#,
    // 4: network share sign-in
    r#"
    ALTER TABLE repositories ADD COLUMN share_auth TEXT NOT NULL DEFAULT 'none';
    ALTER TABLE repositories ADD COLUMN share_user TEXT;
    ALTER TABLE repo_access ADD COLUMN sealed_share TEXT;
    "#,
    // 5: NAS gateway
    r#"
    ALTER TABLE agents ADD COLUMN gateway_port INTEGER;
    ALTER TABLE agents ADD COLUMN gateway_address TEXT;
    ALTER TABLE repositories ADD COLUMN gateway_agent_id TEXT;
    ALTER TABLE repo_access ADD COLUMN via_gateway INTEGER NOT NULL DEFAULT 0;
    "#,
];

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;",
    )?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    for (i, m) in MIGRATIONS.iter().enumerate().skip(version as usize) {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(m)?;
        tx.execute_batch(&format!("PRAGMA user_version = {}", i + 1))?;
        tx.commit()?;
    }
    Ok(())
}

pub fn audit(conn: &Connection, actor: &str, action: &str, detail: &str) {
    let _ = conn.execute(
        "INSERT INTO audit (at, actor, action, detail) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![crate::now(), actor, action, detail],
    );
}

pub fn get_setting<T: serde::de::DeserializeOwned + Default>(conn: &Connection, key: &str) -> T {
    conn.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
        r.get::<_, String>(0)
    })
    .ok()
    .and_then(|v| serde_json::from_str(&v).ok())
    .unwrap_or_default()
}

pub fn set_setting<T: serde::Serialize>(
    conn: &Connection,
    key: &str,
    value: &T,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![key, serde_json::to_string(value).unwrap_or_default()],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn migrations_apply_and_are_idempotent() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        super::migrate(&c).unwrap();
        super::migrate(&c).unwrap();
        let v: i64 = c
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v as usize, super::MIGRATIONS.len());
        c.execute("INSERT INTO settings (key, value) VALUES ('a', '1')", [])
            .unwrap();
    }
}
