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
