use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use protocol::seal::{seal, AgentKey};
use protocol::*;
use serde_json::{json, Value};
use server::{router, AppState, Config, Shared, TlsInfo};
use tower::ServiceExt;

struct T {
    st: Shared,
    cookie: Option<String>,
    _dir: tempfile::TempDir,
}

impl T {
    fn new() -> T {
        let dir = tempfile::tempdir().unwrap();
        let agents = dir.path().join("agents");
        for (t, f) in [
            ("x86_64-pc-windows-msvc", "fenrir-agent.exe"),
            ("x86_64-unknown-linux-musl", "fenrir-agent"),
        ] {
            std::fs::create_dir_all(agents.join(t)).unwrap();
            std::fs::write(agents.join(t).join(f), format!("binary for {t}")).unwrap();
        }
        let conn = rusqlite::Connection::open(dir.path().join("db")).unwrap();
        let st = AppState::new(
            conn,
            Config {
                public_url: None,
                agents_dir: agents,
                ui_dir: None,
                tls: Some(TlsInfo {
                    cert_sha256: "ab".repeat(32),
                    spki_sha256_b64: "c3BraQ==".into(),
                    pinned: true,
                }),
                poll_seconds: 15,
            },
        )
        .unwrap();
        T {
            st,
            cookie: None,
            _dir: dir,
        }
    }

    async fn req(
        &mut self,
        method: &str,
        uri: &str,
        body: Option<Value>,
        bearer: Option<&str>,
        csrf: bool,
    ) -> (StatusCode, Value, Option<String>) {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, "backup.test:8443");
        if let Some(c) = &self.cookie {
            b = b.header(header::COOKIE, c.clone());
        }
        if csrf {
            b = b.header("x-fenrir-csrf", "1");
        }
        if let Some(t) = bearer {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let req = match body {
            Some(v) => b
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let resp = router(self.st.clone()).oneshot(req).await.unwrap();
        let status = resp.status();
        if let Some(sc) = resp.headers().get(header::SET_COOKIE) {
            let v = sc.to_str().unwrap().split(';').next().unwrap().to_string();
            self.cookie = if v.ends_with('=') { None } else { Some(v) };
        }
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&bytes).to_string();
        let v = serde_json::from_slice(&bytes).unwrap_or(Value::String(text.clone()));
        (status, v, ct.filter(|c| !c.contains("json")).map(|_| text))
    }

    async fn get(&mut self, uri: &str) -> (StatusCode, Value) {
        let (s, v, _) = self.req("GET", uri, None, None, false).await;
        (s, v)
    }
    async fn post(&mut self, uri: &str, body: Value) -> (StatusCode, Value) {
        let (s, v, _) = self.req("POST", uri, Some(body), None, true).await;
        (s, v)
    }
    async fn agent(&mut self, uri: &str, token: &str, body: Value) -> (StatusCode, Value) {
        let saved = self.cookie.take();
        let (s, v, _) = self.req("POST", uri, Some(body), Some(token), false).await;
        self.cookie = saved;
        (s, v)
    }
}

fn inventory(caps: &[&str]) -> Value {
    serde_json::to_value(Inventory {
        hostname: "web01".into(),
        os: OsSummary {
            family: "linux".into(),
            name: "Debian".into(),
            version: "13".into(),
            arch: "x86_64".into(),
        },
        agent_version: "0.1.0".into(),
        capabilities: caps.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    })
    .unwrap()
}

async fn setup_admin(t: &mut T) {
    let (s, _) = t
        .post(
            "/api/setup",
            json!({ "username": "admin", "password": "correct horse battery" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(t.cookie.is_some());
}

async fn enroll(t: &mut T, key: &AgentKey, machine: &str) -> (String, String) {
    let (s, tok) = t
        .post(
            "/api/enrollment-tokens",
            json!({ "label": "test", "role": "server" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let req = EnrollRequest {
        protocol: PROTOCOL_VERSION,
        token: tok["token"].as_str().unwrap().into(),
        hostname: "web01".into(),
        machine_id: machine.into(),
        os: OsSummary::default(),
        role: AgentRole::Server,
        agent_version: "0.1.0".into(),
        public_key: key.public_b64(),
    };
    let (s, v) = t
        .agent("/api/agent/enroll", "", serde_json::to_value(req).unwrap())
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    (
        v["agent_id"].as_str().unwrap().into(),
        v["agent_token"].as_str().unwrap().into(),
    )
}

async fn heartbeat(
    t: &mut T,
    token: &str,
    caps: &[&str],
    running: Option<&str>,
) -> HeartbeatResponse {
    let (s, v) = t
        .agent(
            "/api/agent/heartbeat",
            token,
            json!({ "inventory": inventory(caps), "running_job": running }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    serde_json::from_value(v).unwrap()
}

#[tokio::test]
async fn setup_login_and_csrf() {
    let mut t = T::new();
    let (_, v) = t.get("/api/status").await;
    assert_eq!(v["setup_required"], true);
    // Short password refused.
    let (s, _) = t
        .post(
            "/api/setup",
            json!({ "username": "admin", "password": "short" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    setup_admin(&mut t).await;
    let (_, v) = t.get("/api/status").await;
    assert_eq!(v["setup_required"], false);
    assert_eq!(v["user"]["username"], "admin");
    // Setup only once.
    let (s, _) = t
        .post(
            "/api/setup",
            json!({ "username": "x", "password": "another long password" }),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    // Mutation without the CSRF header is refused even with a session.
    let (s, _, _) = t
        .req(
            "POST",
            "/api/enrollment-tokens",
            Some(json!({})),
            None,
            false,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    t.post("/api/logout", json!({})).await;
    let (s, _) = t.get("/api/agents").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = t
        .post(
            "/api/login",
            json!({ "username": "admin", "password": "wrong password!" }),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = t
        .post(
            "/api/login",
            json!({ "username": "ADMIN", "password": "correct horse battery" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = t.get("/api/agents").await;
    assert_eq!(s, StatusCode::OK);

    for _ in 0..5 {
        t.post(
            "/api/login",
            json!({ "username": "mallory", "password": "guess guess guess" }),
        )
        .await;
    }
    let (s, _) = t
        .post(
            "/api/login",
            json!({ "username": "mallory", "password": "guess guess guess" }),
        )
        .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn downloads_and_installers() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let (_, tok) = t
        .post("/api/enrollment-tokens", json!({ "role": "workstation" }))
        .await;
    let token = tok["token"].as_str().unwrap().to_string();
    let (s, cat) = t.get(&format!("/api/downloads?token={token}")).await;
    assert_eq!(s, StatusCode::OK, "{cat}");
    assert_eq!(cat["server_url"], "https://backup.test:8443");
    let p = |id: &str| {
        cat["platforms"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(p("windows")["available"], true);
    assert_eq!(p("macos")["available"], false, "no mac build in agents dir");
    assert!(p("linux")["command"]
        .as_str()
        .unwrap()
        .contains("--pinnedpubkey 'sha256//c3BraQ=='"));
    assert!(p("hyperv")["command"]
        .as_str()
        .unwrap()
        .contains(&"AB".repeat(32)));

    // Installer scripts: public by token, carry everything needed.
    t.cookie = None;
    let (s, _, body) = t
        .req(
            "GET",
            &format!("/install/{token}/hyperv"),
            None,
            None,
            false,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let body = body.unwrap();
    let win_sha = server::sha256_hex(b"binary for x86_64-pc-windows-msvc");
    assert!(body.contains(&format!("$Token  = '{token}'")));
    assert!(
        body.contains("$Role   = 'hyperv'"),
        "Hyper-V installer forces the role"
    );
    assert!(body.contains(&format!("$Sha256 = '{win_sha}'")));
    assert!(body.contains("$Server = 'https://backup.test:8443'"));
    assert!(body.contains("Get-Service vmms"));
    let (_, _, body) = t
        .req("GET", &format!("/install/{token}/linux"), None, None, false)
        .await;
    let body = body.unwrap();
    assert!(body.contains("ROLE='workstation'"));
    assert!(body.contains(&server::sha256_hex(b"binary for x86_64-unknown-linux-musl")));
    assert!(
        body.contains("aarch64-unknown-linux-musl; SHA=''"),
        "missing arm build reported as empty hash"
    );

    let (s, _) = t
        .get("/install/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/linux")
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, bin) = t
        .req(
            "GET",
            "/agent/x86_64-pc-windows-msvc/fenrir-agent.exe",
            None,
            None,
            false,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(bin.unwrap(), "binary for x86_64-pc-windows-msvc");
    let (s, _) = t.get("/agent/..%2F..%2Fetc/passwd").await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Hostile Host header cannot inject into scripts.
    let (s, _, _) = {
        let req = Request::builder()
            .uri(format!("/install/{token}/linux"))
            .header(header::HOST, "x';rm -rf /;'")
            .body(Body::empty())
            .unwrap();
        let r = router(t.st.clone()).oneshot(req).await.unwrap();
        (r.status(), Value::Null, None::<String>)
    };
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // HTTP/2 clients send :authority instead of Host; it arrives in the URI.
    let req = Request::builder()
        .uri(format!("https://h2.backup.test:9443/install/{token}/linux"))
        .body(Body::empty())
        .unwrap();
    let r = router(t.st.clone()).oneshot(req).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body =
        String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(body.contains("SERVER='https://h2.backup.test:9443'"));

    // Revoked tokens stop working.
    t.post(
        "/api/login",
        json!({ "username": "admin", "password": "correct horse battery" }),
    )
    .await;
    let id = tok["id"].as_str().unwrap();
    t.req(
        "DELETE",
        &format!("/api/enrollment-tokens/{id}"),
        None,
        None,
        true,
    )
    .await;
    let (s, _) = t.get(&format!("/install/{token}/linux")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn enrollment_repository_and_job_lifecycle() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (agent_id, agent_token) = enroll(&mut t, &key, "machine-1").await;
    let caps = ["backup_disks", "verify"];
    assert!(heartbeat(&mut t, &agent_token, &caps, None)
        .await
        .jobs
        .is_empty());
    let (_, agents) = t.get("/api/agents").await;
    assert_eq!(agents[0]["online"], true);
    assert_eq!(agents[0]["public_key"], key.public_b64());

    // A backup without a repository is refused.
    let (s, _) = t
        .post(
            &format!("/api/agents/{agent_id}/jobs"),
            json!({ "kind": { "type": "backup_disks", "paths": ["/dev/sdb"] } }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Create a repository: the "browser" seals the secret to the agent.
    let repo_uuid = uuid::Uuid::new_v4();
    let secret = json!({ "passphrase": "repo passphrase", "recovery_key": "{...}" }).to_string();
    let sealed = seal(&key.public_b64(), secret.as_bytes()).unwrap();
    let (s, r) = t
        .post(
            "/api/repositories",
            json!({ "name": "NAS", "path": "/mnt/nas/fenrir", "repo_uuid": repo_uuid, "init_agent_id": agent_id,
                    "access": [{ "agent_id": agent_id, "sealed": sealed }] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let repo_id = r["id"].as_str().unwrap().to_string();

    // Not ready yet: backups refused.
    let (s, _) = t
        .post(&format!("/api/agents/{agent_id}/jobs"), json!({ "kind": { "type": "backup_disks", "paths": ["/dev/sdb"] }, "repository_id": repo_id }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Agent receives the init job with a secret only it can open.
    let hb = heartbeat(&mut t, &agent_token, &caps, None).await;
    assert_eq!(hb.jobs.len(), 1);
    let job = &hb.jobs[0];
    assert_eq!(job.kind, JobKind::InitRepository);
    let access = job.repository.as_ref().unwrap();
    assert_eq!(access.path, "/mnt/nas/fenrir");
    let opened: RepoSecret =
        serde_json::from_slice(&key.open(&access.sealed_secret).unwrap()).unwrap();
    assert_eq!(opened.passphrase, "repo passphrase");
    // The database never holds the plaintext.
    let db_dump: String =
        t.st.db()
            .query_row("SELECT group_concat(sealed) FROM repo_access", [], |r| {
                r.get(0)
            })
            .unwrap();
    assert!(!db_dump.contains("repo passphrase"));

    // Only one job at a time per agent.
    assert!(
        heartbeat(&mut t, &agent_token, &caps, Some(&job.id.to_string()))
            .await
            .jobs
            .is_empty()
    );
    let (s, _) = t
        .agent(
            &format!("/api/agent/jobs/{}/update", job.id),
            &agent_token,
            json!({ "state": "succeeded", "repo_uuid": repo_uuid }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (_, repos) = t.get("/api/repositories").await;
    assert_eq!(repos[0]["status"], "ready");

    // Run a backup job end to end.
    let (s, j) = t
        .post(&format!("/api/agents/{agent_id}/jobs"), json!({ "kind": { "type": "backup_disks", "paths": ["/dev/sdb"] }, "repository_id": repo_id }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let hb = heartbeat(&mut t, &agent_token, &caps, None).await;
    let jid = hb.jobs[0].id;
    t.agent(
        &format!("/api/agent/jobs/{jid}/update"),
        &agent_token,
        json!({ "state": "running", "progress": { "phase": "reading", "done": 5, "total": 10 } }),
    )
    .await;
    let (_, agents) = t.get("/api/agents").await;
    assert_eq!(agents[0]["running_job"]["progress"]["done"], 5);
    let image = ImageReport {
        image_id: uuid::Uuid::new_v4(),
        machine_id: "machine-1".into(),
        hostname: "web01".into(),
        created: "2026-11-20T10:00:00Z".into(),
        created_unix: 1_795_168_800,
        kind: "full".into(),
        consistency: "offline".into(),
        captured_bytes: 1 << 30,
        stored_new_bytes: 1 << 29,
        disks: vec![1 << 34],
        label: None,
        vm_name: None,
        chunks_total: 0,
        chunks_new: 0,
        bytes_new_raw: 0,
    };
    let (s, _) = t
        .agent(
            &format!("/api/agent/jobs/{jid}/update"),
            &agent_token,
            json!({ "state": "succeeded", "images": [image], "result": { "chunks_new": 3 } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    // Final states are final.
    let (s, _) = t
        .agent(
            &format!("/api/agent/jobs/{jid}/update"),
            &agent_token,
            json!({ "state": "running" }),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (_, imgs) = t.get(&format!("/api/images?agent_id={agent_id}")).await;
    assert_eq!(imgs.as_array().unwrap().len(), 1);
    let (_, ov) = t.get("/api/overview").await;
    assert_eq!(
        ov["last_24h"]["succeeded"], 1,
        "only backups count, not the repository creation"
    );
    assert_eq!(ov["storage"]["images"], 1);

    // Another agent cannot touch this agent's jobs.
    let key2 = AgentKey::generate();
    let (_, tok2) = enroll(&mut t, &key2, "machine-2").await;
    let (s, _) = t
        .agent(
            &format!("/api/agent/jobs/{jid}/update"),
            &tok2,
            json!({ "state": "failed" }),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // A plan creates one job when due, and never piles up.
    let (s, p) = t
        .post(
            "/api/plans",
            json!({ "name": "Nightly", "agent_id": agent_id, "repository_id": repo_id,
                    "job": { "type": "backup_disks", "paths": ["/dev/sdb"] }, "schedule": { "type": "interval", "hours": 24 } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{p}");
    t.st.db()
        .execute("UPDATE plans SET next_run = 1", [])
        .unwrap();
    assert_eq!(server::schedule::run_due(&t.st).unwrap(), 1);
    t.st.db()
        .execute("UPDATE plans SET next_run = 1", [])
        .unwrap();
    assert_eq!(
        server::schedule::run_due(&t.st).unwrap(),
        0,
        "previous run still queued"
    );

    // A dispatched job the agent forgets about (restart) is failed.
    let hb = heartbeat(&mut t, &agent_token, &caps, None).await;
    let lost = hb.jobs[0].id;
    t.st.db()
        .execute(
            "UPDATE jobs SET dispatched = dispatched - 1000 WHERE id = ?1",
            [lost.to_string()],
        )
        .unwrap();
    heartbeat(&mut t, &agent_token, &caps, None).await;
    let (_, j) = t.get(&format!("/api/jobs/{lost}")).await;
    assert_eq!(j["state"], "failed");

    // Removing the machine locks its agent out.
    let (s, _, _) = t
        .req(
            "DELETE",
            &format!("/api/agents/{agent_id}"),
            None,
            None,
            true,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = t
        .agent(
            "/api/agent/heartbeat",
            &agent_token,
            json!({ "inventory": inventory(&caps) }),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn reinstall_with_new_key_drops_sealed_access() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (agent_id, _) = enroll(&mut t, &key, "machine-1").await;
    let sealed = seal(&key.public_b64(), b"{\"passphrase\":\"p\"}").unwrap();
    t.post(
        "/api/repositories",
        json!({ "name": "R", "path": "/r", "repo_uuid": uuid::Uuid::new_v4(), "init_agent_id": agent_id, "access": [{ "agent_id": agent_id, "sealed": sealed }] }),
    )
    .await;
    // Same key: identity and access kept.
    let (again, _) = enroll(&mut t, &key, "machine-1").await;
    assert_eq!(again, agent_id);
    let (_, repos) = t.get("/api/repositories").await;
    assert_eq!(repos[0]["agents"].as_array().unwrap().len(), 1);
    // New key: same identity, access dropped (old seals are useless).
    let (again, _) = enroll(&mut t, &AgentKey::generate(), "machine-1").await;
    assert_eq!(again, agent_id);
    let (_, repos) = t.get("/api/repositories").await;
    assert_eq!(repos[0]["agents"].as_array().unwrap().len(), 0);
}

// ---------- retention, anomaly hold, notifications, restore, updates ----------

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

/// Minimal HTTP listener recording request bodies (webhook target).
fn webhook_listener() -> (String, Arc<Mutex<Vec<String>>>) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let got = Arc::new(Mutex::new(Vec::new()));
    let g2 = got.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            let body = loop {
                let n = s.read(&mut tmp).unwrap_or(0);
                if n == 0 {
                    break String::new();
                }
                buf.extend_from_slice(&tmp[..n]);
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some(i) = text.find("\r\n\r\n") {
                    let len = text[..i]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if buf.len() >= i + 4 + len {
                        break String::from_utf8_lossy(&buf[i + 4..i + 4 + len]).to_string();
                    }
                }
            };
            g2.lock().unwrap().push(body);
            let _ =
                s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        }
    });
    (format!("http://{addr}/hook"), got)
}

fn wait_for(got: &Arc<Mutex<Vec<String>>>, needle: &str) -> bool {
    for _ in 0..100 {
        if got.lock().unwrap().iter().any(|b| b.contains(needle)) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

const CAPS: &[&str] = &[
    "backup_disks",
    "verify",
    "maintenance",
    "restore_vhdx",
    "restore_disk",
];

async fn ready_repo(t: &mut T, key: &AgentKey, agent_id: &str, token: &str) -> String {
    let repo_uuid = uuid::Uuid::new_v4();
    let sealed = seal(&key.public_b64(), b"{\"passphrase\":\"p\"}").unwrap();
    let (_, r) = t
        .post(
            "/api/repositories",
            json!({ "name": "R", "path": "/r", "repo_uuid": repo_uuid, "init_agent_id": agent_id, "access": [{ "agent_id": agent_id, "sealed": sealed }] }),
        )
        .await;
    let hb = heartbeat(t, token, CAPS, None).await;
    t.agent(
        &format!("/api/agent/jobs/{}/update", hb.jobs[0].id),
        token,
        json!({ "state": "succeeded", "repo_uuid": repo_uuid }),
    )
    .await;
    r["id"].as_str().unwrap().to_string()
}

fn image(n: u64, new: u64, raw: u64, stored: u64) -> ImageReport {
    ImageReport {
        image_id: uuid::Uuid::new_v4(),
        machine_id: "machine-1".into(),
        hostname: "web01".into(),
        created: "x".into(),
        created_unix: 1_795_000_000 + n as i64 * 86_400,
        kind: "incremental".into(),
        consistency: "offline".into(),
        captured_bytes: 1 << 30,
        stored_new_bytes: stored,
        disks: vec![1 << 34],
        label: None,
        vm_name: None,
        chunks_total: 1000,
        chunks_new: new,
        bytes_new_raw: raw,
    }
}

/// Run the next dispatched job to completion with `update`.
async fn complete_next(t: &mut T, token: &str, update: Value) -> Option<JobSpec> {
    let hb = heartbeat(t, token, CAPS, None).await;
    let j = hb.jobs.into_iter().next()?;
    let (s, v) = t
        .agent(&format!("/api/agent/jobs/{}/update", j.id), token, update)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    Some(j)
}

#[tokio::test]
async fn retention_anomaly_hold_and_notifications() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let (hook, got) = webhook_listener();
    let (s, v, _) = t
        .req(
            "PUT",
            "/api/settings",
            Some(json!({ "notifications": { "webhook": { "url": hook, "format": "generic" } } })),
            None,
            true,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let key = AgentKey::generate();
    let (agent_id, token) = enroll(&mut t, &key, "machine-1").await;
    heartbeat(&mut t, &token, CAPS, None).await;
    let repo = ready_repo(&mut t, &key, &agent_id, &token).await;

    let (s, plan) = t
        .post(
            "/api/plans",
            json!({ "name": "Nightly", "agent_id": agent_id, "repository_id": repo, "job": { "type": "backup_disks", "paths": ["/dev/sdb"] },
                    "schedule": { "type": "manual" }, "retention": { "keep_last": 3 } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{plan}");
    let plan = plan["id"].as_str().unwrap().to_string();
    let (_, plans) = t.get("/api/plans").await;
    assert_eq!(plans[0]["retention"]["keep_last"], 3);

    // Six normal nightly backups; each is followed by a retention job.
    for n in 0..6u64 {
        t.post(&format!("/api/plans/{plan}/run"), json!({})).await;
        let j = complete_next(
            &mut t,
            &token,
            json!({ "state": "succeeded", "images": [image(n, 30, 30 << 20, 12 << 20)] }),
        )
        .await
        .unwrap();
        assert!(matches!(j.kind, JobKind::BackupDisks { .. }));
        let r = complete_next(
            &mut t,
            &token,
            json!({ "state": "succeeded", "removed_images": [] }),
        )
        .await
        .unwrap();
        match r.kind {
            JobKind::ApplyRetention {
                machine_ids,
                retention,
                ..
            } => {
                assert_eq!(machine_ids, vec!["machine-1"]);
                assert_eq!(retention.keep_last, 3);
            }
            k => panic!("expected retention, got {k:?}"),
        }
    }
    // Retention reports removals: the server forgets those images.
    let (_, imgs) = t.get("/api/images").await;
    let oldest = imgs.as_array().unwrap().last().unwrap()["image_id"]
        .as_str()
        .unwrap()
        .to_string();
    t.post(&format!("/api/plans/{plan}/run"), json!({})).await;
    complete_next(
        &mut t,
        &token,
        json!({ "state": "succeeded", "images": [image(7, 25, 25 << 20, 10 << 20)] }),
    )
    .await;
    complete_next(
        &mut t,
        &token,
        json!({ "state": "succeeded", "removed_images": [oldest] }),
    )
    .await;
    let (_, imgs) = t.get("/api/images").await;
    assert_eq!(imgs.as_array().unwrap().len(), 6);
    assert!(!imgs
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["image_id"] == oldest.as_str()));

    // Mass encryption: 70% changed, incompressible.
    t.post(&format!("/api/plans/{plan}/run"), json!({})).await;
    complete_next(
        &mut t,
        &token,
        json!({ "state": "succeeded", "images": [image(8, 700, 700 << 20, 699 << 20)] }),
    )
    .await;
    let (_, repos) = t.get("/api/repositories").await;
    assert_eq!(repos[0]["hold"], true);
    assert!(repos[0]["hold_reason"]
        .as_str()
        .unwrap()
        .contains("ransomware"));
    assert_eq!(repos[0]["anomalies"], 1);
    assert!(wait_for(&got, "Possible ransomware"), "webhook alert sent");

    // On hold: the queued retention job is not dispatched, prune refused.
    assert!(heartbeat(&mut t, &token, CAPS, None).await.jobs.is_empty());
    let (s, _) = t
        .post(&format!("/api/repositories/{repo}/prune"), json!({}))
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    // Backups still run during a hold.
    t.post(&format!("/api/plans/{plan}/run"), json!({})).await;
    let j = complete_next(
        &mut t,
        &token,
        json!({ "state": "failed", "error": "disk read error" }),
    )
    .await
    .unwrap();
    assert!(matches!(j.kind, JobKind::BackupDisks { .. }));
    assert!(wait_for(&got, "failed: web01"), "failure alert sent");

    // Releasing the hold lets retention proceed.
    t.post(
        &format!("/api/repositories/{repo}/hold"),
        json!({ "hold": false }),
    )
    .await;
    let r = complete_next(&mut t, &token, json!({ "state": "succeeded" }))
        .await
        .unwrap();
    assert!(matches!(r.kind, JobKind::ApplyRetention { .. }));
}

#[tokio::test]
async fn maintenance_restore_settings_and_updates() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (agent_id, token) = enroll(&mut t, &key, "machine-1").await;
    heartbeat(&mut t, &token, CAPS, None).await;
    let repo = ready_repo(&mut t, &key, &agent_id, &token).await;

    // Weekly prune on the maintenance machine (the creator by default).
    let (_, repos) = t.get("/api/repositories").await;
    assert_eq!(repos[0]["maintenance_agent_id"], agent_id.as_str());
    assert_eq!(
        server::schedule::run_maintenance(&t.st).unwrap(),
        0,
        "not due yet"
    );
    t.st.db()
        .execute("UPDATE repositories SET created = 0", [])
        .unwrap();
    assert_eq!(server::schedule::run_maintenance(&t.st).unwrap(), 1);
    assert_eq!(
        server::schedule::run_maintenance(&t.st).unwrap(),
        0,
        "one at a time"
    );
    let j = complete_next(
        &mut t,
        &token,
        json!({ "state": "succeeded", "result": { "chunks_deleted": 3 } }),
    )
    .await
    .unwrap();
    assert_eq!(j.kind, JobKind::Prune { dry_run: false });
    let (_, repos) = t.get("/api/repositories").await;
    assert!(repos[0]["last_prune"].as_i64().is_some());

    // Restore: needs a known image, matching capability and typed confirmation.
    t.st.db()
        .execute(
            "INSERT INTO images (image_id, repository_id, agent_id, machine_id, hostname, created, kind, consistency, captured_bytes, stored_new_bytes, disks_json)
             VALUES ('6b2f7c1e-9f2a-4b8e-9d5f-0a1b2c3d4e5f', ?1, ?2, 'machine-1', 'web01', 1, 'full', 'offline', 1, 1, '[1]')",
            rusqlite::params![repo, agent_id],
        )
        .unwrap();
    let img = "6b2f7c1e-9f2a-4b8e-9d5f-0a1b2c3d4e5f";
    let (s, _) = t
        .post("/api/restores", json!({ "image_id": img, "agent_id": agent_id, "target": { "type": "disk", "device": "/dev/sdc", "disk": 0, "confirm": "/dev/sdb" } }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "confirmation must match");
    let (s, _) = t
        .post("/api/restores", json!({ "image_id": img, "agent_id": agent_id, "target": { "type": "hyperv_vm", "name": "x", "directory": "D:\\\\VMs" } }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "not a Hyper-V host");
    let (s, v) = t.post("/api/restores", json!({ "image_id": img, "agent_id": agent_id, "target": { "type": "vhdx", "directory": "/restores" } })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let hb = heartbeat(&mut t, &token, CAPS, None).await;
    assert!(
        matches!(&hb.jobs[0].kind, JobKind::Restore { target: RestoreTarget::Vhdx { directory }, .. } if directory == "/restores")
    );
    assert!(
        hb.jobs[0].repository.is_some(),
        "restore carries repository access"
    );
    // Prune/retention/restore cannot be smuggled through the generic job endpoint.
    let (s, _) = t
        .post(
            &format!("/api/agents/{agent_id}/jobs"),
            json!({ "kind": { "type": "prune" }, "repository_id": repo }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Settings: the SMTP password is never returned and survives an update without it.
    let email = json!({ "host": "smtp.example", "port": 587, "username": "u", "password": "s3cret", "from": "fenrir@example.com", "to": ["ops@example.com"] });
    let (s, _, _) = t
        .req(
            "PUT",
            "/api/settings",
            Some(json!({ "notifications": { "email": email } })),
            None,
            true,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = t.get("/api/settings").await;
    assert_eq!(v["notifications"]["email"]["password"], "");
    assert_eq!(v["notifications"]["email"]["has_password"], true);
    let mut e2 = email.clone();
    e2["password"] = json!("");
    e2["host"] = json!("smtp2.example");
    t.req(
        "PUT",
        "/api/settings",
        Some(json!({ "notifications": { "email": e2 } })),
        None,
        true,
    )
    .await;
    let stored: server::notify::NotifySettings =
        server::db::get_setting(&t.st.db(), server::notify::KEY);
    assert_eq!(stored.email.as_ref().unwrap().password, "s3cret");
    assert_eq!(stored.email.unwrap().host, "smtp2.example");

    // Updates: offered when the agent runs a different build of its target.
    let mut inv: Inventory = serde_json::from_value(inventory(CAPS)).unwrap();
    inv.agent_target = "x86_64-unknown-linux-musl".into();
    inv.agent_sha256 = "0".repeat(64);
    let (_, v) = t
        .agent("/api/agent/heartbeat", &token, json!({ "inventory": inv }))
        .await;
    let u: HeartbeatResponse = serde_json::from_value(v).unwrap();
    let up = u.update.expect("update offered");
    assert_eq!(up.path, "/agent/x86_64-unknown-linux-musl/fenrir-agent");
    assert_eq!(
        up.sha256,
        server::sha256_hex(b"binary for x86_64-unknown-linux-musl")
    );
    // A glibc build of the same CPU is moved onto the static build.
    let mut gnu = inv.clone();
    gnu.agent_target = "x86_64-unknown-linux-gnu".into();
    let (_, v) = t
        .agent("/api/agent/heartbeat", &token, json!({ "inventory": gnu }))
        .await;
    assert_eq!(
        v["update"]["path"],
        "/agent/x86_64-unknown-linux-musl/fenrir-agent"
    );
    // A MinGW Windows build uses the Windows slot.
    let mut mingw = inv.clone();
    mingw.agent_target = "x86_64-pc-windows-gnu".into();
    let (_, v) = t
        .agent(
            "/api/agent/heartbeat",
            &token,
            json!({ "inventory": mingw }),
        )
        .await;
    assert_eq!(
        v["update"]["path"],
        "/agent/x86_64-pc-windows-msvc/fenrir-agent.exe"
    );
    inv.agent_sha256 = up.sha256.clone();
    let (_, v) = t
        .agent(
            "/api/agent/heartbeat",
            &token,
            json!({ "inventory": inv.clone() }),
        )
        .await;
    assert!(v["update"].is_null(), "already current");
    inv.agent_sha256 = "1".repeat(64);
    t.req(
        "PUT",
        "/api/settings",
        Some(json!({ "auto_update": false })),
        None,
        true,
    )
    .await;
    let (_, v) = t
        .agent("/api/agent/heartbeat", &token, json!({ "inventory": inv }))
        .await;
    assert!(v["update"].is_null(), "auto-update off");
}

#[tokio::test]
async fn boot_checks_results_and_schedule() {
    use base64::Engine;
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (agent_id, token) = enroll(&mut t, &key, "machine-1").await;
    heartbeat(&mut t, &token, CAPS, None).await;
    let repo = ready_repo(&mut t, &key, &agent_id, &token).await;
    let img = "6b2f7c1e-9f2a-4b8e-9d5f-0a1b2c3d4e5f";
    t.st.db()
        .execute(
            "INSERT INTO images (image_id, repository_id, agent_id, machine_id, hostname, created, kind, consistency, captured_bytes, stored_new_bytes, disks_json)
             VALUES (?3, ?1, ?2, 'machine-1', 'web01', 1, 'full', 'offline', 1, 1, '[1]')",
            rusqlite::params![repo, agent_id, img],
        )
        .unwrap();

    // Needs a host that can boot VMs.
    let req = json!({ "agent_id": agent_id });
    let (s, _) = t
        .post(&format!("/api/images/{img}/boot-check"), req.clone())
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let mut caps: Vec<&str> = CAPS.to_vec();
    caps.push("boot_kvm");
    heartbeat(&mut t, &token, &caps, None).await;
    let (s, v) = t
        .post(
            &format!("/api/images/{img}/boot-check"),
            json!({ "agent_id": agent_id, "keep_running": true }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    let png = b"\x89PNG\r\n\x1a\nfake".to_vec();
    let result = json!({
        "image_id": img, "outcome": "verified", "method": "SSH", "seconds": 68, "firmware": "uefi", "accel": "tcg",
        "message": "the guest's SSH service answered",
        "screenshot_png": base64::engine::general_purpose::STANDARD.encode(&png),
        "session": { "session_id": "11111111-2222-4333-8444-555555555555", "image_id": img, "started_unix": 1, "vnc_port": 5901, "forwards": { "SSH": 40022 } }
    });
    let hb = heartbeat(&mut t, &token, &caps, None).await;
    let j = &hb.jobs[0];
    assert!(matches!(
        &j.kind,
        JobKind::BootCheck {
            keep_running: true,
            ..
        }
    ));
    assert!(j.repository.is_some());
    let (s, v) = t
        .agent(
            &format!("/api/agent/jobs/{}/update", j.id),
            &token,
            json!({ "state": "succeeded", "boot_check": result }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    let (_, images) = t.get(&format!("/api/images?repository_id={repo}")).await;
    let b = &images[0]["boot_check"];
    assert_eq!(b["outcome"], "verified");
    assert_eq!(b["has_screenshot"], true);
    let (s, body) = t
        .get(&format!("/api/boot-checks/{}/screenshot.png", b["id"]))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.as_str().unwrap().ends_with("PNG\r\n\u{1a}\nfake"));
    let (_, hist) = t.get(&format!("/api/images/{img}/boot-checks")).await;
    assert_eq!(hist.as_array().unwrap().len(), 1);
    let (_, ov) = t.get("/api/overview").await;
    assert_eq!(ov["boot"]["verified_30d"], 1);
    assert_eq!(ov["boot"]["last_verified"]["hostname"], "web01");

    // Stop a kept-running VM.
    let (s, _) = t
        .post(
            &format!("/api/agents/{agent_id}/vms/11111111-2222-4333-8444-555555555555/stop"),
            json!({}),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let j = complete_next(&mut t, &token, json!({ "state": "succeeded" }))
        .await
        .unwrap();
    assert!(matches!(j.kind, JobKind::StopVm { .. }));

    // Scheduled boot verification: weekly; the recent check means not due.
    heartbeat(&mut t, &token, &caps, None).await;
    let (s, _) = t
        .post(
            &format!("/api/repositories/{repo}/boot-verification"),
            json!({ "agent_id": agent_id, "every_days": 0 }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = t
        .post(
            &format!("/api/repositories/{repo}/boot-verification"),
            json!({ "agent_id": agent_id, "every_days": 7 }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        server::schedule::run_boot_checks(&t.st).unwrap(),
        0,
        "checked recently"
    );
    t.st.db()
        .execute("UPDATE boot_checks SET at = 0", [])
        .unwrap();
    assert_eq!(server::schedule::run_boot_checks(&t.st).unwrap(), 1);
    assert_eq!(
        server::schedule::run_boot_checks(&t.st).unwrap(),
        0,
        "one at a time"
    );
    // A failed result is recorded and alerts; the job fails.
    let failed = json!({ "image_id": img, "outcome": "failed", "method": "firmware", "seconds": 19, "firmware": "bios", "accel": "kvm", "message": "No bootable device" });
    let j = complete_next(
        &mut t,
        &token,
        json!({ "state": "failed", "error": "did not boot", "boot_check": failed }),
    )
    .await
    .unwrap();
    assert!(matches!(
        j.kind,
        JobKind::BootCheck {
            keep_running: false,
            ..
        }
    ));
    let (_, images) = t.get(&format!("/api/images?repository_id={repo}")).await;
    assert_eq!(images[0]["boot_check"]["outcome"], "failed");
    assert_eq!(
        server::schedule::run_boot_checks(&t.st).unwrap(),
        0,
        "a failed check counts as checked"
    );
    let (_, repos) = t.get("/api/repositories").await;
    assert_eq!(repos[0]["boot_every_days"], 7);
    assert!(repos[0]["last_verified_boot"].as_i64().is_some());
}
