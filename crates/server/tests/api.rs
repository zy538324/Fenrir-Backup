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
            ("x86_64-pc-windows-msvc", "fenrir-backup-agent.exe"),
            ("x86_64-unknown-linux-musl", "fenrir-backup-agent"),
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
                downloads_dir: dir.path().join("downloads"),
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
    assert!(p("windows")["setup_url"]
        .as_str()
        .unwrap()
        .ends_with("/windows/Fenrir-Backup-Setup.exe"));
    assert!(p("linux")["setup_url"].is_null());
    assert_eq!(p("macos")["available"], false, "no mac build in agents dir");
    assert!(p("linux")["command"]
        .as_str()
        .unwrap()
        .contains("--pinnedpubkey 'sha256//c3BraQ=='"));
    assert!(p("hyperv")["command"]
        .as_str()
        .unwrap()
        .contains(&format!("[FenrirDl]::Pin = '{}'", "ab".repeat(32))));

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
    // Windows setup programs: the agent build with the settings appended.
    for (platform, file, role) in [
        ("windows", "Fenrir-Backup-Setup.exe", "workstation"),
        ("hyperv", "Fenrir-Backup-Setup-HyperV.exe", "hyperv"),
    ] {
        let req = Request::builder()
            .uri(format!("/install/{token}/{platform}/{file}"))
            .header(header::HOST, "backup.test:8443")
            .body(Body::empty())
            .unwrap();
        let resp = router(t.st.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers()[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .contains(file));
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let (cfg, at) = protocol::setup::read(&bytes).expect("settings appended");
        assert_eq!(&bytes[..at], b"binary for x86_64-pc-windows-msvc");
        assert_eq!(cfg.server, "https://backup.test:8443");
        assert_eq!(cfg.pin, "ab".repeat(32));
        assert_eq!(cfg.token, token);
        assert_eq!(cfg.role, role);
    }
    for bad in ["windows/setup.exe", "linux/Fenrir-Backup-Setup.exe"] {
        let (s, _) = t.get(&format!("/install/{token}/{bad}")).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{bad}");
    }
    let (s, _) = t
        .get("/install/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/windows/Fenrir-Backup-Setup.exe")
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "unknown token");

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
            "/agent/x86_64-pc-windows-msvc/fenrir-backup-agent.exe",
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
        applications: vec![protocol::ImageApplication {
            writer: "SqlServerWriter".into(),
            component: "WEB01\\sales".into(),
            caption: "sales".into(),
            included: true,
            note: None,
            file_sets: 0,
        }],
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
    assert_eq!(imgs[0]["applications"][0]["writer"], "SqlServerWriter");
    assert_eq!(imgs[0]["applications"][0]["included"], true);
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
            let g2 = g2.clone();
            // One thread per connection: a slow delivery must not hold up
            // the next one.
            std::thread::spawn(move || {
                let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(10)));
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
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                );
            });
        }
    });
    (format!("http://{addr}/hook"), got)
}

fn wait_for(got: &Arc<Mutex<Vec<String>>>, needle: &str) -> bool {
    for _ in 0..400 {
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
        applications: vec![],
    }
}

/// Run the next dispatched job to completion with `update`.
async fn complete_next(t: &mut T, token: &str, update: Value) -> Option<JobSpec> {
    complete_next_with(t, token, CAPS, update).await
}

async fn complete_next_with(
    t: &mut T,
    token: &str,
    caps: &[&str],
    update: Value,
) -> Option<JobSpec> {
    let hb = heartbeat(t, token, caps, None).await;
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
    assert!(
        wait_for(&got, "Possible ransomware"),
        "webhook alert sent; received: {:?}",
        got.lock().unwrap()
    );

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
    assert_eq!(
        up.path,
        "/agent/x86_64-unknown-linux-musl/fenrir-backup-agent"
    );
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
        "/agent/x86_64-unknown-linux-musl/fenrir-backup-agent"
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
        "/agent/x86_64-pc-windows-msvc/fenrir-backup-agent.exe"
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

#[tokio::test]
async fn network_share_signin_sealed_per_machine() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let k1 = AgentKey::generate();
    let k2 = AgentKey::generate();
    let (a1, tok1) = enroll(&mut t, &k1, "pc-1").await;
    let (a2, tok2) = enroll(&mut t, &k2, "pc-2").await;
    heartbeat(&mut t, &tok1, CAPS, None).await;
    heartbeat(&mut t, &tok2, CAPS, None).await;
    let pass = |k: &AgentKey| seal(&k.public_b64(), b"{\"passphrase\":\"p\"}").unwrap();
    let creds = |k: &AgentKey, pw: &str| {
        seal(
            &k.public_b64(),
            json!({ "domain": "CORP", "username": "backup-svc", "password": pw })
                .to_string()
                .as_bytes(),
        )
        .unwrap()
    };
    let unc = r"\\nas01\backups\fenrir";
    let repo_uuid = uuid::Uuid::new_v4();
    let body = |with_share: bool| {
        json!({ "name": "NAS", "path": unc, "repo_uuid": repo_uuid, "init_agent_id": a1,
                "share_auth": "password", "share_user": "CORP\\backup-svc",
                "access": [{ "agent_id": a1, "sealed": pass(&k1), "sealed_share": if with_share { Some(creds(&k1, "pw1")) } else { None } }] })
    };
    let (s, _) = t.post("/api/repositories", body(false)).await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "password mode needs a sealed sign-in"
    );
    let (s, _) = t
        .post(
            "/api/repositories",
            json!({ "name": "L", "path": "/srv/r", "repo_uuid": repo_uuid, "init_agent_id": a1, "share_auth": "machine",
                    "access": [{ "agent_id": a1, "sealed": pass(&k1) }] }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "share sign-in on a local path");
    let (s, r) = t.post("/api/repositories", body(true)).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let repo = r["id"].as_str().unwrap().to_string();

    // The init job carries the sealed sign-in; only that agent can open it.
    let hb = heartbeat(&mut t, &tok1, CAPS, None).await;
    let acc = hb.jobs[0].repository.as_ref().unwrap();
    assert_eq!(acc.path, unc);
    let c: ShareCredentials =
        serde_json::from_slice(&k1.open(acc.sealed_share.as_ref().unwrap()).unwrap()).unwrap();
    assert_eq!(
        (c.domain.as_str(), c.username.as_str(), c.password.as_str()),
        ("CORP", "backup-svc", "pw1")
    );
    assert!(k2.open(acc.sealed_share.as_ref().unwrap()).is_err());
    t.agent(
        &format!("/api/agent/jobs/{}/update", hb.jobs[0].id),
        &tok1,
        json!({ "state": "succeeded", "repo_uuid": repo_uuid }),
    )
    .await;
    // The server stored only sealed data.
    let raw: String =
        t.st.db()
            .query_row(
                "SELECT sealed_share FROM repo_access WHERE agent_id = ?1",
                rusqlite::params![a1],
                |r| r.get(0),
            )
            .unwrap();
    assert!(!raw.contains("pw1") && !raw.contains("backup-svc"));
    let (_, repos) = t.get("/api/repositories").await;
    assert_eq!(repos[0]["share_auth"], "password");
    assert_eq!(repos[0]["share_user"], "CORP\\backup-svc");

    // A second machine needs the sign-in too.
    let (s, _) = t
        .post(
            &format!("/api/repositories/{repo}/access"),
            json!({ "agent_id": a2, "sealed": pass(&k2) }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = t
        .post(
            &format!("/api/repositories/{repo}/access"),
            json!({ "agent_id": a2, "sealed": pass(&k2), "sealed_share": creds(&k2, "pw1") }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);

    // New password: must be sealed for every machine with access.
    let (s, _) = t
        .post(
            &format!("/api/repositories/{repo}/share"),
            json!({ "share_auth": "password", "share_user": "CORP\\backup-svc", "access": [{ "agent_id": a1, "sealed_share": creds(&k1, "pw2") }] }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "pc-2 missing");
    let (s, _) = t
        .post(
            &format!("/api/repositories/{repo}/share"),
            json!({ "share_auth": "password", "share_user": "CORP\\backup-svc", "access": [
                { "agent_id": a1, "sealed_share": creds(&k1, "pw2") }, { "agent_id": a2, "sealed_share": creds(&k2, "pw2") }] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    // Switching to the computer account drops the stored sign-ins.
    let (s, _) = t
        .post(
            &format!("/api/repositories/{repo}/share"),
            json!({ "share_auth": "machine" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let n: i64 =
        t.st.db()
            .query_row(
                "SELECT COUNT(*) FROM repo_access WHERE sealed_share IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(n, 0);

    // Test connection: a job with the path and the sign-in.
    let (s, j) = t
        .post(
            &format!("/api/agents/{a2}/check-access"),
            json!({ "path": unc, "sealed_share": creds(&k2, "pw3") }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let hb = heartbeat(&mut t, &tok2, CAPS, None).await;
    assert!(
        matches!(&hb.jobs[0].kind, JobKind::CheckAccess { path, sealed_share: Some(_), .. } if path == unc)
    );
}

#[tokio::test]
async fn browse_and_restore_files() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (agent_id, token) = enroll(&mut t, &key, "machine-1").await;
    let caps: Vec<&str> = CAPS.iter().copied().chain(["restore_files"]).collect();
    heartbeat(&mut t, &token, &caps, None).await;
    let repo = ready_repo(&mut t, &key, &agent_id, &token).await;
    let (s, j) = t.post(&format!("/api/agents/{agent_id}/jobs"), json!({ "kind": { "type": "backup_disks", "paths": ["/dev/sda"] }, "repository_id": repo })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let im = image(1, 30, 30 << 20, 12 << 20);
    complete_next_with(
        &mut t,
        &token,
        &caps,
        json!({ "state": "succeeded", "images": [im] }),
    )
    .await
    .unwrap();
    assert_eq!(
        heartbeat(&mut t, &token, &caps, None).await.poll_seconds,
        15
    );

    // Volumes, then a folder; the machine polls every second meanwhile.
    let (s, v) = t
        .post(&format!("/api/images/{}/browse", im.image_id), json!({}))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["agent_id"], agent_id);
    let hb = heartbeat(&mut t, &token, &caps, None).await;
    assert_eq!(hb.poll_seconds, 1);
    assert_eq!(
        hb.jobs[0].kind,
        JobKind::BrowseFiles {
            image_id: im.image_id,
            volume: None,
            path: "/".into()
        }
    );
    t.agent(
        &format!("/api/agent/jobs/{}/update", hb.jobs[0].id),
        &token,
        json!({ "state": "succeeded", "result": { "volumes": [] } }),
    )
    .await;
    let (s, _) = t
        .post(
            &format!("/api/images/{}/browse", im.image_id),
            json!({ "disk": 0, "partition": 2, "path": "/Users/../x" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = t
        .post(
            &format!("/api/images/{}/browse", im.image_id),
            json!({ "disk": 0, "partition": 2, "path": "/Users" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let j = complete_next_with(
        &mut t,
        &token,
        &caps,
        json!({ "state": "succeeded", "result": { "listing": { "path": "/Users" } } }),
    )
    .await
    .unwrap();
    assert_eq!(
        j.kind,
        JobKind::BrowseFiles {
            image_id: im.image_id,
            volume: Some(VolumeRef {
                disk: 0,
                partition: 2
            }),
            path: "/Users".into()
        }
    );

    // Restore files; a failed browse sends no alert (nothing to check here, but it must not error).
    let (s, v) = t.post(&format!("/api/images/{}/restore-files", im.image_id), json!({
        "disk": 0, "partition": 2, "paths": ["/Users/anna/report.txt"], "target": "C:\\Restored", "conflict": "rename" })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let j = complete_next_with(
        &mut t,
        &token,
        &caps,
        json!({ "state": "succeeded", "result": { "files": 1 } }),
    )
    .await
    .unwrap();
    assert_eq!(
        j.kind,
        JobKind::RestoreFiles {
            image_id: im.image_id,
            volume: VolumeRef {
                disk: 0,
                partition: 2
            },
            paths: vec!["/Users/anna/report.txt".into()],
            target: "C:\\Restored".into(),
            keep_structure: true,
            conflict: "rename".into()
        }
    );
    let (s, _) = t
        .post(
            &format!("/api/images/{}/restore-files", im.image_id),
            json!({
        "disk": 0, "partition": 2, "paths": ["/x"], "target": "C:\\R", "conflict": "explode" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // An agent without file restore is told to update.
    heartbeat(&mut t, &token, CAPS, None).await;
    let (s, v) = t
        .post(&format!("/api/images/{}/browse", im.image_id), json!({}))
        .await;
    assert!(
        s == StatusCode::BAD_REQUEST && v["error"].as_str().unwrap().contains("too old"),
        "{v}"
    );
}

#[tokio::test]
async fn hyperv_boot_test_keeps_the_vm_in_a_chosen_folder() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (agent_id, token) = enroll(&mut t, &key, "machine-1").await;
    let caps: Vec<&str> = CAPS
        .iter()
        .copied()
        .chain(["boot_hyperv", "restore_hyperv"])
        .collect();
    heartbeat(&mut t, &token, &caps, None).await;
    let repo = ready_repo(&mut t, &key, &agent_id, &token).await;
    t.post(
        &format!("/api/agents/{agent_id}/jobs"),
        json!({ "kind": { "type": "backup_disks", "paths": ["/dev/sda"] }, "repository_id": repo }),
    )
    .await;
    let im = image(1, 30, 30 << 20, 12 << 20);
    complete_next_with(
        &mut t,
        &token,
        &caps,
        json!({ "state": "succeeded", "images": [im] }),
    )
    .await
    .unwrap();

    let url = format!("/api/images/{}/boot-check", im.image_id);
    let (s, _) = t
        .post(
            &url,
            json!({ "agent_id": agent_id, "keep_running": true, "directory": "relative" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) = t
        .post(
            &url,
            json!({ "agent_id": agent_id, "keep_running": true, "directory": "D:\\Fenrir checks" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let j = heartbeat(&mut t, &token, &caps, None).await.jobs.remove(0);
    assert_eq!(
        j.kind,
        JobKind::BootCheck {
            image_id: im.image_id,
            keep_running: true,
            memory_mb: None,
            cpus: None,
            directory: Some("D:\\Fenrir checks".into())
        }
    );
}

async fn gw_heartbeat(t: &mut T, token: &str, inv: Value) -> HeartbeatResponse {
    let (s, v) = t
        .agent("/api/agent/heartbeat", token, json!({ "inventory": inv }))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    serde_json::from_value(v).unwrap()
}

/// A raw agent request (binary body), as the gateway relay uses.
async fn raw(
    st: &Shared,
    method: &str,
    uri: &str,
    token: &str,
    body: Vec<u8>,
) -> (StatusCode, Option<String>, Vec<u8>) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "backup.test:8443")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(body))
        .unwrap();
    let resp = router(st.clone()).oneshot(req).await.unwrap();
    let s = resp.status();
    let rid = resp
        .headers()
        .get("X-Relay-Id")
        .map(|v| v.to_str().unwrap().to_string());
    (
        s,
        rid,
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
}

#[tokio::test]
async fn nas_gateway_routes_relays_and_keeps_retention_on_the_gateway() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let gw_key = AgentKey::generate();
    let (gw, gw_token) = enroll(&mut t, &gw_key, "nas-gw").await;
    let caps: Vec<&str> = CAPS.iter().copied().chain(["gateway"]).collect();
    let mut inv = inventory(&caps);
    inv["gateway_addresses"] = json!(["192.168.1.20:8475"]);
    gw_heartbeat(&mut t, &gw_token, inv.clone()).await;
    let repo = ready_repo(&mut t, &gw_key, &gw, &gw_token).await;
    gw_heartbeat(&mut t, &gw_token, inv.clone()).await;
    let laptop_key = AgentKey::generate();
    let (laptop, laptop_token) = enroll(&mut t, &laptop_key, "laptop").await;
    heartbeat(&mut t, &laptop_token, CAPS, None).await;
    let sealed = seal(&laptop_key.public_b64(), b"{\"passphrase\":\"p\"}").unwrap();

    // Through the gateway needs a gateway; the gateway needs direct access.
    let (s, _) = t
        .post(
            &format!("/api/repositories/{repo}/access"),
            json!({ "agent_id": laptop, "sealed": sealed, "via_gateway": true }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = t
        .post(
            &format!("/api/repositories/{repo}/gateway"),
            json!({ "agent_id": laptop }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) = t
        .post(
            &format!("/api/repositories/{repo}/gateway"),
            json!({ "agent_id": gw, "port": 8475, "address": "backup.example.com:18475" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = t
        .post(
            &format!("/api/repositories/{repo}/access"),
            json!({ "agent_id": laptop, "sealed": sealed, "via_gateway": true }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // The gateway learns what to serve and to whom; the laptop how to reach it.
    let cfg = gw_heartbeat(&mut t, &gw_token, inv.clone())
        .await
        .gateway
        .unwrap();
    assert_eq!(cfg.listen_port, 8475);
    assert_eq!(cfg.repositories[0].repository_id.to_string(), repo);
    assert_eq!(
        cfg.repositories[0].clients[0].public_key,
        laptop_key.public_b64()
    );
    assert!(heartbeat(&mut t, &laptop_token, CAPS, None)
        .await
        .gateway
        .is_none());
    t.post(
        &format!("/api/agents/{laptop}/jobs"),
        json!({ "kind": { "type": "backup_disks", "paths": ["/dev/sda"] }, "repository_id": repo }),
    )
    .await;
    let spec = heartbeat(&mut t, &laptop_token, CAPS, None)
        .await
        .jobs
        .remove(0);
    let route = spec.repository.as_ref().unwrap().gateway.clone().unwrap();
    assert_eq!(route.agent_id.to_string(), gw);
    assert_eq!(route.public_key, gw_key.public_b64());
    assert_eq!(
        route.addresses,
        vec![
            "backup.example.com:18475".to_string(),
            "192.168.1.20:8475".into()
        ]
    );
    t.agent(
        &format!("/api/agent/jobs/{}/update", spec.id),
        &laptop_token,
        json!({ "state": "succeeded" }),
    )
    .await;
    let (_, repos) = t.get("/api/repositories").await;
    let r = repos
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == repo)
        .unwrap();
    assert_eq!(r["gateway"]["agent_id"], gw);
    assert_eq!(r["maintenance_agent_id"], gw);

    // A plan backup by the laptop: retention is queued on the gateway.
    let (_, plan) = t.post("/api/plans", json!({ "name": "Laptop", "agent_id": laptop, "repository_id": repo,
        "job": { "type": "backup_disks", "paths": ["/dev/sda"] }, "schedule": { "type": "manual" }, "retention": { "keep_last": 2 } })).await;
    t.post(
        &format!("/api/plans/{}/run", plan["id"].as_str().unwrap()),
        json!({}),
    )
    .await;
    complete_next(
        &mut t,
        &laptop_token,
        json!({ "state": "succeeded", "images": [image(1, 30, 30 << 20, 12 << 20)] }),
    )
    .await
    .unwrap();
    assert!(heartbeat(&mut t, &laptop_token, CAPS, None)
        .await
        .jobs
        .is_empty());
    let j = gw_heartbeat(&mut t, &gw_token, inv.clone())
        .await
        .jobs
        .remove(0);
    assert!(
        matches!(j.kind, JobKind::ApplyRetention { .. }),
        "{:?}",
        j.kind
    );

    // Relay: the laptop's message reaches the gateway, its answer comes back byte for byte.
    let st = t.st.clone();
    let (lt, gwid) = (laptop_token.clone(), gw.clone());
    let sender = tokio::spawn(async move {
        raw(
            &st,
            "POST",
            &format!("/api/agent/relay/{gwid}"),
            &lt,
            b"\x01sealed-request".to_vec(),
        )
        .await
    });
    let (s, rid, body) = raw(&t.st, "GET", "/api/agent/relay/next", &gw_token, vec![]).await;
    assert_eq!(
        (s, body.as_slice()),
        (StatusCode::OK, &b"\x01sealed-request"[..])
    );
    let (s, _, _) = raw(
        &t.st,
        "POST",
        &format!("/api/agent/relay/reply/{}", rid.unwrap()),
        &gw_token,
        b"\x01sealed-answer".to_vec(),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _, body) = sender.await.unwrap();
    assert_eq!(
        (s, body.as_slice()),
        (StatusCode::OK, &b"\x01sealed-answer"[..])
    );
    // Others may not use the gateway; it cannot be removed from under its clients.
    let other = AgentKey::generate();
    let (_, other_token) = enroll(&mut t, &other, "other").await;
    let (s, _, _) = raw(
        &t.st,
        "POST",
        &format!("/api/agent/relay/{gw}"),
        &other_token,
        b"x".to_vec(),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = t
        .post(&format!("/api/repositories/{repo}/gateway"), json!({}))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, _) = t
        .req(
            "DELETE",
            &format!("/api/repositories/{repo}/access/{gw}"),
            None,
            None,
            true,
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

/// Recovery media: the ISO download carries this server's settings in its
/// placeholder block (and nothing else changes), the settings file works
/// for a stick, and recovery tokens enrol recovery sessions only.
#[tokio::test]
async fn recovery_media_is_personalised_and_enrols_recovery_sessions_only() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    // A stand-in ISO: noise with the placeholder across a 1 MiB boundary.
    let mut iso: Vec<u8> = (0..3u32 << 20)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let at = (1 << 20) - 2048;
    iso[at..at + 4096].copy_from_slice(&protocol::recovery::placeholder());
    let dir = t._dir.path().join("agents").join("recovery");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("fenrir-recovery.iso"), &iso).unwrap();

    let (_, rt) = t
        .post(
            "/api/enrollment-tokens",
            json!({ "label": "stick", "role": "recovery", "expires_days": 30 }),
        )
        .await;
    let rtok = rt["token"].as_str().unwrap().to_string();
    let (_, cat) = t.get(&format!("/api/downloads?token={rtok}")).await;
    assert_eq!(cat["recovery"]["available"], true);
    assert_eq!(cat["recovery"]["size"], iso.len());
    let iso_url = cat["recovery"]["iso_url"].as_str().unwrap();
    let path = iso_url.strip_prefix("https://backup.test:8443").unwrap();

    let (s, _, body) = raw(&t.st, "GET", path, "", vec![]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body.len(), iso.len());
    assert_eq!(&body[..at], &iso[..at]);
    assert_eq!(&body[at + 4096..], &iso[at + 4096..]);
    let cfg = protocol::recovery::parse(&body[at..at + 4096])
        .unwrap()
        .unwrap();
    assert_eq!(cfg.server, "https://backup.test:8443");
    assert_eq!(cfg.token, rtok);
    assert_eq!(cfg.pin, "ab".repeat(32));

    let (s, _, js) = raw(
        &t.st,
        "GET",
        &format!("/recovery/{rtok}/fenrir-recovery.json"),
        "",
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(protocol::recovery::parse(&js).unwrap().unwrap(), cfg);

    // An ordinary token does not give recovery media, and the other way round.
    let (_, st) = t
        .post("/api/enrollment-tokens", json!({ "role": "server" }))
        .await;
    let stok = st["token"].as_str().unwrap();
    let (s, _, _) = raw(
        &t.st,
        "GET",
        &format!("/recovery/{stok}/fenrir-recovery.iso"),
        "",
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let key = AgentKey::generate();
    let enroll = |token: &str, role: AgentRole| {
        serde_json::to_value(EnrollRequest {
            protocol: PROTOCOL_VERSION,
            token: token.into(),
            hostname: "recovery-abc".into(),
            machine_id: "recovery:abc".into(),
            os: OsSummary::default(),
            role,
            agent_version: "0.1.0".into(),
            public_key: key.public_b64(),
        })
        .unwrap()
    };
    let (s, _) = t
        .agent("/api/agent/enroll", "", enroll(&rtok, AgentRole::Server))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = t
        .agent("/api/agent/enroll", "", enroll(stok, AgentRole::Recovery))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, v) = t
        .agent("/api/agent/enroll", "", enroll(&rtok, AgentRole::Recovery))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["agent_id"].as_str().unwrap().to_string();

    // Gone a week: removed, and no offline alert is due for it.
    t.st.db()
        .execute(
            "UPDATE agents SET last_seen = last_seen - 8 * 86400 WHERE id = ?1",
            [&id],
        )
        .unwrap();
    assert_eq!(
        server::schedule::expire_recovery_sessions(&t.st).unwrap(),
        1
    );
    let (_, agents) = t.get("/api/agents").await;
    assert!(agents
        .as_array()
        .unwrap()
        .iter()
        .all(|a| a["id"] != id.as_str()));
}

/// S3 repositories: the settings are checked, travel with the job to the
/// agent (keys sealed like a share sign-in), an Object Lock must outlast the
/// maintenance interval, and a NAS gateway is refused.
#[tokio::test]
async fn s3_repositories_with_object_lock() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (agent_id, token) = enroll(&mut t, &key, "s3-machine").await;
    heartbeat(&mut t, &token, CAPS, None).await;
    let sealed = seal(
        &key.public_b64(),
        b"{\"passphrase\":\"p\",\"recovery_key\":null}",
    )
    .unwrap();
    let keys = seal(
        &key.public_b64(),
        b"{\"username\":\"AKID\",\"password\":\"secret\"}",
    )
    .unwrap();
    let s3 = json!({ "endpoint": "https://s3.eu-west-2.amazonaws.com", "region": "eu-west-2", "lock_mode": "compliance", "lock_days": 30 });
    let body = |path: &str, s3: Value, with_keys: bool| {
        json!({ "name": "Cloud", "path": path, "repo_uuid": uuid::Uuid::new_v4(), "init_agent_id": agent_id,
                "share_auth": if with_keys { "password" } else { "none" }, "share_user": "AKID", "s3": s3,
                "access": [{ "agent_id": agent_id, "sealed": sealed, "sealed_share": if with_keys { Some(&keys) } else { None } }] })
    };
    for (path, s3v, keys_given, why) in [
        (
            "s3://backups/office",
            Value::Null,
            true,
            "needs its endpoint",
        ),
        ("s3://Bad_Bucket/x", s3.clone(), true, "bucket name"),
        ("s3://backups/office", s3.clone(), false, "access key"),
        (
            "s3://backups/office",
            json!({ "endpoint": "https://s3.example/path" }),
            true,
            "without a path",
        ),
        (
            "s3://backups/office",
            json!({ "endpoint": "https://s3.example", "lock_mode": "compliance", "lock_days": 5 }),
            true,
            "more often",
        ),
        ("/mnt/nas", s3.clone(), true, "s3://"),
        ("azure://Bad--Name/x", s3.clone(), true, "container name"),
    ] {
        let (s, v) = t
            .post("/api/repositories", body(path, s3v, keys_given))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{path}: {v}");
        assert!(v.to_string().contains(why), "{why}: {v}");
    }
    let (s, r) = t
        .post(
            "/api/repositories",
            body("s3://backups/office", s3.clone(), true),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let repo = r["id"].as_str().unwrap().to_string();
    let hb = heartbeat(&mut t, &token, CAPS, None).await;
    let job = &hb.jobs[0];
    let access = job.repository.as_ref().unwrap();
    assert_eq!(access.path, "s3://backups/office");
    let s = access.s3.as_ref().unwrap();
    assert_eq!(
        (s.region.as_str(), s.lock_mode.as_deref(), s.lock_days),
        ("eu-west-2", Some("compliance"), 30)
    );
    assert!(access.sealed_share.is_some(), "keys sealed to the machine");
    let (s, v) = t
        .agent(
            &format!("/api/agent/jobs/{}/update", job.id),
            &token,
            json!({ "state": "succeeded" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, repos) = t.get("/api/repositories").await;
    assert_eq!(repos[0]["s3"]["lock_days"], 30);

    // Maintenance must stay more frequent than the lock.
    let (s, _) = t
        .post(
            &format!("/api/repositories/{repo}/maintenance"),
            json!({ "prune_every_days": 0 }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = t
        .post(
            &format!("/api/repositories/{repo}/maintenance"),
            json!({ "prune_every_days": 14 }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    // No NAS gateway for object storage.
    let (s, v) = t
        .post(
            &format!("/api/repositories/{repo}/gateway"),
            json!({ "agent_id": agent_id, "port": 0 }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    // Test connection carries the settings too.
    let (s, _) = t
        .post(
            &format!("/api/agents/{agent_id}/check-access"),
            json!({ "path": "s3://backups/new", "sealed_share": keys, "s3": s3 }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let hb = heartbeat(&mut t, &token, CAPS, None).await;
    assert!(hb
        .jobs
        .iter()
        .any(|j| matches!(&j.kind, JobKind::CheckAccess { s3: Some(_), .. })));

    // Azure Blob uses the same settings; its endpoint may name the account
    // in the path (the Azurite emulator).
    let azure = json!({ "endpoint": "http://127.0.0.1:10000/devstoreaccount1", "region": "", "lock_mode": "compliance", "lock_days": 30 });
    let (s, r) = t
        .post(
            "/api/repositories",
            body("azure://backups/office", azure, true),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
}

#[tokio::test]
async fn offsite_copy_after_each_plan_backup() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (agent_id, token) = enroll(&mut t, &key, "machine-1").await;
    heartbeat(&mut t, &token, CAPS, None).await;
    let local = ready_repo(&mut t, &key, &agent_id, &token).await;
    let offsite = ready_repo(&mut t, &key, &agent_id, &token).await;

    // Not into itself, and only where the machine has access.
    let plan_body = |copy: &str| {
        json!({ "name": "Nightly", "agent_id": agent_id, "repository_id": local, "job": { "type": "backup_disks", "paths": ["/dev/sdb"] },
                "schedule": { "type": "manual" }, "copy_to_repository_id": copy })
    };
    let (s, _) = t.post("/api/plans", plan_body(&local)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, plan) = t.post("/api/plans", plan_body(&offsite)).await;
    assert_eq!(s, StatusCode::OK, "{plan}");
    let plan = plan["id"].as_str().unwrap().to_string();
    let (_, plans) = t.get("/api/plans").await;
    assert_eq!(plans[0]["copy_to_repository_id"], offsite.as_str());

    // A backup is followed by a copy job carrying both repositories.
    t.post(&format!("/api/plans/{plan}/run"), json!({})).await;
    let im = image(1, 30, 30 << 20, 12 << 20);
    complete_next(
        &mut t,
        &token,
        json!({ "state": "succeeded", "images": [im] }),
    )
    .await
    .unwrap();
    let hb = heartbeat(&mut t, &token, CAPS, None).await;
    let job = &hb.jobs[0];
    match &job.kind {
        JobKind::CopyImages {
            target_repository_id,
            images,
            ..
        } => {
            assert_eq!(target_repository_id.to_string(), offsite);
            assert_eq!(images, &vec![im.image_id]);
        }
        other => panic!("expected a copy, got {other:?}"),
    }
    assert_eq!(
        job.repository.as_ref().unwrap().repository_id.to_string(),
        local
    );
    assert_eq!(
        job.copy_target.as_ref().unwrap().repository_id.to_string(),
        offsite
    );
    // The copied image is listed in the destination.
    let (s, _) = t
        .agent(
            &format!("/api/agent/jobs/{}/update", job.id),
            &token,
            json!({ "state": "succeeded", "images": [ImageReport { image_id: uuid::Uuid::new_v4(), ..im.clone() }] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (_, imgs) = t.get(&format!("/api/images?repository_id={offsite}")).await;
    assert_eq!(imgs.as_array().unwrap().len(), 1);

    // Copy now, by hand; and the plan's copy can be turned off.
    let (s, v) = t
        .post(
            &format!("/api/repositories/{local}/copy"),
            json!({ "agent_id": agent_id, "target_repository_id": offsite }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, _) = t
        .req(
            "PATCH",
            &format!("/api/plans/{plan}"),
            Some(json!({ "copy_to_repository_id": null })),
            None,
            true,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (_, plans) = t.get("/api/plans").await;
    assert!(plans[0]["copy_to_repository_id"].is_null());
}

#[tokio::test]
async fn existing_repository_is_adopted_and_config_exported() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (agent_id, token) = enroll(&mut t, &key, "machine-1").await;
    heartbeat(&mut t, &token, CAPS, None).await;
    let sealed = seal(&key.public_b64(), b"{\"passphrase\":\"p\"}").unwrap();
    let body = json!({ "name": "Moved", "path": "/mnt/old", "existing": true, "init_agent_id": agent_id,
                       "access": [{ "agent_id": agent_id, "sealed": sealed }] });
    let (s, r) = t.post("/api/repositories", body.clone()).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let repo = r["id"].as_str().unwrap().to_string();
    // The machine lists it (no new repository is created) and reports its ID.
    let real = uuid::Uuid::new_v4();
    let hb = heartbeat(&mut t, &token, CAPS, None).await;
    assert!(matches!(hb.jobs[0].kind, JobKind::ListImages));
    let im = image(1, 30, 30 << 20, 12 << 20);
    t.agent(
        &format!("/api/agent/jobs/{}/update", hb.jobs[0].id),
        &token,
        json!({ "state": "succeeded", "repo_uuid": real, "images": [im] }),
    )
    .await;
    let (_, repos) = t.get("/api/repositories").await;
    let r0 = repos
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == repo.as_str())
        .unwrap();
    assert_eq!(
        (r0["status"].as_str(), r0["repo_uuid"].as_str()),
        (Some("ready"), Some(real.to_string().as_str()))
    );
    assert_eq!(r0["images"], 1, "its history came with it");
    // Adding the same repository twice is refused.
    let (_, r2) = t.post("/api/repositories", body).await;
    let hb = heartbeat(&mut t, &token, CAPS, None).await;
    t.agent(
        &format!("/api/agent/jobs/{}/update", hb.jobs[0].id),
        &token,
        json!({ "state": "succeeded", "repo_uuid": real, "images": [] }),
    )
    .await;
    let (_, repos) = t.get("/api/repositories").await;
    let dup = repos
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == r2["id"])
        .unwrap();
    assert_eq!(dup["status"], "failed");
    assert!(dup["status_message"]
        .as_str()
        .unwrap()
        .contains("already registered"));

    // Export: repositories and plans, no secrets.
    let (s, _) = t
        .post(
            "/api/plans",
            json!({ "name": "Nightly", "agent_id": agent_id, "repository_id": repo, "job": { "type": "backup_disks", "paths": ["/dev/sdb"] },
                    "schedule": { "type": "interval", "hours": 0, "minutes": 30 }, "retention": { "keep_hourly": 24 } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, ex) = t.get("/api/export").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(ex["format"], "fenrir-backup-export");
    assert_eq!(ex["repositories"][0]["repo_uuid"], real.to_string());
    assert_eq!(ex["plans"][0]["machine_id"], "machine-1");
    assert_eq!(ex["plans"][0]["repo_uuid"], real.to_string());
    assert_eq!(ex["plans"][0]["schedule"]["minutes"], 30);
    let text = ex.to_string();
    assert!(
        !text.contains("sealed") && !text.contains("passphrase"),
        "no secrets: {text}"
    );
}

#[tokio::test]
async fn files_download_through_the_server_encrypted_for_the_browser() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (agent_id, token) = enroll(&mut t, &key, "machine-1").await;
    let caps: Vec<&str> = CAPS.iter().copied().chain(["restore_files"]).collect();
    heartbeat(&mut t, &token, &caps, None).await;
    let repo = ready_repo(&mut t, &key, &agent_id, &token).await;
    t.post(
        &format!("/api/agents/{agent_id}/jobs"),
        json!({ "kind": { "type": "backup_disks", "paths": ["/dev/sda"] }, "repository_id": repo }),
    )
    .await;
    let im = image(1, 30, 30 << 20, 12 << 20);
    complete_next_with(
        &mut t,
        &token,
        &caps,
        json!({ "state": "succeeded", "images": [im] }),
    )
    .await
    .unwrap();

    let browser = AgentKey::generate();
    let url = format!("/api/images/{}/download-files", im.image_id);
    let (s, _) = t
        .post(
            &url,
            json!({ "disk": 0, "partition": 2, "paths": ["/Users/ann"], "recipient": "not-a-key" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, j) = t
        .post(&url, json!({ "disk": 0, "partition": 2, "paths": ["/Users/ann"], "recipient": browser.public_b64() }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let job = j["id"].as_str().unwrap().to_string();
    let hb = heartbeat(&mut t, &token, &caps, None).await;
    assert!(
        matches!(&hb.jobs[0].kind, JobKind::DownloadFiles { recipient, .. } if *recipient == browser.public_b64())
    );

    // The agent uploads the stream in parts; a retried part is harmless, a gap is refused.
    let up = format!("/api/agent/jobs/{job}/download?offset=");
    let (a, b) = (vec![1u8; 1000], vec![2u8; 500]);
    assert_eq!(
        raw(&t.st, "POST", &format!("{up}0"), &token, a.clone())
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        raw(&t.st, "POST", &format!("{up}0"), &token, a.clone())
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        raw(&t.st, "POST", &format!("{up}5000"), &token, b.clone())
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        raw(&t.st, "POST", &format!("{up}1000"), &token, b.clone())
            .await
            .0,
        StatusCode::OK
    );
    // Another machine cannot write to it.
    let (_, other) = enroll(&mut t, &AgentKey::generate(), "machine-2").await;
    assert_eq!(
        raw(&t.st, "POST", &format!("{up}1500"), &other, b.clone())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    // Not before the job finishes; then the stream as uploaded.
    let (s, _) = t.get(&format!("/api/jobs/{job}/download")).await;
    assert_eq!(s, StatusCode::CONFLICT);
    t.agent(
        &format!("/api/agent/jobs/{job}/update"),
        &token,
        json!({ "state": "succeeded", "result": { "download": {} } }),
    )
    .await;
    let (s, _, body) = t
        .req(
            "GET",
            &format!("/api/jobs/{job}/download"),
            None,
            None,
            false,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let body = body.expect("binary body").into_bytes();
    let stored = std::fs::read(t.st.cfg.downloads_dir.join(format!("{job}.bin"))).unwrap();
    assert_eq!(stored, [a, b].concat());
    assert_eq!(body.len(), stored.len());
    // A finished download takes no more uploads.
    assert_eq!(
        raw(&t.st, "POST", &format!("{up}1500"), &token, vec![3u8])
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        server::schedule::purge_downloads(&t.st.cfg.downloads_dir, 0),
        1
    );
}

#[tokio::test]
async fn dedup_group_repositories_share_storage_and_key() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (agent_id, token) = enroll(&mut t, &key, "machine-1").await;
    heartbeat(&mut t, &token, CAPS, None).await;
    let sealed = seal(&key.public_b64(), b"{\"passphrase\":\"p\"}").unwrap();
    let new_repo = |uuid: uuid::Uuid, dedup: &str| {
        json!({ "name": format!("R {dedup}"), "path": "/mnt/group", "repo_uuid": uuid, "dedup": dedup,
                "init_agent_id": agent_id, "access": [{ "agent_id": agent_id, "sealed": sealed }] })
    };
    // A new group: the repository lives in <group>/repos/<its id>.
    let a_uuid = uuid::Uuid::new_v4();
    let (s, r) = t.post("/api/repositories", new_repo(a_uuid, "new")).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let a = r["id"].as_str().unwrap().to_string();
    let job = complete_next(
        &mut t,
        &token,
        json!({ "state": "succeeded", "repo_uuid": a_uuid }),
    )
    .await
    .unwrap();
    assert_eq!(
        job.repository.as_ref().unwrap().path,
        format!("/mnt/group/repos/{a_uuid}")
    );
    assert!(job.group_source.is_none(), "a new group makes its own key");

    // Joining it: same group folder, and the group's key comes from A.
    let b_uuid = uuid::Uuid::new_v4();
    let mut elsewhere = new_repo(b_uuid, &a);
    elsewhere["path"] = json!("/mnt/other");
    let (s, _) = t.post("/api/repositories", elsewhere).await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "a member is stored in the group's folder"
    );
    let (s, r) = t.post("/api/repositories", new_repo(b_uuid, &a)).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let job = complete_next(
        &mut t,
        &token,
        json!({ "state": "succeeded", "repo_uuid": b_uuid }),
    )
    .await
    .unwrap();
    assert_eq!(
        job.repository.as_ref().unwrap().path,
        format!("/mnt/group/repos/{b_uuid}")
    );
    let src = job
        .group_source
        .as_ref()
        .expect("the group's key comes from A");
    assert_eq!(src.repository_id.to_string(), a);
    assert_eq!(src.path, format!("/mnt/group/repos/{a_uuid}"));

    // A repository in no group cannot be joined.
    let plain = ready_repo(&mut t, &key, &agent_id, &token).await;
    let (s, _) = t
        .post("/api/repositories", new_repo(uuid::Uuid::new_v4(), &plain))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // A machine without access to A cannot create a member of its group.
    let key2 = AgentKey::generate();
    let (agent2, token2) = enroll(&mut t, &key2, "machine-2").await;
    heartbeat(&mut t, &token2, CAPS, None).await;
    let sealed2 = seal(&key2.public_b64(), b"{\"passphrase\":\"p\"}").unwrap();
    let (s, r) = t
        .post(
            "/api/repositories",
            json!({ "name": "C", "path": "/mnt/group", "repo_uuid": uuid::Uuid::new_v4(), "dedup": a,
                    "init_agent_id": agent2, "access": [{ "agent_id": agent2, "sealed": sealed2 }] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert!(heartbeat(&mut t, &token2, CAPS, None).await.jobs.is_empty());
    let (_, jobs) = t.get("/api/jobs").await;
    let failed = jobs
        .as_array()
        .unwrap()
        .iter()
        .find(|j| j["agent_id"] == agent2.as_str())
        .unwrap();
    assert_eq!(failed["state"], "failed");
    assert!(
        failed["error"].as_str().unwrap().contains("dedup group"),
        "{failed}"
    );
}

#[tokio::test]
async fn local_recovery_partition_jobs_and_their_enrolment_code() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (agent_id, token) = enroll(&mut t, &key, "pc-1").await;
    let url = format!("/api/agents/{agent_id}/local-recovery");
    // Only machines that report the capability (Windows).
    heartbeat(&mut t, &token, CAPS, None).await;
    let (s, _) = t
        .post(&url, json!({ "action": "install", "confirm": "web01" }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let caps: Vec<&str> = CAPS.iter().copied().chain(["local_recovery"]).collect();
    heartbeat(&mut t, &token, &caps, None).await;
    // The machine's name must be typed.
    let (s, v) = t
        .post(&url, json!({ "action": "install", "confirm": "web02" }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, _) = t.post(&url, json!({ "action": "refresh" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "nothing to refresh yet");
    let (s, v) = t
        .post(
            &url,
            json!({ "action": "install", "confirm": "WEB01", "auto_start": true }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let hb = heartbeat(&mut t, &token, &caps, None).await;
    let job = &hb.jobs[0];
    assert!(matches!(
        job.kind,
        JobKind::LocalRecovery {
            action: protocol::LocalRecoveryAction::Install,
            auto_start: true,
            ..
        }
    ));
    let cfg = job
        .recovery_settings
        .clone()
        .expect("an enrolment code for the recovery system");
    assert!(
        cfg.server.is_empty(),
        "the agent adds its own server address"
    );
    assert!(cfg.expires as i64 > 300 * 86_400 + 1_700_000_000);

    // The code enrols recovery sessions only.
    let enrol = |role: AgentRole, tok: String| EnrollRequest {
        protocol: PROTOCOL_VERSION,
        token: tok,
        hostname: "MINWINPC".into(),
        machine_id: "pe".into(),
        os: OsSummary::default(),
        role,
        agent_version: "0.1.0".into(),
        public_key: AgentKey::generate().public_b64(),
    };
    let (s, _) = t
        .agent(
            "/api/agent/enroll",
            "",
            serde_json::to_value(enrol(AgentRole::Server, cfg.token.clone())).unwrap(),
        )
        .await;
    assert_ne!(s, StatusCode::OK, "not as an ordinary machine");
    let (s, v) = t
        .agent(
            "/api/agent/enroll",
            "",
            serde_json::to_value(enrol(AgentRole::Recovery, cfg.token.clone())).unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // Installed: reported in the inventory. After an agent update it is rebuilt by the schedule.
    t.agent(
        &format!("/api/agent/jobs/{}/update", job.id),
        &token,
        json!({ "state": "succeeded" }),
    )
    .await;
    let mut inv = inventory(&caps);
    inv["local_recovery"] = json!({ "disk": 0, "partition": 5, "size": 1 << 30, "built_unix": 1_700_000_000,
                                    "agent_version": "0.0.9", "expires": cfg.expires, "auto_start": true });
    let (s, _) = t
        .agent(
            "/api/agent/heartbeat",
            &token,
            json!({ "inventory": inv, "running_job": null }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = t
        .post(&url, json!({ "action": "install", "confirm": "web01" }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "already installed");
    assert_eq!(server::schedule::refresh_local_recovery(&t.st).unwrap(), 1);
    assert_eq!(
        server::schedule::refresh_local_recovery(&t.st).unwrap(),
        0,
        "one at a time"
    );
    let (_, v) = t
        .agent(
            "/api/agent/heartbeat",
            &token,
            json!({ "inventory": inv, "running_job": null }),
        )
        .await;
    let hb: HeartbeatResponse = serde_json::from_value(v).unwrap();
    let refresh = &hb.jobs[0];
    assert!(matches!(
        refresh.kind,
        JobKind::LocalRecovery {
            action: protocol::LocalRecoveryAction::Refresh,
            auto_start: true,
            ..
        }
    ));
    let new = refresh.recovery_settings.clone().unwrap();
    assert_ne!(new.token, cfg.token, "a new code replaces the old one");
    let (s, _) = t
        .agent(
            "/api/agent/enroll",
            "",
            serde_json::to_value(enrol(AgentRole::Recovery, cfg.token.clone())).unwrap(),
        )
        .await;
    assert_ne!(s, StatusCode::OK, "the old code no longer works");
    t.agent(
        &format!("/api/agent/jobs/{}/update", refresh.id),
        &token,
        json!({ "state": "succeeded" }),
    )
    .await;

    // Removing: confirmed, and the code is revoked when the job is sent.
    let (s, _) = t
        .post(&url, json!({ "action": "remove", "confirm": "web01" }))
        .await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = t
        .agent(
            "/api/agent/heartbeat",
            &token,
            json!({ "inventory": inv, "running_job": null }),
        )
        .await;
    let hb: HeartbeatResponse = serde_json::from_value(v).unwrap();
    assert!(hb.jobs[0].recovery_settings.is_none());
    let (s, _) = t
        .agent(
            "/api/agent/enroll",
            "",
            serde_json::to_value(enrol(AgentRole::Recovery, new.token)).unwrap(),
        )
        .await;
    assert_ne!(s, StatusCode::OK);
}

#[tokio::test]
async fn kubernetes_and_saas_plans_carry_only_sealed_credentials() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (agent_id, token) = enroll(&mut t, &key, "runner").await;
    heartbeat(&mut t, &token, CAPS, None).await;
    let repo = ready_repo(&mut t, &key, &agent_id, &token).await;
    let sealed_secret = seal(&key.public_b64(), b"client-secret-value").unwrap();
    let saas = json!({ "type": "backup_saas", "sealed_secret": sealed_secret,
        "tenant": { "service": "m365", "tenant": "contoso.onmicrosoft.com", "client_id": "app-id" } });
    let plan = |job: Value| json!({ "name": "SaaS", "agent_id": agent_id, "repository_id": repo, "job": job, "schedule": { "type": "manual" } });

    // A machine that does not report the capability cannot run it.
    let (s, v) = t.post("/api/plans", plan(saas.clone())).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(v.to_string().contains("saas"), "{v}");
    let caps: Vec<&str> = CAPS.iter().copied().chain(["kubernetes", "saas"]).collect();
    heartbeat(&mut t, &token, &caps, None).await;

    // Incomplete settings are refused.
    let mut bad = saas.clone();
    bad["tenant"]["client_id"] = json!("");
    let (s, _) = t.post("/api/plans", plan(bad)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, p) = t.post("/api/plans", plan(saas)).await;
    assert_eq!(s, StatusCode::OK, "{p}");
    let p = p["id"].as_str().unwrap().to_string();
    t.post(&format!("/api/plans/{p}/run"), json!({})).await;
    let hb = heartbeat(&mut t, &token, &caps, None).await;
    let JobKind::BackupSaas {
        tenant,
        sealed_secret,
    } = &hb.jobs[0].kind
    else {
        panic!("{:?}", hb.jobs[0].kind)
    };
    assert_eq!(tenant.service, "m365");
    assert_eq!(
        &key.open(sealed_secret).unwrap()[..],
        b"client-secret-value"
    );
    let (_, plans) = t.get("/api/plans").await;
    assert!(!plans.to_string().contains("client-secret-value"));

    // Kubernetes: the cluster must name namespaces; a restore renames one.
    let sealed_token = seal(&key.public_b64(), b"eyJ-token").unwrap();
    let cluster = json!({ "name": "prod", "api_server": "https://k8s.lan:6443", "ca_pem": "", "namespaces": [] });
    let url = format!("/api/agents/{agent_id}/jobs");
    let job = |c: Value, replace: bool, confirm: &str| json!({ "repository_id": repo, "confirm": confirm, "kind": { "type": "restore_kubernetes", "image_id": uuid::Uuid::new_v4(), "cluster": c, "sealed_token": sealed_token, "namespaces": ["shop"], "rename_to": "shop-restored", "replace": replace } });
    let (s, _) = t.post(&url, job(cluster.clone(), false, "")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "no namespaces");
    let mut ok = cluster;
    ok["namespaces"] = json!(["shop"]);
    let (s, v) = t.post(&url, job(ok.clone(), false, "")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = t.post(&url, job(ok.clone(), true, "")).await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "replacing objects needs the name typed"
    );
    let (s, v) = t.post(&url, job(ok, true, "PROD")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn scans_search_app_restore_folder_plans_standby_and_legal_hold() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (agent_id, token) = enroll(&mut t, &key, "machine-1").await;
    let caps: Vec<&str> = CAPS
        .iter()
        .copied()
        .chain([
            "backup_files",
            "scan_images",
            "search_files",
            "restore_apps",
            "restore_vm_files",
            "legal_hold",
        ])
        .collect();
    heartbeat(&mut t, &token, &caps, None).await;
    let repo = ready_repo(&mut t, &key, &agent_id, &token).await;
    heartbeat(&mut t, &token, &caps, None).await;

    // Detection content: hashes are checked, rules named.
    let (s, _, _) = t
        .req(
            "PUT",
            "/api/scan-content",
            Some(json!({ "rules": [], "indicators": ["nothex"] })),
            None,
            true,
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let bad = "AB".repeat(32);
    let (s, v, _) = t
        .req("PUT", "/api/scan-content", Some(json!({ "rules": [{ "name": "eicar", "source": "rule eicar { condition: true }" }], "indicators": [bad] })), None, true)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // A plan of folders that scans each backup and keeps a standby VM.
    let plan = json!({ "name": "Docs", "agent_id": agent_id, "repository_id": repo,
        "job": { "type": "backup_files", "paths": ["relative/path"] }, "schedule": { "type": "manual" } });
    let (s, _) = t.post("/api/plans", plan.clone()).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "paths must be full paths");
    let mut plan = plan;
    plan["job"]["paths"] = json!(["/home/anna", "C:\\Users\\anna\\Documents"]);
    plan["scan_after_backup"] = json!(true);
    plan["standby"] = json!({ "agent_id": agent_id, "type": "vm_files", "format": "qcow2", "name": "web standby", "directory": "/srv/standby" });
    plan["retention"] = json!({ "keep_last": 1 });
    let (s, p) = t.post("/api/plans", plan).await;
    assert_eq!(s, StatusCode::OK, "{p}");
    let plan_id = p["id"].as_str().unwrap().to_string();
    let (_, plans) = t.get("/api/plans").await;
    assert_eq!(plans[0]["scan_after_backup"], true);
    assert_eq!(plans[0]["standby"]["format"], "qcow2");

    // A disk image backup to scan, search and restore.
    t.post(&format!("/api/plans/{plan_id}/run"), json!({}))
        .await;
    let mut im = image(1, 10, 10 << 20, 4 << 20);
    im.applications = vec![protocol::ImageApplication {
        writer: "SqlServerWriter".into(),
        component: "WEB01\\sales".into(),
        caption: "sales".into(),
        included: true,
        note: None,
        file_sets: 2,
    }];
    let image_id = im.image_id;
    let j = complete_next_with(
        &mut t,
        &token,
        &caps,
        json!({ "state": "succeeded", "images": [im] }),
    )
    .await
    .unwrap();
    assert!(matches!(j.kind, JobKind::BackupFiles { .. }));
    // After it: the file catalogue, a scan with the content, the standby, then retention.
    // (handed out one per heartbeat; the others are finished as they come)
    let mut jobs: Vec<JobSpec> = Vec::new();
    for _ in 0..8 {
        let hb = heartbeat(&mut t, &token, &caps, None).await;
        for j in hb.jobs {
            if !matches!(j.kind, JobKind::ScanImage { .. }) {
                t.agent(
                    &format!("/api/agent/jobs/{}/update", j.id),
                    &token,
                    json!({ "state": "succeeded" }),
                )
                .await;
            }
            jobs.push(j);
        }
    }
    let kinds: Vec<&JobKind> = jobs.iter().map(|j| &j.kind).collect();
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, JobKind::IndexImage { image_id: i } if *i == image_id)),
        "{kinds:?}"
    );
    let scan = jobs
        .iter()
        .find(|j| matches!(j.kind, JobKind::ScanImage { .. }))
        .expect("a scan after the backup");
    let JobKind::ScanImage {
        rules, indicators, ..
    } = &scan.kind
    else {
        unreachable!()
    };
    assert_eq!(rules[0].name, "eicar");
    assert_eq!(indicators[0], "ab".repeat(32));
    let (_, all) = t.get("/api/jobs").await;
    assert!(
        all.as_array()
            .unwrap()
            .iter()
            .any(|j| j["kind"]["type"] == "restore"
                && j["kind"]["target"]["type"] == "vm_files"
                && j["kind"]["target"]["replace"] == true),
        "the standby VM is updated: {all}"
    );
    assert!(kinds
        .iter()
        .any(|k| matches!(k, JobKind::ApplyRetention { .. })));

    // The scan finds malware: restores of that image need an explicit yes.
    let (s, v) = t
        .agent(
            &format!("/api/agent/jobs/{}/update", scan.id),
            &token,
            json!({ "state": "succeeded", "result": { "image_id": image_id, "scan": {
                "files_scanned": 40, "bytes_scanned": 1000, "volumes_scanned": ["C:\\\\"],
                "findings": [{ "volume": "C:\\\\", "path": "Users/anna/evil.exe", "size": 68, "sha256": "ab".repeat(32),
                               "detections": [{ "kind": "hash", "name": "known bad" }] }] } } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, scans) = t.get(&format!("/api/images/{image_id}/scans")).await;
    assert_eq!(scans[0]["state"], "infected");
    let (_, imgs) = t.get("/api/images").await;
    assert_eq!(imgs[0]["last_scan"]["state"], "infected");
    let restore = json!({ "image_id": image_id, "agent_id": agent_id, "target": { "type": "vhdx", "directory": "/restore" } });
    let (s, v) = t.post("/api/restores", restore.clone()).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let mut yes = restore;
    yes["allow_infected"] = json!(true);
    let (s, v) = t.post("/api/restores", yes).await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // One database, into a folder, attached under a new name.
    let url = format!("/api/images/{image_id}/restore-app");
    let app = json!({ "agent_id": agent_id, "component": "WEB01\\sales", "directory": "D:\\Restores", "attach_as": "sales_copy", "allow_infected": true });
    let (s, v) = t.post(&url, app.clone()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let mut no = app.clone();
    no["component"] = json!("WEB01\\nope");
    assert_eq!(t.post(&url, no).await.0, StatusCode::BAD_REQUEST);
    let mut rel = app;
    rel["directory"] = json!("Restores");
    assert_eq!(t.post(&url, rel).await.0, StatusCode::BAD_REQUEST);

    // Search: one job per repository on a machine that can.
    let (s, v) = t
        .post(
            "/api/search",
            json!({ "query": "budget", "machine_id": "machine-1" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["jobs"].as_array().unwrap().len(), 1);

    // Legal hold of a machine; released only with the password.
    let (s, v) = t
        .post(
            "/api/legal-hold/machine",
            json!({ "machine_id": "machine-1", "reason": "Case 42" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["held"], 1);
    let hold = format!("/api/images/{image_id}/legal-hold");
    let (s, _) = t
        .post(&hold, json!({ "hold": false, "password": "wrong" }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) = t
        .post(
            &hold,
            json!({ "hold": false, "password": "correct horse battery" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["legal_hold"].is_null());
}

#[tokio::test]
async fn storage_is_checked_daily_and_a_failure_is_shown_and_alerted() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (agent_id, token) = enroll(&mut t, &key, "nas-client").await;
    heartbeat(&mut t, &token, CAPS, None).await;
    let repo = ready_repo(&mut t, &key, &agent_id, &token).await;

    assert_eq!(server::schedule::check_storage(&t.st).unwrap(), 1);
    assert_eq!(
        server::schedule::check_storage(&t.st).unwrap(),
        0,
        "once a day"
    );
    let j = complete_next(
        &mut t,
        &token,
        json!({ "state": "failed", "error": "access denied: the key was revoked" }),
    )
    .await
    .unwrap();
    assert!(
        matches!(j.kind, JobKind::CheckAccess { .. }),
        "{:?}",
        j.kind
    );
    let (_, repos) = t.get("/api/repositories").await;
    let r = repos
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == repo.as_str())
        .unwrap();
    assert_eq!(r["storage_error"], "access denied: the key was revoked");
    assert!(r["storage_checked_at"].as_i64().is_some());

    // The next day it works again: the error goes.
    t.st.db()
        .execute(
            "UPDATE repositories SET storage_checked_at = storage_checked_at - 90000",
            [],
        )
        .unwrap();
    t.st.db()
        .execute(
            "UPDATE jobs SET created = created - 90000 WHERE requested_by = 'storage check'",
            [],
        )
        .unwrap();
    assert_eq!(server::schedule::check_storage(&t.st).unwrap(), 1);
    complete_next(
        &mut t,
        &token,
        json!({ "state": "succeeded", "result": { "free_bytes": 1 } }),
    )
    .await
    .unwrap();
    let (_, repos) = t.get("/api/repositories").await;
    let r = repos
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == repo.as_str())
        .unwrap();
    assert!(r["storage_error"].is_null(), "{r}");
}

#[tokio::test]
async fn offline_media_set_copies_go_to_the_attached_drive() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (agent_id, token) = enroll(&mut t, &key, "machine-1").await;
    heartbeat(&mut t, &token, CAPS, None).await;
    let local = ready_repo(&mut t, &key, &agent_id, &token).await;
    let drive_a = ready_repo(&mut t, &key, &agent_id, &token).await;
    let drive_b = ready_repo(&mut t, &key, &agent_id, &token).await;
    for d in [&drive_a, &drive_b] {
        let (s, v) = t
            .post(
                &format!("/api/repositories/{d}/media-set"),
                json!({ "media_set": "Weekly rotation" }),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    let (_, repos) = t.get("/api/repositories").await;
    assert_eq!(
        repos
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["media_set"] == "Weekly rotation")
            .count(),
        2
    );

    let (s, plan) = t
        .post("/api/plans", json!({ "name": "Nightly", "agent_id": agent_id, "repository_id": local,
            "job": { "type": "backup_disks", "paths": ["/dev/sdb"] }, "schedule": { "type": "manual" }, "copy_to_repository_id": drive_a }))
        .await;
    assert_eq!(s, StatusCode::OK, "{plan}");
    t.post(
        &format!("/api/plans/{}/run", plan["id"].as_str().unwrap()),
        json!({}),
    )
    .await;
    complete_next(
        &mut t,
        &token,
        json!({ "state": "succeeded", "images": [image(1, 30, 30 << 20, 12 << 20)] }),
    )
    .await
    .unwrap();
    // The copy carries the other drive of the set and copies everything the drive lacks.
    let hb = heartbeat(&mut t, &token, CAPS, None).await;
    let copy = hb
        .jobs
        .iter()
        .find(|j| matches!(j.kind, JobKind::CopyImages { .. }))
        .expect("a copy");
    let JobKind::CopyImages { images, .. } = &copy.kind else {
        unreachable!()
    };
    assert!(
        images.is_empty(),
        "a rotated drive gets every image it lacks"
    );
    assert_eq!(
        copy.copy_target.as_ref().unwrap().repository_id.to_string(),
        drive_a
    );
    assert_eq!(copy.copy_alternatives.len(), 1);
    assert_eq!(copy.copy_alternatives[0].repository_id.to_string(), drive_b);
    // Drive B was attached: the copies are listed under it.
    let mut copied = image(2, 30, 30 << 20, 12 << 20);
    copied.machine_id = "machine-1".into();
    let (s, v) = t
        .agent(&format!("/api/agent/jobs/{}/update", copy.id), &token,
               json!({ "state": "succeeded", "images": [copied], "result": { "target_repository_id": drive_b } }))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, on_b) = t.get(&format!("/api/images?repository_id={drive_b}")).await;
    let (_, on_a) = t.get(&format!("/api/images?repository_id={drive_a}")).await;
    assert_eq!(
        (
            on_b.as_array().unwrap().len(),
            on_a.as_array().unwrap().len()
        ),
        (1, 0)
    );
}

#[tokio::test]
async fn restore_users_see_and_restore_only_their_machines() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (mine, token) = enroll(&mut t, &key, "anna-laptop").await;
    let (other, other_token) = enroll(&mut t, &AgentKey::generate(), "finance-server").await;
    let caps: Vec<&str> = CAPS.iter().copied().chain(["restore_files"]).collect();
    heartbeat(&mut t, &token, &caps, None).await;
    heartbeat(&mut t, &other_token, &caps, None).await;
    let repo = ready_repo(&mut t, &key, &mine, &token).await;
    heartbeat(&mut t, &token, &caps, None).await;
    // One backup of each machine in the repository.
    for (agent, machine) in [(&mine, "anna"), (&other, "finance")] {
        let mut im = image(1, 1, 1, 1);
        im.machine_id = machine.into();
        t.st.db()
            .execute(
                "INSERT INTO images (image_id, repository_id, agent_id, machine_id, hostname, created, kind, consistency, captured_bytes, stored_new_bytes, disks_json)
                 VALUES (?1, ?2, ?3, ?4, ?4, 1, 'full', 'crash', 1, 1, '[1]')",
                rusqlite::params![im.image_id.to_string(), repo, agent, machine],
            )
            .unwrap();
    }
    let (s, v) = t
        .post(
            "/api/users",
            json!({ "username": "anna", "password": "anna's long password", "machines": [mine] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let admin_cookie = t.cookie.clone();

    // Anna signs in: her machine's backups only, nothing administrative.
    t.cookie = None;
    let (s, _) = t
        .post(
            "/api/login",
            json!({ "username": "anna", "password": "anna's long password" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (_, st) = t.get("/api/status").await;
    assert_eq!(st["user"]["role"], "restore");
    assert_eq!(t.get("/api/agents").await.0, StatusCode::FORBIDDEN);
    assert_eq!(t.get("/api/images").await.0, StatusCode::FORBIDDEN);
    let (_, imgs) = t.get("/api/self/images").await;
    let imgs = imgs.as_array().unwrap().clone();
    assert_eq!(imgs.len(), 1);
    let my_image = imgs[0]["image_id"].as_str().unwrap().to_string();
    let theirs: String =
        t.st.db()
            .query_row(
                "SELECT image_id FROM images WHERE machine_id = 'finance'",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(
        t.post(&format!("/api/self/images/{theirs}/browse"), json!({}))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (s, v) = t
        .post(&format!("/api/self/images/{my_image}/browse"), json!({}))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let job = v["id"].as_str().unwrap().to_string();
    let (s, j) = t.get(&format!("/api/self/jobs/{job}")).await;
    assert_eq!(s, StatusCode::OK, "{j}");

    // Someone else's job is not hers.
    t.cookie = admin_cookie;
    let (_, admin_job) = t
        .post(&format!("/api/images/{theirs}/browse"), json!({}))
        .await;
    let (_, users) = t.get("/api/users").await;
    assert!(users
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["username"] == "anna" && u["role"] == "restore"));
    t.cookie = None;
    t.post(
        "/api/login",
        json!({ "username": "anna", "password": "anna's long password" }),
    )
    .await;
    assert_eq!(
        t.get(&format!(
            "/api/self/jobs/{}",
            admin_job["id"].as_str().unwrap()
        ))
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn ediscovery_case_holds_searches_exports_and_chain_of_custody() {
    let mut t = T::new();
    setup_admin(&mut t).await;
    let key = AgentKey::generate();
    let (agent_id, token) = enroll(&mut t, &key, "machine-1").await;
    let caps: Vec<&str> = CAPS
        .iter()
        .copied()
        .chain(["search_files", "ediscovery"])
        .collect();
    heartbeat(&mut t, &token, &caps, None).await;
    let repo = ready_repo(&mut t, &key, &agent_id, &token).await;
    heartbeat(&mut t, &token, &caps, None).await;
    let backup = |n: u64, machine: &str| {
        let mut im = image(n, 30, 30 << 20, 12 << 20);
        im.machine_id = machine.into();
        im
    };
    let first = backup(1, "machine-1");
    let saas = backup(2, "saas:m365:contoso");
    let (s, v) = t
        .post(
            &format!("/api/agents/{agent_id}/jobs"),
            json!({ "kind": { "type": "backup_disks", "paths": ["/dev/sdb"] }, "repository_id": repo }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    complete_next_with(
        &mut t,
        &token,
        &caps,
        json!({ "state": "succeeded", "images": [first, saas] }),
    )
    .await
    .unwrap();
    while complete_next_with(&mut t, &token, &caps, json!({ "state": "succeeded" }))
        .await
        .is_some()
    {}

    let (s, _) = t
        .post(
            "/api/cases",
            json!({ "name": "Smith v Acme", "custodians": [{ "machine_id": "nobody" }] }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, case) = t
        .post("/api/cases", json!({ "name": "Smith v Acme", "matter": "M-14", "custodians": [
            { "machine_id": "machine-1" }, { "machine_id": "saas:m365:contoso", "accounts": ["ann@contoso.com"] }] }))
        .await;
    assert_eq!(s, StatusCode::OK, "{case}");
    assert_eq!(case["held_backups"], 2);
    let id = case["id"].as_str().unwrap().to_string();

    // A later backup of a custodian is held too.
    let later = backup(3, "machine-1");
    let later_id = later.image_id.to_string();
    t.post(
        &format!("/api/agents/{agent_id}/jobs"),
        json!({ "kind": { "type": "backup_disks", "paths": ["/dev/sdb"] }, "repository_id": repo }),
    )
    .await;
    complete_next_with(
        &mut t,
        &token,
        &caps,
        json!({ "state": "succeeded", "images": [later] }),
    )
    .await
    .unwrap();
    while complete_next_with(&mut t, &token, &caps, json!({ "state": "succeeded" }))
        .await
        .is_some()
    {}
    let (_, c) = t.get(&format!("/api/cases/{id}")).await;
    assert_eq!(c["held_backups"], 3);

    // Search: the matches are kept, only the case's accounts of the tenant.
    let (s, v) = t
        .post(
            &format!("/api/cases/{id}/search"),
            json!({ "query": "budget" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let hits = json!({ "hits": [
        { "image_id": first.image_id, "path": "/home/ann/budget.xlsx", "size": 10, "folder": false, "volume": { "disk": 1, "partition": 1 } },
        { "image_id": saas.image_id, "account": "ann@contoso.com", "kind": "mail", "path": "Inbox/Budget", "size": 5 },
        { "image_id": saas.image_id, "account": "bob@contoso.com", "kind": "mail", "path": "Inbox/Budget", "size": 5 }] });
    let spec = complete_next_with(
        &mut t,
        &token,
        &caps,
        json!({ "state": "succeeded", "result": hits }),
    )
    .await
    .unwrap();
    assert!(matches!(spec.kind, JobKind::SearchFiles { .. }));
    let (_, c) = t.get(&format!("/api/cases/{id}")).await;
    assert_eq!(c["searches"][0]["state"], "done");
    assert_eq!(c["searches"][0]["hits"].as_array().unwrap().len(), 2);

    // Export: SaaS items for this browser, with the hashes recorded.
    let browser = AgentKey::generate();
    let (s, _) = t
        .post(&format!("/api/cases/{id}/export"), json!({ "image_id": saas.image_id, "accounts": ["bob@contoso.com"], "recipient": browser.public_b64() }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, ex) = t
        .post(&format!("/api/cases/{id}/export"), json!({ "image_id": saas.image_id, "kinds": ["mail"], "recipient": browser.public_b64() }))
        .await;
    assert_eq!(s, StatusCode::OK, "{ex}");
    let hb = heartbeat(&mut t, &token, &caps, None).await;
    let JobKind::ExportSaas {
        accounts, kinds, ..
    } = &hb.jobs[0].kind
    else {
        panic!("{:?}", hb.jobs[0].kind)
    };
    assert_eq!(
        (accounts.clone(), kinds.clone()),
        (
            vec!["ann@contoso.com".to_string()],
            vec!["mail".to_string()]
        )
    );
    let stream = b"ciphertext".repeat(20);
    let (s, _, _) = raw(
        &t.st,
        "POST",
        &format!("/api/agent/jobs/{}/download?offset=0", hb.jobs[0].id),
        &token,
        stream.clone(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    t.agent(&format!("/api/agent/jobs/{}/update", hb.jobs[0].id), &token,
            json!({ "state": "succeeded", "result": { "download": {}, "manifest_sha256": "ab".repeat(32), "manifest_files": 3 } }))
        .await;
    let eid = ex["id"].as_str().unwrap();
    let (s, _) = t
        .post(
            &format!("/api/cases/{id}/exports/{eid}/receipt"),
            json!({ "sha256": "cd".repeat(32), "bytes": 100 }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, doc) = t.get(&format!("/api/cases/{id}/manifest")).await;
    assert_eq!(s, StatusCode::OK);
    let ex = &doc["exports"][0];
    assert_eq!(ex["manifest_sha256"], "ab".repeat(32));
    assert_eq!(
        ex["ciphertext_sha256"],
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&stream))
    );
    assert_eq!(ex["receipts"][0]["sha256"], "cd".repeat(32));
    assert_eq!(doc["holds"].as_array().unwrap().len(), 3);
    let mut body = doc.clone();
    body.as_object_mut().unwrap().remove("sha256");
    assert_eq!(
        doc["sha256"],
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
            serde_json::to_vec(&body).unwrap()
        ))
    );

    // A hold by hand stays when the case closes; the case's own are released.
    let (s, _) = t
        .post(
            &format!("/api/images/{}/legal-hold", first.image_id),
            json!({ "hold": true, "reason": "HR matter" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = t
        .post(
            &format!("/api/cases/{id}/close"),
            json!({ "password": "wrong" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, c) = t
        .post(
            &format!("/api/cases/{id}/close"),
            json!({ "password": "correct horse battery" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{c}");
    assert_eq!(c["held_backups"], 0);
    let (_, imgs) = t.get(&format!("/api/images?repository_id={repo}")).await;
    let hold_of = |i: &str| {
        imgs.as_array()
            .unwrap()
            .iter()
            .find(|x| x["image_id"] == i)
            .unwrap()["legal_hold"]
            .clone()
    };
    assert!(hold_of(&later_id).is_null());
    assert_eq!(hold_of(&first.image_id.to_string())["reason"], "HR matter");
}
