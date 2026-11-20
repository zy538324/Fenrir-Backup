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
