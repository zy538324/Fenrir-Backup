//! NAS gateway (protocol::gateway): one agent inside a network serves a
//! repository on a NAS or file server to chosen agents elsewhere.
//!
//! This server tells the gateway what to serve and to whom (heartbeat),
//! tells each client how to reach it (job specs), and relays messages when a
//! client cannot reach the gateway directly. Messages are encrypted and
//! authenticated end to end between the two agents: the relay moves bytes it
//! can neither read nor forge.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use protocol::gateway::{GatewayClient, GatewayConfig, GatewayRepo, GatewayRoute};
use rusqlite::{params, Connection, OptionalExtension};
use tokio::sync::{oneshot, Notify};
use uuid::Uuid;

use crate::auth::AgentAuth;
use crate::{ApiError, ApiResult, Shared};

pub const DEFAULT_PORT: u16 = 8475;
const MAX_MESSAGE: usize = (64 << 20) + 8192;
const MAX_QUEUED: usize = 512 << 20;
const REPLY_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_TIMEOUT: Duration = Duration::from_secs(25);

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/agent/relay/next", get(next))
        .route("/api/agent/relay/reply/{rid}", post(reply))
        .route("/api/agent/relay/{gateway}", post(send))
        .layer(DefaultBodyLimit::max(MAX_MESSAGE))
}

/// What `agent` serves, for its heartbeat.
pub fn config(db: &Connection, agent: &str) -> rusqlite::Result<Option<GatewayConfig>> {
    let mut s = db.prepare(
        "SELECT r.id, r.path, x.sealed_share FROM repositories r
         JOIN repo_access x ON x.repository_id = r.id AND x.agent_id = ?1
         WHERE r.gateway_agent_id = ?1",
    )?;
    let repos: Vec<(String, String, Option<String>)> = s
        .query_map(params![agent], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    drop(s);
    let mut out = Vec::new();
    for (id, path, share) in repos {
        let mut c = db.prepare(
            "SELECT a.id, a.public_key FROM agents a JOIN repo_access x ON x.agent_id = a.id
             WHERE x.repository_id = ?1 AND x.via_gateway = 1 AND a.revoked = 0 AND a.id != ?2",
        )?;
        let clients = c
            .query_map(params![id, agent], |r| {
                Ok(GatewayClient {
                    agent_id: r.get::<_, String>(0)?.parse().unwrap_or_default(),
                    public_key: r.get(1)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        out.push(GatewayRepo {
            repository_id: id.parse().unwrap_or_default(),
            path,
            sealed_share: share.as_deref().and_then(|s| serde_json::from_str(s).ok()),
            clients,
        });
    }
    if out.is_empty() {
        return Ok(None);
    }
    let port: Option<i64> = db.query_row(
        "SELECT gateway_port FROM agents WHERE id = ?1",
        params![agent],
        |r| r.get(0),
    )?;
    Ok(Some(GatewayConfig {
        listen_port: port.unwrap_or(0).clamp(0, 65535) as u16,
        repositories: out,
    }))
}

/// Where clients try the gateway directly: the address set in the web UI,
/// then the one it reports while it listens.
pub fn addresses(db: &Connection, gateway: &str) -> rusqlite::Result<Vec<String>> {
    let (port, address, inv): (Option<i64>, Option<String>, Option<String>) = db.query_row(
        "SELECT gateway_port, gateway_address, inventory_json FROM agents WHERE id = ?1",
        params![gateway],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let mut out: Vec<String> = address.into_iter().collect();
    if port.unwrap_or(0) > 0 {
        if let Some(inv) = inv.and_then(|s| serde_json::from_str::<protocol::Inventory>(&s).ok()) {
            out.extend(inv.gateway_addresses);
        }
    }
    out.dedup();
    out.truncate(8);
    Ok(out)
}

/// How `agent` reaches repository `repo`, when it goes through the gateway.
pub fn route(db: &Connection, repo: &str, agent: &str) -> rusqlite::Result<Option<GatewayRoute>> {
    let row: Option<(Option<String>, i64)> = db
        .query_row(
            "SELECT r.gateway_agent_id, x.via_gateway FROM repositories r
             JOIN repo_access x ON x.repository_id = r.id AND x.agent_id = ?2 WHERE r.id = ?1",
            params![repo, agent],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((Some(gw), 1)) = row else {
        return Ok(None);
    };
    if gw == agent {
        return Ok(None);
    }
    let pk: Option<String> = db
        .query_row(
            "SELECT public_key FROM agents WHERE id = ?1 AND revoked = 0",
            params![gw],
            |r| r.get(0),
        )
        .optional()?;
    let Some(public_key) = pk else {
        return Ok(None);
    };
    Ok(Some(GatewayRoute {
        agent_id: gw.parse().unwrap_or_default(),
        public_key,
        addresses: addresses(db, &gw)?,
        relay: true,
    }))
}

// ---------------------------------------------------------------------------
// Relay: in memory, in this process
// ---------------------------------------------------------------------------

struct Pending {
    gateway: String,
    body: Option<Bytes>,
    reply: oneshot::Sender<Bytes>,
}

#[derive(Default)]
pub struct Relay {
    queues: Mutex<HashMap<String, VecDeque<String>>>,
    wake: Mutex<HashMap<String, std::sync::Arc<Notify>>>,
    pending: Mutex<HashMap<String, Pending>>,
    queued: AtomicUsize,
    /// (client, gateway) → when the permission was last checked.
    allowed: Mutex<HashMap<(String, String), Instant>>,
}

impl Relay {
    fn notify(&self, gateway: &str) -> std::sync::Arc<Notify> {
        self.wake
            .lock()
            .unwrap()
            .entry(gateway.to_string())
            .or_default()
            .clone()
    }

    fn take(&self, gateway: &str) -> Option<(String, Bytes)> {
        let mut q = self.queues.lock().unwrap();
        let queue = q.get_mut(gateway)?;
        while let Some(rid) = queue.pop_front() {
            let mut p = self.pending.lock().unwrap();
            if let Some(body) = p.get_mut(&rid).and_then(|x| x.body.take()) {
                self.queued.fetch_sub(body.len(), Ordering::SeqCst);
                return Some((rid, body));
            }
        }
        None
    }
}

fn may_relay(st: &Shared, client: &str, gateway: &str) -> ApiResult<bool> {
    let key = (client.to_string(), gateway.to_string());
    if st
        .relay
        .allowed
        .lock()
        .unwrap()
        .get(&key)
        .is_some_and(|t| t.elapsed() < Duration::from_secs(60))
    {
        return Ok(true);
    }
    let ok: bool = st.db().query_row(
        "SELECT EXISTS(SELECT 1 FROM repo_access x JOIN repositories r ON r.id = x.repository_id
         WHERE x.agent_id = ?1 AND x.via_gateway = 1 AND r.gateway_agent_id = ?2)",
        params![client, gateway],
        |r| r.get(0),
    )?;
    if ok {
        st.relay.allowed.lock().unwrap().insert(key, Instant::now());
    }
    Ok(ok)
}

fn octets(b: Bytes) -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        b,
    )
        .into_response()
}

/// A client's message for its gateway; answers with the gateway's reply.
async fn send(
    State(st): State<Shared>,
    agent: AgentAuth,
    Path(gateway): Path<String>,
    body: Bytes,
) -> ApiResult<Response> {
    let gateway = Uuid::parse_str(&gateway)
        .map_err(|_| ApiError::bad("invalid gateway id"))?
        .to_string();
    if !may_relay(&st, &agent.agent_id, &gateway)? {
        return Err(ApiError::forbidden(
            "this machine is not routed through that gateway",
        ));
    }
    if st.relay.queued.load(Ordering::SeqCst) + body.len() > MAX_QUEUED {
        return Err(ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "the relay is busy; try again shortly".into(),
        });
    }
    let rid = Uuid::new_v4().simple().to_string();
    let (tx, rx) = oneshot::channel();
    st.relay.queued.fetch_add(body.len(), Ordering::SeqCst);
    st.relay.pending.lock().unwrap().insert(
        rid.clone(),
        Pending {
            gateway: gateway.clone(),
            body: Some(body),
            reply: tx,
        },
    );
    st.relay
        .queues
        .lock()
        .unwrap()
        .entry(gateway.clone())
        .or_default()
        .push_back(rid.clone());
    st.relay.notify(&gateway).notify_one();
    let answer = tokio::time::timeout(REPLY_TIMEOUT, rx).await;
    if let Some(p) = st.relay.pending.lock().unwrap().remove(&rid) {
        if let Some(b) = p.body {
            st.relay.queued.fetch_sub(b.len(), Ordering::SeqCst);
        }
    }
    match answer {
        Ok(Ok(b)) => Ok(octets(b)),
        _ => Err(ApiError {
            status: StatusCode::GATEWAY_TIMEOUT,
            message: "the gateway did not answer: is it online?".into(),
        }),
    }
}

/// Long poll for a gateway: the next client message, or 204 after 25 seconds.
async fn next(State(st): State<Shared>, agent: AgentAuth) -> ApiResult<Response> {
    let deadline = Instant::now() + POLL_TIMEOUT;
    let wake = st.relay.notify(&agent.agent_id);
    loop {
        if let Some((rid, body)) = st.relay.take(&agent.agent_id) {
            let mut h = HeaderMap::new();
            h.insert("X-Relay-Id", HeaderValue::from_str(&rid).expect("hex id"));
            return Ok((h, octets(body)).into_response());
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(StatusCode::NO_CONTENT.into_response());
        }
        let _ = tokio::time::timeout(left, wake.notified()).await;
    }
}

async fn reply(
    State(st): State<Shared>,
    agent: AgentAuth,
    Path(rid): Path<String>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let p = {
        let mut pending = st.relay.pending.lock().unwrap();
        match pending.get(&rid) {
            Some(p) if p.gateway == agent.agent_id => pending.remove(&rid),
            _ => None,
        }
    };
    match p {
        Some(p) => {
            let _ = p.reply.send(body);
            Ok(StatusCode::NO_CONTENT)
        }
        None => Err(ApiError::not_found(
            "nobody is waiting for that answer any more",
        )),
    }
}
