"""NAS gateway end to end: the real fenrir-server and two real backup agents on one Linux machine.

The "laptop" (its own /etc/machine-id in a private mount namespace, so it is a different machine) backs up into a
repository only the "gateway" can reach: first through the server relay, then directly. Needs root (unshare/mount)
and Python with httpx and cryptography.

    sudo python3 ci/e2e-gateway.py <work dir> <fenrir-server> <fenrir-backup-agent>
"""

import base64
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

W, SERVER, AGENT = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
shutil.rmtree(W, ignore_errors=True)
W.mkdir(parents=True)
BASE = "http://127.0.0.1:18443"
env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
procs = []


def b64(b):
    return base64.b64encode(b).decode()


def seal(pk_b64, plaintext: bytes):
    """The web UI's half of protocol::seal (fenrir-agent-seal-v1)."""
    apk = base64.b64decode(pk_b64)
    eph = X25519PrivateKey.generate()
    epk = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key = HKDF(SHA256(), 32, salt=epk + apk, info=b"fenrir-agent-seal-v1").derive(eph.exchange(X25519PublicKey.from_public_bytes(apk)))
    nonce = os.urandom(12)
    return {"v": 1, "epk": b64(epk), "nonce": b64(nonce), "ct": b64(AESGCM(key).encrypt(nonce, plaintext, None))}


def agent(name, *args, background=False):
    state = W / name
    state.mkdir(exist_ok=True)
    e = dict(env, FENRIR_AGENT_STATE=str(state))
    cmd = [AGENT, *args]
    if name == "laptop":
        mid = W / "laptop-machine-id"
        if not mid.exists():
            mid.write_text(uuid.uuid4().hex + "\n")
        cmd = ["unshare", "--mount", "sh", "-c", f'mount --bind "{mid}" /etc/machine-id && exec "$0" "$@"', *cmd]
    if background:
        p = subprocess.Popen(cmd, env=e, stdout=open(W / f"{name}.log", "w"), stderr=subprocess.STDOUT)
        procs.append(p)
        return p
    r = subprocess.run(cmd, env=e, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, (name, args, r.stdout, r.stderr)
    return r.stdout


def wait_job(c, jid, what, seconds=300):
    for _ in range(seconds):
        j = c.get(f"/api/jobs/{jid}").json()
        if j["state"] in ("succeeded", "warning", "failed", "cancelled"):
            print(f"  {what}: {j['state']} {j.get('error') or ''}")
            assert j["state"] in ("succeeded", "warning"), j
            return j
        time.sleep(1)
    raise SystemExit(f"{what} did not finish")


try:
    procs.append(subprocess.Popen([SERVER, "--http", "--listen", "127.0.0.1:18443", "--data-dir", str(W / "srv"),
                                   "--agents-dir", str(W / "agents"), "--public-url", BASE],
                                  env=env, stdout=open(W / "server.log", "w"), stderr=subprocess.STDOUT))
    for _ in range(60):
        try:
            if httpx.get(f"{BASE}/healthz", timeout=2).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.5)
    c = httpx.Client(base_url=BASE, timeout=60, headers={"x-fenrir-csrf": "1"})
    assert c.post("/api/setup", json={"username": "admin", "password": "e2e correct horse battery"}).status_code == 200
    token = c.post("/api/enrollment-tokens", json={"label": "e2e", "role": "server"}).json()["token"]
    agent("gateway", "enroll", "--server", BASE, "--token", token, "--role", "server")
    agent("laptop", "enroll", "--server", BASE, "--token", token, "--role", "workstation")
    agent("gateway", "run", background=True)
    agent("laptop", "run", background=True)
    ids = {json.loads((W / n / "agent.json").read_text())["agent_id"]: n for n in ("gateway", "laptop")}
    for _ in range(60):
        agents = {ids.get(a["id"]): a for a in c.get("/api/agents").json()}
        if all(n in agents and "gateway" in agents[n]["capabilities"] for n in ("gateway", "laptop")):
            break
        time.sleep(1)
    gw, laptop = agents["gateway"], agents["laptop"]
    print("agents online:", gw["online"], laptop["online"])

    nas = W / "nas" / "repo"
    repo_uuid = str(uuid.uuid4())
    rk = {"format": "fenrir-recovery-key", "version": 1, "repo_id": repo_uuid, "slot_id": str(uuid.uuid4()), "key": b64(os.urandom(32))}
    secret = lambda first: json.dumps({"passphrase": "e2e repository passphrase", "recovery_key": json.dumps(rk) if first else None}).encode()
    r = c.post("/api/repositories", json={"name": "NAS", "path": str(nas), "repo_uuid": repo_uuid, "init_agent_id": gw["id"],
                                          "access": [{"agent_id": gw["id"], "sealed": seal(gw["public_key"], secret(True))}]})
    assert r.status_code == 200, r.text
    repo_id = r.json()["id"]
    wait_job(c, r.json()["init_job_id"], "create repository on the gateway")

    assert c.post(f"/api/repositories/{repo_id}/gateway", json={"agent_id": gw["id"], "port": 0}).status_code == 200
    assert c.post(f"/api/repositories/{repo_id}/access", json={
        "agent_id": laptop["id"], "sealed": seal(laptop["public_key"], secret(False)), "via_gateway": True}).status_code == 200
    disk = W / "laptop-disk.img"
    disk.write_bytes(bytes((i * 31 + i // 4096) % 251 for i in range(24 << 20)))
    t = time.time()
    j = c.post(f"/api/agents/{laptop['id']}/jobs", json={"kind": {"type": "backup_disks", "paths": [str(disk)]}, "repository_id": repo_id}).json()
    wait_job(c, j["id"], "laptop backup through the RELAY")
    print(f"  ({time.time() - t:.1f}s for 24 MiB)")
    assert (nas / "manifests").is_dir() and any((nas / "manifests").iterdir()), "nothing written on the NAS"
    j = c.post(f"/api/agents/{laptop['id']}/jobs", json={"kind": {"type": "verify", "level": "full"}, "repository_id": repo_id}).json()
    wait_job(c, j["id"], "laptop full verify through the relay")
    j = c.post(f"/api/repositories/{repo_id}/prune", json={"dry_run": True}).json()
    wait_job(c, j["id"], "space-reclamation estimate (runs on the gateway)")

    assert c.post(f"/api/repositories/{repo_id}/gateway", json={"agent_id": gw["id"], "port": 18475}).status_code == 200
    for _ in range(60):
        g = [x for x in c.get("/api/repositories").json() if x["id"] == repo_id][0]["gateway"]
        if g["addresses"]:
            break
        time.sleep(1)
    print("  gateway addresses:", g["addresses"])
    disk.write_bytes(bytes((i * 17 + i // 999) % 249 for i in range(24 << 20)))
    j = c.post(f"/api/agents/{laptop['id']}/jobs", json={"kind": {"type": "backup_disks", "paths": [str(disk)]}, "repository_id": repo_id}).json()
    wait_job(c, j["id"], "laptop backup DIRECT")
    images = c.get("/api/images", params={"repository_id": repo_id}).json()
    print("  images:", len(images))
    assert len(images) == 2, images
    print("E2E OK")
finally:
    for p in procs:
        p.send_signal(signal.SIGTERM)
    for p in procs:
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
