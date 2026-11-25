"""One SQL Server database restored by a real agent through the server (design: docs/design/app-restore.md).

Runs after ci/windows-sql-app-aware.ps1, which left an application-aware repository made by the CLI. The real
fenrir-server and a Windows backup agent adopt that repository (the passphrase sealed as the web UI does), and the
server asks the agent to restore only the `fenrirci` database from the latest backup into a folder and attach it
under a new name. The attached database must have the rows written before that backup and pass DBCC CHECKDB.

    python ci/e2e-sql-app-restore.py <work dir> <fenrir-server> <fenrir-backup-agent> <repository> <passphrase>

Needs Python with httpx and cryptography, sqlcmd, SQL Server Express (.\\SQLEXPRESS), and an administrator.
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

W, SERVER, AGENT, REPO, PASS = Path(sys.argv[1]).resolve(), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
INSTANCE = ".\\SQLEXPRESS"
TARGET = "C:\\FenrirRestores"
shutil.rmtree(W, ignore_errors=True)
shutil.rmtree(TARGET, ignore_errors=True)
W.mkdir(parents=True)
BASE = "http://127.0.0.1:18445"
env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
env["FENRIR_AGENT_STATE"] = str(W / "agent")
procs = []


def b64(b):
    return base64.b64encode(b).decode()


def seal(pk_b64, plaintext: bytes):
    """The web UI's half of protocol::seal (fenrir-agent-seal-v1)."""
    apk = base64.b64decode(pk_b64)
    eph = X25519PrivateKey.generate()
    epk = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key = HKDF(SHA256(), 32, salt=epk + apk, info=b"fenrir-agent-seal-v1").derive(
        eph.exchange(X25519PublicKey.from_public_bytes(apk)))
    nonce = os.urandom(12)
    return {"v": 1, "epk": b64(epk), "nonce": b64(nonce), "ct": b64(AESGCM(key).encrypt(nonce, plaintext, None))}


def wait_job(c, jid, what, seconds=900):
    t = time.time()
    while time.time() - t < seconds:
        j = c.get(f"/api/jobs/{jid}").json()
        if j["state"] in ("succeeded", "warning", "failed", "cancelled"):
            print(f"  {what}: {j['state']} in {time.time() - t:.1f}s {j.get('error') or ''} {j.get('warnings') or ''}")
            assert j["state"] in ("succeeded", "warning"), j
            return j, time.time() - t
        time.sleep(1)
    raise SystemExit(f"{what} did not finish")


def sql(q):
    r = subprocess.run(["sqlcmd", "-S", INSTANCE, "-E", "-b", "-h", "-1", "-W", "-Q", f"SET NOCOUNT ON; {q}"],
                       capture_output=True, text=True)
    assert r.returncode == 0, (q, r.stdout, r.stderr)
    return r.stdout.strip()


try:
    procs.append(subprocess.Popen([SERVER, "--http", "--listen", "127.0.0.1:18445", "--data-dir", str(W / "srv"),
                                   "--agents-dir", str(W / "agents"), "--public-url", BASE, "--poll-seconds", "2"],
                                  env=env, stdout=open(W / "server.log", "w"), stderr=subprocess.STDOUT))
    for _ in range(120):
        try:
            if httpx.get(f"{BASE}/healthz", timeout=2).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.5)
    c = httpx.Client(base_url=BASE, timeout=60, headers={"x-fenrir-csrf": "1"})
    assert c.post("/api/setup", json={"username": "admin", "password": "e2e correct horse battery"}).status_code == 200
    token = c.post("/api/enrollment-tokens", json={"label": "sql", "role": "server"}).json()["token"]
    r = subprocess.run([AGENT, "enroll", "--server", BASE, "--token", token, "--role", "server"],
                       env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, (r.stdout, r.stderr)
    procs.append(subprocess.Popen([AGENT, "run"], env=env, stdout=open(W / "agent.log", "w"), stderr=subprocess.STDOUT))
    for _ in range(120):
        agents = c.get("/api/agents").json()
        if agents and agents[0]["online"] and "restore_apps" in agents[0]["capabilities"]:
            break
        time.sleep(1)
    a = agents[0]
    assert "restore_apps" in a["capabilities"], a["capabilities"]
    print(f"agent online: {a['name']}")

    # The repository the CLI made, adopted with its history.
    r = c.post("/api/repositories", json={"name": "SQL", "path": REPO, "existing": True, "init_agent_id": a["id"],
                                          "access": [{"agent_id": a["id"], "sealed": seal(a["public_key"], json.dumps({"passphrase": PASS}).encode())}]})
    assert r.status_code == 200, r.text
    wait_job(c, r.json()["init_job_id"], "adopt the repository")
    images = c.get("/api/images", params={"repository_id": r.json()["id"]}).json()
    images.sort(key=lambda i: i["created"], reverse=True)
    im = images[0]
    apps = [x for x in im.get("applications") or [] if x["writer"] == "SqlServerWriter" and "fenrirci" in x["component"]]
    assert apps, json.dumps(im, indent=1)[:3000]
    comp = apps[0]["component"]
    print(f"  backup {im['image_id']} ({im.get('label')}): component {comp}, {apps[0].get('file_sets')} file sets")

    bad = c.post(f"/api/images/{im['image_id']}/restore-app", json={"agent_id": a["id"], "component": comp,
                                                                     "directory": "relative\\path"})
    assert bad.status_code == 400, bad.text
    t0 = time.time()
    r = c.post(f"/api/images/{im['image_id']}/restore-app", json={
        "agent_id": a["id"], "component": comp, "directory": TARGET, "attach_as": "fenrirapp", "sql_instance": INSTANCE})
    assert r.status_code == 200, r.text
    j, secs = wait_job(c, r.json()["id"], "restore one database and attach it")
    res = j.get("result") or {}
    print(f"  files: {res.get('files')}")
    assert res.get("attached") == "fenrirapp", res
    rows = sql("SELECT COUNT(*) FROM fenrirapp.dbo.t")
    late = sql("SELECT COUNT(*) FROM fenrirapp.dbo.t WHERE id = 900002")
    assert rows == "5001" and late == "0", (rows, late)
    sql("DBCC CHECKDB (fenrirapp) WITH NO_INFOMSGS;")
    print(f"  fenrirapp has the 5001 rows from before the backup, not the later one; DBCC CHECKDB clean")
    print(json.dumps({"evidence": "BDR-03 one SQL Server database", "image": im["image_id"], "component": comp,
                      "restore_seconds": round(secs, 1), "rto_measured_seconds": round(time.time() - t0, 1)}))
    print("SQL APP RESTORE OK")
finally:
    for p in procs:
        p.terminate()
    for p in procs:
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
