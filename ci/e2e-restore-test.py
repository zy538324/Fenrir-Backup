"""Scheduled restore test through the server with a real agent (docs/design/restore-tests.md).

A real fenrir-server and backup agent on a Linux host with QEMU. A bootable disk image (CirrOS) is backed up; the
repository is set to a weekly full restore test on today's weekday through the API; the server's own scheduler
queues the test. The agent must restore the image in full (read back and matched), boot the VM from the restored
disk, take a screenshot, and delete the VM and its disk. The result, the restore facts and the screenshot are then
read back through the API, and the agent's restore-test folder must be gone.

    python3 ci/e2e-restore-test.py <work dir> <fenrir-server> <fenrir-backup-agent> <bootable raw disk image>

Needs Python with httpx and cryptography, and QEMU (qemu-system-x86, qemu-utils, ovmf) on the host.
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

W, SERVER, AGENT, DISK = Path(sys.argv[1]).resolve(), sys.argv[2], sys.argv[3], Path(sys.argv[4]).resolve()
shutil.rmtree(W, ignore_errors=True)
W.mkdir(parents=True)
BASE = "http://127.0.0.1:18446"
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


def wait_job(c, jid, what, seconds=1500):
    t = time.time()
    while time.time() - t < seconds:
        j = c.get(f"/api/jobs/{jid}").json()
        if j["state"] in ("succeeded", "warning", "failed", "cancelled"):
            print(f"  {what}: {j['state']} in {time.time() - t:.0f}s {j.get('error') or ''} {j.get('warnings') or ''}")
            assert j["state"] in ("succeeded", "warning"), j
            return j
        time.sleep(2)
    raise SystemExit(f"{what} did not finish")


try:
    procs.append(subprocess.Popen([SERVER, "--http", "--listen", "127.0.0.1:18446", "--data-dir", str(W / "srv"),
                                   "--agents-dir", str(W / "agents"), "--public-url", BASE, "--poll-seconds", "5"],
                                  env=env, stdout=open(W / "server.log", "w"), stderr=subprocess.STDOUT))
    for _ in range(120):
        try:
            if httpx.get(f"{BASE}/healthz", timeout=2).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.5)
    c = httpx.Client(base_url=BASE, timeout=60, headers={"x-fenrir-csrf": "1"})
    assert c.post("/api/setup", json={"username": "admin", "password": "e2e correct horse battery"}).status_code == 200
    token = c.post("/api/enrollment-tokens", json={"label": "e2e", "role": "server"}).json()["token"]
    r = subprocess.run([AGENT, "enroll", "--server", BASE, "--token", token, "--role", "server"],
                       env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, (r.stdout, r.stderr)
    procs.append(subprocess.Popen([AGENT, "run"], env=env, stdout=open(W / "agent.log", "w"), stderr=subprocess.STDOUT))
    for _ in range(90):
        agents = c.get("/api/agents").json()
        if agents and agents[0]["online"] and "backup_disks" in agents[0]["capabilities"]:
            break
        time.sleep(1)
    a = agents[0]
    assert "boot_kvm" in a["capabilities"], f"the agent cannot boot VMs here: {a['capabilities']}"

    repo_uuid = str(uuid.uuid4())
    rk = {"format": "fenrir-recovery-key", "version": 1, "repo_id": repo_uuid, "slot_id": str(uuid.uuid4()),
          "key": b64(os.urandom(32))}
    secret = json.dumps({"passphrase": "e2e repository passphrase", "recovery_key": json.dumps(rk)}).encode()
    r = c.post("/api/repositories", json={"name": "Local", "path": str(W / "repo"), "repo_uuid": repo_uuid,
                                          "init_agent_id": a["id"],
                                          "access": [{"agent_id": a["id"], "sealed": seal(a["public_key"], secret)}]})
    assert r.status_code == 200, r.text
    repo_id = r.json()["id"]
    wait_job(c, r.json()["init_job_id"], "create repository")
    r = c.post(f"/api/agents/{a['id']}/jobs", json={"kind": {"type": "backup_disks", "paths": [str(DISK)]},
                                                     "repository_id": repo_id})
    assert r.status_code == 200, r.text
    wait_job(c, r.json()["id"], "back up the bootable disk")
    im = c.get("/api/images", params={"repository_id": repo_id}).json()[0]

    # Weekly full restore test, today: the server's scheduler (every 20 s) queues it.
    today = datetime.now(timezone.utc).weekday()
    r = c.post(f"/api/repositories/{repo_id}/boot-verification",
               json={"agent_id": a["id"], "every_days": 7, "full_restore": True, "weekday": today})
    assert r.status_code == 200, r.text
    job = None
    for _ in range(60):
        job = next((j for j in c.get("/api/jobs", params={"limit": 50}).json()
                    if j["requested_by"] == "boot verification"), None)
        if job:
            break
        time.sleep(2)
    assert job, "the scheduler did not queue the restore test"
    assert job["kind"]["full_restore"] is True and job["kind"]["keep_running"] is False, job["kind"]
    j = wait_job(c, job["id"], "scheduled restore test")
    t = j["result"]["restore_test"]
    print(f"  restored {t['bytes_restored']} bytes as {t['format']} in {t['restore_seconds']}s, "
          f"{t['chunks_checked']} chunks read back, {t['mismatches']} mismatched; VM deleted: {t['vm_removed']}")
    assert j["result"]["outcome"] == "verified", j["result"]
    assert t["format"] == "raw" and t["chunks_checked"] > 0 and t["mismatches"] == 0, t
    assert t["vm_removed"] and t["removed_unix"] > 0 and not t.get("removal_error"), t

    checks = c.get(f"/api/images/{im['image_id']}/boot-checks").json()
    assert checks and checks[0]["restore_test"]["vm_removed"] is True and checks[0]["has_screenshot"], checks[0]
    png = c.get(f"/api/boot-checks/{checks[0]['id']}/screenshot.png").content
    assert png.startswith(b"\x89PNG"), "the screenshot is a PNG"
    (W / "restore-test-screen.png").write_bytes(png)
    left = W / "agent" / "restore-tests" / uuid.UUID(im["image_id"]).hex
    assert not left.exists(), f"the restored disks were left in {left}"
    print(f"  screenshot {len(png)} bytes; the restored disks are gone from the host")
    print("E2E RESTORE TEST OK")
finally:
    for p in procs:
        p.terminate()
    for p in procs:
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
