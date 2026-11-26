"""Backup and restore through the server with a real agent, on Linux or Windows (AT-19).

The real fenrir-server and one real backup agent run on this machine. The agent creates a repository (its
passphrase sealed as the web UI does), backs up a disk image file, a full verify runs, and the latest backup is
restored by the agent onto a new file through the server's restore API (the device path typed as confirmation).
The restored file must be byte-identical to the source (SHA-256), and the recorded timings are printed as the
recovery evidence (backup time, restore time, recovery point).

    python3 ci/e2e-agent-roundtrip.py <work dir> <fenrir-server> <fenrir-backup-agent>

Needs Python with httpx and cryptography. No root: it backs up and restores files.
"""

import base64
import hashlib
import json
import os
import shutil
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

W, SERVER, AGENT = Path(sys.argv[1]).resolve(), sys.argv[2], sys.argv[3]
shutil.rmtree(W, ignore_errors=True)
W.mkdir(parents=True)
BASE = "http://127.0.0.1:18444"
env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
env["FENRIR_AGENT_STATE"] = str(W / "agent")
procs = []
SIZE = 48 << 20


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


def wait_job(c, jid, what, seconds=600):
    t = time.time()
    while time.time() - t < seconds:
        j = c.get(f"/api/jobs/{jid}").json()
        if j["state"] in ("succeeded", "warning", "failed", "cancelled"):
            print(f"  {what}: {j['state']} in {time.time() - t:.1f}s {j.get('error') or ''}")
            assert j["state"] in ("succeeded", "warning"), j
            return j, time.time() - t
        time.sleep(1)
    raise SystemExit(f"{what} did not finish")


def sha(p: Path, n: int) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        left = n
        while left:
            b = f.read(min(left, 1 << 20))
            if not b:
                break
            h.update(b)
            left -= len(b)
    return h.hexdigest()


try:
    procs.append(subprocess.Popen([SERVER, "--http", "--listen", "127.0.0.1:18444", "--data-dir", str(W / "srv"),
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
    token = c.post("/api/enrollment-tokens", json={"label": "e2e", "role": "server"}).json()["token"]
    r = subprocess.run([AGENT, "enroll", "--server", BASE, "--token", token, "--role", "server"],
                       env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, (r.stdout, r.stderr)
    procs.append(subprocess.Popen([AGENT, "run"], env=env, stdout=open(W / "agent.log", "w"), stderr=subprocess.STDOUT))
    for _ in range(90):
        agents = c.get("/api/agents").json()
        if agents and agents[0]["online"] and "restore_disk" in agents[0]["capabilities"]:
            break
        time.sleep(1)
    a = agents[0]
    print(f"agent online: {a['name']} ({a['os']['family']}), capabilities {len(a['capabilities'])}")

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

    evidence = []
    caps = set(a["capabilities"])
    assert caps & {"backup_disks", "backup_files"}, caps

    if "backup_disks" in caps:
        # A disk with varied content (and a zero run, which a restore must reproduce).
        disk = W / "source-disk.img"
        with open(disk, "wb") as f:
            for i in range(SIZE >> 20):
                f.write(bytes(1 << 20) if i == 7 else hashlib.sha256(str(i).encode()).digest() * 32768)
        src = sha(disk, SIZE)
        r = c.post(f"/api/agents/{a['id']}/jobs",
                   json={"kind": {"type": "backup_disks", "paths": [str(disk)]}, "repository_id": repo_id})
        assert r.status_code == 200, r.text
        _, backup_secs = wait_job(c, r.json()["id"], "disk backup")
        r = c.post(f"/api/agents/{a['id']}/jobs", json={"kind": {"type": "verify", "level": "full"}, "repository_id": repo_id})
        wait_job(c, r.json()["id"], "full verify")
        im = [i for i in c.get("/api/images", params={"repository_id": repo_id}).json() if i["source"] == "disks"][0]
        target = W / "restored-disk.img"
        t0 = time.time()
        r = c.post("/api/restores", json={"image_id": im["image_id"], "agent_id": a["id"], "disks": [],
                                          "target": {"type": "disk", "device": str(target), "disk": 0,
                                                     "confirm": str(target) + "x"}})
        assert r.status_code == 400, f"a wrong confirmation must be refused: {r.status_code} {r.text}"
        r = c.post("/api/restores", json={"image_id": im["image_id"], "agent_id": a["id"], "disks": [],
                                          "target": {"type": "disk", "device": str(target), "disk": 0,
                                                     "confirm": str(target), "grow": False}})
        assert r.status_code == 200, r.text
        disk_job = r.json()["id"]
        _, restore_secs = wait_job(c, disk_job, "restore to a new disk file")
        got = sha(target, SIZE)
        print(f"  source   {src}\n  restored {got}")
        assert got == src, "restored disk differs from the source"
        # Restore evidence (BDR-03): every chunk read back from the target and matched to the backup.
        ev = c.get(f"/api/jobs/{disk_job}/evidence").json()
        assert ev["intact"], ev
        e = ev["evidence"]
        v = e["verification"][0]
        assert v["supported"] and v["mismatches"] == 0 and v["chunksChecked"] > 0, e
        assert e["verified"] and e["recoveryPoint"] and e["rpoSeconds"] >= 0 and e["rtoSeconds"] >= 0, e
        print(f"  evidence: {v['chunksChecked']} chunks read back and matched; RPO {e['rpoSeconds']} s, RTO {e['rtoSeconds']} s, sha256 {ev['sha256'][:16]}…")
        evidence.append({"kind": "disk", "image": im["image_id"], "recovery_point_unix": im["created"], "bytes": SIZE,
                         "backup_seconds": round(backup_secs, 1), "restore_seconds": round(restore_secs, 1),
                         "rto_measured_seconds": round(time.time() - t0, 1), "sha256": src})

    if "backup_files" in caps:
        # A folder of files (Windows backs up folders and whole systems, not raw disks).
        src_dir = W / "source files"
        files = {}
        for n in range(12):
            p = src_dir / f"sub{n % 3}" / f"file {n}.bin"
            p.parent.mkdir(parents=True, exist_ok=True)
            data = hashlib.sha256(str(n).encode()).digest() * (1000 + n * 4000)
            p.write_bytes(data)
            files[p.name] = hashlib.sha256(data).hexdigest()
        r = c.post(f"/api/agents/{a['id']}/jobs",
                   json={"kind": {"type": "backup_files", "paths": [str(src_dir)]}, "repository_id": repo_id})
        assert r.status_code == 200, r.text
        fj, backup_secs = wait_job(c, r.json()["id"], "files and folders backup")
        snapshot = (fj.get("result") or {}).get("snapshot")
        print(f"  read from: {snapshot or 'the live files'}")
        if a["os"]["family"] == "macos":
            # Hosted macOS runners refuse local snapshots (no Full Disk Access for tmutil); then the
            # backup must say why it read the live files.
            assert (snapshot and snapshot.startswith("APFS ")) or any("No APFS snapshot" in w for w in fj["warnings"]), fj
        if a["os"]["family"] == "windows":
            assert snapshot == "VSS", f"Windows folder backups read from a VSS snapshot: {fj}"
        im = [i for i in c.get("/api/images", params={"repository_id": repo_id}).json() if i["source"] == "files"][0]
        # Folder backups are one volume (disk 1, partition 1) from the root: C:/... or home/...
        sel = str(src_dir).replace("\\", "/").lstrip("/")
        out = W / "restored files"
        t0 = time.time()
        r = c.post(f"/api/images/{im['image_id']}/restore-files",
                   json={"agent_id": a["id"], "disk": 1, "partition": 1, "paths": [sel], "target": str(out),
                         "keep_structure": True, "conflict": "overwrite"})
        assert r.status_code == 200, r.text
        files_job = r.json()["id"]
        _, restore_secs = wait_job(c, files_job, "restore the folder")
        got = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in out.rglob("*") if p.is_file()}
        assert got == files, f"restored files differ: {sorted(set(files) ^ set(got))} {len(got)}/{len(files)}"
        print(f"  {len(files)} files restored byte-identical")
        # Restore evidence (BDR-03): the agent's SHA-256 of each restored file matches the source.
        ev = c.get(f"/api/jobs/{files_job}/evidence").json()
        assert ev["intact"], ev
        e = ev["evidence"]
        reported = {Path(o["path"]).name: o["sha256"] for o in e["outputs"]}
        assert reported == files, f"evidence hashes differ from the source: {reported}"
        assert e["verified"] and e["recoveryPoint"] and e["rpoSeconds"] >= 0 and e["rtoSeconds"] >= 0, e
        print(f"  evidence: {len(reported)} file hashes match the source; RPO {e['rpoSeconds']} s, RTO {e['rtoSeconds']} s")
        evidence.append({"kind": "files", "image": im["image_id"], "recovery_point_unix": im["created"],
                         "files": len(files), "backup_seconds": round(backup_secs, 1),
                         "restore_seconds": round(restore_secs, 1), "rto_measured_seconds": round(time.time() - t0, 1)})

    print(json.dumps({"evidence": "AT-19", "os": a["os"]["family"], "round_trips": evidence}))
    print("E2E OK")
finally:
    for p in procs:
        p.terminate()
    for p in procs:
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
