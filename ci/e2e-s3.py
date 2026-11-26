"""S3 repository with Object Lock, end to end (design: docs/design/phase-4-storage.md).

A real fenrir-server and agent: the repository is created on S3-compatible storage through the API with its keys
sealed to the agent, a disk is backed up, and boto3 (independently of our code) checks that every object carries a
compliance lock and that deleting one is refused. Maintenance then extends the locks, and a full verify passes.

Cloud VM restore (BDR-03, docs/design/cloud-restore.md), as far as emulators allow: the backup is restored for AWS
VM Import (a VHDX uploaded to the S3 server) and, given an Azurite endpoint, for Azure (a fixed VHD page blob). Each
result is downloaded independently of Fenrir and its disk content compared with the source disk byte for byte
(qemu-img reads the VHDX); the restore evidence must be verified and its hashes must match what was downloaded.
Creating the managed disk and VM needs a real cloud account and is not covered.

    python3 ci/e2e-s3.py WORK fenrir-server fenrir-backup-agent ENDPOINT ACCESS_KEY SECRET [AZURITE_URL]

ENDPOINT is an S3-compatible server (moto). AZURITE_URL is Azurite's blob endpoint with the account,
e.g. http://127.0.0.1:10000/devstoreaccount1. Needs httpx, cryptography, boto3 and qemu-img.
"""

import base64
import datetime
import hashlib
import hmac
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

import boto3
import httpx
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

W, SERVER, AGENT, ENDPOINT, KEY, SECRET = Path(sys.argv[1]), *sys.argv[2:7]
AZURITE = sys.argv[7] if len(sys.argv) > 7 else ""
AZ_ACCOUNT = "devstoreaccount1"
AZ_KEY = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="  # Azurite's public dev key
shutil.rmtree(W, ignore_errors=True)
W.mkdir(parents=True)
PORT = 18445
BASE = f"http://127.0.0.1:{PORT}"
env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
LOCK_DAYS = 8
BUCKET = f"fenrir-e2e-{uuid.uuid4().hex[:8]}"
procs = []


def b64(b):
    return base64.b64encode(b).decode()


def seal(pk_b64, plaintext: bytes):
    apk = base64.b64decode(pk_b64)
    eph = X25519PrivateKey.generate()
    epk = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key = HKDF(SHA256(), 32, salt=epk + apk, info=b"fenrir-agent-seal-v1").derive(
        eph.exchange(X25519PublicKey.from_public_bytes(apk)))
    nonce = os.urandom(12)
    return {"v": 1, "epk": b64(epk), "nonce": b64(nonce), "ct": b64(AESGCM(key).encrypt(nonce, plaintext, None))}


def wait_job(c, jid, what, seconds=600):
    for _ in range(seconds):
        j = c.get(f"/api/jobs/{jid}").json()
        if j["state"] in ("succeeded", "warning", "failed", "cancelled"):
            print(f"  {what}: {j['state']} {j.get('error') or ''} {j.get('warnings') or ''}")
            assert j["state"] in ("succeeded", "warning"), j
            return j
        time.sleep(1)
    raise SystemExit(f"{what} did not finish")


def azure(method, path, query=None, headers=None, body=b""):
    """A Blob service request to Azurite signed with Shared Key, written here so the check does not use Fenrir's client."""
    query = query or {}
    h = {"x-ms-date": datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT"),
         "x-ms-version": "2021-08-06", **(headers or {})}
    canon_h = "".join(f"{k}:{v}\n" for k, v in sorted((k.lower(), v) for k, v in h.items() if k.lower().startswith("x-ms-")))
    canon_r = f"/{AZ_ACCOUNT}/{AZ_ACCOUNT}{path}" + "".join(f"\n{k}:{v}" for k, v in sorted(query.items()))
    to_sign = "\n".join([method, "", "", str(len(body)) if body else "", "", "", "", "", "", "", "", ""]) + "\n" + canon_h + canon_r
    sig = b64(hmac.new(base64.b64decode(AZ_KEY), to_sign.encode(), hashlib.sha256).digest())
    return httpx.request(method, f"{AZURITE}{path}", params=query, content=body,
                         headers={**h, "Authorization": f"SharedKey {AZ_ACCOUNT}:{sig}"}, timeout=120)


def check_evidence(c, jid, what):
    ev = c.get(f"/api/jobs/{jid}/evidence").json()
    assert ev["intact"] and ev["evidence"]["verified"], ev
    e = ev["evidence"]
    assert e["recoveryPoint"] and e["rpoSeconds"] is not None and e["rtoSeconds"] is not None, e
    print(f"  {what} evidence: verified, RPO {e['rpoSeconds']} s, RTO {e['rtoSeconds']} s, sha256 {ev['sha256'][:16]}…")
    return e


s3 = boto3.client("s3", endpoint_url=ENDPOINT, aws_access_key_id=KEY, aws_secret_access_key=SECRET,
                  region_name="us-east-1")
s3.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)

try:
    procs.append(subprocess.Popen(
        [SERVER, "--http", "--listen", f"127.0.0.1:{PORT}", "--data-dir", str(W / "srv"),
         "--agents-dir", str(W / "agents"), "--public-url", BASE],
        env=env, stdout=open(W / "server.log", "w"), stderr=subprocess.STDOUT))
    for _ in range(60):
        try:
            if httpx.get(f"{BASE}/healthz", timeout=2).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.5)
    c = httpx.Client(base_url=BASE, timeout=120, headers={"x-fenrir-csrf": "1"})
    assert c.post("/api/setup", json={"username": "admin", "password": "e2e correct horse battery"}).status_code == 200
    token = c.post("/api/enrollment-tokens", json={"role": "server"}).json()["token"]
    st = W / "agent"
    st.mkdir()
    e = dict(env, FENRIR_AGENT_STATE=str(st))
    subprocess.run([AGENT, "enroll", "--server", BASE, "--token", token, "--role", "server"], env=e, check=True,
                   stdout=subprocess.DEVNULL)
    procs.append(subprocess.Popen([AGENT, "run"], env=e, stdout=open(W / "agent.log", "w"), stderr=subprocess.STDOUT))
    aid = json.loads((st / "agent.json").read_text())["agent_id"]
    for _ in range(60):
        a = next((a for a in c.get("/api/agents").json() if a["id"] == aid), None)
        if a and a["online"]:
            break
        time.sleep(1)

    repo_uuid = str(uuid.uuid4())
    rk = {"format": "fenrir-recovery-key", "version": 1, "repo_id": repo_uuid, "slot_id": str(uuid.uuid4()),
          "key": b64(os.urandom(32))}
    secret = json.dumps({"passphrase": "e2e repository passphrase", "recovery_key": json.dumps(rk)}).encode()
    keys = json.dumps({"domain": "", "username": KEY, "password": SECRET}).encode()
    settings = {"endpoint": ENDPOINT, "region": "us-east-1", "path_style": True, "lock_mode": "compliance",
                "lock_days": LOCK_DAYS}

    # Test connection first: it must see the lock enforced.
    j = c.post(f"/api/agents/{aid}/check-access", json={"path": f"s3://{BUCKET}/check", "sealed_share": seal(a["public_key"], keys), "s3": settings}).json()
    j = wait_job(c, j["id"], "test connection")
    print("   ", j["result"]["note"])
    assert "Object Lock is enforced" in j["result"]["note"]

    r = c.post("/api/repositories", json={
        "name": "Cloud", "path": f"s3://{BUCKET}/fenrir", "repo_uuid": repo_uuid, "init_agent_id": aid,
        "share_auth": "password", "share_user": KEY, "s3": settings,
        "access": [{"agent_id": aid, "sealed": seal(a["public_key"], secret), "sealed_share": seal(a["public_key"], keys)}]})
    assert r.status_code == 200, r.text
    repo_id = r.json()["id"]
    wait_job(c, r.json()["init_job_id"], "create the repository on S3")

    disk = W / "disk.img"
    disk.write_bytes(bytes((i * 31 + i // 4096) % 251 for i in range(12 << 20)))
    j = c.post(f"/api/agents/{aid}/jobs", json={"kind": {"type": "backup_disks", "paths": [str(disk)]}, "repository_id": repo_id}).json()
    wait_job(c, j["id"], "back up to S3")

    # Independently of Fenrir: every object is locked in compliance mode.
    objs = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET, Prefix="fenrir/"):
        objs += [o["Key"] for o in page.get("Contents", [])]
    chunks = [k for k in objs if k.startswith("fenrir/chunks/")]
    print(f"  {len(objs)} objects, {len(chunks)} chunks")
    assert chunks and any(k.startswith("fenrir/manifests/") for k in objs) and "fenrir/config.json" in objs
    assert not any(k.startswith("fenrir/locks/") for k in objs), "repository locks are released"
    soon = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=LOCK_DAYS - 1)
    for k in [k for k in objs if not k.startswith("fenrir/locks/")]:
        h = s3.head_object(Bucket=BUCKET, Key=k)
        assert h.get("ObjectLockMode") == "COMPLIANCE", (k, h.get("ObjectLockMode"))
        assert h["ObjectLockRetainUntilDate"] > soon, (k, h["ObjectLockRetainUntilDate"])
    first = s3.head_object(Bucket=BUCKET, Key=chunks[0])
    try:
        s3.delete_object(Bucket=BUCKET, Key=chunks[0], VersionId=first["VersionId"])
        raise SystemExit("a locked chunk could be deleted")
    except ClientError as ex:
        print("  deleting a locked chunk is refused:", ex.response["Error"]["Code"])

    # Maintenance: nothing to reclaim, every object in use gets its lock extended.
    j = c.post(f"/api/repositories/{repo_id}/prune", json={"dry_run": False}).json()
    j = wait_job(c, j["id"], "maintenance (space reclamation + lock extension)")
    res = j["result"]
    print("  ", {k: res.get(k) for k in ("chunks_deleted", "chunks_retained", "locks_extended")})
    assert res["locks_extended"] >= len(chunks) and res["chunks_deleted"] == 0
    j = c.post(f"/api/agents/{aid}/jobs", json={"kind": {"type": "verify", "level": "full"}, "repository_id": repo_id}).json()
    wait_job(c, j["id"], "full verify from S3")

    # ---- Cloud VM restore: AWS (VHDX for VM Import, uploaded to the S3 server).
    source = disk.read_bytes()
    im = c.get("/api/images", params={"repository_id": repo_id}).json()[0]
    dr = f"fenrir-dr-{uuid.uuid4().hex[:8]}"
    s3.create_bucket(Bucket=dr)
    staging = W / "staging"
    staging.mkdir()
    r = c.post("/api/restores", json={"image_id": im["image_id"], "agent_id": aid, "disks": [], "target": {
        "type": "aws", "location": f"s3://{dr}/import", "endpoint": ENDPOINT, "region": "us-east-1", "name": "e2e-vm",
        "staging": str(staging), "sealed": seal(a["public_key"], keys)}})
    assert r.status_code == 200, r.text
    j = wait_job(c, r.json()["id"], "restore to AWS (VHDX on S3)")
    assert j["result"]["objects"] == [f"s3://{dr}/import/e2e-vm-disk0.vhdx"], j["result"]
    assert "aws ec2 import-image" in j["result"]["commands"]
    assert not any(staging.iterdir()), "the staging copy is removed after upload"
    vhdx = W / "aws.vhdx"
    s3.download_file(dr, "import/e2e-vm-disk0.vhdx", str(vhdx))
    e = check_evidence(c, r.json()["id"], "AWS")
    assert e["outputs"][0]["sha256"] == hashlib.sha256(vhdx.read_bytes()).hexdigest(), "uploaded VHDX matches the evidence hash"
    raw = W / "aws.raw"
    subprocess.run(["qemu-img", "convert", "-f", "vhdx", "-O", "raw", str(vhdx), str(raw)], check=True)
    assert raw.read_bytes()[:len(source)] == source, "the VHDX on S3 holds the source disk"
    print(f"  AWS: {vhdx.stat().st_size} byte VHDX downloaded; its disk equals the source ({len(source)} bytes)")

    # ---- Cloud VM restore: Azure (fixed VHD page blob), on Azurite.
    if AZURITE:
        assert azure("PUT", "/restores", {"restype": "container"}).status_code in (201, 409)
        az_keys = json.dumps({"domain": "", "username": AZ_ACCOUNT, "password": AZ_KEY}).encode()
        r = c.post("/api/restores", json={"image_id": im["image_id"], "agent_id": aid, "disks": [], "target": {
            "type": "azure", "location": f"azure://restores/{dr}", "endpoint": AZURITE, "name": "e2e-vm",
            "sealed": seal(a["public_key"], az_keys)}})
        assert r.status_code == 200, r.text
        j = wait_job(c, r.json()["id"], "restore to Azure (page blob)")
        assert j["state"] == "succeeded", "a plain disk backup (no OS recorded) gets no Windows warning"
        assert j["result"]["blobs"][0].endswith(f"/restores/{dr}/e2e-vm-disk0.vhd"), j["result"]
        e = check_evidence(c, r.json()["id"], "Azure")
        checked = sum(v.get("chunksChecked", 0) for v in e["verification"])
        assert checked > 0 and all(v.get("mismatches", 0) == 0 for v in e["verification"]), e["verification"]
        blob = azure("GET", f"/restores/{dr}/e2e-vm-disk0.vhd")
        assert blob.status_code == 200, blob.text
        data = blob.content
        assert data[-512:].startswith(b"conectix"), "a fixed VHD footer ends the blob"
        assert len(data) % 512 == 0 and (len(data) - 512) % (1 << 20) == 0, "Azure needs a whole number of MiB"
        assert data[:len(source)] == source and not any(data[len(source):-512]), "the page blob holds the source disk"
        again = c.post("/api/restores", json={"image_id": im["image_id"], "agent_id": aid, "disks": [], "target": {
            "type": "azure", "location": f"azure://restores/{dr}", "endpoint": AZURITE, "name": "e2e-vm",
            "sealed": seal(a["public_key"], az_keys)}}).json()
        for _ in range(120):
            jj = c.get(f"/api/jobs/{again['id']}").json()
            if jj["state"] in ("succeeded", "warning", "failed"):
                break
            time.sleep(1)
        assert jj["state"] == "failed" and "already exists" in jj["error"], jj
        assert azure("GET", f"/restores/{dr}/e2e-vm-disk0.vhd").content == data, "an existing blob is never overwritten"
        print(f"  Azure: {checked} chunks read back from the page blob by the agent; the blob downloaded equals the source")
    else:
        print("  Azure: no Azurite endpoint given, skipped")
    print("E2E S3 OK")
finally:
    for p in procs:
        p.send_signal(signal.SIGTERM)
    for p in procs:
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
