"""Bare-metal restore end to end (design: docs/design/phase-2.md §8).

A real fenrir-server and a real agent back up a small UEFI disk whose only boot loader is at the Windows path
(\\EFI\\Microsoft\\Boot\\bootmgfw.efi, a GRUB build that prints FENRIR-RESTORED-OK). Then a recovery ISO personalised
by the server boots in QEMU with Secure Boot on, enrols by itself, and restores the image onto the VM's blank,
larger disk through the API. Finally that disk boots on its own under fresh UEFI firmware with no boot entries,
which needs the fallback loader the restore added.

    sudo python3 ci/e2e-recovery.py WORK fenrir-server fenrir-backup-agent fenrir-recovery.iso [SYSTEM_DISK MARKER]

With SYSTEM_DISK (a raw disk image of a real installed system, e.g. Windows from ci/windows-install.py) that disk is
backed up instead of the stand-in, restored onto a blank disk 4 GiB larger, and the restored disk must boot on an
AHCI controller and print MARKER on the first serial port (Windows: its start-up task).

Needs root, qemu-system-x86_64, OVMF (/usr/share/OVMF), grub-efi-amd64-bin, dosfstools, mtools, fdisk
(sfdisk), and Python with httpx and cryptography. Without KVM it is slow (about 15 minutes).
"""

import base64
import json
import os
import shutil
import signal
import struct
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

W, SERVER, AGENT, ISO = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
REAL = Path(sys.argv[5]).resolve() if len(sys.argv) > 5 else None
MARKER = sys.argv[6] if len(sys.argv) > 6 else "FENRIR-RESTORED-OK"
shutil.rmtree(W, ignore_errors=True)
W.mkdir(parents=True)
PORT = 18444
BASE = f"http://127.0.0.1:{PORT}"
os.environ["PATH"] += ":/usr/sbin:/sbin"
env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
OVMF = Path("/usr/share/OVMF")
KVM = os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.W_OK)
MIB = 1 << 20
procs = []


def run(*cmd, **kw):
    subprocess.run(cmd, check=True, **kw)


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


def wait_job(c, jid, what, seconds=1200):
    for _ in range(seconds // 2):
        j = c.get(f"/api/jobs/{jid}").json()
        if j["state"] in ("succeeded", "warning", "failed", "cancelled"):
            print(f"  {what}: {j['state']} {j.get('error') or ''} {j.get('warnings') or ''}")
            assert j["state"] in ("succeeded", "warning"), j
            return j
        time.sleep(2)
    raise SystemExit(f"{what} did not finish")


def make_disk(path: Path):
    """64 MiB GPT disk: 40 MiB ESP holding only the Windows loader path, and a data partition."""
    cfg = W / "grub.cfg"
    cfg.write_text("serial --unit=0 --speed=115200\nterminal_output serial console\n"
                   "echo FENRIR-RESTORED-OK\nsleep 3\nhalt\n")
    efi = W / "bootmgfw.efi"
    run("grub-mkstandalone", "-O", "x86_64-efi", "-o", str(efi), "--modules=serial echo sleep halt",
        f"boot/grub/grub.cfg={cfg}")
    esp = W / "esp.img"
    run("mkfs.vfat", "-F", "32", "-C", str(esp), str(40 * 1024), stdout=subprocess.DEVNULL)
    for d in ("::/EFI", "::/EFI/Microsoft", "::/EFI/Microsoft/Boot"):
        run("mmd", "-i", str(esp), d)
    run("mcopy", "-i", str(esp), str(efi), "::/EFI/Microsoft/Boot/bootmgfw.efi")
    with open(path, "wb") as f:
        f.truncate(64 * MIB)
    run("sfdisk", "--quiet", str(path), input=(
        "label: gpt\n"
        f"start=2048, size={40 * 2048}, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name=EFI\n"
        "type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, name=data\n").encode())
    with open(path, "r+b") as f:
        f.seek(MIB)
        f.write(esp.read_bytes())
        f.seek(50 * MIB)
        f.write(b"FENRIR-DATA-MARKER" * 100)


def qemu(name, *args, secure, memory=2048):
    code = OVMF / ("OVMF_CODE_4M.secboot.fd" if secure else "OVMF_CODE_4M.fd")
    vars_ = W / f"{name}-vars.fd"
    shutil.copy(OVMF / ("OVMF_VARS_4M.ms.fd" if secure else "OVMF_VARS_4M.fd"), vars_)
    log = W / f"{name}.serial"
    cmd = ["qemu-system-x86_64", "-machine", "q35,smm=on" + (",accel=kvm" if KVM else ""),
           "-cpu", "host" if KVM else "max", "-m", str(memory), "-smp", "2", "-display", "none", "-monitor", "none",
           "-global", f"driver=cfi.pflash01,property=secure,value={'on' if secure else 'off'}",
           "-drive", f"if=pflash,format=raw,unit=0,file={code},readonly=on",
           "-drive", f"if=pflash,format=raw,unit=1,file={vars_}",
           "-serial", f"file:{log}", *args]
    p = subprocess.Popen(cmd, stdout=open(W / f"{name}.qemu.log", "w"), stderr=subprocess.STDOUT)
    procs.append(p)
    return p, log


def serial(log):
    return log.read_bytes().decode("utf-8", "replace") if log.exists() else ""


try:
    agents_dir = W / "agents"
    (agents_dir / "recovery").mkdir(parents=True)
    shutil.copy(ISO, agents_dir / "recovery" / "fenrir-recovery.iso")
    # Agents on the VM reach the host's loopback at 10.0.2.2 (QEMU user networking).
    procs.append(subprocess.Popen(
        [SERVER, "--http", "--listen", f"127.0.0.1:{PORT}", "--data-dir", str(W / "srv"),
         "--agents-dir", str(agents_dir), "--public-url", f"http://10.0.2.2:{PORT}"],
        env=env, stdout=open(W / "server.log", "w"), stderr=subprocess.STDOUT))
    for _ in range(60):
        try:
            if httpx.get(f"{BASE}/healthz", timeout=2).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.5)
    c = httpx.Client(base_url=BASE, timeout=120, headers={"x-fenrir-csrf": "1"})
    assert c.post("/api/setup", json={"username": "admin", "password": "e2e correct horse battery"}).status_code == 200

    # The machine that holds the backups (here: the host itself).
    token = c.post("/api/enrollment-tokens", json={"role": "server"}).json()["token"]
    st = W / "nas"
    st.mkdir()
    e = dict(env, FENRIR_AGENT_STATE=str(st))
    run(AGENT, "enroll", "--server", BASE, "--token", token, "--role", "server", env=e, stdout=subprocess.DEVNULL)
    procs.append(subprocess.Popen([AGENT, "run"], env=e, stdout=open(W / "nas.log", "w"), stderr=subprocess.STDOUT))
    nas_id = json.loads((st / "agent.json").read_text())["agent_id"]
    for _ in range(60):
        nas = next((a for a in c.get("/api/agents").json() if a["id"] == nas_id), None)
        if nas and nas["online"]:
            break
        time.sleep(1)

    repo_uuid = str(uuid.uuid4())
    rk = {"format": "fenrir-recovery-key", "version": 1, "repo_id": repo_uuid, "slot_id": str(uuid.uuid4()),
          "key": b64(os.urandom(32))}
    secret = lambda first: json.dumps({"passphrase": "e2e repository passphrase",
                                       "recovery_key": json.dumps(rk) if first else None}).encode()
    r = c.post("/api/repositories", json={"name": "Backups", "path": str(W / "repo"), "repo_uuid": repo_uuid,
                                          "init_agent_id": nas_id,
                                          "access": [{"agent_id": nas_id, "sealed": seal(nas["public_key"], secret(True))}]})
    assert r.status_code == 200, r.text
    repo_id = r.json()["id"]
    wait_job(c, r.json()["init_job_id"], "create repository")

    if REAL:
        disk = REAL
        TARGET = (disk.stat().st_size + (4 << 30)) // MIB * MIB
    else:
        disk = W / "pc-disk.img"
        make_disk(disk)
        TARGET = 96 * MIB
    j = c.post(f"/api/agents/{nas_id}/jobs", json={"kind": {"type": "backup_disks", "paths": [str(disk)]},
                                                  "repository_id": repo_id}).json()
    wait_job(c, j["id"], "back up the PC's disk")
    image = c.get("/api/images", params={"repository_id": repo_id}).json()[0]
    print("  image", image["image_id"])

    # Recovery media, personalised by the server.
    rtok = c.post("/api/enrollment-tokens", json={"role": "recovery", "label": "e2e stick", "expires_days": 30}).json()["token"]
    iso_url = c.get("/api/downloads", params={"token": rtok}).json()["recovery"]["iso_url"]
    personal = W / "personal.iso"
    with httpx.stream("GET", iso_url.replace(f"http://10.0.2.2:{PORT}", BASE), timeout=300) as resp:
        assert resp.status_code == 200, resp.status_code
        with open(personal, "wb") as f:
            for chunk in resp.iter_bytes():
                f.write(chunk)
    assert personal.stat().st_size == Path(ISO).stat().st_size

    # The "new PC": a blank, larger disk, booted from the stick with Secure Boot on. Zeros written to it stay holes.
    target = W / "new-disk.raw"
    with open(target, "wb") as f:
        f.truncate(TARGET)
    t0 = time.time()
    vm, vm_log = qemu("recovery", "-cdrom", str(personal),
                      "-drive", f"file={target},if=none,id=newdisk,format=raw,detect-zeroes=unmap,discard=unmap",
                      "-device", "virtio-blk-pci,drive=newdisk,serial=NEWDISK",
                      "-nic", "user,model=virtio-net-pci", secure=True)
    rec = None
    for _ in range(900):
        a = next((a for a in c.get("/api/agents").json() if a.get("role") == "recovery" and a["online"]), None)
        if a:
            detail = c.get(f"/api/agents/{a['id']}").json()
            if (detail.get("inventory") or {}).get("disks"):
                rec = dict(a, inventory=detail["inventory"])
        if rec or vm.poll() is not None:
            break
        time.sleep(2)
    assert rec, "recovery session did not appear:\n" + serial(vm_log)[-3000:]
    print(f"  recovery session {rec['hostname']} online after {time.time() - t0:.0f}s, firmware "
          f"{rec['inventory'].get('firmware')}, secure boot {rec['inventory'].get('secure_boot')}")
    assert rec["inventory"].get("secure_boot") is True, rec["inventory"]
    disks = rec["inventory"]["disks"]
    print("  disks:", [(d["path"], d["size"], d.get("in_use", False)) for d in disks])
    dev = next(d["path"] for d in disks if d["size"] == TARGET and not d.get("in_use"))
    # The stick itself is refused.
    busy = [d for d in disks if d.get("in_use")]
    if busy:
        r = c.post("/api/restores", json={"image_id": image["image_id"], "agent_id": rec["id"],
                                          "target": {"type": "disk", "device": busy[0]["path"], "disk": 0,
                                                     "confirm": busy[0]["path"]}})
        assert r.status_code == 400, r.text

    # The repository is on storage only the backup machine reaches (as on a NAS): the recovery session gets it
    # through that machine as a gateway, relayed by the server.
    assert c.post(f"/api/repositories/{repo_id}/gateway", json={"agent_id": nas_id, "port": 0}).status_code == 200
    r = c.post(f"/api/repositories/{repo_id}/access", json={
        "agent_id": rec["id"], "sealed": seal(rec["public_key"], secret(False)), "via_gateway": True})
    assert r.status_code == 200, r.text
    r = c.post("/api/restores", json={"image_id": image["image_id"], "agent_id": rec["id"],
                                      "target": {"type": "disk", "device": dev, "disk": 0, "confirm": dev}})
    assert r.status_code == 200, r.text
    j = wait_job(c, r.json()["id"], f"bare-metal restore onto {dev}", seconds=3600)
    boot = (j.get("result") or {}).get("boot") or {}
    print("  boot fix-up:", boot)
    if not REAL:  # the stand-in has only the Windows path; real Windows already has the fallback loader
        assert "\\EFI\\BOOT\\BOOTX64.EFI" in boot.get("added", []), j
    vm.send_signal(signal.SIGTERM)
    vm.wait(30)

    # The restored disk: GPT moved to the new end, data intact.
    with open(target, "rb") as f:
        primary = f.read(1024)[512:]
        f.seek(TARGET - 512)
        backup = f.read(512)
        f.seek(50 * MIB)
        data = f.read(18)
    assert primary[:8] == b"EFI PART"
    assert backup[:8] == b"EFI PART", "backup GPT header at the new last sector"
    alt = struct.unpack_from("<Q", primary, 32)[0]
    assert alt == TARGET // 512 - 1, alt
    if not REAL:
        assert data == b"FENRIR-DATA-MARKER"

    # And it boots by itself: fresh firmware, no boot entries, no stick.
    if REAL:  # Windows: an AHCI disk (in-box driver), as it was installed
        pc, pc_log = qemu("restored", "-drive", f"file={target},if=none,id=sys,format=raw",
                          "-device", "ide-hd,drive=sys,bus=ide.0", "-nic", "none", secure=False, memory=4096)
    else:
        pc, pc_log = qemu("restored", "-drive", f"file={target},if=virtio,format=raw", "-nic", "none", secure=False)
    t0 = time.time()
    for _ in range(1200 if REAL else 300):
        if MARKER in serial(pc_log) or pc.poll() is not None:
            break
        time.sleep(1)
    assert MARKER in serial(pc_log), "restored disk did not boot:\n" + serial(pc_log)[-2000:]
    print(f"  restored disk boots and reports {MARKER} after {time.time() - t0:.0f}s")
    print("  restored disk boots")
    print("E2E OK")
finally:
    for p in procs:
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
    for p in procs:
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
