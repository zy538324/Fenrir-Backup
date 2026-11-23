# Fenrir-Backup

Open-source disk imaging and recovery for Windows 10/11 and Linux:
full system images with incrementals, bare-metal restore, boot-from-backup as
a VM, file-level restore, cloning, and ransomware-resistant storage.

**Status:** Phase 1 (format, Windows VSS imaging, verify, restore), the
management server and web UI, and Phase 3 (boot from backup). What works
today:

* **Web app** (`fenrir-server`): a dashboard for every machine, backup plans
  with schedules, repositories, activity and audit log, light and dark
  themes, phone-friendly.
* **Downloads for every platform**: the web UI generates installers for
  Windows, Hyper-V hosts, Linux and macOS. On Windows it is a setup program,
  `Fenrir-Backup-Setup.exe` (double-click, or `/quiet` for silent installs); on
  Linux and macOS a script. Each installs the agent as a service and enrols
  it with your server.
* **Hyper-V hosts**: install once on the host; every VM is backed up through
  recovery checkpoints, with nothing installed inside the VMs.
* **Windows**: application-consistent system images through VSS.
* **Linux**: images of unmounted disks (live snapshots come later).
* **macOS**: enrols, reports and verifies; system protection needs file-level
  backup, which is next.
* **End-to-end encryption**: the server never holds repository keys. The
  browser encrypts each machine's passphrase to that machine, and generates
  the recovery key locally.
* **Retention** per plan (grandfather-father-son), weekly space
  reclamation, and a **ransomware guard**: a backup that looks like mass
  encryption puts the repository on hold so no clean image is aged out.
* **Restore from the UI**: as a VHDX (mount it to copy files, or attach it
  to a VM), as a new Hyper-V VM on the host, or onto a disk.
* **Boot from backup**: start any image as a VM on a Linux host with QEMU,
  straight from the repository, on an isolated network, without restoring
  it first. **Boot verification** proves backups boot (guest answers on
  SSH/RDP/WinRM or through the guest agent; screenshot kept as evidence),
  on demand or weekly per repository. Hyper-V hosts can run the same check.
* **Alerts** by email, Slack, Teams or webhook; **agents update themselves**
  when the server is upgraded.
* Deduplicated, signed, verifiable images (format: [docs/FORMAT.md](docs/FORMAT.md)),
  and a CLI (`fenrir-backup`) for scripting.

Not yet: recovery media and bare-metal restore (Phase 2), S3 and Object Lock (4),
dissimilar-hardware restore and cloning (5), live Linux snapshots (6).

Before relying on it, work through [docs/DEPLOYMENT-TEST-PLAN.md](docs/DEPLOYMENT-TEST-PLAN.md).

## Quick start

With Docker:

```bash
docker compose up -d --build
```

Or download a server bundle from CI (or build it, below), then:

```bash
./fenrir-server --public-url https://backup.example.lan:8443
```

Open that URL, create the administrator account, and follow **Add machines**.
Full guide: [docs/DEPLOY.md](docs/DEPLOY.md).

Build from source:

```bash
cargo build --release
```

```bash
cd ui && npm ci && npm run build
```

## Layout

| Path | Contents |
|---|---|
| `crates/core-format` | Repository format, crypto, manifests, storage backends, `fenrir-reader` |
| `crates/engine` | Backup, restore, verify |
| `crates/snapshot-win` | VSS, NTFS bitmaps, Windows disk layout |
| `crates/snapshot-linux` | Linux sources (raw disks now; LVM/btrfs/ZFS later) |
| `crates/cli` | `fenrir-backup` command-line tool |
| `crates/server` | `fenrir-server`: web UI host, API, installers, scheduler |
| `crates/agent` | `fenrir-backup-agent`: Windows service / systemd / launchd agent, Hyper-V backups |
| `crates/protocol` | Server–agent protocol and secret sealing |
| `crates/vdisk` | VHDX reader (from the MS-VHDX specification) |
| `ui` | Web UI (React + TypeScript) |
| `crates/nbd-server` | Read-only NBD server exporting images from the repository |
| `crates/vmboot` | Boot images under QEMU/KVM and decide whether they booted |
| `recovery-env` | Later phases |
| `docs/design` | One design note per phase |
| `fuzz` | Fuzz targets |

## Shared with Fenrir Cloud

The agent, CLI, engine, formats, file browsing, boot checks and recovery
environment are also used by the Fenrir Platform, which manages backups
from its own console (zy538324/AntiVirus, folder `backup/`). This
repository is their single source: change them here, then bring them
across with `python3 backup/sync-upstream.py <this checkout>` in the
AntiVirus repository. Its CI fails if the copy drifts. The server and web
UI here (`crates/server`, `ui/`) are this product's own; new backup features
need a matching change in Fenrir Cloud's backup module.

## Documentation

* [Deploying the server](docs/DEPLOY.md) · [Format](docs/FORMAT.md) · [CLI](docs/CLI.md) · [Testing](docs/TESTING.md)
* [Phase 1 design](docs/design/phase-1.md) · [Management server design](docs/design/management-server.md) · [Phase 3 design](docs/design/phase-3.md)
* [Security policy](SECURITY.md) · [NCSC Code of Practice mapping](docs/SECURITY-CODE-OF-PRACTICE.md)
* [Third-party components](THIRD_PARTY.md)

Fenrir-Backup is a clean-room implementation built from public standards
and operating system documentation.
