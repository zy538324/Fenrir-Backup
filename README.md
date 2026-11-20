# Fenrir-Backup

Open-source disk imaging and recovery for Windows 10/11 and Linux:
full system images with incrementals, bare-metal restore, boot-from-backup as
a VM, file-level restore, cloning, and ransomware-resistant storage.

**Status:** Phase 1 (format, Windows VSS imaging, verify, restore) plus the
management server and web UI. What works today:

* **Web app** (`fenrir-server`): a dashboard for every machine, backup plans
  with schedules, repositories, activity and audit log, light and dark
  themes, phone-friendly.
* **Downloads for every platform**: the web UI generates installers for
  Windows, Hyper-V hosts, Linux and macOS. Each one downloads the agent from
  your server, checks its hash, installs it as a service and enrols it.
* **Hyper-V hosts**: install once on the host; every VM is backed up through
  recovery checkpoints, with nothing installed inside the VMs.
* **Windows**: application-consistent system images through VSS.
* **Linux**: images of unmounted disks (live snapshots come later).
* **macOS**: enrols, reports and verifies; system protection needs file-level
  backup, which is next.
* **End-to-end encryption**: the server never holds repository keys. The
  browser encrypts each machine's passphrase to that machine, and generates
  the recovery key locally.
* Deduplicated, signed, verifiable images (format: [docs/FORMAT.md](docs/FORMAT.md)),
  and a CLI (`fenrir`) for scripting.

Not yet: recovery media and bare-metal restore from the UI (Phase 2),
boot-as-VM (3), retention, S3 and Object Lock (4), dissimilar-hardware
restore, cloning and file-level restore (5), live Linux snapshots (6).

## Quick start

Download a server bundle from CI (or build it, below), then:

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
| `crates/cli` | `fenrir` command-line tool |
| `crates/server` | `fenrir-server`: web UI host, API, installers, scheduler |
| `crates/agent` | `fenrir-agent`: Windows service / systemd / launchd agent, Hyper-V backups |
| `crates/protocol` | Server–agent protocol and secret sealing |
| `crates/vdisk` | VHDX reader (from the MS-VHDX specification) |
| `ui` | Web UI (React + TypeScript) |
| `crates/nbd-server`, `recovery-env` | Later phases |
| `docs/design` | One design note per phase |
| `fuzz` | Fuzz targets |

## Documentation

* [Deploying the server](docs/DEPLOY.md) · [Format](docs/FORMAT.md) · [CLI](docs/CLI.md) · [Testing](docs/TESTING.md)
* [Phase 1 design](docs/design/phase-1.md) · [Management server design](docs/design/management-server.md)
* [Security policy](SECURITY.md) · [NCSC Code of Practice mapping](docs/SECURITY-CODE-OF-PRACTICE.md)
* [Third-party components](THIRD_PARTY.md)

Fenrir-Backup is a clean-room implementation built from public standards
and operating system documentation.
