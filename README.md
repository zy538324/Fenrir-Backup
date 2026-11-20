# Fenrir-Backup

Open-source disk imaging and recovery for Windows 10/11 and Linux:
full system images with incrementals, bare-metal restore, boot-from-backup as
a VM, file-level restore, cloning, and ransomware-resistant storage.

**Status: Phase 1 of 8.** What works today:

* Encrypted, deduplicated repository on a local path or mounted share
  (format: [docs/FORMAT.md](docs/FORMAT.md)).
* Windows system image through VSS with application writers; free space,
  `pagefile.sys`, `hiberfil.sys` and `swapfile.sys` skipped; ESP and MSR
  captured raw.
* Images of unmounted disks and raw image files on any platform.
* Incremental runs upload only changed chunks.
* Verify (quick, sampled, full) and restore of a disk image to a device or
  file, with safety checks.
* `fenrir-reader`, a small read-only reference reader.

Not yet: recovery media and bootloader repair (Phase 2), boot-as-VM (3),
retention, S3 and Object Lock (4), dissimilar-hardware restore, cloning and
file-level mount (5), live Linux snapshots (6), agent and web UI (7).

## Quick start

```bash
cargo build --release
```

```bash
export FENRIR_REPO=/mnt/backups/fenrir
fenrir repo init --recovery-key-out ~/fenrir-recovery.json
```

On Windows, as Administrator:

```powershell
fenrir --repo E:\Backups backup system
fenrir --repo E:\Backups verify --sample 5
```

See [docs/CLI.md](docs/CLI.md) for every command and exit code.

## Layout

| Path | Contents |
|---|---|
| `crates/core-format` | Repository format, crypto, manifests, storage backends, `fenrir-reader` |
| `crates/engine` | Backup, restore, verify |
| `crates/snapshot-win` | VSS, NTFS bitmaps, Windows disk layout |
| `crates/snapshot-linux` | Linux sources (raw disks now; LVM/btrfs/ZFS later) |
| `crates/cli` | `fenrir` |
| `crates/nbd-server`, `crates/agent` | Later phases |
| `recovery-env`, `ui` | Later phases |
| `docs/design` | One design note per phase |
| `fuzz` | Fuzz targets |

## Documentation

* [Format](docs/FORMAT.md) · [CLI](docs/CLI.md) · [Testing](docs/TESTING.md)
* [Phase 1 design](docs/design/phase-1.md)
* [Security policy](SECURITY.md) · [NCSC Code of Practice mapping](docs/SECURITY-CODE-OF-PRACTICE.md)
* [Third-party components](THIRD_PARTY.md)

Fenrir-Backup is a clean-room implementation built from public standards
and operating system documentation.
