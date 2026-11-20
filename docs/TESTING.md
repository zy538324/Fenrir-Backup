# Testing

## What runs today (every push)

| Layer | Where | Covers |
|---|---|---|
| Unit tests | each crate | crypto wrap/unwrap, object tamper detection (every byte flipped), key slots, recovery key files, GPT/MBR parsing incl. 4Kn, damaged primary GPT, EBR chains, random/mutated tables; manifest sign/verify/validate; local backend create-only semantics; Windows structure parsing (bitmaps, retrieval pointers, disk extents, EFI load options); composite disk routing |
| Engine integration | `crates/engine/tests` | backup→restore byte comparison on a synthetic GPT disk; partition table byte-exact incl. backup GPT; free-space garbage never stored; incremental stores only changed chunks; zero chunks skipped and zero-filled on dirty targets; full verify finds a corrupted chunk, quick verify finds a missing one; restore refuses corrupt data; **fault injection**: backend failing mid-backup → no manifest, rerun completes and reuses chunks; cancellation; restore safety (confirmation mismatch, too-small target); MBR disk; multi-disk image |
| CLI end-to-end | `crates/cli/tests` | real binary with `--json`: init, backup, list, show, dry-run, verify, restore with and without `--yes`, wrong passphrase, recovery key unlock, corrupted chunk → exit 3 |
| Reference reader | `crates/core-format/tests` | `fenrir-reader export` rebuilds a sparse disk written via the library API |
| VHDX reader | `crates/vdisk/tests` | dynamic and differencing VHDX files built by a spec-following test writer: reads match, parent-linkage mismatch refused, damaged/dirty-log files refused, random corruption never panics, engine reads only allocated blocks and restores byte-exact |
| Server API | `crates/server/tests` | first-run setup, login throttling, CSRF header, enrollment tokens and revocation, installers carry URL/pin/token/hashes and resist Host-header injection, HTTP/2 authority, sealed secrets never stored in plaintext, one job at a time, lost-job detection, plans never pile up, cross-agent isolation, re-enrollment with a new key drops access |
| Sealing interop | `crates/protocol` | a blob sealed by `ui/src/seal.ts` on WebCrypto opens in the Rust agent |
| Hyper-V parsing | `crates/agent` | PowerShell/WMI output (single and multi-element), script injection refused |
| Windows VSS smoke | CI `windows-vss-smoke` | real VSS snapshot set with writers on a Windows runner, NTFS bitmap, pagefile exclusion, probe reads through shadow devices, abort |
| Fuzzing | `fuzz/`, CI `fuzz-smoke` | manifest envelope/body, sealed objects, partition tables, key files (60 s per target per push; longer runs before release) |
| Supply chain | CI `supply-chain` | `cargo audit`, `cargo deny` (licences, sources, advisories) |

End-to-end (run by hand during development, recorded in the PR): the real
server with a self-signed pinned certificate, the UI driven in Chromium,
the generated Linux one-liner piped to `sh` (pinned `curl`, hash check,
enrollment), a repository created through the UI wizard with
browser-sealed secrets and a browser-generated recovery key, a disk backup
plus an incremental that stores 0 new bytes, and the recovery key opening
the repository with the CLI. Hyper-V backups need a Hyper-V host and run in
the VM matrix.

Run locally:

```bash
cargo test --workspace
```

```bash
cargo clippy --workspace --all-targets
```

Cross-check the Windows code from Linux (needs `gcc-mingw-w64-x86-64`):

```bash
cargo clippy -p cli -p snapshot-win --target x86_64-pc-windows-gnu
```

## VM test matrix (release gate; infrastructure not yet built)

Guests:

* Windows 11, UEFI, Secure Boot, BitLocker on
* Windows Server 2022, UEFI
* Windows 10, BIOS/MBR
* Ubuntu LTS, ext4
* Fedora, btrfs

For each guest:

1. Full backup; change files; incremental backup.
2. Restore to a blank disk of the same size; boot; compare SHA-256 of a
   fixed set of user files against the source.
3. Restore to a larger disk (Phase 2/5).
4. Restore to a VM with a different storage controller (Phase 5).
5. Boot-as-VM (Phase 3); file-level restore (Phase 5).

Fault injection on real guests: kill the agent mid-backup, drop the network
mid-upload, corrupt a chunk on storage; the next run must detect and recover.
The engine tests above already cover the same faults against a synthetic
disk.

Planned implementation: libvirt/QEMU on a self-hosted runner for KVM guests
and a Hyper-V host for Windows guests, driven by a test harness in
`tests/vm/` that provisions from cloud images / evaluation ISOs the
operator supplies (no Microsoft media is redistributed).
