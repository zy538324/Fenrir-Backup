# Deploying the Fenrir-Backup server

The server is one program, `fenrir-server`, plus two folders it serves:
`ui/` (the web interface) and `agents/` (agent builds for each platform).
CI produces ready bundles: `fenrir-server-linux-x64.tar.gz` and
`fenrir-server-windows-x64.zip`, each with a `SHA256SUMS` file.

```text
fenrir-server-linux-x64/
  fenrir-server
  ui/                         web interface
  agents/
    x86_64-pc-windows-msvc/fenrir-agent.exe     Windows and Hyper-V hosts
    x86_64-unknown-linux-musl/fenrir-agent      Linux x86-64 (static)
    aarch64-unknown-linux-musl/fenrir-agent     Linux arm64 (static)
    aarch64-apple-darwin/fenrir-agent           macOS, Apple silicon
    x86_64-apple-darwin/fenrir-agent            macOS, Intel
  SHA256SUMS
```

## Run it (Linux)

```bash
sudo tar -xzf fenrir-server-linux-x64.tar.gz -C /opt
```

```bash
sudo /opt/fenrir-server-linux-x64/fenrir-server --public-url https://backup.example.lan:8443
```

Open the URL in a browser, accept the certificate warning once (see TLS
below), and create the administrator account.

As a service, `/etc/systemd/system/fenrir-server.service`:

```ini
[Unit]
Description=Fenrir-Backup server
After=network-online.target

[Service]
ExecStart=/opt/fenrir-server-linux-x64/fenrir-server --public-url https://backup.example.lan:8443
Restart=always
DynamicUser=yes
StateDirectory=fenrir-server
Environment=FENRIR_DATA_DIR=/var/lib/fenrir-server

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now fenrir-server
```

## Options

| Option | Default | Meaning |
|---|---|---|
| `--listen` | `0.0.0.0:8443` | Address and port. |
| `--public-url` | the address your browser used | What agents use to reach the server. Set it when browsers and machines use different names. |
| `--data-dir` | `/var/lib/fenrir-server`, `C:\ProgramData\Fenrir\server` | Database and generated certificate. Back this folder up. |
| `--ui-dir`, `--agents-dir` | `ui/` and `agents/` next to the program | Override when not using the bundle layout. |
| `--tls-cert`, `--tls-key` | — | Your own certificate (PEM). |
| `--tls-name` | — | Extra names/IPs for the generated certificate. |
| `--http` | off | Plain HTTP, only behind a reverse proxy that terminates TLS. |
| `--poll-seconds` | 15 | How often agents check in. |

## TLS

Without `--tls-cert`, the server creates a self-signed certificate on first
start and **pins** it: every installer it generates carries the
certificate's fingerprint, and agents accept no other certificate. This is
safe without a certificate authority. Browsers show a warning the first
time; compare the fingerprint in the warning with the one the server logs
at start (`cert_sha256`).

With a certificate from your CA or Let's Encrypt, pass `--tls-cert` and
`--tls-key`; agents then validate it normally.

## Where backups go

The server stores no backup data. Each repository is a folder that the
machines write to directly: a local disk, a USB disk, or a network share
(`\\nas\backups\fenrir` on Windows, a mounted share on Linux). On Windows
the agent runs as LocalSystem, which reaches a share as the computer
account: grant `DOMAIN\COMPUTERNAME$` write access, or use a local disk.
Storage on S3 with Object Lock and SFTP arrives with Phase 4.

## Keys and what the server can see

Repository passphrases are encrypted in the administrator's browser for
each machine and stored on the server only in that encrypted form. The
recovery key is generated in the browser and downloaded there. Someone who
takes over the server cannot read any backup. Keep the recovery key
offline: if the passphrase and the recovery key are both lost, the backups
cannot be restored by anyone.

## Backing up the server

Copy `--data-dir` (the database and certificate). Losing it does not lose
backups: reinstall the server, enrol the machines again, and recreate the
repositories' access using the same passphrase; the repositories
themselves are untouched.
