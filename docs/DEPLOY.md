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
    x86_64-pc-windows-msvc/fenrir-backup-agent.exe     Windows and Hyper-V hosts
    x86_64-unknown-linux-musl/fenrir-backup-agent      Linux x86-64 (static)
    aarch64-unknown-linux-musl/fenrir-backup-agent     Linux arm64 (static)
    aarch64-apple-darwin/fenrir-backup-agent           macOS, Apple silicon
    x86_64-apple-darwin/fenrir-backup-agent            macOS, Intel
  SHA256SUMS
```

## Run it with Docker

The image holds the server, the web UI, the `fenrir-backup` CLI, the Linux agent
for its own CPU architecture (x86-64 or arm64) and the Windows agent (used
for Windows machines and Hyper-V hosts; cross-compiled with MinGW).

```bash
docker compose up -d --build
```

or without compose:

```bash
docker build -t fenrir-server .
```

```bash
docker run -d --name fenrir -p 8443:8443 -v fenrir-data:/var/lib/fenrir-server --restart unless-stopped fenrir-server
```

Then open `https://<docker-host>:8443`. Machines enrol against the address
your browser used; if they reach the server by another name, set
`FENRIR_PUBLIC_URL` (see `compose.yaml`). Server options can also be passed
as arguments after the image name, e.g. `fenrir-server --poll-seconds 30`.

* **Data:** the database and generated certificate are in the
  `fenrir-data` volume. Back it up; keep it when upgrading, because the
  agents pin the certificate stored there.
* **macOS agents** are not built inside Docker (they need a Mac). The
  server sync fetches them from CI (see "Keep it updated from GitHub");
  without it, copy `fenrir-backup-agent` from a CI server bundle into
  `./agents/aarch64-apple-darwin/` and `./agents/x86_64-apple-darwin/`.
  The Add machines page marks platforms without a build as unavailable.
* **Bind mount instead of a volume:** the server runs as UID 10001, so
  `chown -R 10001:10001` the host folder first.
* **Upgrades:** `docker compose up -d --build` (or pull the new image and
  recreate the container). The volume carries over.
* **Logs:** `docker logs fenrir` (JSON lines). `GET /healthz` is the health
  check the image already uses.

### Keep it updated from GitHub

`scripts/server-sync/` holds a systemd timer that checks GitHub every 5
minutes and, when there is a new commit, rebuilds the image and restarts
the container. The data volume is kept. If a build fails, the running
version stays up and that commit is not tried again until a newer one
arrives (`fenrir-sync.sh --force` retries).

```bash
sudo git clone --branch <branch> https://github.com/zy538324/Fenrir-Backup /opt/fenrir-backup
```

```bash
sudo sh /opt/fenrir-backup/scripts/server-sync/install.sh
```

The same timer installs the **macOS agents**. They can only be built on a
Mac, so CI builds them on GitHub's macOS runners and publishes them to the
`agent-builds` branch after each successful run of `main` or the
development branch. The sync fetches that branch with the same read-only
access, checks every file against its `SHA256SUMS`, and places them in
`/opt/fenrir-backup/agents/`, which `compose.yaml` mounts into the
container. No restart is needed. If CI cannot push the branch, set the
repository's Settings → Actions → General → Workflow permissions to "Read
and write".

Put local settings (e.g. `FENRIR_PUBLIC_URL`) in
`/opt/fenrir-backup/compose.override.yaml`, not in `compose.yaml`: the
sync discards edits to tracked files. Logs: `journalctl -u fenrir-sync`.

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

## Alerts

Settings → Alerts: SMTP email (STARTTLS, TLS or none) and/or a webhook
(Slack, Teams or generic JSON). You are told about failed backups,
backups with warnings (optional), possible ransomware, machines offline
for longer than a threshold (default 24 h) and machines with an active
plan but no good backup for a few days (default 2). "Save and send a
test" shows the mail or webhook server's answer if delivery fails. The
SMTP password is stored on the server (it is the only server-side
secret) and is never sent back to the browser.

## Windows setup program

`Fenrir-Backup-Setup.exe` is the Windows agent with the enrollment settings
(server address, certificate fingerprint, enrollment token) appended. The
server builds one per download; it is only as secret as the link it came
from, and stops working when that link expires or is revoked. Run it
interactively, or silently with `Fenrir-Backup-Setup.exe /quiet` from deployment
tools (it must then run elevated). The installed copy in
`C:\Program Files\Fenrir-Backup` is the plain agent. Remove the agent with
`"C:\Program Files\Fenrir-Backup\fenrir-backup-agent.exe" uninstall`.

The file is not code-signed, so SmartScreen and some antivirus products
warn about it ("More info › Run anyway"). If you sign `fenrir-backup-agent.exe`
with your own code-signing certificate before placing it in the server's
agents folder, deploy with the PowerShell script or one-liner instead: they
download the signed agent unchanged, while the setup program appends data
to the file, which invalidates an Authenticode signature.

## Names on the machines (and installs from before the rename)

Everything the agent installs is named for Fenrir-Backup, so it cannot
clash with other software that uses "Fenrir" names:

| | Windows | Linux | macOS |
|---|---|---|---|
| Service | `FenrirBackupAgent` ("Fenrir-Backup Agent") | `fenrir-backup-agent.service` | `uk.fenrir-backup.agent` |
| Program | `C:\Program Files\Fenrir-Backup\fenrir-backup-agent.exe` | `/usr/local/bin/fenrir-backup-agent` | same |
| Identity and log | `C:\ProgramData\Fenrir-Backup\agent` | `/var/lib/fenrir-backup-agent` | `/Library/Application Support/Fenrir-Backup/agent` |

The installers and `uninstall` refuse to stop, change or delete a service
with this name that runs a different program.

Earlier test builds used `FenrirAgent`, `C:\Program Files\Fenrir\fenrir-agent.exe`
and `C:\ProgramData\Fenrir\agent` (Linux: `fenrir-agent`). If another
product uses those names, an old installer may have stopped or replaced
its service. Nothing removes the old names automatically, because they may
belong to the other product. To check a Windows machine, in an elevated
prompt:

```
sc.exe qc FenrirAgent
```

If `BINARY_PATH_NAME` ends in `fenrir-agent.exe" service` and the machine
does not run that other product, it is a Fenrir-Backup test install:
`sc.exe delete FenrirAgent`, then delete `C:\Program Files\Fenrir` and
`C:\ProgramData\Fenrir\agent`. If the other product is installed, repair or
reinstall it instead, and install Fenrir-Backup with the current installer.
Agents from before the rename that are already enrolled keep working and
keep their old names when they update themselves.

## Agent updates

Agents run the build the server carries for their platform: when the
server is upgraded, each agent downloads the new build between jobs over
its pinned connection, checks the SHA-256, swaps its executable and
restarts. Settings → Agent updates turns this off. Linux agents are
static builds; an agent you built yourself against glibc is moved onto
the static build the same way.

## Retention and the ransomware hold

Each backup plan says how many images to keep. Old images are removed
after each backup, and the space they used is reclaimed weekly by the
repository's maintenance machine (Repositories → Space reclamation).
If a backup looks like mass encryption (far more changed data than usual,
and the new data does not compress), the repository goes **on hold**:
nothing is deleted or reclaimed until an administrator reviews it and
types `release`. Backups continue during a hold. You can also place a
hold by hand.

## Repositories on a network share (NAS, file server)

Type the folder as a share path, `\\backup-server\backups\fenrir`, in
**New repository**, and choose how machines sign in:

* **Username and password** (domain optional; empty for a NAS's own
  accounts; `user@domain` also works). The browser encrypts the sign-in
  separately for each machine; the server stores only those encrypted
  copies, like the repository passphrase.
* **This computer's account**: domain-joined Windows machines reach the
  share as `DOMAIN\COMPUTERNAME$` (the agent runs as SYSTEM). Grant those
  computer accounts, or an AD group of them, change rights. Nothing is
  stored.

**Test connection** signs in from the chosen machine, writes and deletes a
test file and shows free space. Machines connect only while a job runs and
disconnect afterwards; on Windows the connection lives in the agent's
SYSTEM session, so it never appears as a drive in a user's Explorer.

Recommended setup on the backup server: a dedicated account used for
nothing else, with change rights on the backup share only; no person and
no administrator account; SMB 3 with encryption if the network is shared.
To change the password, change it on the server first, then use **Change
sign-in** on the repository (it re-encrypts it for every machine).

Linux machines mount the share privately (`/run/fenrir-backup-agent/smb`) and need
the `cifs-utils` package. macOS machines cannot use share repositories yet:
use a folder the system has mounted.

## Remote machines through a gateway

A repository on a NAS can be served to machines that cannot reach the NAS
(laptops at home, another site). On the Repositories page click **Serve
through a gateway** and pick an enrolled machine on the NAS's network that already
has access; then **Give access** to a remote machine and tick **Through the
gateway**.

* **Relay** (always on): the remote machine sends its requests to this
  server, which passes them to the gateway. Nothing to open on any firewall.
* **Direct** (optional): give the gateway a port (8475 suggested) and,
  when it sits behind NAT, the address remote machines should use
  (`backup.example.com:8475`). Machines try it first and fall back to the
  relay. On Windows the agent adds the firewall rule "Fenrir-Backup
  gateway" for domain and private networks.

Requests are encrypted and signed between the two agents (X25519 + AES-256-GCM),
so neither the relay nor the network can read or forge them. Remote machines
can only add data: deletion goes through the gateway, which also runs
retention and space reclamation for the repository.

## Restoring single files

**Files** next to an image (on the machine's page) opens an image's NTFS and ext2/3/4 volumes on any
machine with access to the repository, decrypted there with the
repository key (nothing readable goes through the server). Tick files or
folders and restore them to a folder on any machine with access: into a new
folder, keeping their paths, or next to the originals with a choice of
rename, skip or overwrite.

## Recovery media (bare-metal restore)

For a machine that no longer starts, has a new disk, or is replaced by new
hardware. The server bundle includes `agents/recovery/fenrir-recovery.iso`
(Docker: mount a folder holding it at `/opt/fenrir/agents/recovery`).

1. **Add machines › Recovery media › Create recovery media**, then
   download `fenrir-recovery.iso`. The download carries this server's
   address, certificate fingerprint and an enrolment code for recovery
   sessions (valid 7–90 days; revoke it in the list of links). Write it to
   a USB stick with balenaEtcher, Rufus (DD mode) or `dd`, or attach it to a
   VM as a DVD.
2. Start the machine from it. Secure Boot can stay on. Wired networks with
   DHCP connect by themselves; **Network settings** on its screen handles
   Wi-Fi and fixed addresses.
3. It appears under **Machines › Recovery sessions**. Open it, choose a
   backup, give the session access (the passphrase is encrypted in your
   browser for that session only), pick the disk and type its name to
   confirm. A repository on a NAS the session cannot reach is served to it
   through the NAS's gateway machine (above).
4. When the restore finishes, remove the stick and restart.

What the restore does for new hardware: the target disk may be larger (the
partition table moves to its end; the extra space is left unallocated, to
add with Disk Management or `growpart`) or smaller if every partition fits.
On UEFI systems it adds the fallback boot loader `\EFI\BOOT\BOOTX64.EFI`
when missing and a firmware boot entry. If the machine started in a
different firmware mode (UEFI vs legacy BIOS) from the backed-up system,
the job says which setting to change.

BitLocker: the Windows agent backs volumes up through their snapshot, which
reads them decrypted (the image is encrypted with the repository key
instead). They restore **unencrypted** and start without the recovery key;
the job reminds you to turn BitLocker on again. Volumes captured still
encrypted (a Hyper-V VM's own BitLocker backed up from the host, a volume
VSS could not snapshot, or a Windows disk backed up from Linux) need their
48-digit recovery key on first start on different hardware; the job says
which. Drivers for different storage controllers are not added
yet (Phase 5).

Without a server (or without network): choose **Restore from a repository
here** on the recovery screen. It reads a repository from a USB disk or an
SMB share (read-only), asks for the passphrase or a recovery-key file,
and restores onto a disk you choose and confirm by typing its name. A stock
ISO, or one whose link expired, can still connect to a server: put the
settings file from **Recovery media › Settings file only** in the root of
any USB stick and choose **Look for server settings on a USB stick**.

The recovery system never writes to a disk except the one you confirm, and
the stick it runs from, and disks with anything mounted, are refused by the
server and by the agent. Sessions end when the machine restarts and are
removed from the list after a week.

## Boot verification (booting backups as VMs)

A **boot host** starts images as virtual machines to prove they boot. Any
enrolled Linux machine becomes one when QEMU is installed (the agent
checks at start-up):

```bash
sudo apt-get install -y qemu-system-x86 qemu-utils ovmf     # Debian/Ubuntu
sudo dnf install -y qemu-kvm qemu-img edk2-ovmf             # Fedora/RHEL
```

With `/dev/kvm` available a boot takes about a minute; without it QEMU
emulates the CPU and Windows images can take 10–20 minutes. The VM boots
straight from the repository (nothing is copied), writes go to a
temporary overlay that is deleted afterwards, and its network is isolated:
it cannot reach your LAN or the internet, so a booted copy never clashes
with the real machine. Hyper-V hosts can run boot checks too; they copy
the image to a folder first, so they need free space for the whole image:
choose the folder in **Test boot** (for example the volume your VMs live
on), or leave it empty for `C:\ProgramData\Fenrir-Backup\agent\boot-checks`.
On a Hyper-V host, **Keep it running** leaves the VM in Hyper-V Manager,
switched off from the network, until you click **Stop** on the Boot page
(which deletes the VM and its folder): a way to restore a machine as a VM and
check it by hand.

Give the boot host access to the repository, then either click **Test
boot** next to an image, or turn on **Boot verification** for the
repository (Repositories page) to test the newest image of every machine
weekly. Failures raise an alert. "Keep it running" leaves the VM up for up
to 8 hours with VNC, RDP and SSH on the host's loopback interface only;
reach them with an SSH tunnel to the host (the UI shows the command).

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
