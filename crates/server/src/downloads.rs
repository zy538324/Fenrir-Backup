//! Agent downloads: per-platform installers generated with the server
//! address, certificate pin, enrollment token and binary hashes baked in,
//! and the agent binaries themselves.
//!
//! Binaries live in `<agents_dir>/<rust target triple>/<file>`, produced by
//! CI. A platform whose binary is missing is reported as unavailable.

use std::path::PathBuf;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::Admin;
use crate::{now, sha256_hex, ApiError, ApiResult, Shared};

pub struct Target {
    pub triple: &'static str,
    pub file: &'static str,
    pub arch: &'static str,
}

pub struct Platform {
    pub id: &'static str,
    pub name: &'static str,
    pub summary: &'static str,
    pub targets: &'static [Target],
    /// Role the installer enrolls with; `None` = the token's role.
    pub role: Option<&'static str>,
    pub script_name: &'static str,
}

const WIN: &[Target] = &[Target {
    triple: "x86_64-pc-windows-msvc",
    file: "fenrir-agent.exe",
    arch: "x64",
}];
const LINUX: &[Target] = &[
    Target {
        triple: "x86_64-unknown-linux-musl",
        file: "fenrir-agent",
        arch: "x86_64",
    },
    Target {
        triple: "aarch64-unknown-linux-musl",
        file: "fenrir-agent",
        arch: "arm64",
    },
];
const MAC: &[Target] = &[
    Target {
        triple: "aarch64-apple-darwin",
        file: "fenrir-agent",
        arch: "Apple silicon",
    },
    Target {
        triple: "x86_64-apple-darwin",
        file: "fenrir-agent",
        arch: "Intel",
    },
];

pub const PLATFORMS: &[Platform] = &[
    Platform {
        id: "windows",
        name: "Windows",
        summary: "Windows 10/11 and Windows Server. Full system images through VSS, application-consistent.",
        targets: WIN,
        role: None,
        script_name: "install-fenrir.ps1",
    },
    Platform {
        id: "hyperv",
        name: "Hyper-V host",
        summary: "Install on the Hyper-V host. Backs up every VM on it through recovery checkpoints, with no software inside the VMs.",
        targets: WIN,
        role: Some("hyperv"),
        script_name: "install-fenrir-hyperv.ps1",
    },
    Platform {
        id: "linux",
        name: "Linux",
        summary: "x86-64 and arm64 with systemd. Images disks; live snapshots of mounted systems arrive with LVM/btrfs support.",
        targets: LINUX,
        role: None,
        script_name: "install-fenrir.sh",
    },
    Platform {
        id: "macos",
        name: "macOS",
        summary: "macOS 12 or later. Enrols, reports and verifies; system protection needs file-level backup, coming next.",
        targets: MAC,
        role: None,
        script_name: "install-fenrir-macos.sh",
    },
];

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/downloads", get(catalogue))
        .route("/install/{token}/{platform}", get(installer))
        .route("/uninstall/{platform}", get(uninstaller))
        .route("/agent/{target}/{file}", get(binary))
}

fn binary_path(st: &Shared, t: &Target) -> PathBuf {
    st.cfg.agents_dir.join(t.triple).join(t.file)
}

/// SHA-256 and size of an agent binary, if present.
fn binary_info(st: &Shared, t: &Target) -> Option<(String, u64)> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::SystemTime;
    // Hash once per file version, not on every heartbeat.
    /// path -> (modified, length, sha256)
    type HashCache = HashMap<PathBuf, (SystemTime, u64, String)>;
    static CACHE: Mutex<Option<HashCache>> = Mutex::new(None);
    let path = binary_path(st, t);
    let meta = std::fs::metadata(&path).ok()?;
    let (mtime, len) = (meta.modified().ok()?, meta.len());
    let mut c = CACHE.lock().unwrap_or_else(|p| p.into_inner());
    let map = c.get_or_insert_with(HashMap::new);
    if let Some((m, l, h)) = map.get(&path) {
        if *m == mtime && *l == len {
            return Some((h.clone(), len));
        }
    }
    let data = std::fs::read(&path).ok()?;
    let h = sha256_hex(&data);
    map.insert(path, (mtime, len, h.clone()));
    Some((h, len))
}

/// The build this agent should run, if it differs from what it runs now.
pub fn update_offer(st: &Shared, inv: &protocol::Inventory) -> Option<protocol::AgentUpdate> {
    if inv.agent_target.is_empty() || inv.agent_sha256.is_empty() {
        return None;
    }
    // Linux builds are shipped static (musl); an agent built against glibc
    // for the same CPU is moved onto the static build.
    let want = inv
        .agent_target
        .replace("-unknown-linux-gnu", "-unknown-linux-musl");
    let t = PLATFORMS
        .iter()
        .flat_map(|p| p.targets.iter())
        .find(|t| t.triple == want)?;
    let (sha, _) = binary_info(st, t)?;
    (!sha.eq_ignore_ascii_case(&inv.agent_sha256)).then(|| protocol::AgentUpdate {
        path: format!("/agent/{}/{}", t.triple, t.file),
        sha256: sha,
    })
}

/// URL agents use to reach this server.
pub fn public_url(st: &Shared, headers: &HeaderMap, uri: &Uri) -> ApiResult<String> {
    let url = match &st.cfg.public_url {
        Some(u) => u.trim_end_matches('/').to_string(),
        None => {
            // HTTP/1.1 sends Host; HTTP/2 carries it as the :authority
            // pseudo-header, which appears in the request URI.
            let host = headers
                .get(header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(str::to_string)
                .or_else(|| uri.authority().map(|a| a.to_string()))
                .ok_or_else(|| ApiError::bad("no Host header"))?;
            format!(
                "{}://{host}",
                if st.cfg.tls.is_some() {
                    "https"
                } else {
                    "http"
                }
            )
        }
    };
    // Only characters that are inert inside both shell and PowerShell
    // single-quoted strings.
    if !url
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b":/.-_[]%".contains(&b))
        || !(url.starts_with("https://") || url.starts_with("http://"))
    {
        return Err(ApiError::bad(
            "server URL contains unexpected characters; set --public-url",
        ));
    }
    Ok(url)
}

fn token_valid(st: &Shared, token: &str) -> ApiResult<String> {
    if !token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || token.len() != 43
    {
        return Err(ApiError::not_found("unknown or expired download link"));
    }
    let row: Option<(String, i64, i64)> = st
        .db()
        .query_row(
            "SELECT role, expires, revoked FROM enrollment_tokens WHERE token_hash = ?1",
            params![sha256_hex(token.as_bytes())],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    match row {
        Some((role, exp, 0)) if exp > now() => Ok(role),
        _ => Err(ApiError::not_found(
            "unknown or expired download link; create a new one in the web UI",
        )),
    }
}

#[derive(Deserialize)]
struct CatalogueQuery {
    #[serde(default)]
    token: Option<String>,
}

async fn catalogue(
    State(st): State<Shared>,
    _a: Admin,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<CatalogueQuery>,
) -> ApiResult<Json<Value>> {
    let url = public_url(&st, &headers, &uri)?;
    let pin = st.cfg.tls.as_ref().filter(|t| t.pinned);
    let token = match &q.token {
        Some(t) => {
            token_valid(&st, t)?;
            Some(t.clone())
        }
        None => None,
    };
    let platforms: Vec<Value> = PLATFORMS
        .iter()
        .map(|p| {
            let targets: Vec<Value> = p
                .targets
                .iter()
                .map(|t| {
                    let info = binary_info(&st, t);
                    json!({ "triple": t.triple, "arch": t.arch, "available": info.is_some(),
                            "sha256": info.as_ref().map(|i| i.0.clone()), "size": info.map(|i| i.1) })
                })
                .collect();
            let available = targets.iter().any(|t| t["available"] == true);
            let (script_url, command) = match &token {
                Some(tok) => {
                    let su = format!("{url}/install/{tok}/{}", p.id);
                    let cmd = if p.targets[0].triple.contains("windows") {
                        let cb = match pin {
                            Some(t) => format!(
                                "[Net.ServicePointManager]::ServerCertificateValidationCallback={{param($s,$c)$c.GetCertHashString('SHA256') -eq '{}'}}; ",
                                t.cert_sha256.to_uppercase()
                            ),
                            None => String::new(),
                        };
                        format!("powershell -NoProfile -ExecutionPolicy Bypass -Command \"{cb}iex (iwr -UseBasicParsing '{su}').Content\"")
                    } else {
                        let pinarg = pin.map(|t| format!("-k --pinnedpubkey 'sha256//{}' ", t.spki_sha256_b64)).unwrap_or_default();
                        format!("curl -fsSL {pinarg}'{su}' | sudo sh")
                    };
                    (Some(su), Some(cmd))
                }
                None => (None, None),
            };
            json!({
                "id": p.id, "name": p.name, "summary": p.summary, "available": available, "targets": targets,
                "script_name": p.script_name, "script_url": script_url, "command": command,
                "uninstall_url": format!("{url}/uninstall/{}", p.id),
            })
        })
        .collect();
    Ok(Json(
        json!({ "server_url": url, "pinned": pin.is_some(), "cert_sha256": st.cfg.tls.as_ref().map(|t| t.cert_sha256.clone()), "platforms": platforms }),
    ))
}

fn script_response(name: &str, body: String) -> Response {
    let ct = if name.ends_with(".ps1") {
        "text/plain; charset=utf-8"
    } else {
        "text/x-shellscript; charset=utf-8"
    };
    (
        [
            (header::CONTENT_TYPE, ct.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        body,
    )
        .into_response()
}

async fn installer(
    State(st): State<Shared>,
    headers: HeaderMap,
    uri: Uri,
    Path((token, platform)): Path<(String, String)>,
) -> ApiResult<Response> {
    let token_role = token_valid(&st, &token)?;
    let p = PLATFORMS
        .iter()
        .find(|p| p.id == platform)
        .ok_or_else(|| ApiError::not_found("unknown platform"))?;
    let url = public_url(&st, &headers, &uri)?;
    let role = p.role.unwrap_or(&token_role).to_string();
    let pin = st
        .cfg
        .tls
        .as_ref()
        .filter(|t| t.pinned)
        .map(|t| t.cert_sha256.clone())
        .unwrap_or_default();
    let hashes: Vec<(&Target, String)> = p
        .targets
        .iter()
        .map(|t| (t, binary_info(&st, t).map(|i| i.0).unwrap_or_default()))
        .collect();
    let body = match p.id {
        "windows" | "hyperv" => {
            windows_script(&url, &pin, &token, &role, &hashes[0].1, p.id == "hyperv")
        }
        "linux" => linux_script(&url, &pin, &token, &role, &hashes),
        "macos" => macos_script(&url, &pin, &token, &role, &hashes),
        _ => unreachable!(),
    };
    Ok(script_response(p.script_name, body))
}

async fn uninstaller(Path(platform): Path<String>) -> ApiResult<Response> {
    let (name, body) = match platform.as_str() {
        "windows" | "hyperv" => ("uninstall-fenrir.ps1", WIN_UNINSTALL.to_string()),
        "linux" => ("uninstall-fenrir.sh", LINUX_UNINSTALL.to_string()),
        "macos" => ("uninstall-fenrir-macos.sh", MAC_UNINSTALL.to_string()),
        _ => return Err(ApiError::not_found("unknown platform")),
    };
    Ok(script_response(name, body))
}

async fn binary(
    State(st): State<Shared>,
    Path((target, file)): Path<(String, String)>,
) -> ApiResult<Response> {
    let t = PLATFORMS
        .iter()
        .flat_map(|p| p.targets.iter())
        .find(|t| t.triple == target && t.file == file)
        .ok_or_else(|| ApiError::not_found("no such agent build"))?;
    let data = tokio::fs::read(binary_path(&st, t))
        .await
        .map_err(|_| ApiError::not_found("this agent build is not installed on the server"))?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", t.file),
            ),
        ],
        Body::from(data),
    )
        .into_response())
}

// ---------- script templates ----------
//
// Values substituted below are restricted to [A-Za-z0-9:/._-%[]] (URL),
// hex (pin, hashes), base64url (token) and fixed role names, so they are
// inert inside single-quoted strings in both shells.

fn windows_script(
    url: &str,
    pin: &str,
    token: &str,
    role: &str,
    sha: &str,
    hyperv: bool,
) -> String {
    let hyperv_check = if hyperv {
        "if (-not (Get-Service vmms -ErrorAction SilentlyContinue)) { throw 'This machine is not a Hyper-V host (the vmms service is missing). Use the Windows installer instead.' }\n"
    } else {
        ""
    };
    format!(
        r#"# Fenrir-Backup agent installer for Windows{kind}.
# Generated by the Fenrir-Backup server for this enrollment only.
# Run in an elevated PowerShell:  powershell -ExecutionPolicy Bypass -File .\install-fenrir{suffix}.ps1
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$Server = '{url}'
$Pin    = '{pin}'
$Token  = '{token}'
$Role   = '{role}'
$Sha256 = '{sha}'

if (-not $Sha256) {{ throw 'The server has no Windows agent build installed yet.' }}
{hyperv_check}[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$web = @{{ UseBasicParsing = $true }}
if ($Pin) {{
  # Self-signed server certificate: accept only the pinned one.
  if ($PSVersionTable.PSVersion.Major -ge 6) {{ $web.SkipCertificateCheck = $true }}
  else {{ [Net.ServicePointManager]::ServerCertificateValidationCallback = {{ param($s, $c) $c.GetCertHashString('SHA256') -eq $Pin.ToUpper() }} }}
}}

$dir = Join-Path $env:ProgramFiles 'Fenrir'
$exe = Join-Path $dir 'fenrir-agent.exe'
$tmp = "$exe.download"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Write-Host 'Downloading the Fenrir-Backup agent...'
Invoke-WebRequest @web -Uri "$Server/agent/x86_64-pc-windows-msvc/fenrir-agent.exe" -OutFile $tmp
$got = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash
if ($got -ne $Sha256.ToUpper()) {{ Remove-Item $tmp -Force; throw "Downloaded agent failed its integrity check ($got)." }}

$svc = Get-Service FenrirAgent -ErrorAction SilentlyContinue
if ($svc) {{ Stop-Service FenrirAgent -Force; Start-Sleep -Seconds 2 }}
Move-Item -Force $tmp $exe

Write-Host 'Enrolling with the server...'
& $exe enroll --server $Server --pin $Pin --token $Token --role $Role
if ($LASTEXITCODE -ne 0) {{ throw "Enrollment failed (exit code $LASTEXITCODE)." }}

if (-not $svc) {{
  New-Service -Name FenrirAgent -DisplayName 'Fenrir-Backup Agent' -BinaryPathName ('"' + $exe + '" service') `
    -StartupType Automatic -Description 'Backs up this machine for Fenrir-Backup.' | Out-Null
  sc.exe failure FenrirAgent reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Null
}}
Start-Service FenrirAgent
Write-Host 'Fenrir-Backup agent installed and running. This machine will appear in the web UI within a minute.' -ForegroundColor Green
"#,
        kind = if hyperv { " (Hyper-V host)" } else { "" },
        suffix = if hyperv { "-hyperv" } else { "" },
    )
}

fn unix_common(url: &str, pin: &str, token: &str, role: &str) -> String {
    format!(
        r#"set -eu
SERVER='{url}'
PIN='{pin}'
TOKEN='{token}'
ROLE='{role}'
if [ "$(id -u)" -ne 0 ]; then echo "Please run as root (sudo)." >&2; exit 1; fi
CURL="curl -fsS"
# Self-signed server: the binary is checked against the hash below, and
# the agent pins the server certificate itself.
if [ -n "$PIN" ]; then CURL="$CURL -k"; fi
"#
    )
}

fn linux_script(
    url: &str,
    pin: &str,
    token: &str,
    role: &str,
    hashes: &[(&Target, String)],
) -> String {
    let sha = |t: &str| {
        hashes
            .iter()
            .find(|(x, _)| x.triple == t)
            .map(|(_, h)| h.clone())
            .unwrap_or_default()
    };
    format!(
        r#"#!/bin/sh
# Fenrir-Backup agent installer for Linux. Generated for this enrollment only.
{common}
case "$(uname -m)" in
  x86_64|amd64) TARGET=x86_64-unknown-linux-musl; SHA='{x64}' ;;
  aarch64|arm64) TARGET=aarch64-unknown-linux-musl; SHA='{arm}' ;;
  *) echo "Unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac
if [ -z "$SHA" ]; then echo "The server has no agent build for $TARGET yet." >&2; exit 1; fi
command -v systemctl >/dev/null || {{ echo "systemd is required." >&2; exit 1; }}
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
echo "Downloading the Fenrir-Backup agent..."
$CURL -o "$TMP" "$SERVER/agent/$TARGET/fenrir-agent"
echo "$SHA  $TMP" | sha256sum -c --status - || {{ echo "Downloaded agent failed its integrity check." >&2; exit 1; }}
systemctl stop fenrir-agent 2>/dev/null || true
install -m 0755 "$TMP" /usr/local/bin/fenrir-agent
echo "Enrolling with the server..."
/usr/local/bin/fenrir-agent enroll --server "$SERVER" --pin "$PIN" --token "$TOKEN" --role "$ROLE"
cat > /etc/systemd/system/fenrir-agent.service <<'UNIT'
[Unit]
Description=Fenrir-Backup agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/fenrir-agent run
Restart=always
RestartSec=30
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now fenrir-agent
echo "Fenrir-Backup agent installed and running. This machine will appear in the web UI within a minute."
"#,
        common = unix_common(url, pin, token, role),
        x64 = sha("x86_64-unknown-linux-musl"),
        arm = sha("aarch64-unknown-linux-musl"),
    )
}

fn macos_script(
    url: &str,
    pin: &str,
    token: &str,
    role: &str,
    hashes: &[(&Target, String)],
) -> String {
    let sha = |t: &str| {
        hashes
            .iter()
            .find(|(x, _)| x.triple == t)
            .map(|(_, h)| h.clone())
            .unwrap_or_default()
    };
    format!(
        r#"#!/bin/sh
# Fenrir-Backup agent installer for macOS. Generated for this enrollment only.
{common}
case "$(uname -m)" in
  arm64) TARGET=aarch64-apple-darwin; SHA='{arm}' ;;
  x86_64) TARGET=x86_64-apple-darwin; SHA='{x64}' ;;
  *) echo "Unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac
if [ -z "$SHA" ]; then echo "The server has no agent build for $TARGET yet." >&2; exit 1; fi
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
echo "Downloading the Fenrir-Backup agent..."
$CURL -o "$TMP" "$SERVER/agent/$TARGET/fenrir-agent"
GOT=$(shasum -a 256 "$TMP" | cut -d' ' -f1)
if [ "$GOT" != "$SHA" ]; then echo "Downloaded agent failed its integrity check." >&2; exit 1; fi
launchctl bootout system/uk.fenrir.agent 2>/dev/null || true
mkdir -p /usr/local/bin
install -m 0755 "$TMP" /usr/local/bin/fenrir-agent
echo "Enrolling with the server..."
/usr/local/bin/fenrir-agent enroll --server "$SERVER" --pin "$PIN" --token "$TOKEN" --role "$ROLE"
cat > /Library/LaunchDaemons/uk.fenrir.agent.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>uk.fenrir.agent</string>
  <key>ProgramArguments</key><array><string>/usr/local/bin/fenrir-agent</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/Library/Logs/fenrir-agent.log</string>
</dict>
</plist>
PLIST
chmod 0644 /Library/LaunchDaemons/uk.fenrir.agent.plist
launchctl bootstrap system /Library/LaunchDaemons/uk.fenrir.agent.plist
echo "Fenrir-Backup agent installed and running."
echo "To let it read disks, add /usr/local/bin/fenrir-agent under System Settings > Privacy & Security > Full Disk Access."
"#,
        common = unix_common(url, pin, token, role),
        arm = sha("aarch64-apple-darwin"),
        x64 = sha("x86_64-apple-darwin"),
    )
}

const WIN_UNINSTALL: &str = r#"# Removes the Fenrir-Backup agent. Backups already stored are not touched.
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
if (Get-Service FenrirAgent -ErrorAction SilentlyContinue) {
  Stop-Service FenrirAgent -Force
  sc.exe delete FenrirAgent | Out-Null
}
Remove-Item -Recurse -Force (Join-Path $env:ProgramFiles 'Fenrir') -ErrorAction SilentlyContinue
# Agent identity and key: remove to make a later reinstall a new machine.
Remove-Item -Recurse -Force (Join-Path $env:ProgramData 'Fenrir\agent') -ErrorAction SilentlyContinue
Write-Host 'Fenrir-Backup agent removed. Remove the machine in the web UI as well.'
"#;

const LINUX_UNINSTALL: &str = r#"#!/bin/sh
# Removes the Fenrir-Backup agent. Backups already stored are not touched.
set -eu
systemctl disable --now fenrir-agent 2>/dev/null || true
rm -f /etc/systemd/system/fenrir-agent.service /usr/local/bin/fenrir-agent
systemctl daemon-reload
rm -rf /var/lib/fenrir-agent
echo "Fenrir-Backup agent removed. Remove the machine in the web UI as well."
"#;

const MAC_UNINSTALL: &str = r#"#!/bin/sh
# Removes the Fenrir-Backup agent. Backups already stored are not touched.
set -eu
launchctl bootout system/uk.fenrir.agent 2>/dev/null || true
rm -f /Library/LaunchDaemons/uk.fenrir.agent.plist /usr/local/bin/fenrir-agent
rm -rf "/Library/Application Support/Fenrir/agent"
echo "Fenrir-Backup agent removed. Remove the machine in the web UI as well."
"#;
