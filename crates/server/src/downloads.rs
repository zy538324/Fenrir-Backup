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
    file: "fenrir-backup-agent.exe",
    arch: "x64",
}];
const LINUX: &[Target] = &[
    Target {
        triple: "x86_64-unknown-linux-musl",
        file: "fenrir-backup-agent",
        arch: "x86_64",
    },
    Target {
        triple: "aarch64-unknown-linux-musl",
        file: "fenrir-backup-agent",
        arch: "arm64",
    },
];
const MAC: &[Target] = &[
    Target {
        triple: "aarch64-apple-darwin",
        file: "fenrir-backup-agent",
        arch: "Apple silicon",
    },
    Target {
        triple: "x86_64-apple-darwin",
        file: "fenrir-backup-agent",
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
        script_name: "install-fenrir-backup.ps1",
    },
    Platform {
        id: "hyperv",
        name: "Hyper-V host",
        summary: "Install on the Hyper-V host. Backs up every VM on it through recovery checkpoints, with no software inside the VMs.",
        targets: WIN,
        role: Some("hyperv"),
        script_name: "install-fenrir-backup-hyperv.ps1",
    },
    Platform {
        id: "linux",
        name: "Linux",
        summary: "x86-64 and arm64 with systemd. Images disks; live snapshots of mounted systems arrive with LVM/btrfs support.",
        targets: LINUX,
        role: None,
        script_name: "install-fenrir-backup.sh",
    },
    Platform {
        id: "macos",
        name: "macOS",
        summary: "macOS 12 or later. Enrols, reports and verifies; system protection needs file-level backup, coming next.",
        targets: MAC,
        role: None,
        script_name: "install-fenrir-backup-macos.sh",
    },
];

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/downloads", get(catalogue))
        .route("/install/{token}/{platform}", get(installer))
        .route("/install/{token}/{platform}/{file}", get(setup_exe))
        .route("/uninstall/{platform}", get(uninstaller))
        .route("/agent/{target}/{file}", get(binary))
        .route("/recovery/{token}/{file}", get(recovery_media))
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
    // for the same CPU is moved onto the static build. The Windows slot
    // holds either an MSVC build (CI) or a MinGW build (Docker image).
    let want = inv
        .agent_target
        .replace("-unknown-linux-gnu", "-unknown-linux-musl")
        .replace("-pc-windows-gnu", "-pc-windows-msvc");
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
                        windows_one_liner(&su, pin.map(|t| t.cert_sha256.as_str()).unwrap_or(""))
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
                "setup_name": matches!(p.id, "windows" | "hyperv").then(|| setup_name(p.id)),
                "setup_url": match (&token, p.id) {
                    (Some(tok), "windows" | "hyperv") => Some(format!("{url}/install/{tok}/{}/{}", p.id, setup_name(p.id))),
                    _ => None,
                },
                "uninstall_url": format!("{url}/uninstall/{}", p.id),
            })
        })
        .collect();
    let iso = recovery_iso_path(&st);
    let iso_size = std::fs::metadata(&iso).ok().map(|m| m.len());
    let recovery = json!({
        "available": iso_size.is_some(),
        "size": iso_size,
        "iso_url": token.as_ref().map(|t| format!("{url}/recovery/{t}/{RECOVERY_ISO}")),
        "settings_url": token.as_ref().map(|t| format!("{url}/recovery/{t}/{RECOVERY_SETTINGS}")),
    });
    Ok(Json(
        json!({ "server_url": url, "pinned": pin.is_some(), "cert_sha256": st.cfg.tls.as_ref().map(|t| t.cert_sha256.clone()), "platforms": platforms, "recovery": recovery }),
    ))
}

// ---------- recovery media (design: phase-2 §2) ----------

const RECOVERY_ISO: &str = "fenrir-recovery.iso";
const RECOVERY_SETTINGS: &str = "fenrir-recovery.json";

/// The stock recovery ISO, built by CI (`recovery-env/build.sh`).
pub fn recovery_iso_path(st: &Shared) -> PathBuf {
    st.cfg.agents_dir.join("recovery").join(RECOVERY_ISO)
}

/// Offset of the personalisation block in the ISO at `path`, cached per
/// file version.
fn iso_block_offset(path: &std::path::Path) -> std::io::Result<Option<u64>> {
    use std::collections::HashMap;
    use std::io::Read;
    use std::sync::Mutex;
    use std::time::SystemTime;
    type Cache = HashMap<PathBuf, (SystemTime, u64, Option<u64>)>;
    static CACHE: Mutex<Option<Cache>> = Mutex::new(None);
    let meta = std::fs::metadata(path)?;
    let key = (meta.modified()?, meta.len());
    if let Some((m, l, o)) = CACHE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get_or_insert_with(HashMap::new)
        .get(path)
    {
        if (*m, *l) == key {
            return Ok(*o);
        }
    }
    // Scan sector by sector; the block (two sectors) is the marker followed
    // by spaces.
    let mut f = std::io::BufReader::with_capacity(1 << 20, std::fs::File::open(path)?);
    let mut sector = [0u8; 2048];
    let mut pending: Option<(u64, [u8; 2048])> = None;
    let mut found = None;
    let mut off = 0u64;
    loop {
        match f.read_exact(&mut sector) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        if let Some((at, first)) = pending.take() {
            let win = [first.as_slice(), sector.as_slice()].concat();
            if protocol::recovery::find_block(&win) == Some(0) {
                found = Some(at);
                break;
            }
        }
        if sector.starts_with(protocol::recovery::MARKER) {
            pending = Some((off, sector));
        }
        off += 2048;
    }
    CACHE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get_or_insert_with(HashMap::new)
        .insert(path.to_path_buf(), (key.0, key.1, found));
    Ok(found)
}

/// `/recovery/<token>/fenrir-recovery.iso`: the stock ISO with this server's
/// settings in it; `/recovery/<token>/fenrir-recovery.json`: the same
/// settings as a file for a USB stick. The token must be a recovery token.
async fn recovery_media(
    State(st): State<Shared>,
    Path((token, file)): Path<(String, String)>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<Response> {
    if token_valid(&st, &token)? != "recovery" {
        return Err(ApiError::not_found(
            "this link is not for recovery media; create one under Add machine > Recovery media",
        ));
    }
    let expires: i64 = st.db().query_row(
        "SELECT expires FROM enrollment_tokens WHERE token_hash = ?1",
        params![sha256_hex(token.as_bytes())],
        |r| r.get(0),
    )?;
    let cfg = protocol::recovery::RecoveryConfig {
        server: public_url(&st, &headers, &uri)?,
        pin: st
            .cfg
            .tls
            .as_ref()
            .filter(|t| t.pinned)
            .map(|t| t.cert_sha256.clone())
            .unwrap_or_default(),
        token,
        expires: expires.max(0) as u64,
    };
    let attachment = |name: &str| format!("attachment; filename=\"{name}\"");
    match file.as_str() {
        RECOVERY_SETTINGS => Ok((
            [
                (header::CONTENT_TYPE, "application/json".to_string()),
                (header::CONTENT_DISPOSITION, attachment(RECOVERY_SETTINGS)),
                (header::CACHE_CONTROL, "no-store".to_string()),
            ],
            serde_json::to_string_pretty(&cfg)?,
        )
            .into_response()),
        RECOVERY_ISO => {
            let path = recovery_iso_path(&st);
            let p2 = path.clone();
            let off = tokio::task::spawn_blocking(move || iso_block_offset(&p2))
                .await
                .map_err(|e| ApiError::internal(e.to_string()))?
                .map_err(|_| {
                    ApiError::not_found("the recovery ISO is not installed on the server")
                })?
                .ok_or_else(|| {
                    ApiError::internal("the recovery ISO on the server has no settings block")
                })?;
            let block = protocol::recovery::render(&cfg).map_err(ApiError::internal)?;
            let nf = |_| ApiError::not_found("the recovery ISO is not installed on the server");
            let len = tokio::fs::metadata(&path).await.map_err(nf)?.len();
            let f = tokio::fs::File::open(&path).await.map_err(nf)?;
            let stream = futures_util::stream::unfold((f, 0u64), move |(mut f, pos)| {
                let block = block.clone();
                async move {
                    use tokio::io::AsyncReadExt;
                    let mut buf = vec![0u8; 1 << 20];
                    let n = match f.read(&mut buf).await {
                        Ok(0) => return None,
                        Ok(n) => n,
                        Err(e) => return Some((Err(e), (f, pos))),
                    };
                    buf.truncate(n);
                    // Replace the overlap with the settings block.
                    let (bs, be) = (off, off + block.len() as u64);
                    let (cs, ce) = (pos, pos + n as u64);
                    let (s, e) = (bs.max(cs), be.min(ce));
                    if s < e {
                        buf[(s - cs) as usize..(e - cs) as usize]
                            .copy_from_slice(&block[(s - bs) as usize..(e - bs) as usize]);
                    }
                    Some((Ok(axum::body::Bytes::from(buf)), (f, ce)))
                }
            });
            Ok((
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                    (header::CONTENT_DISPOSITION, attachment(RECOVERY_ISO)),
                    (header::CONTENT_LENGTH, len.to_string()),
                    (header::CACHE_CONTROL, "no-store".to_string()),
                ],
                Body::from_stream(stream),
            )
                .into_response())
        }
        _ => Err(ApiError::not_found("no such file")),
    }
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

/// Windows setup program: the agent with this enrollment's settings
/// appended (`protocol::setup`). Double-click to install.
async fn setup_exe(
    State(st): State<Shared>,
    headers: HeaderMap,
    uri: Uri,
    Path((token, platform, file)): Path<(String, String, String)>,
) -> ApiResult<Response> {
    let token_role = token_valid(&st, &token)?;
    let p = PLATFORMS
        .iter()
        .find(|p| p.id == platform && (p.id == "windows" || p.id == "hyperv"))
        .ok_or_else(|| ApiError::not_found("setup programs exist for Windows and Hyper-V hosts"))?;
    if file != setup_name(p.id) {
        return Err(ApiError::not_found("no such file"));
    }
    let exe = tokio::fs::read(binary_path(&st, &p.targets[0]))
        .await
        .map_err(|_| ApiError::not_found("this agent build is not installed on the server"))?;
    let cfg = protocol::setup::SetupConfig {
        server: public_url(&st, &headers, &uri)?,
        pin: st
            .cfg
            .tls
            .as_ref()
            .filter(|t| t.pinned)
            .map(|t| t.cert_sha256.clone())
            .unwrap_or_default(),
        token,
        role: p.role.unwrap_or(&token_role).to_string(),
    };
    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                "application/vnd.microsoft.portable-executable".to_string(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{file}\""),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        Body::from(protocol::setup::append(&exe, &cfg)),
    )
        .into_response())
}

fn setup_name(platform: &str) -> &'static str {
    if platform == "hyperv" {
        "Fenrir-Backup-Setup-HyperV.exe"
    } else {
        "Fenrir-Backup-Setup.exe"
    }
}

async fn uninstaller(Path(platform): Path<String>) -> ApiResult<Response> {
    let (name, body) = match platform.as_str() {
        "windows" | "hyperv" => ("uninstall-fenrir-backup.ps1", WIN_UNINSTALL.to_string()),
        "linux" => ("uninstall-fenrir-backup.sh", LINUX_UNINSTALL.to_string()),
        "macos" => (
            "uninstall-fenrir-backup-macos.sh",
            MAC_UNINSTALL.to_string(),
        ),
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
# Run in an elevated PowerShell:  powershell -ExecutionPolicy Bypass -File .\install-fenrir-backup{suffix}.ps1
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$Server = '{url}'
$Pin    = '{pin}'
$Token  = '{token}'
$Role   = '{role}'
$Sha256 = '{sha}'

if (-not $Sha256) {{ throw 'The server has no Windows agent build installed yet.' }}
{hyperv_check}# Downloads go through a small compiled helper: with a self-signed server
# certificate it accepts only the pinned one (SHA-256 of the certificate),
# otherwise normal certificate validation applies. Works in Windows
# PowerShell 5.1 and PowerShell 7.
if (-not ('FenrirDl' -as [type])) {{ Add-Type -IgnoreWarnings -TypeDefinition '{cs}' }}
[FenrirDl]::Pin = $Pin

# Names specific to Fenrir-Backup (other products use "Fenrir" ones).
$Svc = 'FenrirBackupAgent'
$dir = Join-Path $env:ProgramFiles 'Fenrir-Backup'
$exe = Join-Path $dir 'fenrir-backup-agent.exe'
$tmp = "$exe.download"

# A service with our name that runs something else is not ours: leave it.
# (PowerShell variable names ignore case: $existing must not be called $svc.)
$existing = Get-Service $Svc -ErrorAction SilentlyContinue
if ($existing) {{
  $runs = (Get-CimInstance Win32_Service -Filter "Name='$Svc'").PathName
  if ($runs -notlike "*$exe*") {{ throw "A service named $Svc already exists but runs $runs; it is not Fenrir-Backup's and was left untouched." }}
}}

New-Item -ItemType Directory -Force -Path $dir | Out-Null
Write-Host 'Downloading the Fenrir-Backup agent...'
[IO.File]::WriteAllBytes($tmp, [FenrirDl]::Get("$Server/agent/x86_64-pc-windows-msvc/fenrir-backup-agent.exe"))
$got = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash
if ($got -ne $Sha256.ToUpper()) {{ Remove-Item $tmp -Force; throw "Downloaded agent failed its integrity check ($got)." }}

if ($existing) {{ Stop-Service $Svc -Force; Start-Sleep -Seconds 2 }}
Move-Item -Force $tmp $exe

Write-Host 'Enrolling with the server...'
& $exe enroll --server $Server --pin $Pin --token $Token --role $Role
if ($LASTEXITCODE -ne 0) {{ throw "Enrollment failed (exit code $LASTEXITCODE)." }}

if (-not $existing) {{
  New-Service -Name $Svc -DisplayName 'Fenrir-Backup Agent' -BinaryPathName ('"' + $exe + '" service') `
    -StartupType Automatic -Description 'Backs up this machine for Fenrir-Backup.' | Out-Null
  sc.exe failure $Svc reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Null
}}
Start-Service $Svc
Write-Host 'Fenrir-Backup agent installed and running. This machine will appear in the web UI within a minute.' -ForegroundColor Green
"#,
        kind = if hyperv { " (Hyper-V host)" } else { "" },
        suffix = if hyperv { "-hyperv" } else { "" },
        cs = WIN_DOWNLOADER_CS,
    )
}

/// C# (5, so the compiler built into .NET Framework accepts it) for
/// downloads from the server: pins the certificate's SHA-256 when one is
/// given, otherwise validates normally. A compiled delegate, because a
/// PowerShell scriptblock as certificate callback can be invoked on a
/// thread without a runspace (Windows PowerShell 5.1 then fails with "The
/// underlying connection was closed: An unexpected error occurred on a
/// send"). Must not contain single quotes: it is embedded in a PowerShell
/// single-quoted string.
pub const WIN_DOWNLOADER_CS: &str = "using System;using System.IO;using System.Net;using System.Net.Security;using System.Security.Cryptography;using System.Security.Cryptography.X509Certificates;\
public static class FenrirDl{public static string Pin=\"\";\
static bool Ok(object s,X509Certificate c,X509Chain h,SslPolicyErrors e){if(String.IsNullOrEmpty(Pin))return e==SslPolicyErrors.None;\
using(SHA256 x=SHA256.Create()){return BitConverter.ToString(x.ComputeHash(c.GetRawCertData())).Replace(\"-\",\"\").Equals(Pin,StringComparison.OrdinalIgnoreCase);}}\
public static byte[] Get(string u){ServicePointManager.SecurityProtocol=ServicePointManager.SecurityProtocol|SecurityProtocolType.Tls12;\
HttpWebRequest r=(HttpWebRequest)WebRequest.Create(u);r.ServerCertificateValidationCallback=Ok;\
using(WebResponse w=r.GetResponse())using(Stream st=w.GetResponseStream())using(MemoryStream m=new MemoryStream()){st.CopyTo(m);return m.ToArray();}}}";

/// The command shown in the UI: paste into PowerShell (as Administrator).
fn windows_one_liner(script_url: &str, pin: &str) -> String {
    format!(
        "if (-not ('FenrirDl' -as [type])) {{ Add-Type -IgnoreWarnings -TypeDefinition '{WIN_DOWNLOADER_CS}' }}; [FenrirDl]::Pin = '{pin}'; iex ([Text.Encoding]::UTF8.GetString([FenrirDl]::Get('{script_url}')))"
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
$CURL -o "$TMP" "$SERVER/agent/$TARGET/fenrir-backup-agent"
echo "$SHA  $TMP" | sha256sum -c --status - || {{ echo "Downloaded agent failed its integrity check." >&2; exit 1; }}
systemctl stop fenrir-backup-agent 2>/dev/null || true
install -m 0755 "$TMP" /usr/local/bin/fenrir-backup-agent
echo "Enrolling with the server..."
/usr/local/bin/fenrir-backup-agent enroll --server "$SERVER" --pin "$PIN" --token "$TOKEN" --role "$ROLE"
cat > /etc/systemd/system/fenrir-backup-agent.service <<'UNIT'
[Unit]
Description=Fenrir-Backup agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/fenrir-backup-agent run
Restart=always
RestartSec=30
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now fenrir-backup-agent
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
$CURL -o "$TMP" "$SERVER/agent/$TARGET/fenrir-backup-agent"
GOT=$(shasum -a 256 "$TMP" | cut -d' ' -f1)
if [ "$GOT" != "$SHA" ]; then echo "Downloaded agent failed its integrity check." >&2; exit 1; fi
launchctl bootout system/uk.fenrir-backup.agent 2>/dev/null || true
mkdir -p /usr/local/bin
install -m 0755 "$TMP" /usr/local/bin/fenrir-backup-agent
echo "Enrolling with the server..."
/usr/local/bin/fenrir-backup-agent enroll --server "$SERVER" --pin "$PIN" --token "$TOKEN" --role "$ROLE"
cat > /Library/LaunchDaemons/uk.fenrir-backup.agent.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>uk.fenrir-backup.agent</string>
  <key>ProgramArguments</key><array><string>/usr/local/bin/fenrir-backup-agent</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/Library/Logs/fenrir-backup-agent.log</string>
</dict>
</plist>
PLIST
chmod 0644 /Library/LaunchDaemons/uk.fenrir-backup.agent.plist
launchctl bootstrap system /Library/LaunchDaemons/uk.fenrir-backup.agent.plist
echo "Fenrir-Backup agent installed and running."
echo "To let it read disks, add /usr/local/bin/fenrir-backup-agent under System Settings > Privacy & Security > Full Disk Access."
"#,
        common = unix_common(url, pin, token, role),
        arm = sha("aarch64-apple-darwin"),
        x64 = sha("x86_64-apple-darwin"),
    )
}

const WIN_UNINSTALL: &str = r#"# Removes the Fenrir-Backup agent. Backups already stored are not touched.
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$Svc = 'FenrirBackupAgent'
$dir = Join-Path $env:ProgramFiles 'Fenrir-Backup'
$exe = Join-Path $dir 'fenrir-backup-agent.exe'
if (Get-Service $Svc -ErrorAction SilentlyContinue) {
  # Only our own service: one with this name that runs something else is left alone.
  $runs = (Get-CimInstance Win32_Service -Filter "Name='$Svc'").PathName
  if ($runs -notlike "*$exe*") { throw "A service named $Svc exists but runs $runs; it is not Fenrir-Backup's and was left untouched." }
  Stop-Service $Svc -Force
  sc.exe delete $Svc | Out-Null
}
Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
# Agent identity and key: remove to make a later reinstall a new machine.
Remove-Item -Recurse -Force (Join-Path $env:ProgramData 'Fenrir-Backup\agent') -ErrorAction SilentlyContinue
Write-Host 'Fenrir-Backup agent removed. Remove the machine in the web UI as well.'
"#;
const LINUX_UNINSTALL: &str = r#"#!/bin/sh
# Removes the Fenrir-Backup agent. Backups already stored are not touched.
set -eu
systemctl disable --now fenrir-backup-agent 2>/dev/null || true
rm -f /etc/systemd/system/fenrir-backup-agent.service /usr/local/bin/fenrir-backup-agent
systemctl daemon-reload
rm -rf /var/lib/fenrir-backup-agent
echo "Fenrir-Backup agent removed. Remove the machine in the web UI as well."
"#;
const MAC_UNINSTALL: &str = r#"#!/bin/sh
# Removes the Fenrir-Backup agent. Backups already stored are not touched.
set -eu
launchctl bootout system/uk.fenrir-backup.agent 2>/dev/null || true
rm -f /Library/LaunchDaemons/uk.fenrir-backup.agent.plist /usr/local/bin/fenrir-backup-agent
rm -rf "/Library/Application Support/Fenrir-Backup/agent"
echo "Fenrir-Backup agent removed. Remove the machine in the web UI as well."
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_installer_text() {
        // Embedded in PowerShell single-quoted strings.
        assert!(!WIN_DOWNLOADER_CS.contains('\''));
        // C# 5 only (.NET Framework's built-in compiler): no `=>`, `$"`, `?.`.
        for newer in ["=>", "$\"", "?."] {
            assert!(!WIN_DOWNLOADER_CS.contains(newer), "{newer}");
        }
        let pin = "89f93aae6e9aad9ed80272581bce6507762437a2728a3abf2c9ba6e541a8ca9d";
        for hyperv in [false, true] {
            let s = windows_script(
                "https://198.51.100.7:8443",
                pin,
                "tok",
                "server",
                "abc",
                hyperv,
            );
            assert!(
                s.is_ascii(),
                "PowerShell 5.1 reads BOM-less scripts as ANSI"
            );
            assert!(s.contains(
                "[FenrirDl]::Get(\"$Server/agent/x86_64-pc-windows-msvc/fenrir-backup-agent.exe\")"
            ));
            assert!(
                !s.contains("ServerCertificateValidationCallback = {"),
                "no scriptblock callbacks"
            );
            assert!(!s.contains("Invoke-WebRequest"));
            // Names specific to Fenrir-Backup; never another product's service.
            assert!(!s.contains("FenrirAgent") && !s.contains("'Fenrir'"));
            assert!(s.contains("$Svc = 'FenrirBackupAgent'"));
            assert!(s.contains("it is not Fenrir-Backup's and was left untouched"));
        }
        for u in [WIN_UNINSTALL, LINUX_UNINSTALL, MAC_UNINSTALL] {
            assert!(u.contains("ackup"), "product-specific names only");
            assert!(
                !u.contains("FenrirAgent")
                    && !u.contains("fenrir-agent")
                    && !u.contains("uk.fenrir.agent")
            );
        }
        assert!(WIN_UNINSTALL.contains("was left untouched"));
        let one = windows_one_liner("https://198.51.100.7:8443/install/tok/windows", pin);
        assert!(one.is_ascii());
        // Native PowerShell: no nested powershell.exe, so no `$` expansion surprises.
        assert!(!one.contains("powershell"));
        // Outside the single-quoted C#, no double quotes: nothing for
        // PowerShell to expand.
        assert!(!one.replace(WIN_DOWNLOADER_CS, "").contains('"'));
        assert!(one.contains(&format!("[FenrirDl]::Pin = '{pin}'")));
    }
}
