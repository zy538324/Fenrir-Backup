import { useEffect, useRef, useState } from "react";
import { Ban, CheckCircle2, Download, Fingerprint, Loader2, RefreshCw } from "lucide-react";
import { api, type Agent, type Downloads, type EnrollmentToken, type Platform } from "../api";
import { bytes, when } from "../format";
import { Command, Field, Link, Loading, Notice, OsBadge, useApi } from "../ui";

/** Windows and Hyper-V hosts: the setup program. */
const SETUP_STEPS: Partial<Record<Platform["id"], string[]>> = {
  windows: [
    "Run the downloaded Fenrir-Setup.exe on the machine and allow it to make changes (administrator prompt).",
    "If Windows SmartScreen says it protected your PC, choose More info › Run anyway: the file is built by your server for this link and is not code-signed.",
    "The machine appears below within a minute. For silent installs (scripts, remote tools): Fenrir-Setup.exe /quiet",
  ],
  hyperv: [
    "Run the downloaded Fenrir-Setup-HyperV.exe on the Hyper-V host itself (not inside a VM) and allow the administrator prompt.",
    "If Windows SmartScreen says it protected your PC, choose More info › Run anyway: the file is built by your server for this link and is not code-signed.",
    "The host and its VMs appear below within a minute. Nothing is installed in the VMs. Silent install: Fenrir-Setup-HyperV.exe /quiet",
  ],
};

const INSTRUCTIONS: Record<Platform["id"], string[]> = {
  windows: [
    "Copy the installer to the machine (or use the one-line command below).",
    "Open PowerShell as Administrator in the folder with the file.",
    "Run: powershell -ExecutionPolicy Bypass -File .\\install-fenrir.ps1",
    "The machine appears below within a minute.",
  ],
  hyperv: [
    "Run this on the Hyper-V host itself, not inside a VM. Nothing is installed in the VMs.",
    "Open PowerShell as Administrator in the folder with the file.",
    "Run: powershell -ExecutionPolicy Bypass -File .\\install-fenrir-hyperv.ps1",
    "The host and its VMs appear below within a minute.",
  ],
  linux: ["Copy the installer to the machine, or use the one-line command below.", "Run: sudo sh install-fenrir.sh", "The machine appears below within a minute."],
  macos: [
    "Copy the installer to the Mac, or use the one-line command below in Terminal.",
    "Run: sudo sh install-fenrir-macos.sh",
    "Give fenrir-agent Full Disk Access in System Settings › Privacy & Security.",
  ],
};

export default function AddMachinePage() {
  const base = useApi<Downloads>("/api/downloads");
  const [platform, setPlatform] = useState<Platform["id"]>("windows");
  const [role, setRole] = useState<"server" | "workstation">("server");
  const [days, setDays] = useState(7);
  const [token, setToken] = useState<EnrollmentToken | null>(null);
  const [dl, setDl] = useState<Downloads | null>(null);
  const [err, setErr] = useState<string | null>(null);

  // Any change of choice needs a fresh download.
  useEffect(() => {
    setToken(null);
    setDl(null);
  }, [platform, role, days]);

  if (base.error) return <div className="page"><Notice tone="bad">{base.error}</Notice></div>;
  if (!base.data) return <div className="page"><Loading /></div>;
  const tiles = base.data.platforms;

  const generate = async () => {
    setErr(null);
    try {
      const t = await api.post<EnrollmentToken>("/api/enrollment-tokens", {
        role: platform === "hyperv" ? "hyperv" : role,
        expires_days: days,
        label: `${tiles.find((p) => p.id === platform)!.name} download`,
      });
      setToken(t);
      setDl(await api.get<Downloads>(`/api/downloads?token=${encodeURIComponent(t.token)}`));
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const chosen = dl?.platforms.find((p) => p.id === platform);
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Add machines</h1>
          <div className="sub">Download an installer, run it on the machine, and it connects to this server by itself.</div>
        </div>
      </div>

      <div className="grid cols-4">
        {tiles.map((p) => (
          <button key={p.id} className={`platform${platform === p.id ? " on" : ""}`} onClick={() => setPlatform(p.id)}>
            <OsBadge role={p.id === "hyperv" ? "hyperv" : undefined} family={p.id === "hyperv" ? "windows" : p.id} size={22} />
            <div style={{ fontWeight: 650, fontSize: 15 }}>{p.name}</div>
            <div className="muted small">{p.summary}</div>
            {!p.available && <span className="pill warn" style={{ alignSelf: "flex-start" }}>Agent build not installed on server</span>}
          </button>
        ))}
      </div>

      <div className="card">
        <div className="card-head"><h2>Installer for {tiles.find((p) => p.id === platform)!.name}</h2></div>
        <div className="card-body stack">
          {platform !== "hyperv" && (
            <Field label="This machine is a">
              <div className="seg" style={{ alignSelf: "flex-start" }}>
                <button className={role === "server" ? "on" : ""} onClick={() => setRole("server")}>Server</button>
                <button className={role === "workstation" ? "on" : ""} onClick={() => setRole("workstation")}>Desktop or laptop</button>
              </div>
            </Field>
          )}
          <Field label="Link valid for" hint="The installer can enrol any number of machines until it expires. You can revoke it below at any time.">
            <select className="input" style={{ width: 180 }} value={days} onChange={(e) => setDays(Number(e.target.value))}>
              <option value={1}>1 day</option>
              <option value={7}>7 days</option>
              <option value={30}>30 days</option>
            </select>
          </Field>
          {err && <Notice tone="bad">{err}</Notice>}
          {!tiles.find((p) => p.id === platform)!.available && (
            <Notice tone="warn">
              The {tiles.find((p) => p.id === platform)!.name} agent has not been copied to this server yet. Place the release build in the server's <span className="mono">agents</span> folder; see the deployment guide.
            </Notice>
          )}
          {!chosen ? (
            <div>
              <button className="btn primary lg" onClick={generate} disabled={!tiles.find((p) => p.id === platform)!.available}>
                <Download size={17} /> Create installer
              </button>
            </div>
          ) : (
            <Ready platform={chosen} downloads={dl!} token={token!} onNew={generate} />
          )}
        </div>
      </div>
      <Links />
    </div>
  );
}

interface TokenRow { id: string; label: string; role: string; created: number; expires: number; uses: number; active: boolean }

function Links() {
  const { data, reload } = useApi<TokenRow[]>("/api/enrollment-tokens", 10000);
  const active = (data ?? []).filter((t) => t.active);
  if (active.length === 0) return null;
  return (
    <div className="card">
      <div className="card-head"><h2>Active download links</h2><span className="faint small">Anyone with one of these links can enrol a machine until it expires.</span></div>
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Link</th><th>Role</th><th>Created</th><th>Expires</th><th>Machines enrolled</th><th /></tr></thead>
          <tbody>
            {active.map((t) => (
              <tr key={t.id}>
                <td>{t.label}</td>
                <td>{t.role === "hyperv" ? "Hyper-V host" : t.role === "workstation" ? "Desktop or laptop" : "Server"}</td>
                <td className="nowrap">{when(t.created)}</td>
                <td className="nowrap">{when(t.expires)}</td>
                <td>{t.uses}</td>
                <td style={{ textAlign: "right" }}>
                  <button className="btn sm danger" onClick={async () => { await api.del(`/api/enrollment-tokens/${t.id}`); reload(); }}><Ban size={13} /> Revoke</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Ready({ platform, downloads, token, onNew }: { platform: Platform; downloads: Downloads; token: EnrollmentToken; onNew: () => void }) {
  const setup = platform.setup_url ? SETUP_STEPS[platform.id] : undefined;
  const script = (
    <>
      <a className={`btn ${setup ? "" : "primary lg"}`} href={platform.script_url!} download={platform.script_name}>
        <Download size={setup ? 15 : 17} /> Download {platform.script_name}
      </a>
      <ol className="steps">
        {INSTRUCTIONS[platform.id].map((s, i) => <li key={i}><span>{s}</span></li>)}
      </ol>
    </>
  );
  const oneLiner = (
    <Field label={platform.id === "windows" || platform.id === "hyperv" ? "Or paste this into PowerShell opened as Administrator" : "Or paste this into an elevated terminal on the machine"}>
      <Command text={platform.command!} />
    </Field>
  );
  return (
    <div className="stack">
      <div className="grid cols-2" style={{ alignItems: "start" }}>
        <div className="stack">
          {setup ? (
            <>
              <a className="btn primary lg" href={platform.setup_url!} download={platform.setup_name!}>
                <Download size={17} /> Download {platform.setup_name}
              </a>
              <ol className="steps">
                {setup.map((s, i) => <li key={i}><span>{s}</span></li>)}
              </ol>
            </>
          ) : (
            script
          )}
        </div>
        <div className="stack">
          {setup ? (
            <details>
              <summary className="small" style={{ cursor: "pointer", fontWeight: 600 }}>Other ways to install (PowerShell)</summary>
              <div className="stack" style={{ marginTop: 12 }}>
                {script}
                {oneLiner}
              </div>
            </details>
          ) : (
            oneLiner
          )}
          <div className="faint small row" style={{ gap: 6, alignItems: "flex-start" }}>
            <Fingerprint size={14} style={{ flex: "none", marginTop: 2 }} />
            <span>
              {downloads.pinned
                ? <>Agents trust only this server's certificate, SHA-256 <span className="mono">{downloads.cert_sha256?.slice(0, 16)}…</span>, and every download is checked against its hash before it runs.</>
                : <>Every download is checked against its hash before it runs.</>}
            </span>
          </div>
          <div className="faint small">
            {platform.targets.filter((t) => t.available).map((t) => `${t.arch}: ${bytes(t.size)}`).join(" · ")} · link valid until {when(token.expires)} ·{" "}
            <button className="btn sm ghost" onClick={onNew}><RefreshCw size={12} /> New link</button>
          </div>
        </div>
      </div>
      <Waiting />
      <div className="faint small">
        To remove the agent later,{" "}
        {platform.setup_url ? <>run <span className="mono">"C:\Program Files\Fenrir\fenrir-agent.exe" uninstall</span> as Administrator, or the </> : <>run the </>}
        <a href={platform.uninstall_url} download>uninstaller</a> on the machine.
      </div>
    </div>
  );
}

/** Watches for newly enrolled machines while the page is open. */
function Waiting() {
  const { data } = useApi<Agent[]>("/api/agents", 4000);
  const initial = useRef<Set<string> | null>(null);
  if (data && initial.current === null) initial.current = new Set(data.map((a) => a.id));
  const fresh = data?.filter((a) => !initial.current?.has(a.id)) ?? [];
  return fresh.length === 0 ? (
    <Notice tone="info">
      <span className="row" style={{ gap: 8 }}><Loader2 size={15} className="spin" /> Waiting for a machine to connect…</span>
    </Notice>
  ) : (
    <Notice tone="ok">
      <div className="stack tight">
        {fresh.map((a) => (
          <div key={a.id} className="row"><CheckCircle2 size={15} /> <strong>{a.name}</strong> connected. <Link to={`/machines/${a.id}`}>Open it</Link></div>
        ))}
      </div>
    </Notice>
  );
}
