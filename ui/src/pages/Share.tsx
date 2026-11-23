import { useState } from "react";
import { CheckCircle2, Eye, EyeOff, KeyRound, Loader2, Network, PlugZap, XCircle } from "lucide-react";
import { api, type Agent, type Job, type Repository, type S3Settings } from "../api";
import { bytes } from "../format";
import { seal } from "../seal";
import { Field, Modal, Notice, useToast } from "../ui";

export const isSharePath = (p: string) => /^(\\\\|\/\/|smb:\/\/)/i.test(p.trim());

export interface ShareSignin {
  mode: "password" | "machine";
  domain: string;
  username: string;
  password: string;
}

export const emptySignin = (): ShareSignin => ({ mode: "password", domain: "", username: "", password: "" });

/** "CORP\\user" or "user" as stored for display; back into its parts. */
export function signinFromDisplay(display: string | null): ShareSignin {
  const s = emptySignin();
  if (!display) return s;
  const i = display.indexOf("\\");
  if (i > 0) {
    s.domain = display.slice(0, i);
    s.username = display.slice(i + 1);
  } else s.username = display;
  return s;
}

export const signinDisplay = (s: ShareSignin) => (s.domain.trim() && !s.username.includes("\\") && !s.username.includes("@") ? `${s.domain.trim()}\\${s.username.trim()}` : s.username.trim());

export const signinComplete = (s: ShareSignin) => s.mode === "machine" || (s.username.trim() !== "" && s.password !== "");

/** The sign-in sealed for one machine (only that machine can read it). */
export async function sealSignin(agent: Agent, s: ShareSignin) {
  return seal(agent.public_key, JSON.stringify({ domain: s.domain.trim(), username: s.username.trim(), password: s.password }));
}

export function ShareFields({ value, onChange, machines, lockUser }: { value: ShareSignin; onChange: (s: ShareSignin) => void; machines: Agent[]; lockUser?: boolean }) {
  const [show, setShow] = useState(false);
  const nonWindows = machines.filter((m) => m.os.family !== "windows");
  return (
    <div className="stack tight">
      <div className="seg" style={{ alignSelf: "flex-start" }}>
        <button className={value.mode === "password" ? "on" : ""} onClick={() => onChange({ ...value, mode: "password" })}>Username and password</button>
        <button className={value.mode === "machine" ? "on" : ""} onClick={() => onChange({ ...value, mode: "machine" })}>This computer's account</button>
      </div>
      {value.mode === "password" ? (
        <>
          <div className="grid cols-2">
            <Field label="Domain" hint="Optional. Empty for a NAS's own account; or type user@domain as the username.">
              <input className="input" value={value.domain} disabled={lockUser} onChange={(e) => onChange({ ...value, domain: e.target.value })} placeholder="CORP" autoComplete="off" />
            </Field>
            <Field label="Username">
              <input className="input" value={value.username} disabled={lockUser} onChange={(e) => onChange({ ...value, username: e.target.value })} placeholder="backup-svc" autoComplete="off" />
            </Field>
          </div>
          <Field label="Password" hint="Encrypted in this browser for each machine that uses this repository. The Fenrir-Backup server never sees it.">
            <div className="row" style={{ gap: 6 }}>
              <input className="input grow" type={show ? "text" : "password"} value={value.password} onChange={(e) => onChange({ ...value, password: e.target.value })} autoComplete="new-password" />
              <button className="icon-btn" aria-label={show ? "Hide password" : "Show password"} onClick={() => setShow(!show)}>{show ? <EyeOff size={16} /> : <Eye size={16} />}</button>
            </div>
          </Field>
          <div className="faint small">
            Tip: use a dedicated account that only this share accepts, not a person's or an administrator's account. Machines connect only while a backup runs, out of sight of logged-in users, so ransomware on a PC cannot browse to it.
          </div>
        </>
      ) : (
        <Notice tone="info">
          For domain-joined Windows machines: the agent runs as SYSTEM and reaches the share as the computer account. Give <span className="mono">DOMAIN\COMPUTERNAME$</span> (or an AD group of backup machines) change rights on the share and folder. No password is stored.
          {nonWindows.length > 0 && <> {nonWindows.map((m) => m.name).join(", ")} {nonWindows.length === 1 ? "is not a Windows machine and needs" : "are not Windows machines and need"} a username and password instead.</>}
        </Notice>
      )}
    </div>
  );
}

interface CheckResult { exists: boolean; repository: boolean; writable: boolean; free_bytes: number | null; total_bytes: number | null; share: boolean; s3?: boolean; note?: string }

/** Run a connection test on a machine and show the result. */
export function TestConnection({ agent, path, signin, s3 }: { agent: Agent | undefined; path: string; signin: ShareSignin | null; s3?: S3Settings | null }) {
  const [state, setState] = useState<{ busy: boolean; job?: Job; err?: string; for?: string }>({ busy: false });
  // A result belongs to the folder, machine and sign-in it was tested with.
  const inputs = JSON.stringify([agent?.id, path.trim(), signin, s3]);
  const run = async () => {
    if (!agent) return;
    const tested = inputs;
    setState({ busy: true, for: tested });
    try {
      const sealed_share = signin && signin.mode === "password" ? await sealSignin(agent, signin) : null;
      const { id } = await api.post<{ id: string }>(`/api/agents/${agent.id}/check-access`, { path, sealed_share, s3: s3 ?? null });
      for (let i = 0; i < 90; i++) {
        await new Promise((r) => setTimeout(r, 2000));
        const j = await api.get<Job>(`/api/jobs/${id}`);
        if (["succeeded", "warning", "failed", "cancelled"].includes(j.state)) return setState({ busy: false, job: j, for: tested });
      }
      setState({ busy: false, err: `${agent.name} did not answer in time. Is it online?`, for: tested });
    } catch (e) {
      setState({ busy: false, err: (e as Error).message, for: tested });
    }
  };
  const current = state.for === inputs;
  const job = current ? state.job : undefined;
  const err = current ? state.err : undefined;
  const r = job?.result as CheckResult | undefined;
  return (
    <div className="stack tight">
      <div className="row" style={{ gap: 8 }}>
        <button className="btn sm" disabled={!agent || !path.trim() || state.busy || (signin !== null && !signinComplete(signin))} onClick={run}>
          {state.busy ? <Loader2 size={14} className="spin" /> : <PlugZap size={14} />} Test connection{agent ? ` from ${agent.name}` : ""}
        </button>
        {state.busy && <span className="faint small">The machine picks this up within its next check-in…</span>}
      </div>
      {err && <Notice tone="bad">{err}</Notice>}
      {job && job.state === "failed" && <Notice tone="bad">{job.error}</Notice>}
      {job && r && job.state !== "failed" && (
        <Notice tone={job.state === "warning" ? "warn" : "ok"}>
          <div className="stack tight">
            <div className="row" style={{ gap: 6 }}><CheckCircle2 size={15} /> {r.s3 ? `Object storage: ${r.note}.` : r.share ? "Signed in to the share and wrote a test file." : "Wrote a test file."}</div>
            <div className="small">
              {r.s3 ? (r.repository ? "A Fenrir-Backup repository is already there." : "") : r.repository ? "A Fenrir-Backup repository is already there." : r.exists ? "The folder exists." : "The folder will be created."}
              {r.free_bytes != null && r.total_bytes != null && <> Free space: {bytes(r.free_bytes)} of {bytes(r.total_bytes)}.</>}
            </div>
            {job.warnings.map((w, i) => <div key={i} className="small">{w}</div>)}
          </div>
        </Notice>
      )}
    </div>
  );
}

/** Repository card: how machines sign in to the share; change it. */
export function ShareSigninRow({ repo, agents, onSaved }: { repo: Repository; agents: Agent[]; onSaved: () => void }) {
  const [open, setOpen] = useState(false);
  if (!isSharePath(repo.path) && !repo.s3) return null;
  if (repo.s3) {
    return (
      <div className="row wrap" style={{ gap: 8 }}>
        <Network size={15} style={{ color: "var(--text-2)" }} />
        <span className="small">
          Object storage at <span className="mono">{repo.s3.endpoint}</span>, access key <span className="mono">{repo.share_user}</span>
          {" · "}{repo.s3.lock_mode ? <>Object Lock ({repo.s3.lock_mode}, {repo.s3.lock_days} days): backups cannot be deleted early</> : <>no Object Lock</>}
        </span>
        <button className="btn sm ghost" onClick={() => setOpen(true)}><KeyRound size={13} /> Change keys</button>
        {open && <ShareDialog repo={repo} agents={agents} onClose={() => setOpen(false)} onSaved={() => { setOpen(false); onSaved(); }} />}
      </div>
    );
  }
  const how = repo.share_auth === "password" ? <>signs in as <span className="mono">{repo.share_user}</span></> : repo.share_auth === "machine" ? <>uses each computer's account</> : <>no sign-in (the share must allow the machines as they are)</>;
  return (
    <div className="row wrap" style={{ gap: 8 }}>
      <Network size={15} style={{ color: "var(--text-2)" }} />
      <span className="small">Network share: {how}</span>
      <button className="btn sm ghost" onClick={() => setOpen(true)}><KeyRound size={13} /> Change sign-in</button>
      {open && <ShareDialog repo={repo} agents={agents} onClose={() => setOpen(false)} onSaved={() => { setOpen(false); onSaved(); }} />}
    </div>
  );
}

function ShareDialog({ repo, agents, onClose, onSaved }: { repo: Repository; agents: Agent[]; onClose: () => void; onSaved: () => void }) {
  const machines = agents.filter((a) => repo.agents.some((x) => x.id === a.id));
  const [s, setS] = useState<ShareSignin>(() => ({ ...signinFromDisplay(repo.share_user), mode: repo.share_auth === "machine" ? "machine" : "password" }));
  const [tester, setTester] = useState(machines.find((m) => m.online)?.id ?? machines[0]?.id ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const toast = useToast();
  const save = async () => {
    setBusy(true);
    setErr(null);
    try {
      const access = s.mode === "password" ? await Promise.all(machines.map(async (m) => ({ agent_id: m.id, sealed_share: await sealSignin(m, s) }))) : [];
      await api.post(`/api/repositories/${repo.id}/share`, { share_auth: s.mode, share_user: s.mode === "password" ? signinDisplay(s) : null, access });
      toast("ok", `Sign-in for ${repo.name} updated on ${machines.length} machine${machines.length === 1 ? "" : "s"}`);
      onSaved();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      wide
      title={repo.s3 ? `Access keys for ${repo.name}` : `Network sign-in for ${repo.name}`}
      sub={<span className="mono">{repo.path}</span>}
      onClose={onClose}
      foot={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy || !signinComplete(s)} onClick={save}>Save for all {machines.length} machine{machines.length === 1 ? "" : "s"}</button></>}
    >
      {err && <Notice tone="bad">{err}</Notice>}
      {repo.s3 ? (
        <div className="grid cols-2">
          <Field label="Access key ID"><input className="input mono" value={s.username} onChange={(e) => setS({ ...s, mode: "password", domain: "", username: e.target.value })} autoComplete="off" /></Field>
          <Field label="Secret access key" hint="Encrypted in this browser for each machine.">
            <input className="input mono" type="password" value={s.password} onChange={(e) => setS({ ...s, mode: "password", password: e.target.value })} autoComplete="new-password" />
          </Field>
        </div>
      ) : (
        <ShareFields value={s} onChange={setS} machines={machines} />
      )}
      {machines.length > 0 && (
        <Field label="Test from">
          <div className="row wrap" style={{ gap: 8 }}>
            <select className="input" style={{ width: "auto" }} value={tester} onChange={(e) => setTester(e.target.value)}>
              {machines.map((m) => <option key={m.id} value={m.id}>{m.name}{m.online ? "" : " (offline)"}</option>)}
            </select>
          </div>
        </Field>
      )}
      <TestConnection agent={machines.find((m) => m.id === tester)} path={repo.path} signin={s} s3={repo.s3} />
      <div className="faint small row" style={{ gap: 6 }}><XCircle size={13} /> {repo.s3 ? "Create the new keys at the storage provider first, then enter them here; remove the old ones afterwards." : "Changing the password here does not change it on the server or NAS; change it there first, then here."}</div>
    </Modal>
  );
}
