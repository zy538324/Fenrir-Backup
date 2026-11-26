// Actions on one backup: malware scans and their results, legal hold, and
// restoring one SQL Server or Exchange database.
import { useState } from "react";
import { Database, Gavel, ShieldAlert, ShieldCheck } from "lucide-react";
import { api, guardInfected, type Agent, type Image } from "../api";
import { bytes, when } from "../format";
import { Field, Loading, Modal, Notice, Pill, useApi, useToast } from "../ui";

interface Scan {
  id: number;
  at: number;
  state: "clean" | "infected" | "incomplete";
  files_scanned: number;
  bytes_scanned: number;
  findings: { volume: string; path: string; size: number; sha256: string; detections: { kind: string; name: string }[] }[];
  summary: { volumes_scanned?: string[]; volumes_skipped?: string[]; rule_errors?: string[]; error?: string; rules_used?: number; indicators_used?: number };
  agent_name: string | null;
}

/** The latest scan of a backup, as a pill that opens the scan dialog. */
export function ScanPill({ image, onClick }: { image: Image; onClick: () => void }) {
  const s = image.last_scan;
  const pill = !s
    ? <span className="faint small">not scanned</span>
    : s.state === "infected"
      ? <Pill tone="bad">{s.findings} infected</Pill>
      : s.state === "clean"
        ? <Pill tone="ok">Clean</Pill>
        : <Pill tone="warn">Incomplete</Pill>;
  return <button className="link-btn" onClick={onClick} title="Malware scans of this backup">{pill}</button>;
}

export function ScanDialog({ image, onClose }: { image: Image; onClose: () => void }) {
  const scans = useApi<Scan[]>(`/api/images/${image.image_id}/scans`, 5000);
  const [all, setAll] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const toast = useToast();
  const start = async () => {
    setBusy(true);
    setErr(null);
    try {
      await api.post(`/api/images/${image.image_id}/scan`, { all_files: all });
      toast("ok", "Scan started: the result appears here when it finishes");
      scans.reload();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      wide
      title={`Malware scans of ${image.vm_name ?? image.hostname}`}
      sub={`Backup from ${when(image.created)}`}
      onClose={onClose}
      foot={<><button className="btn" onClick={onClose}>Close</button><button className="btn primary" disabled={busy} onClick={start}><ShieldCheck size={15} /> Scan now</button></>}
    >
      {err && <Notice tone="bad">{err}</Notice>}
      <div className="muted small">
        A machine with access to the repository reads the files inside the backup and checks them against the YARA rules and known-bad hashes in Settings. File contents never leave that machine; only findings are reported.
      </div>
      <label className="check"><input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} /> <span>Every file<div className="faint small">Otherwise programs, libraries, scripts and macro documents only (much faster).</div></span></label>
      {!scans.data ? <Loading /> : scans.data.length === 0 ? <div className="muted">Not scanned yet.</div> : scans.data.map((s) => (
        <div key={s.id} className="card" style={{ padding: 12 }}>
          <div className="row" style={{ gap: 8 }}>
            {s.state === "infected" ? <ShieldAlert size={16} color="var(--bad)" /> : <ShieldCheck size={16} />}
            <strong>{s.state === "infected" ? `${s.findings.length} infected file${s.findings.length === 1 ? "" : "s"}` : s.state === "clean" ? "Clean" : "Incomplete"}</strong>
            <span className="faint small">{when(s.at)} on {s.agent_name ?? "a machine"} · {s.files_scanned} files, {bytes(s.bytes_scanned)}</span>
          </div>
          {s.summary.error && <div className="small" style={{ color: "var(--bad)" }}>{s.summary.error}</div>}
          {(s.summary.volumes_skipped ?? []).map((v, i) => <div key={i} className="faint small">Skipped: {v}</div>)}
          {(s.summary.rule_errors ?? []).map((v, i) => <div key={i} className="small" style={{ color: "var(--warn)" }}>Rule not used: {v}</div>)}
          {s.findings.slice(0, 50).map((f, i) => (
            <div key={i} className="small mono" style={{ marginTop: 4 }}>{f.volume} {f.path} <span className="faint">({f.detections.map((d) => d.name).join(", ")})</span></div>
          ))}
        </div>
      ))}
    </Modal>
  );
}

export function LegalHoldDialog({ image, onClose, onDone }: { image: Image; onClose: () => void; onDone: () => void }) {
  const held = image.legal_hold;
  const [reason, setReason] = useState("");
  const [password, setPassword] = useState("");
  const [machine, setMachine] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const go = async () => {
    setBusy(true);
    setErr(null);
    try {
      if (held) await api.post(`/api/images/${image.image_id}/legal-hold`, { hold: false, password });
      else if (machine) await api.post("/api/legal-hold/machine", { machine_id: image.machine_id, reason });
      else await api.post(`/api/images/${image.image_id}/legal-hold`, { hold: true, reason });
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={held ? "Release legal hold" : "Legal hold"}
      onClose={onClose}
      foot={<><button className="btn" onClick={onClose}>Cancel</button><button className={`btn ${held ? "danger solid" : "primary"}`} disabled={busy || (held ? !password : reason.trim().length < 3)} onClick={go}><Gavel size={15} /> {held ? "Release" : "Hold"}</button></>}
    >
      {err && <Notice tone="bad">{err}</Notice>}
      {held ? (
        <>
          <div>Held since {when(held.at)} by {held.by}: {held.reason}</div>
          <div className="muted small">Once released, retention may delete this backup. Releases are recorded in the audit log.</div>
          <Field label="Your password"><input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" /></Field>
        </>
      ) : (
        <>
          <div className="muted small">A held backup is never deleted by retention until the hold is released (with a password). Machines apply retention, so older agents are not sent retention while backups are held.</div>
          <Field label="Reason" hint="A case or matter reference; 3 to 500 characters."><input className="input" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} /></Field>
          <label className="check"><input type="checkbox" checked={machine} onChange={(e) => setMachine(e.target.checked)} /> <span>Every current backup of {image.vm_name ?? image.hostname}<div className="faint small">Backups taken later are not held.</div></span></label>
        </>
      )}
    </Modal>
  );
}

export function AppRestoreDialog({ image, onClose }: { image: Image; onClose: () => void }) {
  const agents = useApi<Agent[]>("/api/agents");
  const apps = (image.applications ?? []).filter((a) => a.included && (a.file_sets ?? 0) > 0);
  const able = (agents.data ?? []).filter((a) => a.capabilities.includes("restore_apps"));
  const [component, setComponent] = useState(apps[0]?.component ?? "");
  const [agentId, setAgentId] = useState("");
  const [directory, setDirectory] = useState("D:\\Restores");
  const [attach, setAttach] = useState("");
  const [instance, setInstance] = useState("");
  const [source, setSource] = useState("");
  const [target, setTarget] = useState("");
  const [folder, setFolder] = useState(`Restored ${new Date().toISOString().slice(0, 10)}`);
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const toast = useToast();
  const app = apps.find((a) => a.component === component);
  const sql = app?.writer === "SqlServerWriter";
  const exchange = /exchange/i.test(app?.writer ?? "");
  const mailbox = exchange && source.trim() !== "";
  const confirmed = !mailbox || (target.trim() !== "" && confirm.trim().toLowerCase() === target.trim().toLowerCase());
  const agent = able.find((a) => a.id === agentId) ?? able.find((a) => a.id === image.agent_id) ?? able[0];
  const go = async () => {
    if (!agent) return;
    setBusy(true);
    setErr(null);
    try {
      const r = await guardInfected((allow_infected) => api.post(`/api/images/${image.image_id}/restore-app`, {
        agent_id: agent.id, component, directory: directory.trim(), attach_as: sql && attach.trim() ? attach.trim() : null, sql_instance: instance.trim(), allow_infected,
        mailbox: mailbox ? { source: source.trim(), target: target.trim(), folder: folder.trim(), confirm: confirm.trim() } : null,
      }));
      if (r === null) return;
      toast("ok", `Restoring ${app?.caption || component} on ${agent.name}`);
      onClose();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      wide
      title="Restore one database"
      sub={`${image.vm_name ?? image.hostname}, ${when(image.created)}`}
      onClose={onClose}
      foot={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy || !agent || !component || !directory.trim() || !confirmed} onClick={go}><Database size={15} /> {mailbox ? "Restore mailbox" : "Restore"}</button></>}
    >
      {err && <Notice tone="bad">{err}</Notice>}
      {apps.length === 0 ? <Notice tone="warn">This backup does not list its databases' files (taken by an older agent): restore the volume instead.</Notice> : (
        <>
          <Field label="Database">
            <select className="input" value={component} onChange={(e) => setComponent(e.target.value)}>
              {apps.map((a) => <option key={a.component} value={a.component}>{a.caption || a.component} ({a.writer === "SqlServerWriter" ? "SQL Server" : a.writer.replace(/ Writer$/, "")})</option>)}
            </select>
          </Field>
          <Field label="On" hint="A Windows machine with access to the repository.">
            {able.length === 0 ? <div className="muted small">No machine can restore application data yet (Windows, up-to-date agent).</div> : (
              <select className="input" value={agent?.id} onChange={(e) => setAgentId(e.target.value)}>
                {able.map((a) => <option key={a.id} value={a.id}>{a.name}{a.online ? "" : " (offline)"}</option>)}
              </select>
            )}
          </Field>
          <Field label="Into the folder" hint="Its files are written to a new folder here; nothing existing is replaced."><input className="input mono" value={directory} onChange={(e) => setDirectory(e.target.value)} /></Field>
          {sql && (
            <div className="grid cols-2">
              <Field label="Attach as" hint="Optional: attach the files to SQL Server under this new name."><input className="input" value={attach} onChange={(e) => setAttach(e.target.value)} placeholder="sales_restored" maxLength={128} /></Field>
              <Field label="SQL Server instance" hint="Blank for the default instance."><input className="input" value={instance} onChange={(e) => setInstance(e.target.value)} placeholder={"SERVER\\INSTANCE"} /></Field>
            </div>
          )}
          {exchange && (
            <>
              <div className="muted small">Optional: restore one mailbox unattended. The agent replays the logs, mounts the files as a recovery database on this Exchange server, restores the mailbox, then removes the recovery database. The machine must be an Exchange Mailbox server and the agent's account needs the Mailbox Import Export role. Leave the mailbox blank to only restore the files and a script.</div>
              <div className="grid cols-2">
                <Field label="Mailbox in the backup" hint="Display name or mailbox GUID."><input className="input" value={source} onChange={(e) => setSource(e.target.value)} placeholder="Anna Smith" maxLength={256} /></Field>
                <Field label="Restore into mailbox" hint="A live mailbox: items are added to it."><input className="input" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="anna@example.com" maxLength={320} /></Field>
                <Field label="Under the folder" hint="Blank merges items into their original folders."><input className="input" value={folder} onChange={(e) => setFolder(e.target.value)} maxLength={255} /></Field>
                {mailbox && <Field label="Type the target mailbox to confirm"><input className="input" value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder={target} /></Field>}
              </div>
            </>
          )}
        </>
      )}
    </Modal>
  );
}
