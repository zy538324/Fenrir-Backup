import { useState } from "react";
import { CalendarClock, Play, Plus, Trash2 } from "lucide-react";
import { api, type Agent, type AgentDetail, type BackupSettings, type JobKind, type Plan, type Retention, type Schedule, type Standby } from "../api";
import { DAY_NAMES, RETENTION_PRESETS, ago, jobWhat, retentionText, scheduleText, until } from "../format";
import { Empty, Field, Link, Loading, Modal, Notice, Switch, useApi, useToast } from "../ui";
import { OptionsPicker, WhatPicker, defaultWhat, useRepos, withSettings } from "./Machine";

export default function PlansPage() {
  const plans = useApi<Plan[]>("/api/plans", 10000);
  const agents = useApi<Agent[]>("/api/agents");
  const [creating, setCreating] = useState(false);
  const toast = useToast();
  if (!plans.data || !agents.data) return <div className="page"><Loading /></div>;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Backup plans</h1>
          <div className="sub">What to back up, where to, and when.</div>
        </div>
        <button className="btn primary right" onClick={() => setCreating(true)} disabled={agents.data.length === 0}><Plus size={16} /> New plan</button>
      </div>
      {plans.data.length === 0 ? (
        <div className="card">
          <Empty icon={<CalendarClock size={26} />} title="No backup plans yet" action={agents.data.length ? <button className="btn primary" onClick={() => setCreating(true)}>Create a plan</button> : <Link to="/add" className="btn primary">Add a machine first</Link>}>
            A plan backs a machine up on a schedule, for example every weekday at 22:00. Machines that were off catch up once when they come back.
          </Empty>
        </div>
      ) : (
        <div className="card table-wrap">
          <table className="table">
            <thead><tr><th>Plan</th><th>Machine</th><th>Schedule</th><th>Keeps</th><th>Last run</th><th>Next run</th><th>On</th><th /></tr></thead>
            <tbody>
              {plans.data.map((p) => (
                <tr key={p.id}>
                  <td><strong>{p.name}</strong><div className="faint small">{jobWhat(p.job)} → {p.repository_name}</div></td>
                  <td><Link to={`/machines/${p.agent_id}`}>{p.agent_name}</Link></td>
                  <td>{scheduleText(p.schedule)}</td>
                  <td>
                    <select
                      className="input"
                      style={{ height: 30, fontSize: 12.5, width: "auto", maxWidth: 190 }}
                      value={presetOf(p.retention)}
                      title={retentionText(p.retention)}
                      onChange={async (e) => {
                        const pr = RETENTION_PRESETS.find((x) => x.id === e.target.value);
                        if (!pr) return;
                        await api.patch(`/api/plans/${p.id}`, { retention: pr.r });
                        toast("ok", `${p.name}: ${pr.text.toLowerCase()}`);
                        plans.reload();
                      }}
                    >
                      {RETENTION_PRESETS.map((x) => <option key={x.id} value={x.id}>{x.label}</option>)}
                      {presetOf(p.retention) === "custom" && <option value="custom">{retentionText(p.retention)}</option>}
                    </select>
                  </td>
                  <td className="nowrap">{ago(p.last_run)}</td>
                  <td className="nowrap">{p.enabled ? until(p.next_run) : <span className="faint">paused</span>}</td>
                  <td><Switch on={p.enabled} label={`Enable ${p.name}`} onChange={async (v) => { await api.patch(`/api/plans/${p.id}`, { enabled: v }); plans.reload(); }} /></td>
                  <td className="nowrap" style={{ textAlign: "right" }}>
                    <button className="btn sm" onClick={async () => { try { await api.post(`/api/plans/${p.id}/run`); toast("ok", `${p.name} started`); } catch (e) { toast("bad", (e as Error).message); } }}><Play size={13} /> Run now</button>{" "}
                    <button className="icon-btn" aria-label="Delete plan" onClick={async () => { if (confirm(`Delete the plan “${p.name}”? Existing backups are kept.`)) { await api.del(`/api/plans/${p.id}`); plans.reload(); } }}><Trash2 size={15} /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {creating && <PlanDialog agents={agents.data} onClose={() => setCreating(false)} onDone={() => { setCreating(false); plans.reload(); }} />}
    </div>
  );
}

function PlanDialog({ agents, onClose, onDone }: { agents: Agent[]; onClose: () => void; onDone: () => void }) {
  const [agentId, setAgentId] = useState(agents[0]?.id ?? "");
  const detail = useApi<AgentDetail>(agentId ? `/api/agents/${agentId}` : null);
  const agent = agents.find((a) => a.id === agentId)!;
  const { usable } = useRepos(agentId);
  const [repo, setRepo] = useState("");
  const [what, setWhat] = useState<JobKind | null>(defaultWhat(agent));
  const [name, setName] = useState("Nightly backup");
  const [mode, setMode] = useState<"daily" | "interval" | "manual">("daily");
  const [time, setTime] = useState("22:00");
  const [days, setDays] = useState<number[]>([]);
  const [hours, setHours] = useState(6);
  const [unit, setUnit] = useState<"hours" | "minutes">("hours");
  const [minutes, setMinutes] = useState(15);
  const [s, setS] = useState<BackupSettings>({ rate_limit_mib: 0, verify_sample_percent: 5 });
  const [retention, setRetention] = useState<Retention | null>(RETENTION_PRESETS[1].r);
  const [copyTo, setCopyTo] = useState("");
  const [scan, setScan] = useState(false);
  const [standby, setStandby] = useState<Standby | null>(null);
  const hosts = agents.filter((x) => x.capabilities.includes("restore_hyperv") || x.capabilities.includes("restore_vm_files"));
  const [err, setErr] = useState<string | null>(null);
  const repoId = repo || usable[0]?.id || "";

  const schedule: Schedule =
    mode === "daily" ? { type: "daily", time, days, utc_offset_minutes: -new Date().getTimezoneOffset() } : mode === "interval" ? (unit === "minutes" ? { type: "interval", hours: 0, minutes } : { type: "interval", hours }) : { type: "manual" };

  const save = async () => {
    if (!what) return;
    setErr(null);
    try {
      await api.post("/api/plans", { name, agent_id: agentId, repository_id: repoId, job: withSettings(what, s), schedule, enabled: true, retention, copy_to_repository_id: copyTo || null, scan_after_backup: scan, standby });
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  return (
    <Modal
      wide
      title="New backup plan"
      onClose={onClose}
      foot={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={!what || !repoId || !name.trim()} onClick={save}>Create plan</button></>}
    >
      {err && <Notice tone="bad">{err}</Notice>}
      <div className="grid cols-2">
        <Field label="Machine">
          <select className="input" value={agentId} onChange={(e) => { const a = agents.find((x) => x.id === e.target.value)!; setAgentId(a.id); setWhat(defaultWhat(a)); setRepo(""); }}>
            {agents.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
          </select>
        </Field>
        <Field label="Repository">
          {usable.length === 0 ? (
            <div className="muted small" style={{ paddingTop: 8 }}>No ready repository for this machine. <Link to="/repositories">Set one up</Link>.</div>
          ) : (
            <select className="input" value={repoId} onChange={(e) => setRepo(e.target.value)}>
              {usable.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
          )}
        </Field>
      </div>
      {agent && <WhatPicker agent={agent} inventory={detail.data?.inventory ?? null} value={what} onChange={setWhat} />}
      <Field label="When">
        <div className="seg" style={{ alignSelf: "flex-start" }}>
          <button className={mode === "daily" ? "on" : ""} onClick={() => setMode("daily")}>At a time of day</button>
          <button className={mode === "interval" ? "on" : ""} onClick={() => setMode("interval")}>Every few minutes or hours</button>
          <button className={mode === "manual" ? "on" : ""} onClick={() => setMode("manual")}>By hand only</button>
        </div>
      </Field>
      {mode === "daily" && (
        <div className="row wrap" style={{ gap: 16 }}>
          <Field label="Time"><input className="input" type="time" value={time} onChange={(e) => setTime(e.target.value)} style={{ width: 130 }} /></Field>
          <Field label="Days" hint="None selected means every day.">
            <div className="chips">
              {DAY_NAMES.map((d, i) => (
                <button key={d} className={`chip${days.includes(i) ? " on" : ""}`} onClick={() => setDays(days.includes(i) ? days.filter((x) => x !== i) : [...days, i].sort())}>{d}</button>
              ))}
            </div>
          </Field>
        </div>
      )}
      {mode === "interval" && (
        <Field label="Every">
          <div className="row">
            {unit === "hours"
              ? <input className="input" type="number" min={1} max={744} value={hours} onChange={(e) => setHours(Math.max(1, Number(e.target.value)))} style={{ width: 100 }} />
              : <input className="input" type="number" min={5} max={59} value={minutes} onChange={(e) => setMinutes(Math.min(59, Math.max(5, Number(e.target.value))))} style={{ width: 100 }} />}
            <select className="input" value={unit} onChange={(e) => setUnit(e.target.value as "hours" | "minutes")} style={{ width: 120 }}>
              <option value="minutes">minutes</option>
              <option value="hours">hours</option>
            </select>
          </div>
        </Field>
      )}
      {mode === "interval" && unit === "minutes" && (
        <Notice tone="info">Backups every few minutes keep data loss short. Each run reads the disk's used space again (only changed data is stored), so pick an interval longer than one backup takes: the next run waits for the previous one. The "Frequent" retention keeps one image per hour for a day.</Notice>
      )}
      <div className="muted small">{scheduleText(schedule)} (your local time).</div>
      <RetentionPicker value={retention} onChange={setRetention} />
      {usable.filter((r) => r.id !== repoId).length > 0 && (
        <Field label="Off-site copy" hint="After each backup, the machine copies it to this repository too, encrypted for it and verified there. The machine needs access to both.">
          <select className="input" value={copyTo} onChange={(e) => setCopyTo(e.target.value)}>
            <option value="">No copy</option>
            {usable.filter((r) => r.id !== repoId).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
          </select>
        </Field>
      )}
      {agent?.capabilities.includes("scan_images") && (
        <label className="check">
          <input type="checkbox" checked={scan} onChange={(e) => setScan(e.target.checked)} />
          <span>Scan each backup for malware<div className="faint small">With the YARA rules and hashes in Settings, on {agent.name} after each backup. A backup with findings raises an alert, and restoring it asks first.</div></span>
        </label>
      )}
      {what?.type !== "backup_files" && hosts.length > 0 && (
        <Field label="Standby VM" hint="After each backup, the newest one is restored as a VM on this host, replacing the previous standby (never one that is running). It must have access to the repository.">
          <div className="stack tight">
            <select className="input" value={standby?.agent_id ?? ""} onChange={(e) => {
              const h = hosts.find((x) => x.id === e.target.value);
              setStandby(h ? { agent_id: h.id, type: h.capabilities.includes("restore_hyperv") ? "hyperv_vm" : "vm_files", format: h.capabilities.includes("restore_hyperv") ? null : "qcow2", name: `${agent?.name ?? "machine"} standby`.replace(/[^A-Za-z0-9 ._-]/g, "-"), directory: h.os.family === "windows" ? "D:\\Standby" : "/var/lib/fenrir-standby" } : null);
            }}>
              <option value="">None</option>
              {hosts.map((h) => <option key={h.id} value={h.id}>{h.name}{h.capabilities.includes("restore_hyperv") ? " (Hyper-V)" : ""}</option>)}
            </select>
            {standby && (
              <div className="grid cols-2">
                {standby.type === "vm_files" && (
                  <select className="input" value={standby.format ?? "qcow2"} onChange={(e) => setStandby({ ...standby, format: e.target.value as "qcow2" | "vdi" | "vmdk" })}>
                    <option value="qcow2">QEMU/KVM (qcow2)</option><option value="vdi">VirtualBox (VDI)</option><option value="vmdk">VMware (VMDK)</option>
                  </select>
                )}
                <input className="input" value={standby.name} onChange={(e) => setStandby({ ...standby, name: e.target.value })} aria-label="Standby VM name" />
                <input className="input mono" value={standby.directory} onChange={(e) => setStandby({ ...standby, directory: e.target.value })} aria-label="Folder on the host" />
              </div>
            )}
          </div>
        </Field>
      )}
      <Field label="Plan name"><input className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={60} /></Field>
      {agent && <OptionsPicker s={s} onChange={setS} windows={agent.os.family === "windows"} />}
    </Modal>
  );
}

function presetOf(r: Retention | null): string {
  if (!r) return "all";
  const same = (a: Retention, b: Retention) =>
    (["keep_last", "keep_hourly", "keep_daily", "keep_weekly", "keep_monthly", "keep_yearly"] as const).every((k) => (a[k] ?? 0) === (b[k] ?? 0));
  return RETENTION_PRESETS.find((p) => p.r && same(p.r, r))?.id ?? "custom";
}

export function RetentionPicker({ value, onChange }: { value: Retention | null; onChange: (r: Retention | null) => void }) {
  const current = presetOf(value);
  const [custom, setCustom] = useState(current === "custom");
  const num = (k: keyof Retention, label: string) => (
    <label className="field" style={{ width: 92 }}>
      <span className="faint small">{label}</span>
      <input
        className="input"
        type="number"
        min={0}
        max={999}
        value={value?.[k] ?? 0}
        onChange={(e) => onChange({ ...(value ?? {}), [k]: Math.max(0, Number(e.target.value)) })}
      />
    </label>
  );
  return (
    <Field label="Keep backups" hint={value ? `Older images are deleted after each backup; space is reclaimed weekly. Never runs while a repository is on hold.` : "Nothing is ever deleted automatically. The repository will keep growing."}>
      <div className="chips">
        {RETENTION_PRESETS.map((p) => (
          <button key={p.id} className={`chip${!custom && current === p.id ? " on" : ""}`} title={p.text} onClick={() => { setCustom(false); onChange(p.r); }}>
            {p.label}
          </button>
        ))}
        <button className={`chip${custom ? " on" : ""}`} onClick={() => { setCustom(true); onChange(value ?? { keep_daily: 7 }); }}>Custom</button>
      </div>
      {!custom && <div className="muted small">{RETENTION_PRESETS.find((p) => p.id === current)?.text ?? retentionText(value)}</div>}
      {custom && (
        <div className="row wrap" style={{ gap: 10, marginTop: 4 }}>
          {num("keep_last", "Last")}
          {num("keep_hourly", "Hourly")}
          {num("keep_daily", "Daily")}
          {num("keep_weekly", "Weekly")}
          {num("keep_monthly", "Monthly")}
          {num("keep_yearly", "Yearly")}
        </div>
      )}
    </Field>
  );
}
