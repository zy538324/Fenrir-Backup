import { useState } from "react";
import { CalendarClock, Play, Plus, Trash2 } from "lucide-react";
import { api, type Agent, type AgentDetail, type BackupSettings, type JobKind, type Plan, type Schedule } from "../api";
import { DAY_NAMES, ago, jobWhat, scheduleText, until } from "../format";
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
            <thead><tr><th>Plan</th><th>Machine</th><th>Schedule</th><th>Last run</th><th>Next run</th><th>On</th><th /></tr></thead>
            <tbody>
              {plans.data.map((p) => (
                <tr key={p.id}>
                  <td><strong>{p.name}</strong><div className="faint small">{jobWhat(p.job)} → {p.repository_name}</div></td>
                  <td><Link to={`/machines/${p.agent_id}`}>{p.agent_name}</Link></td>
                  <td>{scheduleText(p.schedule)}</td>
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
  const [s, setS] = useState<BackupSettings>({ rate_limit_mib: 0, verify_sample_percent: 5 });
  const [err, setErr] = useState<string | null>(null);
  const repoId = repo || usable[0]?.id || "";

  const schedule: Schedule =
    mode === "daily" ? { type: "daily", time, days, utc_offset_minutes: -new Date().getTimezoneOffset() } : mode === "interval" ? { type: "interval", hours } : { type: "manual" };

  const save = async () => {
    if (!what) return;
    setErr(null);
    try {
      await api.post("/api/plans", { name, agent_id: agentId, repository_id: repoId, job: withSettings(what, s), schedule, enabled: true });
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
          <button className={mode === "interval" ? "on" : ""} onClick={() => setMode("interval")}>Every few hours</button>
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
          <div className="row"><input className="input" type="number" min={1} max={744} value={hours} onChange={(e) => setHours(Math.max(1, Number(e.target.value)))} style={{ width: 100 }} /> <span className="muted">hours</span></div>
        </Field>
      )}
      <div className="muted small">{scheduleText(schedule)} (your local time).</div>
      <Field label="Plan name"><input className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={60} /></Field>
      {agent && <OptionsPicker s={s} onChange={setS} windows={agent.os.family === "windows"} />}
    </Modal>
  );
}
