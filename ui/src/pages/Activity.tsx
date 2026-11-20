import { useState } from "react";
import { Activity as ActivityIcon, XCircle } from "lucide-react";
import { api, type AuditEntry, type Job } from "../api";
import { duration, jobWhat, when } from "../format";
import { Empty, Link, Loading, StatePill, useApi, useToast } from "../ui";

export default function ActivityPage() {
  const [tab, setTab] = useState<"jobs" | "audit">("jobs");
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Activity</h1>
          <div className="sub">Every job the machines ran, and every change made on this server.</div>
        </div>
      </div>
      <div className="tabs">
        <button className={tab === "jobs" ? "on" : ""} onClick={() => setTab("jobs")}>Jobs</button>
        <button className={tab === "audit" ? "on" : ""} onClick={() => setTab("audit")}>Audit log</button>
      </div>
      {tab === "jobs" ? <Jobs /> : <Audit />}
    </div>
  );
}

function Jobs() {
  const { data, reload } = useApi<Job[]>("/api/jobs?limit=300", 5000);
  const toast = useToast();
  if (!data) return <Loading />;
  if (data.length === 0) return <div className="card"><Empty icon={<ActivityIcon size={24} />} title="Nothing has run yet" /></div>;
  return (
    <div className="card table-wrap">
      <table className="table">
        <thead><tr><th>Machine</th><th>Job</th><th>Status</th><th>Started</th><th>Duration</th><th>Details</th></tr></thead>
        <tbody>
          {data.map((j) => (
            <tr key={j.id}>
              <td><Link to={`/machines/${j.agent_id}`}>{j.agent_name}</Link></td>
              <td><strong>{j.label}</strong><div className="faint small">{jobWhat(j.kind)}{j.repository_name ? ` → ${j.repository_name}` : ""}</div></td>
              <td><StatePill state={j.state} /></td>
              <td className="nowrap">{when(j.started ?? j.created)}</td>
              <td className="nowrap">{duration(j.started, j.finished)}</td>
              <td className="small" style={{ maxWidth: 420 }}>
                {j.error && <div style={{ color: "var(--bad)" }}>{j.error}</div>}
                {j.warnings.map((w, i) => <div key={i} style={{ color: "var(--warn)" }}>{w}</div>)}
                {(j.state === "queued" || j.state === "running" || j.state === "dispatched") && (
                  <button className="btn sm ghost" onClick={async () => { await api.post(`/api/jobs/${j.id}/cancel`); toast("ok", "Cancelling"); reload(); }}><XCircle size={13} /> Cancel</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Audit() {
  const { data } = useApi<AuditEntry[]>("/api/audit", 15000);
  if (!data) return <Loading />;
  return (
    <div className="card table-wrap">
      <table className="table">
        <thead><tr><th>When</th><th>Who</th><th>What</th><th>Details</th></tr></thead>
        <tbody>
          {data.map((e, i) => (
            <tr key={i}>
              <td className="nowrap">{when(e.at)}</td>
              <td>{e.actor.startsWith("agent:") ? <span className="faint">agent</span> : e.actor}</td>
              <td className="mono">{e.action}</td>
              <td className="small muted">{e.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
