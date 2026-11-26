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
                {RESTORES.has(String((j.kind as { type?: string }).type)) && ["succeeded", "warning", "failed"].includes(j.state) && <Evidence id={j.id} />}
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

const RESTORES = new Set(["restore", "restore_files", "restore_application", "restore_kubernetes", "restore_saas"]);

type EvidenceResponse = { sha256: string; intact: boolean; evidence: { verified: boolean; rpoSeconds: number | null; rtoSeconds: number | null;
  recoveryPoint: string | null; outputs: unknown[]; verification: { mismatches?: number; chunksChecked?: number }[] } };

function secs(s: number): string {
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
}

/** Restore evidence (BDR-03): recovery point, RPO/RTO, what was written and its hashes, downloadable as JSON. */
function Evidence({ id }: { id: string }) {
  const [ev, setEv] = useState<EvidenceResponse | null>(null);
  const toast = useToast();
  const load = async () => {
    try {
      const r = await api.get<EvidenceResponse>(`/api/jobs/${id}/evidence`);
      setEv(r);
      const blob = new Blob([JSON.stringify(r, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `restore-evidence-${id}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e) {
      toast("bad", e instanceof Error ? e.message : String(e));
    }
  };
  const e = ev?.evidence;
  const checked = e?.verification.reduce((n, v) => n + (v.chunksChecked ?? 0), 0) ?? 0;
  return (
    <div>
      <button className="btn sm ghost" onClick={load}>Restore evidence</button>
      {e && <div className="faint">
        {e.verified ? "Verified" : "Not verified"}{checked ? ` · ${checked} chunks read back` : ` · ${e.outputs.length} output(s) hashed`}
        {e.rpoSeconds != null && ` · RPO ${secs(e.rpoSeconds)}`}{e.rtoSeconds != null && ` · RTO ${secs(e.rtoSeconds)}`}
        {!ev?.intact && <span style={{ color: "var(--bad)" }}> · record does not match its SHA-256</span>}
      </div>}
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
