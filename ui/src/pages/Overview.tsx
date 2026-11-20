import { AlertTriangle, ArrowRight, CalendarClock, CheckCircle2, Database, HardDrive, MonitorSmartphone, PlusCircle, ShieldAlert, ShieldCheck, XCircle } from "lucide-react";
import type { Agent, Job, Overview, Repository } from "../api";
import { ago, bytes, health, jobTone, jobWhat, osLabel } from "../format";
import { Empty, Link, Loading, Notice, OsBadge, Pill, ProgressBar, StatePill, useApi, useRoute } from "../ui";

export default function OverviewPage() {
  const { data, error } = useApi<Overview>("/api/overview", 5000);
  if (error && !data) return <div className="page"><Notice tone="bad">{error}</Notice></div>;
  if (!data) return <div className="page"><Loading /></div>;

  const firstRun = data.machines.total === 0 || data.repositories === 0;
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Overview</h1>
          <div className="sub">{new Date().toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long" })}</div>
        </div>
        <Link to="/add" className="btn primary right">
          <PlusCircle size={16} /> Add machines
        </Link>
      </div>

      <Holds />
      {firstRun ? <GettingStarted ov={data} /> : <Hero ov={data} />}

      <div className="grid cols-4">
        <Stat icon={<MonitorSmartphone size={15} />} label="Machines" value={`${data.machines.online}/${data.machines.total}`} foot="online now" />
        <Stat
          icon={<CheckCircle2 size={15} />}
          label="Backups, last 24 h"
          value={String(data.last_24h.succeeded + data.last_24h.warning)}
          foot={data.last_24h.failed ? `${data.last_24h.failed} failed` : "none failed"}
          tone={data.last_24h.failed ? "bad" : undefined}
        />
        <Stat icon={<ShieldCheck size={15} />} label="Data protected" value={bytes(data.storage.protected_bytes)} foot={`${data.storage.images} images kept`} />
        <Stat icon={<HardDrive size={15} />} label="Storage used" value={bytes(data.storage.stored_bytes)} foot="after deduplication and compression" />
      </div>

      <div className="grid cols-2" style={{ alignItems: "start" }}>
        <MachinesCard agents={data.agents} />
        <RecentCard jobs={data.recent_jobs} />
      </div>
    </div>
  );
}

function Stat({ icon, label, value, foot, tone }: { icon: React.ReactNode; label: string; value: string; foot: string; tone?: "bad" }) {
  return (
    <div className="card stat">
      <div className="stat-label">{icon}{label}</div>
      <div className="stat-value" style={tone === "bad" ? { color: "var(--bad)" } : undefined}>{value}</div>
      <div className="stat-foot">{foot}</div>
    </div>
  );
}

function Hero({ ov }: { ov: Overview }) {
  const failing = ov.agents.filter((a) => health(a).tone === "bad").length;
  const attention = ov.machines.attention;
  const [tone, Icon, title, text] =
    failing > 0
      ? (["bad", XCircle, `${failing} machine${failing === 1 ? "" : "s"} failed to back up`, "Open the machine to see why. The previous good image is still available."] as const)
      : attention > 0
        ? (["warn", ShieldAlert, `${attention} machine${attention === 1 ? " needs" : "s need"} attention`, "Offline, overdue or never backed up. Everything else is protected."] as const)
        : (["ok", ShieldCheck, "Everything is protected", `${ov.machines.total} machine${ov.machines.total === 1 ? "" : "s"} backed up within the last three days.`] as const);
  return (
    <div className="hero">
      <div className={`hero-icon ${tone}`}><Icon size={26} /></div>
      <div className="grow">
        <h2>{title}</h2>
        <div className="muted" style={{ marginTop: 4 }}>{text}</div>
      </div>
      {ov.running > 0 && <Pill tone="info" pulse>{ov.running} job{ov.running === 1 ? "" : "s"} running</Pill>}
    </div>
  );
}

function GettingStarted({ ov }: { ov: Overview }) {
  const steps = [
    { done: ov.machines.total > 0, title: "Add your first machine", text: "Download the installer for Windows, a Hyper-V host, Linux or macOS.", to: "/add", icon: <PlusCircle size={18} /> },
    { done: ov.repositories > 0, title: "Create a repository", text: "Choose where backups are stored: a NAS share, a USB disk or a backup server folder.", to: "/repositories", icon: <Database size={18} /> },
    { done: ov.plans > 0, title: "Schedule backups", text: "Pick what to protect and when. Fenrir-Backup does the rest.", to: "/plans", icon: <CalendarClock size={18} /> },
  ];
  return (
    <div className="card">
      <div className="card-head">
        <h2>Get started in three steps</h2>
      </div>
      <div className="grid cols-3" style={{ padding: 16 }}>
        {steps.map((s, i) => (
          <Link key={i} to={s.to} className="card card-pad" >
            <div className="stack tight">
              <div className="row">
                <div className={`hero-icon ${s.done ? "ok" : "info"}`} style={{ width: 36, height: 36, borderRadius: 10 }}>{s.done ? <CheckCircle2 size={18} /> : s.icon}</div>
                <span className="faint small">Step {i + 1}</span>
              </div>
              <h3 style={{ color: "var(--text)" }}>{s.title}</h3>
              <div className="muted small">{s.text}</div>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}

function MachinesCard({ agents }: { agents: Agent[] }) {
  const { go } = useRoute();
  const sorted = [...agents].sort((a, b) => order(health(a).tone) - order(health(b).tone)).slice(0, 8);
  return (
    <div className="card">
      <div className="card-head">
        <h2>Machines</h2>
        <Link to="/machines" className="right small">View all <ArrowRight size={13} style={{ verticalAlign: -2 }} /></Link>
      </div>
      {sorted.length === 0 ? (
        <Empty icon={<MonitorSmartphone size={24} />} title="No machines yet">Add a machine and it appears here within a minute.</Empty>
      ) : (
        <div className="timeline">
          {sorted.map((a) => {
            const h = health(a);
            return (
              <div key={a.id} className="tl-item" style={{ cursor: "pointer" }} onClick={() => go(`/machines/${a.id}`)}>
                <OsBadge role={a.role} family={a.os.family} size={17} />
                <div className="grow">
                  <div className="ellipsis" style={{ fontWeight: 600 }}>{a.name}</div>
                  {a.running_job ? (
                    <div style={{ marginTop: 6 }}><ProgressBar done={a.running_job.progress?.done} total={a.running_job.progress?.total} /></div>
                  ) : (
                    <div className="faint small ellipsis">{osLabel(a)} · last backup {ago(a.last_backup?.at)}</div>
                  )}
                </div>
                <Pill tone={h.tone} pulse={!!a.running_job}>{h.text}</Pill>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function order(t: string) {
  return { bad: 0, warn: 1, info: 2, neutral: 3, ok: 4 }[t] ?? 5;
}

function RecentCard({ jobs }: { jobs: Job[] }) {
  return (
    <div className="card">
      <div className="card-head">
        <h2>Recent activity</h2>
        <Link to="/activity" className="right small">All activity <ArrowRight size={13} style={{ verticalAlign: -2 }} /></Link>
      </div>
      {jobs.length === 0 ? (
        <Empty icon={<CalendarClock size={24} />} title="Nothing has run yet">Backups, verifications and repository changes show up here.</Empty>
      ) : (
        <div className="timeline">
          {jobs.map((j) => (
            <div key={j.id} className="tl-item">
              <div className={`tl-icon ${jobTone(j.state)}`}>
                {j.state === "failed" ? <XCircle size={16} /> : j.state === "warning" ? <AlertTriangle size={16} /> : <CheckCircle2 size={16} />}
              </div>
              <div className="grow">
                <div className="ellipsis"><strong>{j.agent_name}</strong> <span className="muted">· {j.label}</span></div>
                <div className="faint small ellipsis">{j.error ?? jobWhat(j.kind)} · {ago(j.finished ?? j.created)}</div>
              </div>
              <StatePill state={j.state} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Holds() {
  const { data } = useApi<Repository[]>("/api/repositories", 15000);
  const held = (data ?? []).filter((r) => r.hold);
  if (held.length === 0) return null;
  return (
    <>
      {held.map((r) => (
        <Link key={r.id} to="/repositories" className="hero" >
          <div className="hero-icon bad"><ShieldAlert size={26} /></div>
          <div className="grow">
            <h2 style={{ color: "var(--text)" }}>{r.name}: deletions on hold</h2>
            <div className="muted" style={{ marginTop: 4 }}>{r.hold_reason}</div>
          </div>
          <span className="btn">Review</span>
        </Link>
      ))}
    </>
  );
}
