import { useState } from "react";
import { MonitorSmartphone, PlusCircle, Search } from "lucide-react";
import type { Agent } from "../api";
import { ago, health, osLabel } from "../format";
import { Empty, Link, Loading, Notice, OsBadge, Pill, ProgressBar, useApi, useRoute } from "../ui";

const FILTERS = [
  ["all", "All"],
  ["attention", "Needs attention"],
  ["hyperv", "Hyper-V hosts"],
  ["offline", "Offline"],
] as const;

export default function MachinesPage() {
  const { data, error } = useApi<Agent[]>("/api/agents", 5000);
  const [q, setQ] = useState("");
  const [f, setF] = useState<(typeof FILTERS)[number][0]>("all");
  if (error && !data) return <div className="page"><Notice tone="bad">{error}</Notice></div>;
  if (!data) return <div className="page"><Loading /></div>;

  const shown = data.filter((a) => {
    const h = health(a);
    if (q && !`${a.name} ${a.hostname} ${a.os.name}`.toLowerCase().includes(q.toLowerCase())) return false;
    if (f === "attention") return h.tone === "bad" || h.tone === "warn" || !a.online;
    if (f === "hyperv") return a.role === "hyperv";
    if (f === "offline") return !a.online;
    return true;
  });

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Machines</h1>
          <div className="sub">{data.length} enrolled · {data.filter((a) => a.online).length} online</div>
        </div>
        <Link to="/add" className="btn primary right"><PlusCircle size={16} /> Add machines</Link>
      </div>
      {data.length === 0 ? (
        <div className="card">
          <Empty icon={<MonitorSmartphone size={26} />} title="No machines yet" action={<Link to="/add" className="btn primary">Add your first machine</Link>}>
            Download an installer for Windows, a Hyper-V host, Linux or macOS. Machines appear here as soon as the agent starts.
          </Empty>
        </div>
      ) : (
        <>
          <div className="row wrap">
            <div style={{ position: "relative", flex: "1 1 260px", maxWidth: 360 }}>
              <Search size={15} style={{ position: "absolute", left: 11, top: 11, color: "var(--text-3)" }} />
              <input className="input" style={{ paddingLeft: 34 }} placeholder="Search machines" value={q} onChange={(e) => setQ(e.target.value)} />
            </div>
            <div className="seg">
              {FILTERS.map(([k, label]) => (
                <button key={k} className={f === k ? "on" : ""} onClick={() => setF(k)}>{label}</button>
              ))}
            </div>
          </div>
          <div className="grid auto">
            {shown.map((a) => <MachineCard key={a.id} a={a} />)}
          </div>
          {shown.length === 0 && <div className="muted" style={{ textAlign: "center", padding: 30 }}>No machines match.</div>}
        </>
      )}
    </div>
  );
}

function MachineCard({ a }: { a: Agent }) {
  const { go } = useRoute();
  const h = health(a);
  const p = a.running_job?.progress;
  return (
    <div className="card machine" onClick={() => go(`/machines/${a.id}`)} role="link" tabIndex={0} onKeyDown={(e) => e.key === "Enter" && go(`/machines/${a.id}`)}>
      <div className="row">
        <OsBadge role={a.role} family={a.os.family} />
        <div className="grow">
          <div className="ellipsis" style={{ fontWeight: 650, fontSize: 15 }}>{a.name}</div>
          <div className="faint small ellipsis">{osLabel(a)}</div>
        </div>
      </div>
      {a.running_job ? (
        <div className="stack tight">
          <div className="row small"><span className="muted">{a.running_job.label}</span><span className="right faint">{p?.message}</span></div>
          <ProgressBar done={p?.done} total={p?.total} />
        </div>
      ) : (
        <dl className="kv">
          <dt>Last backup</dt>
          <dd>{a.last_backup ? ago(a.last_backup.at) : "never"}</dd>
          {a.role === "hyperv" ? <><dt>VMs</dt><dd>{a.vm_count}</dd></> : <><dt>Seen</dt><dd>{a.online ? "online" : ago(a.last_seen)}</dd></>}
        </dl>
      )}
      <div className="row">
        <Pill tone={h.tone} pulse={!!a.running_job}>{h.text}</Pill>
      </div>
    </div>
  );
}
