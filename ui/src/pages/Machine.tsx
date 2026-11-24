import { useMemo, useState } from "react";
import { ArrowLeft, CalendarClock, Database, FolderOpen, Gavel, HardDrive, Layers, LifeBuoy, Pencil, Play, Rocket, RotateCcw, ShieldCheck, Trash2, XCircle } from "lucide-react";
import { RestoreDialog } from "./Restore";
import { FileBrowser } from "./Files";
import { AppRestoreDialog, LegalHoldDialog, ScanDialog, ScanPill } from "./ImageActions";
import { BootCheckDialog, BootPill, BootResultDialog, RunningVmsCard } from "./Boot";
import { api, type Agent, type AgentDetail, type BackupSettings, type Image, type ImageApplication, type Inventory, type JobKind, type Repository, type Vm } from "../api";
import { ago, bytes, consistencyLabel, duration, health, jobWhat, osLabel, scheduleText, until, when, progressDetail } from "../format";
import { Empty, Field, Link, Loading, Modal, Notice, OsBadge, Pill, ProgressBar, StatePill, useApi, useRoute, useToast } from "../ui";

export default function MachinePage({ id }: { id: string }) {
  const { data, error, reload } = useApi<AgentDetail>(`/api/agents/${id}`, 4000);
  const [tab, setTab] = useState<"overview" | "backups" | "activity">("overview");
  const [dialog, setDialog] = useState<null | "backup" | "verify" | "rename" | "remove">(null);
  const [preselect, setPreselect] = useState<string[]>([]);
  const { go } = useRoute();
  const toast = useToast();

  if (error && !data) return <div className="page"><Notice tone="bad">{error}</Notice></div>;
  if (!data) return <div className="page"><Loading /></div>;
  const a = data.agent;
  const h = health(a);
  const inv = data.inventory;
  const canBackup = a.capabilities.some((c) => c.startsWith("backup_"));
  const isRecovery = a.role === "recovery";

  return (
    <div className="page">
      <Link to="/machines" className="small row" ><ArrowLeft size={14} /> Machines</Link>
      <div className="page-head">
        <OsBadge role={a.role} family={a.os.family} size={24} />
        <div className="grow">
          <div className="row">
            <h1 className="ellipsis">{a.name}</h1>
            <button className="icon-btn" aria-label="Rename" onClick={() => setDialog("rename")}><Pencil size={15} /></button>
          </div>
          <div className="sub row wrap" style={{ gap: 8 }}>
            <Pill tone={h.tone} pulse={!!a.running_job}>{h.text}</Pill>
            <span>{osLabel(a)}</span>
            <span className="faint">· {a.online ? "online" : `last seen ${ago(a.last_seen)}`}</span>
          </div>
        </div>
        {!isRecovery && <div className="row">
          <button className="btn" onClick={() => setDialog("verify")} disabled={!!a.running_job || data.repositories.length === 0}>
            <ShieldCheck size={16} /> Verify
          </button>
          <button className="btn primary" onClick={() => { setPreselect([]); setDialog("backup"); }} disabled={!canBackup || !!a.running_job}>
            <Play size={16} /> Back up now
          </button>
        </div>}
      </div>

      {a.running_job && <RunningCard agent={a} onCancel={async () => { await api.post(`/api/jobs/${a.running_job!.id}/cancel`); toast("ok", "Cancelling…"); reload(); }} />}
      {inv?.notes.map((n, i) => <Notice key={i} tone="info">{n}</Notice>)}
      {isRecovery && <RecoveryCard agent={a} inv={inv} />}
      {!isRecovery && a.capabilities.includes("local_recovery") && <LocalRecoveryCard agent={a} inv={inv} onChange={reload} />}
      {!isRecovery && data.repositories.length === 0 && (
        <Notice tone="warn">
          This machine has no repository to back up to yet. <Link to="/repositories">Create one or grant access</Link>.
        </Notice>
      )}

      <div className="tabs">
        <button className={tab === "overview" ? "on" : ""} onClick={() => setTab("overview")}>Overview</button>
        <button className={tab === "backups" ? "on" : ""} onClick={() => setTab("backups")}>Backups ({data.images.length})</button>
        <button className={tab === "activity" ? "on" : ""} onClick={() => setTab("activity")}>Activity</button>
      </div>

      {tab === "overview" && (
        <div className="grid" style={{ gridTemplateColumns: "minmax(0, 2fr) minmax(260px, 1fr)", alignItems: "start" }}>
          <div className="stack">
            <RunningVmsCard agent={a} vms={inv?.running_vms ?? []} images={data.images} />
            {a.role === "hyperv" && <VmTable vms={inv?.vms ?? []} disabled={!!a.running_job || data.repositories.length === 0} onBackup={(ids) => { setPreselect(ids); setDialog("backup"); }} />}
            {inv && inv.disks.length > 0 && <DiskTable inv={inv} />}
            <PlansCard plans={data.plans} />
          </div>
          <div className="card card-body">
            <h3 style={{ marginBottom: 12 }}>Details</h3>
            <dl className="kv">
              <dt>Hostname</dt><dd>{a.hostname}</dd>
              <dt>Role</dt><dd>{a.role === "hyperv" ? "Hyper-V host" : a.role === "server" ? "Server" : a.role === "recovery" ? "Recovery session (restores only)" : "Workstation"}</dd>
              <dt>System</dt><dd>{a.os.name} {a.os.version}</dd>
              <dt>Architecture</dt><dd>{a.os.arch}</dd>
              <dt>Agent</dt><dd>{a.agent_version}</dd>
              <dt>Enrolled</dt><dd>{when(a.enrolled)}</dd>
              <dt>Repositories</dt><dd>{data.repositories.map((r) => r.name).join(", ") || "none"}</dd>
              {(data.inventory?.other_backup ?? []).length > 0 && (
                <><dt>Other backup software</dt><dd title="Installed programs and services whose names say they back up or replicate, and the system's own backup when set up">{data.inventory!.other_backup!.join(", ")}</dd></>
              )}
            </dl>
            <div style={{ borderTop: "1px solid var(--border)", margin: "16px 0 12px" }} />
            <button className="btn danger sm" onClick={() => setDialog("remove")}><Trash2 size={14} /> Remove machine</button>
          </div>
        </div>
      )}

      {tab === "backups" && <ImagesTable detail={data} onChange={reload} />}
      {tab === "activity" && <JobsTable detail={data} />}

      {dialog === "backup" && <BackupDialog agent={a} inventory={inv} preselectVms={preselect} onClose={() => setDialog(null)} onDone={() => { setDialog(null); reload(); }} />}
      {dialog === "verify" && <VerifyDialog agent={a} onClose={() => setDialog(null)} onDone={() => { setDialog(null); reload(); }} />}
      {dialog === "rename" && <RenameDialog agent={a} onClose={() => setDialog(null)} onDone={() => { setDialog(null); reload(); }} />}
      {dialog === "remove" && (
        <Modal
          title={`Remove ${a.name}?`}
          onClose={() => setDialog(null)}
          foot={
            <>
              <button className="btn" onClick={() => setDialog(null)}>Keep it</button>
              <button className="btn danger solid" onClick={async () => { await api.del(`/api/agents/${a.id}`); toast("ok", `${a.name} removed`); go("/machines"); }}>
                Remove machine
              </button>
            </>
          }
        >
          <div>The agent on this machine is locked out, its plans are paused and its repository access is withdrawn. Backups already stored are kept and can still be restored.</div>
          <div className="muted small">To remove the agent software too, run the uninstaller from the Add machines page on the machine.</div>
        </Modal>
      )}
    </div>
  );
}

function RunningCard({ agent, onCancel }: { agent: Agent; onCancel: () => void }) {
  const j = agent.running_job!;
  const p = j.progress;
  const pct = p && p.total ? Math.round((100 * p.done) / p.total) : null;
  return (
    <div className="card card-body stack tight">
      <div className="row">
        <Pill tone="info" pulse>{j.label}</Pill>
        <span className="muted small ellipsis grow">{p ? `${p.phase}${p.message ? ` · ${p.message}` : ""}` : "starting…"}</span>
        {pct !== null && <strong>{pct}%</strong>}
        <button className="btn sm ghost" onClick={onCancel}><XCircle size={14} /> Cancel</button>
      </div>
      <ProgressBar done={p?.done} total={p?.total} />
      {p && p.total > 0 && <div className="faint small">{bytes(p.done)} of {bytes(p.total)}{progressDetail(p) && ` · ${progressDetail(p)}`}</div>}
    </div>
  );
}

function VmTable({ vms, disabled, onBackup }: { vms: Vm[]; disabled: boolean; onBackup: (ids: string[]) => void }) {
  const [sel, setSel] = useState<string[]>([]);
  const all = sel.length === vms.length && vms.length > 0;
  return (
    <div className="card">
      <div className="card-head">
        <Layers size={17} />
        <h2>Virtual machines</h2>
        <span className="faint small">{vms.length} on this host</span>
        <button className="btn sm right" disabled={disabled || sel.length === 0} onClick={() => onBackup(sel)}>
          <Play size={14} /> Back up {sel.length ? `${sel.length} selected` : "selected"}
        </button>
      </div>
      {vms.length === 0 ? (
        <Empty icon={<Layers size={24} />} title="No VMs reported yet">The agent lists the host's VMs every few minutes.</Empty>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 36 }}><input type="checkbox" aria-label="Select all" checked={all} onChange={() => setSel(all ? [] : vms.map((v) => v.id))} /></th>
                <th>Name</th><th>State</th><th>Generation</th><th>Disks</th><th style={{ textAlign: "right" }}>Size on host</th>
              </tr>
            </thead>
            <tbody>
              {vms.map((v) => (
                <tr key={v.id} className="clickable" onClick={() => setSel(sel.includes(v.id) ? sel.filter((x) => x !== v.id) : [...sel, v.id])}>
                  <td><input type="checkbox" aria-label={`Select ${v.name}`} checked={sel.includes(v.id)} readOnly /></td>
                  <td><strong>{v.name}</strong></td>
                  <td><Pill tone={v.state === "running" ? "ok" : "neutral"}>{v.state}</Pill></td>
                  <td>Gen {v.generation} <span className="faint small">({v.generation === 2 ? "UEFI" : "BIOS"})</span></td>
                  <td>{v.disks.length}</td>
                  <td style={{ textAlign: "right" }}>{bytes(v.disk_bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/** A machine booted from recovery media: choose an image to put on it. */
/** The machine's own recovery partition (docs/design/local-recovery.md). */
function LocalRecoveryCard({ agent, inv, onChange }: { agent: Agent; inv: Inventory | null; onChange: () => void }) {
  const lr = inv?.local_recovery ?? null;
  const toast = useToast();
  const [dialog, setDialog] = useState<"install" | "remove" | null>(null);
  const [confirm, setConfirm] = useState("");
  const [autoStart, setAutoStart] = useState(false);
  const [size, setSize] = useState("");
  const [busy, setBusy] = useState(false);
  const send = async (action: "install" | "refresh" | "remove") => {
    setBusy(true);
    try {
      await api.post(`/api/agents/${agent.id}/local-recovery`, { action, confirm, auto_start: action === "refresh" ? lr?.auto_start ?? false : autoStart, size_mb: Number(size) || 0 });
      toast("ok", action === "install" ? "Installing local recovery: follow it under Activity" : action === "refresh" ? "Rebuilding the recovery image" : "Removing local recovery");
      setDialog(null);
      setConfirm("");
      onChange();
    } catch (e) {
      toast("bad", (e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="card">
      <div className="card-head"><LifeBuoy size={17} /><h2>Local recovery</h2></div>
      <div className="card-body stack">
        {lr ? (
          <div className="small">
            <Pill tone="ok">Installed</Pill> A {bytes(lr.size)} recovery partition (disk {lr.disk}, partition {lr.partition}), built {ago(lr.built_unix)} with agent {lr.agent_version}.
            {" "}If Windows does not start, choose <b>Fenrir Recovery</b> in the boot menu{lr.auto_start ? " (it also starts by itself when Windows fails to start)" : ""}; the machine then appears under Machines as a recovery session to restore it from its backups.
            {lr.expires > 0 && <> Its enrolment code is renewed automatically (now valid until {when(lr.expires)}).</>}
          </div>
        ) : (
          <div className="muted small">
            A small recovery partition on this machine with its own boot menu entry: if Windows no longer starts, start <b>Fenrir Recovery</b> from the boot menu and restore the machine from its backups, onto the same disk or a new one, without recovery media. Built from this machine's own Windows Recovery Environment with its network and storage drivers. About 1 GB is taken from C:.
          </div>
        )}
        <div className="row">
          {!lr && <button className="btn" disabled={!agent.online || !!agent.running_job} onClick={() => setDialog("install")}><LifeBuoy size={15} /> Install</button>}
          {lr && <button className="btn" disabled={!agent.online || !!agent.running_job || busy} onClick={() => send("refresh")}><RotateCcw size={15} /> Rebuild now</button>}
          {lr && <button className="btn danger" disabled={!agent.online || !!agent.running_job} onClick={() => setDialog("remove")}><Trash2 size={15} /> Remove</button>}
        </div>
      </div>
      {dialog && (
        <Modal title={dialog === "install" ? "Install local recovery" : "Remove local recovery"} onClose={() => setDialog(null)}
          foot={<button className={`btn ${dialog === "remove" ? "danger" : "primary"}`} disabled={busy || confirm.trim().toLowerCase() !== agent.hostname.toLowerCase()} onClick={() => send(dialog)}>{dialog === "install" ? "Install" : "Remove"}</button>}>
          <div className="stack">
            {dialog === "install" ? (
              <>
                <Notice tone="warn">This shrinks C: on {agent.name} and creates a recovery partition after it, then adds <b>Fenrir Recovery</b> to the boot menu. Make sure a recent backup exists first.</Notice>
                <Field label="Size in MB (optional)" hint="Left empty, it is what the recovery image needs (about 1 GB)."><input className="input" inputMode="numeric" value={size} onChange={(e) => setSize(e.target.value.replace(/\D/g, ""))} /></Field>
                <label className="check"><input type="checkbox" checked={autoStart} onChange={(e) => setAutoStart(e.target.checked)} /><span>Start it automatically when Windows fails to start<div className="faint small">Instead of Windows' own Startup Repair.</div></span></label>
              </>
            ) : (
              <Notice tone="warn">This deletes the recovery partition and its boot menu entry, and gives the space back to C:.</Notice>
            )}
            <Field label={`Type the machine's name (${agent.hostname}) to confirm`}><input className="input" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" /></Field>
          </div>
        </Modal>
      )}
    </div>
  );
}

function RecoveryCard({ agent, inv }: { agent: Agent; inv: Inventory | null }) {
  const images = useApi<Image[]>("/api/images");
  const [q, setQ] = useState("");
  const [restore, setRestore] = useState<Image | null>(null);
  const list = (images.data ?? [])
    .filter((i) => !q || `${i.vm_name ?? ""} ${i.hostname} ${i.label ?? ""} ${i.repository_name}`.toLowerCase().includes(q.toLowerCase()))
    .sort((x, y) => y.created - x.created)
    .slice(0, 50);
  const free = (inv?.disks ?? []).filter((d) => !d.system && !d.in_use);
  return (
    <div className="card">
      <div className="card-head"><LifeBuoy size={17} /><h2>Restore onto this machine</h2></div>
      <div className="card-body stack">
        <div className="muted small">
          {agent.name} was started from the recovery media
          {inv?.firmware && <> in {inv.firmware === "uefi" ? `UEFI mode${inv.secure_boot ? " with Secure Boot" : ""}` : "legacy BIOS mode"}</>}.
          {" "}Choose a backup to put on one of its disks ({free.length ? free.map((d) => `${d.path} ${bytes(d.size)}`).join(", ") : "none found yet"}).
          The disk may be larger, or smaller if the backed-up partitions fit. Afterwards remove the recovery medium and restart.
        </div>
        {!agent.online && <Notice tone="warn">This session has ended. Start the machine from the recovery media again.</Notice>}
        <input className="input" placeholder="Search backups by machine, label or repository" value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Machine</th><th>Taken</th><th style={{ textAlign: "right" }}>Disks</th><th>Repository</th><th /></tr></thead>
            <tbody>
              {list.map((i) => (
                <tr key={i.image_id}>
                  <td><strong>{i.vm_name ?? i.hostname}</strong>{i.label && <span className="faint small"> · {i.label}</span>}</td>
                  <td>{when(i.created)}</td>
                  <td style={{ textAlign: "right" }}>{i.disks.map((d) => bytes(d)).join(" + ")}</td>
                  <td>{i.repository_name}</td>
                  <td style={{ textAlign: "right" }}>
                    <button className="btn sm" disabled={!agent.online} onClick={() => setRestore(i)}><RotateCcw size={13} /> Restore here</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {images.data && list.length === 0 && <div className="muted small">No backups found.</div>}
      </div>
      {restore && <RestoreDialog image={restore} preferAgent={agent.id} onClose={() => setRestore(null)} />}
    </div>
  );
}

function DiskTable({ inv }: { inv: Inventory }) {
  return (
    <div className="card">
      <div className="card-head"><HardDrive size={17} /><h2>Disks</h2></div>
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Device</th><th>Model</th><th style={{ textAlign: "right" }}>Size</th><th /></tr></thead>
          <tbody>
            {inv.disks.map((d) => (
              <tr key={d.path}>
                <td className="mono">{d.path}</td>
                <td>{d.model || <span className="faint">—</span>}{d.serial && <span className="faint small"> · {d.serial}</span>}</td>
                <td style={{ textAlign: "right" }}>{bytes(d.size)}</td>
                <td>{d.system ? <Pill tone="neutral">system disk</Pill> : d.in_use ? <Pill tone="neutral">in use</Pill> : null}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function PlansCard({ plans }: { plans: AgentDetail["plans"] }) {
  return (
    <div className="card">
      <div className="card-head"><CalendarClock size={17} /><h2>Backup plans</h2><Link to="/plans" className="right small">Manage plans</Link></div>
      {plans.length === 0 ? (
        <div className="card-body muted">No scheduled backups. <Link to="/plans">Create a plan</Link> to back this machine up automatically.</div>
      ) : (
        <div className="timeline">
          {plans.map((p) => (
            <div key={p.id} className="tl-item">
              <div className={`tl-icon ${p.enabled ? "ok" : "neutral"}`}><CalendarClock size={15} /></div>
              <div className="grow">
                <div><strong>{p.name}</strong> <span className="muted">· {jobWhat(p.job)} → {p.repository_name}</span></div>
                <div className="faint small">{scheduleText(p.schedule)}{p.enabled && p.next_run ? ` · next ${until(p.next_run)}` : ""}</div>
              </div>
              {!p.enabled && <Pill tone="neutral">Paused</Pill>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ImagesTable({ detail, onChange }: { detail: AgentDetail; onChange: () => void }) {
  const [restoring, setRestoring] = useState<Image | null>(null);
  const [scanning, setScanning] = useState<Image | null>(null);
  const [holding, setHolding] = useState<Image | null>(null);
  const [appRestore, setAppRestore] = useState<Image | null>(null);
  const [booting, setBooting] = useState<Image | null>(null);
  const [results, setResults] = useState<Image | null>(null);
  const [files, setFiles] = useState<Image | null>(null);
  if (detail.images.length === 0)
    return <div className="card"><Empty icon={<Database size={24} />} title="No backups yet">Images appear here after the first backup finishes.</Empty></div>;
  return (
    <div className="card table-wrap">
      <table className="table">
        <thead>
          <tr><th>Taken</th>{detail.agent.role === "hyperv" && <th>VM</th>}<th>Type</th><th>Consistency</th><th style={{ textAlign: "right" }}>Size</th><th>Boot test</th><th>Malware</th><th /></tr>
        </thead>
        <tbody>
          {detail.images.map((i) => (
            <tr key={i.image_id}>
              <td className="nowrap"><div>{when(i.created)}</div><div className="faint small"><span className="mono">{i.image_id.slice(0, 8)}</span> · {i.repository_name}</div></td>
              {detail.agent.role === "hyperv" && <td><strong>{i.vm_name}</strong></td>}
              <td>
                {i.source === "files" ? "Files and folders" : i.kind === "full" ? "Full" : "Incremental"}
                {i.label && <div className="faint small">{i.label}</div>}
                {i.legal_hold && <div style={{ marginTop: 4 }} title={`${i.legal_hold.reason} (${i.legal_hold.by})`}><Pill tone="info">Legal hold</Pill></div>}
              </td>
              <td>
                <Pill tone={consistencyLabel(i.consistency).tone}>{consistencyLabel(i.consistency).text}</Pill>
                {i.anomaly && <div style={{ marginTop: 4 }} title={i.anomaly}><Pill tone="bad">Possible ransomware</Pill></div>}
                <AppsLine apps={i.applications} />
              </td>
              <td style={{ textAlign: "right" }} className="nowrap">{bytes(i.captured_bytes)}<div className="faint small">{bytes(i.stored_new_bytes)} new</div></td>
              <td>{i.source === "files" ? <span className="faint small">—</span> : <BootPill check={i.boot_check} onClick={() => setResults(i)} />}</td>
              <td><ScanPill image={i} onClick={() => setScanning(i)} /></td>
              <td style={{ textAlign: "right" }} className="nowrap">
                <button className="btn sm ghost" title="Browse the files in this backup and restore some of them" aria-label="Files" onClick={() => setFiles(i)}><FolderOpen size={14} /></button>{" "}
                {(i.applications ?? []).some((a) => a.included && (a.file_sets ?? 0) > 0) && <><button className="btn sm ghost" title="Restore one SQL Server or Exchange database" aria-label="Restore one database" onClick={() => setAppRestore(i)}><Database size={14} /></button>{" "}</>}
                <button className="btn sm ghost" title={i.legal_hold ? "Release the legal hold" : "Keep this backup whatever retention says"} aria-label={i.legal_hold ? "Release legal hold" : "Legal hold"} onClick={() => setHolding(i)}><Gavel size={14} /></button>{" "}
                {i.source !== "files" && <><button className="btn sm ghost" title="Start this backup as an isolated VM and check that it boots" aria-label="Test boot" onClick={() => setBooting(i)}><Rocket size={14} /></button>{" "}
                <button className="btn sm" onClick={() => setRestoring(i)}><RotateCcw size={13} /> Restore</button></>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {restoring && <RestoreDialog image={restoring} onClose={() => setRestoring(null)} />}
      {booting && <BootCheckDialog image={booting} onClose={() => setBooting(null)} />}
      {results && <BootResultDialog image={results} onClose={() => setResults(null)} />}
      {files && <FileBrowser image={files} onClose={() => setFiles(null)} />}
      {scanning && <ScanDialog image={scanning} onClose={() => { setScanning(null); onChange(); }} />}
      {holding && <LegalHoldDialog image={holding} onClose={() => setHolding(null)} onDone={() => { setHolding(null); onChange(); }} />}
      {appRestore && <AppRestoreDialog image={appRestore} onClose={() => setAppRestore(null)} />}
    </div>
  );
}

function JobsTable({ detail }: { detail: AgentDetail }) {
  if (detail.jobs.length === 0) return <div className="card"><Empty icon={<CalendarClock size={24} />} title="Nothing has run on this machine yet" /></div>;
  return (
    <div className="card table-wrap">
      <table className="table">
        <thead><tr><th>Job</th><th>Status</th><th>Started</th><th>Duration</th><th>Details</th></tr></thead>
        <tbody>
          {detail.jobs.map((j) => (
            <tr key={j.id}>
              <td><strong>{j.label}</strong><div className="faint small">{jobWhat(j.kind)}{j.repository_name ? ` → ${j.repository_name}` : ""}</div></td>
              <td><StatePill state={j.state} /></td>
              <td className="nowrap">{when(j.started ?? j.created)}</td>
              <td className="nowrap">{duration(j.started, j.finished)}</td>
              <td className="small" style={{ maxWidth: 380 }}>
                {j.error && <div style={{ color: "var(--bad)" }}>{j.error}</div>}
                {j.warnings.map((w, i) => <div key={i} style={{ color: "var(--warn)" }}>{w}</div>)}
                {!j.error && j.warnings.length === 0 && <span className="faint">{j.requested_by === "schedule" ? "scheduled" : j.requested_by ? `by ${j.requested_by}` : ""}</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------- dialogs ----------

export function useRepos(agentId: string) {
  const r = useApi<Repository[]>("/api/repositories");
  const usable = useMemo(() => (r.data ?? []).filter((x) => x.status === "ready" && x.agents.some((a) => a.id === agentId)), [r.data, agentId]);
  return { usable, loading: r.loading };
}

/** Choose what to back up on a machine. Shared by "Back up now" and plans. */
export function WhatPicker(props: { agent: Agent; inventory: Inventory | null; value: JobKind | null; onChange: (k: JobKind | null) => void }) {
  const { agent, value, onChange } = props;
  if (!agent.capabilities.includes("backup_files")) return <ImageWhatPicker {...props} />;
  const files = value?.type === "backup_files";
  const settings = (value && "settings" in value ? value.settings : undefined) ?? {};
  return (
    <div className="stack">
      <div className="seg" style={{ alignSelf: "flex-start" }}>
        <button className={!files ? "on" : ""} onClick={() => onChange(defaultWhat(agent))}>{agent.capabilities.includes("backup_hyperv") ? "Virtual machines" : "Whole machine or disks"}</button>
        <button className={files ? "on" : ""} onClick={() => onChange({ type: "backup_files", paths: [], excludes: [], settings })}>Files and folders</button>
      </div>
      {files ? <FilesPicker windows={agent.os.family === "windows"} value={value} onChange={onChange} /> : <ImageWhatPicker {...props} />}
    </div>
  );
}

const lines = (s: string) => s.split("\n").map((x) => x.trim()).filter(Boolean);

function FilesPicker({ windows, value, onChange }: { windows: boolean; value: Extract<JobKind, { type: "backup_files" }>; onChange: (k: JobKind | null) => void }) {
  const [paths, setPaths] = useState(value.paths.join("\n"));
  const [excl, setExcl] = useState((value.excludes ?? []).join("\n"));
  const update = (p: string, e: string) => {
    setPaths(p);
    setExcl(e);
    onChange({ ...value, paths: lines(p), excludes: lines(e) });
  };
  return (
    <div className="grid cols-2">
      <Field label="Files and folders" hint={windows ? "One full path per line: C:\\Users\\anna\\Documents or \\\\server\\share\\folder. Read through a shadow copy, so open files are included." : "One full path per line, e.g. /home/anna or /srv/data."}>
        <textarea className="input mono" rows={5} value={paths} onChange={(e) => update(e.target.value, excl)} />
      </Field>
      <Field label="Leave out" hint="Names (*.tmp, node_modules) or full paths, one per line. Paging files and the recycle bin are always left out.">
        <textarea className="input mono" rows={5} value={excl} onChange={(e) => update(paths, e.target.value)} />
      </Field>
    </div>
  );
}

function ImageWhatPicker({ agent, inventory, value, onChange }: { agent: Agent; inventory: Inventory | null; value: JobKind | null; onChange: (k: JobKind | null) => void }) {
  const settings = (value && "settings" in value ? value.settings : undefined) ?? {};
  if (agent.capabilities.includes("backup_hyperv")) {
    const vms = inventory?.vms ?? [];
    const ids = value?.type === "backup_hyperv" ? value.vm_ids : [];
    const all = value?.type === "backup_hyperv" && ids.length === 0;
    return (
      <Field label="Virtual machines" hint="New VMs are included automatically when “All VMs” is chosen.">
        <div className="seg" style={{ alignSelf: "flex-start" }}>
          <button className={all ? "on" : ""} onClick={() => onChange({ type: "backup_hyperv", vm_ids: [], settings })}>All VMs</button>
          <button className={!all ? "on" : ""} onClick={() => onChange({ type: "backup_hyperv", vm_ids: vms.slice(0, 1).map((v) => v.id), settings })}>Choose VMs</button>
        </div>
        {!all && (
          <div className="chips" style={{ marginTop: 6 }}>
            {vms.map((v) => (
              <button
                key={v.id}
                className={`chip${ids.includes(v.id) ? " on" : ""}`}
                onClick={() => {
                  const next = ids.includes(v.id) ? ids.filter((x) => x !== v.id) : [...ids, v.id];
                  onChange(next.length ? { type: "backup_hyperv", vm_ids: next, settings } : null);
                }}
              >
                {v.name}
              </button>
            ))}
          </div>
        )}
      </Field>
    );
  }
  const both = agent.capabilities.includes("backup_system") && agent.capabilities.includes("backup_disks");
  if (agent.capabilities.includes("backup_system") && (!both || value?.type !== "backup_disks")) {
    return (
      <div className="stack">
        {both && <WhatToggle system onChange={(sys) => onChange(sys ? { type: "backup_system", settings } : { type: "backup_disks", paths: [], settings })} />}
        {both ? (
          <Notice tone="info">The running system: every disk holding its file systems. Logical volumes are captured through LVM snapshots and small partitions such as /boot while briefly frozen, so the image is consistent. The volume group needs free space for the snapshots (10 % of each volume, at least 64 MiB); a system without LVM is backed up from the recovery media instead.</Notice>
        ) : (
          <Notice tone="info">The whole system: every partition on the system disk, through a Volume Shadow Copy snapshot so open files and databases are captured consistently.</Notice>
        )}
      </div>
    );
  }
  const disks = inventory?.disks ?? [];
  const paths = value?.type === "backup_disks" ? value.paths : [];
  return (
    <Field label="Disks" hint="Disks in use by the running system are imaged with “Running system”; here, unmounted and secondary disks.">
      <div className="stack tight">
        {both && <WhatToggle system={false} onChange={(sys) => onChange(sys ? { type: "backup_system", settings } : { type: "backup_disks", paths: [], settings })} />}
        {disks.map((d) => (
          <label key={d.path} className="check">
            <input
              type="checkbox"
              checked={paths.includes(d.path)}
              disabled={d.system}
              onChange={() => {
                const next = paths.includes(d.path) ? paths.filter((x) => x !== d.path) : [...paths, d.path];
                onChange(next.length ? { type: "backup_disks", paths: next, settings } : null);
              }}
            />
            <span><span className="mono">{d.path}</span> <span className="muted">{d.model} · {bytes(d.size)}</span> {d.system && <Pill tone="neutral">in use by the system</Pill>}</span>
          </label>
        ))}
        {disks.length === 0 && <div className="muted small">The agent has not reported any disks.</div>}
      </div>
    </Field>
  );
}

function WhatToggle({ system, onChange }: { system: boolean; onChange: (system: boolean) => void }) {
  return (
    <div className="seg" style={{ alignSelf: "flex-start" }}>
      <button className={system ? "on" : ""} onClick={() => onChange(true)}>Running system</button>
      <button className={!system ? "on" : ""} onClick={() => onChange(false)}>Selected disks</button>
    </div>
  );
}

/** Applications the snapshot was coordinated with: "SQL Server, Exchange", or which were not. */
function AppsLine({ apps }: { apps?: ImageApplication[] }) {
  if (!apps || apps.length === 0) return null;
  const pretty = (w: string) => w.replace(/^Microsoft /, "").replace(/ VSS Writer$| Writer$/i, "").replace(/^SqlServerWriter$/, "SQL Server");
  const writers = [...new Set(apps.map((a) => a.writer))];
  const missing = apps.filter((a) => !a.included);
  const title = apps.map((a) => `${a.included ? "✓" : "✗"} ${pretty(a.writer)}: ${a.caption || a.component}${a.note ? ` (${a.note})` : ""}`).join("\n");
  const named = writers.filter((w) => !/^(System|Registry|COM\+ REGDB|WMI|Task Scheduler|VSS Metadata Store|Performance Counters|ASR|Shadow Copy Optimization|BITS|IIS Config|IIS Metabase|MSSearch Service|FRS|DFS Replication|NTDS|Cluster)/i.test(pretty(w)));
  return (
    <div className="faint small" style={{ marginTop: 4 }} title={title}>
      {missing.length === 0
        ? <>Applications: {named.length ? named.map(pretty).join(", ") : "Windows system state"}</>
        : <span style={{ color: "var(--warn, inherit)" }}>{missing.length} application component{missing.length === 1 ? "" : "s"} not coordinated</span>}
    </div>
  );
}

export function defaultWhat(agent: Agent, preselectVms: string[] = []): JobKind | null {
  if (agent.capabilities.includes("backup_hyperv")) return { type: "backup_hyperv", vm_ids: preselectVms };
  if (agent.capabilities.includes("backup_system")) return { type: "backup_system" };
  return null;
}

export function withSettings(k: JobKind, s: BackupSettings): JobKind {
  return k.type === "backup_system" || k.type === "backup_disks" || k.type === "backup_hyperv" || k.type === "backup_files" ? { ...k, settings: s } : k;
}

export function OptionsPicker({ s, onChange, windows }: { s: BackupSettings; onChange: (s: BackupSettings) => void; windows: boolean }) {
  return (
    <details>
      <summary className="small" style={{ cursor: "pointer", fontWeight: 600 }}>Options</summary>
      <div className="stack" style={{ marginTop: 12 }}>
        <label className="check">
          <input type="checkbox" checked={(s.verify_sample_percent ?? 0) > 0} onChange={(e) => onChange({ ...s, verify_sample_percent: e.target.checked ? 5 : null })} />
          <span>Spot-check the new image afterwards<div className="faint small">Reads back 5% of the new image's data to prove it is restorable.</div></span>
        </label>
        <Field label="Bandwidth limit" hint="Reads are throttled to keep the machine responsive. 0 means unlimited.">
          <div className="row"><input className="input" type="number" min={0} style={{ width: 110 }} value={s.rate_limit_mib ?? 0} onChange={(e) => onChange({ ...s, rate_limit_mib: Math.max(0, Number(e.target.value)) })} /> <span className="muted">MiB/s</span></div>
        </Field>
        {windows && (
          <label className="check">
            <input type="checkbox" checked={!!s.vss_full} onChange={(e) => onChange({ ...s, vss_full: e.target.checked })} />
            <span>Let SQL Server and Exchange truncate their logs<div className="faint small">Only if Fenrir-Backup is their backup of record. Off by default so other backup tools keep working.</div></span>
          </label>
        )}
      </div>
    </details>
  );
}

function BackupDialog({ agent, inventory, preselectVms, onClose, onDone }: { agent: Agent; inventory: Inventory | null; preselectVms: string[]; onClose: () => void; onDone: () => void }) {
  const { usable, loading } = useRepos(agent.id);
  const [repo, setRepo] = useState("");
  const [what, setWhat] = useState<JobKind | null>(defaultWhat(agent, preselectVms));
  const [s, setS] = useState<BackupSettings>({ label: "", rate_limit_mib: 0, verify_sample_percent: 5 });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const toast = useToast();
  const repoId = repo || usable[0]?.id || "";

  const start = async () => {
    if (!what) return;
    setBusy(true);
    setErr(null);
    try {
      await api.post(`/api/agents/${agent.id}/jobs`, { kind: withSettings(what, { ...s, label: s.label || null }), repository_id: repoId });
      toast("ok", `Backup of ${agent.name} queued; it starts within seconds`);
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={`Back up ${agent.name}`}
      sub="Runs once, now. Use a backup plan for regular backups."
      onClose={onClose}
      foot={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy || !what || !repoId} onClick={start}><Play size={15} /> Start backup</button></>}
    >
      {err && <Notice tone="bad">{err}</Notice>}
      {!loading && usable.length === 0 ? (
        <Notice tone="warn">No ready repository is available to this machine. <Link to="/repositories">Set one up first</Link>.</Notice>
      ) : (
        <Field label="Repository">
          <select className="input" value={repoId} onChange={(e) => setRepo(e.target.value)}>
            {usable.map((r) => <option key={r.id} value={r.id}>{r.name} — {r.path}</option>)}
          </select>
        </Field>
      )}
      <WhatPicker agent={agent} inventory={inventory} value={what} onChange={setWhat} />
      <Field label="Label (optional)" hint="Shown next to the image, e.g. “before upgrade”.">
        <input className="input" value={s.label ?? ""} onChange={(e) => setS({ ...s, label: e.target.value })} maxLength={80} />
      </Field>
      <OptionsPicker s={s} onChange={setS} windows={agent.os.family === "windows"} />
    </Modal>
  );
}

function VerifyDialog({ agent, onClose, onDone }: { agent: Agent; onClose: () => void; onDone: () => void }) {
  const { usable } = useRepos(agent.id);
  const [repo, setRepo] = useState("");
  const [level, setLevel] = useState<"quick" | "sample" | "full">("sample");
  const toast = useToast();
  const repoId = repo || usable[0]?.id || "";
  return (
    <Modal
      title="Verify backups"
      sub={`${agent.name} reads the repository and checks every image it holds.`}
      onClose={onClose}
      foot={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button
            className="btn primary"
            disabled={!repoId}
            onClick={async () => {
              try {
                await api.post(`/api/agents/${agent.id}/jobs`, { kind: { type: "verify", level, sample_percent: level === "sample" ? 5 : undefined }, repository_id: repoId });
                toast("ok", "Verification queued");
                onDone();
              } catch (e) {
                toast("bad", (e as Error).message);
              }
            }}
          >
            <ShieldCheck size={15} /> Verify
          </button>
        </>
      }
    >
      <Field label="Repository">
        <select className="input" value={repoId} onChange={(e) => setRepo(e.target.value)}>
          {usable.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
        </select>
      </Field>
      <div className="stack tight">
        {(
          [
            ["quick", "Quick", "Signatures and the presence of every piece of data. Seconds."],
            ["sample", "Spot check", "Quick, plus decrypts and re-hashes 5% of the data. Catches silent corruption early."],
            ["full", "Full", "Decrypts and re-hashes everything. Reads the whole repository."],
          ] as const
        ).map(([k, t, d]) => (
          <label key={k} className="check card card-pad" style={{ padding: "12px 14px", borderColor: level === k ? "var(--accent)" : undefined }}>
            <input type="radio" name="lvl" checked={level === k} onChange={() => setLevel(k)} />
            <span><strong>{t}</strong><div className="muted small">{d}</div></span>
          </label>
        ))}
      </div>
    </Modal>
  );
}

function RenameDialog({ agent, onClose, onDone }: { agent: Agent; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(agent.name);
  return (
    <Modal
      title="Rename machine"
      onClose={onClose}
      foot={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" onClick={async () => { await api.patch(`/api/agents/${agent.id}`, { name }); onDone(); }}>Save</button></>}
    >
      <Field label="Display name" hint={`Leave empty to use the hostname (${agent.hostname}).`}>
        <input className="input" autoFocus value={name} onChange={(e) => setName(e.target.value)} maxLength={80} />
      </Field>
    </Modal>
  );
}
