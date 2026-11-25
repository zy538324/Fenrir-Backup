import { useMemo, useState } from "react";
import { Boxes, Cloud, Play, Plus, RotateCcw, Trash2 } from "lucide-react";
import { api, type Agent, type Image, type JobKind, type K8sCluster, type Plan, type Retention, type SaasTenant, type Schedule } from "../api";
import { RETENTION_PRESETS, ago, bytes, scheduleText, until, when } from "../format";
import { Empty, Field, Link, Loading, Modal, Notice, Switch, useApi, useToast } from "../ui";
import { seal, sealSupported, type Sealed } from "../seal";
import { useRepos } from "./Machine";
import { RetentionPicker } from "./Plans";

type Kind = "m365" | "google" | "salesforce" | "quickbooks" | "kubernetes";
const KINDS: { id: Kind; label: string; secret: string; help: string }[] = [
  { id: "m365", label: "Microsoft 365", secret: "Client secret", help: "An app registration in your Entra ID with application permissions User.Read.All, Mail.ReadWrite and Files.ReadWrite.All (admin consent)." },
  { id: "google", label: "Google Workspace", secret: "Service account key (JSON)", help: "A service account with domain-wide delegation for gmail.readonly, drive.readonly and admin.directory.user.readonly (and gmail.insert, gmail.labels, gmail.modify, drive to restore)." },
  { id: "salesforce", label: "Salesforce", secret: "Consumer secret", help: "A connected app with the client credentials flow and a run-as user that can view all data." },
  { id: "quickbooks", label: "QuickBooks Online", secret: "Client secret", help: "Your Intuit app (Accounting scope) connected to the company once; paste its client secret and the refresh token. Intuit replaces the refresh token as it is used: the machine keeps the newest itself." },
  { id: "kubernetes", label: "Kubernetes", secret: "Service account token", help: "A service account that can read (and, to restore, create) the namespaces' objects; with volume data, also create pods, claims and volume snapshots." },
];

const isSource = (k: JobKind): k is Extract<JobKind, { type: "backup_saas" | "backup_kubernetes" }> => k.type === "backup_saas" || k.type === "backup_kubernetes";

function sourceName(k: JobKind): string {
  if (k.type === "backup_kubernetes") return `${k.cluster.name} (${k.cluster.namespaces.join(", ")})`;
  if (k.type === "backup_saas") return `${KINDS.find((x) => x.id === k.tenant.service)?.label ?? k.tenant.service}: ${k.tenant.tenant}`;
  return "";
}

/** The machine ID its images are under. */
function machineOf(k: JobKind): string {
  if (k.type === "backup_kubernetes") return `k8s:${k.cluster.name}`;
  if (k.type === "backup_saas") return `saas:${k.tenant.service}:${k.tenant.tenant}`;
  return "";
}

export default function SourcesPage() {
  const plans = useApi<Plan[]>("/api/plans", 10000);
  const agents = useApi<Agent[]>("/api/agents");
  const [adding, setAdding] = useState(false);
  const [restoring, setRestoring] = useState<Plan | null>(null);
  const toast = useToast();
  if (!plans.data || !agents.data) return <div className="page"><Loading /></div>;
  const runners = agents.data.filter((a) => a.capabilities.includes("saas") || a.capabilities.includes("kubernetes"));
  const mine = plans.data.filter((p) => isSource(p.job));

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Apps & clusters</h1>
          <div className="sub">Microsoft 365, Google Workspace, Salesforce and Kubernetes, backed up by one of your machines.</div>
        </div>
        <button className="btn primary right" onClick={() => setAdding(true)} disabled={runners.length === 0}><Plus size={16} /> Connect</button>
      </div>
      <Notice tone="info">
        You connect your own app registration, service account or connected app. Its secret is encrypted in this browser for the machine that runs the backups; this server stores and forwards it only in that encrypted form.
      </Notice>
      {mine.length === 0 ? (
        <div className="card">
          <Empty icon={<Cloud size={26} />} title="Nothing connected yet" action={runners.length ? <button className="btn primary" onClick={() => setAdding(true)}>Connect a service or cluster</button> : <Link to="/add" className="btn primary">Add a machine first</Link>}>
            Mailboxes, OneDrive and Google Drive files, CRM records and Kubernetes namespaces (with their volumes) go into the same encrypted, deduplicated repositories as your machine images.
          </Empty>
        </div>
      ) : (
        <div className="card table-wrap">
          <table className="table">
            <thead><tr><th>Source</th><th>Runs on</th><th>Schedule</th><th>Last run</th><th>Next run</th><th>On</th><th /></tr></thead>
            <tbody>
              {mine.map((p) => (
                <tr key={p.id}>
                  <td><strong>{p.name}</strong><div className="faint small">{sourceName(p.job)} → {p.repository_name}</div></td>
                  <td><Link to={`/machines/${p.agent_id}`}>{p.agent_name}</Link></td>
                  <td>{scheduleText(p.schedule)}</td>
                  <td className="nowrap">{ago(p.last_run)}</td>
                  <td className="nowrap">{p.enabled ? until(p.next_run) : <span className="faint">paused</span>}</td>
                  <td><Switch on={p.enabled} label={`Enable ${p.name}`} onChange={async (v) => { await api.patch(`/api/plans/${p.id}`, { enabled: v }); plans.reload(); }} /></td>
                  <td className="nowrap" style={{ textAlign: "right" }}>
                    <button className="btn sm" onClick={async () => { try { await api.post(`/api/plans/${p.id}/run`); toast("ok", `${p.name} started`); } catch (e) { toast("bad", (e as Error).message); } }}><Play size={13} /> Back up now</button>{" "}
                    <button className="btn sm" onClick={() => setRestoring(p)}><RotateCcw size={13} /> Restore</button>{" "}
                    <button className="icon-btn" aria-label="Disconnect" onClick={async () => { if (confirm(`Disconnect “${p.name}”? Its backups are kept; the secret is forgotten.`)) { await api.del(`/api/plans/${p.id}`); plans.reload(); } }}><Trash2 size={15} /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {adding && <ConnectDialog agents={runners} onClose={() => setAdding(false)} onDone={() => { setAdding(false); plans.reload(); }} />}
      {restoring && <RestoreDialog plan={restoring} onClose={() => setRestoring(null)} />}
    </div>
  );
}

const lines = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

function ConnectDialog({ agents, onClose, onDone }: { agents: Agent[]; onClose: () => void; onDone: () => void }) {
  const [kind, setKind] = useState<Kind>("m365");
  const able = agents.filter((a) => a.capabilities.includes(kind === "kubernetes" ? "kubernetes" : "saas"));
  const [agentId, setAgentId] = useState(able[0]?.id ?? "");
  const agent = able.find((a) => a.id === agentId) ?? able[0];
  const { usable } = useRepos(agent?.id ?? "");
  const [repo, setRepo] = useState("");
  const repoId = repo || usable[0]?.id || "";
  const [f, setF] = useState({ tenant: "", client_id: "", domain_url: "", admin: "", users: "", objects: "", mail: true, files: true, sites: false, teams: false, directory: false, name: "", api_server: "", ca_pem: "", namespaces: "", volume_image: "" });
  const [secret, setSecret] = useState("");
  const [refresh, setRefresh] = useState("");
  const [time, setTime] = useState("01:00");
  const [retention, setRetention] = useState<Retention | null>(RETENTION_PRESETS[1].r);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const meta = KINDS.find((k) => k.id === kind)!;
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });

  const save = async () => {
    if (!agent) return;
    setErr(null);
    setBusy(true);
    try {
      if (!sealSupported()) throw new Error("This browser cannot encrypt secrets (WebCrypto unavailable). Open the server over HTTPS in a current browser.");
      const plain = kind === "quickbooks" ? JSON.stringify({ client_secret: secret.trim(), refresh_token: refresh.trim() }) : secret.trim();
      const sealed: Sealed = await seal(agent.public_key, plain);
      let job: JobKind;
      let label: string;
      if (kind === "kubernetes") {
        const cluster: K8sCluster = { name: f.name.trim(), api_server: f.api_server.trim(), ca_pem: f.ca_pem.trim(), namespaces: lines(f.namespaces), volume_image: f.volume_image.trim() };
        job = { type: "backup_kubernetes", cluster, sealed_token: sealed };
        label = `Kubernetes ${cluster.name}`;
      } else {
        const tenant: SaasTenant = { service: kind, tenant: f.tenant.trim(), client_id: f.client_id.trim(), domain_url: f.domain_url.trim(), admin: f.admin.trim(), users: lines(f.users), objects: lines(f.objects), mail: f.mail, files: f.files, ...(kind === "m365" ? { sites: f.sites, teams: f.teams, directory: f.directory } : {}) };
        job = { type: "backup_saas", tenant, sealed_secret: sealed };
        label = `${meta.label} ${tenant.tenant}`;
      }
      const schedule: Schedule = { type: "daily", time, days: [], utc_offset_minutes: -new Date().getTimezoneOffset() };
      await api.post("/api/plans", { name: label, agent_id: agent.id, repository_id: repoId, job, schedule, enabled: true, retention });
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      wide
      title="Connect a service or cluster"
      onClose={onClose}
      foot={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy || !agent || !repoId || !secret.trim() || (kind === "quickbooks" && !refresh.trim())} onClick={save}>Connect</button></>}
    >
      {err && <Notice tone="bad">{err}</Notice>}
      <div className="seg" style={{ alignSelf: "flex-start" }}>
        {KINDS.map((k) => <button key={k.id} className={kind === k.id ? "on" : ""} onClick={() => { setKind(k.id); setAgentId(""); setRepo(""); }}>{k.label}</button>)}
      </div>
      <div className="muted small">{meta.help}</div>
      <div className="grid cols-2">
        <Field label="Runs on" hint="This machine signs in to the service and sends the data, encrypted, to the repository.">
          {able.length === 0 ? <div className="muted small" style={{ paddingTop: 8 }}>No machine can run this.</div> : (
            <select className="input" value={agent?.id ?? ""} onChange={(e) => { setAgentId(e.target.value); setRepo(""); }}>
              {able.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
            </select>
          )}
        </Field>
        <Field label="Repository">
          {usable.length === 0 ? <div className="muted small" style={{ paddingTop: 8 }}>No ready repository for this machine. <Link to="/repositories">Set one up</Link>.</div> : (
            <select className="input" value={repoId} onChange={(e) => setRepo(e.target.value)}>
              {usable.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </select>
          )}
        </Field>
      </div>
      {kind === "kubernetes" ? (
        <>
          <div className="grid cols-2">
            <Field label="Cluster name" hint="How its backups are listed."><input className="input" value={f.name} onChange={set("name")} placeholder="prod" /></Field>
            <Field label="API server"><input className="input" value={f.api_server} onChange={set("api_server")} placeholder="https://k8s.example.lan:6443" /></Field>
          </div>
          <Field label="Namespaces" hint="Separated by spaces or commas."><input className="input" value={f.namespaces} onChange={set("namespaces")} placeholder="shop payments" /></Field>
          <Field label="CA certificate (PEM)"><textarea className="input mono" rows={3} value={f.ca_pem} onChange={set("ca_pem")} placeholder="-----BEGIN CERTIFICATE-----" /></Field>
          <Field label="Volume data" hint="The fenrir-backup container image the cluster can pull, for the pods that read and write volumes. Empty: objects only."><input className="input" value={f.volume_image} onChange={set("volume_image")} placeholder="registry.example.lan/fenrir-backup:latest" /></Field>
        </>
      ) : (
        <>
          <div className="grid cols-2">
            <Field label={kind === "m365" ? "Tenant (directory ID or domain)" : kind === "google" ? "Domain" : kind === "quickbooks" ? "Company ID (realm ID)" : "Org name"}><input className="input" value={f.tenant} onChange={set("tenant")} placeholder={kind === "m365" ? "contoso.onmicrosoft.com" : kind === "google" ? "example.com" : kind === "quickbooks" ? "9130350000000000" : "acme"} /></Field>
            {kind === "google"
              ? <Field label="Administrator" hint="Users are listed as this account."><input className="input" value={f.admin} onChange={set("admin")} placeholder="admin@example.com" /></Field>
              : <Field label={kind === "m365" ? "Application (client) ID" : kind === "quickbooks" ? "Client ID" : "Consumer key"}><input className="input" value={f.client_id} onChange={set("client_id")} /></Field>}
          </div>
          {kind === "salesforce" && <Field label="My Domain URL"><input className="input" value={f.domain_url} onChange={set("domain_url")} placeholder="https://acme.my.salesforce.com" /></Field>}
          {kind === "quickbooks" && <Field label="API address" hint="Empty: QuickBooks Online. For an Intuit sandbox company: https://sandbox-quickbooks.api.intuit.com"><input className="input" value={f.domain_url} onChange={set("domain_url")} /></Field>}
          {kind === "salesforce" || kind === "quickbooks"
            ? <Field label={kind === "quickbooks" ? "Entities" : "Objects"} hint={kind === "quickbooks" ? "Empty: accounts, customers, vendors, employees, items and every transaction type." : "Empty: the standard objects and every custom object."}><input className="input" value={f.objects} onChange={set("objects")} placeholder={kind === "quickbooks" ? "Customer Invoice Bill" : "Account Contact Opportunity"} /></Field>
            : (
              <>
                <Field label="Users" hint="Empty: every user."><input className="input" value={f.users} onChange={set("users")} placeholder="ann@example.com bob@example.com" /></Field>
                <div className="row" style={{ gap: 20 }}>
                  <label className="check"><input type="checkbox" checked={f.mail} onChange={(e) => setF({ ...f, mail: e.target.checked })} /> Mail</label>
                  <label className="check"><input type="checkbox" checked={f.files} onChange={(e) => setF({ ...f, files: e.target.checked })} /> {kind === "m365" ? "OneDrive" : "Drive"} files</label>
                  {kind === "m365" && <>
                    <label className="check" title="Needs Sites.ReadWrite.All"><input type="checkbox" checked={f.sites} onChange={(e) => setF({ ...f, sites: e.target.checked })} /> SharePoint sites</label>
                    <label className="check" title="Needs ChannelMessage.Read.All (Microsoft approves this permission per app)"><input type="checkbox" checked={f.teams} onChange={(e) => setF({ ...f, teams: e.target.checked })} /> Teams messages</label>
                    <label className="check" title="Needs Directory.Read.All and Policy.Read.All"><input type="checkbox" checked={f.directory} onChange={(e) => setF({ ...f, directory: e.target.checked })} /> Entra ID</label>
                  </>}
                </div>
              </>
            )}
        </>
      )}
      <Field label={meta.secret} hint="Encrypted in this browser for the machine above; nobody else can read it, this server included.">
        <textarea className="input mono" rows={kind === "google" ? 5 : 2} value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="off" spellCheck={false} />
      </Field>
      {kind === "quickbooks" && <Field label="Refresh token" hint="From connecting your Intuit app to the company (OAuth 2.0). Encrypted like the secret.">
        <textarea className="input mono" rows={2} value={refresh} onChange={(e) => setRefresh(e.target.value)} autoComplete="off" spellCheck={false} />
      </Field>}
      <div className="row wrap" style={{ gap: 16 }}>
        <Field label="Back up every day at"><input className="input" type="time" value={time} onChange={(e) => setTime(e.target.value)} style={{ width: 130 }} /></Field>
      </div>
      <RetentionPicker value={retention} onChange={setRetention} />
    </Modal>
  );
}

function RestoreDialog({ plan, onClose }: { plan: Plan; onClose: () => void }) {
  const images = useApi<Image[]>("/api/images");
  const job = plan.job;
  const mid = machineOf(job);
  const list = useMemo(() => (images.data ?? []).filter((i) => i.machine_id === mid && i.repository_id === plan.repository_id).sort((a, b) => b.created - a.created), [images.data, mid, plan.repository_id]);
  const [image, setImage] = useState("");
  const [f, setF] = useState({ account: "", to_account: "", kind: "", path: "", namespaces: "", rename_to: "", confirm: "" });
  const [overwrite, setOverwrite] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const imageId = image || list[0]?.image_id || "";
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const k8s = job.type === "backup_kubernetes";
  const owner = job.type === "backup_kubernetes" ? job.cluster.name : job.type === "backup_saas" ? job.tenant.tenant : "";

  const go = async () => {
    setErr(null);
    setBusy(true);
    try {
      let kind: JobKind;
      if (job.type === "backup_kubernetes") {
        kind = { type: "restore_kubernetes", image_id: imageId, cluster: job.cluster, sealed_token: job.sealed_token, namespaces: lines(f.namespaces), rename_to: f.rename_to.trim() || null, replace: overwrite };
      } else if (job.type === "backup_saas") {
        kind = { type: "restore_saas", image_id: imageId, tenant: job.tenant, sealed_secret: job.sealed_secret, account: f.account.trim(), to_account: f.to_account.trim() || null, kind: f.kind || null, path: f.path.trim() || null, overwrite };
      } else return;
      await api.post(`/api/agents/${plan.agent_id}/jobs`, { repository_id: plan.repository_id, kind, confirm: f.confirm });
      toast("ok", `Restore started on ${plan.agent_name}`);
      onClose();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const ready = imageId && (k8s ? true : f.account.trim()) && (!overwrite || f.confirm.trim().toLowerCase() === owner.toLowerCase());
  return (
    <Modal
      wide
      title={`Restore ${sourceName(job)}`}
      onClose={onClose}
      foot={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy || !ready} onClick={go}>Restore</button></>}
    >
      {err && <Notice tone="bad">{err}</Notice>}
      {!images.data ? <Loading /> : list.length === 0 ? <Notice tone="warn">No backups of this yet.</Notice> : (
        <Field label="Backup">
          <select className="input" value={imageId} onChange={(e) => setImage(e.target.value)}>
            {list.map((i) => <option key={i.image_id} value={i.image_id}>{when(i.created)} · {bytes(i.stored_new_bytes)} new{i.label ? ` · ${i.label}` : ""}</option>)}
          </select>
        </Field>
      )}
      {k8s ? (
        <>
          <Field label="Namespaces" hint="Empty: every namespace in the backup."><input className="input" value={f.namespaces} onChange={set("namespaces")} /></Field>
          <Field label="Restore under another name" hint="With exactly one namespace above: create it under this name instead, beside the original."><input className="input" value={f.rename_to} onChange={set("rename_to")} placeholder="shop-restored" /></Field>
          <Notice tone="info">Objects that already exist are left as they are unless you choose to replace them. Volume data is written into newly created claims.</Notice>
        </>
      ) : (
        <>
          <div className="grid cols-2">
            <Field label="Account" hint={job.type === "backup_saas" && (job.tenant.service === "salesforce" || job.tenant.service === "quickbooks") ? "The org name or company ID." : "Whose items."}><input className="input" value={f.account} onChange={set("account")} placeholder={job.type === "backup_saas" && (job.tenant.service === "salesforce" || job.tenant.service === "quickbooks") ? job.tenant.tenant : "ann@example.com"} /></Field>
            <Field label="Into account" hint="Empty: the same account."><input className="input" value={f.to_account} onChange={set("to_account")} /></Field>
          </div>
          <div className="grid cols-2">
            <Field label="What">
              <select className="input" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>
                <option value="">Everything</option>
                <option value="mail">Mail</option>
                <option value="file">Files</option>
                <option value="record">Records</option>
                <option value="site-file">SharePoint files (account: the site's address)</option>
                <option value="directory">Entra ID objects (account: directory:tenant)</option>
              </select>
            </Field>
            <Field label="Path starts with" hint="A folder, mail folder or object name; empty: all."><input className="input" value={f.path} onChange={set("path")} /></Field>
          </div>
          <Notice tone="info">Mail and files go into a new “Restored &lt;date&gt;” folder; nothing existing is changed. Deleted records are created again.</Notice>
        </>
      )}
      <label className="check"><input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} /> {k8s ? "Replace objects that exist now with the backed-up ones" : "Update records that still exist with the backed-up values"}</label>
      {overwrite && (
        <Field label={`Type ${owner} to confirm`} hint="This overwrites what is there now.">
          <input className="input" value={f.confirm} onChange={set("confirm")} autoComplete="off" />
        </Field>
      )}
      <div className="faint small"><Boxes size={12} /> Runs on {plan.agent_name}, which holds the secret.</div>
    </Modal>
  );
}
