// eDiscovery cases (docs/design/ediscovery.md): custodians' backups held while the case is open, searches kept with
// the case, exports with each item's SHA-256, and a chain-of-custody manifest.
import { useMemo, useState } from "react";
import { Briefcase, Download, FileJson, Search as SearchIcon } from "lucide-react";
import { api, type Image } from "../api";
import { downloadKey } from "../seal";
import { when } from "../format";
import { Empty, Field, Modal, Notice, Pill, useApi, useToast } from "../ui";
import { waitFast } from "./Files";

interface Custodian { machine_id: string; label: string; accounts: string[] }
interface Hit { image_id: string; volume?: { disk: number; partition: number } | null; path: string; size: number; folder?: boolean; account?: string; kind?: string }
interface Export { id: string; image_id: string; machine: string; what: string; by: string; at: number; job_id: string; state: string; manifest_sha256?: string; manifest_entries?: number; ciphertext_sha256?: string; receipts?: { sha256: string }[] }
interface Case {
  id: string; name: string; matter: string; description: string; status: string; custodians: Custodian[]; hold_new: boolean;
  held_backups: number; created_by: string; created: number;
  searches?: { id: string; query: string; by: string; at: number; state: string; hits: Hit[]; truncated?: boolean }[];
  exports?: Export[];
}

const keys = new Map<string, Awaited<ReturnType<typeof downloadKey>>>();

async function sha256Hex(b: Uint8Array<ArrayBuffer>): Promise<string> {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", b))].map((x) => x.toString(16).padStart(2, "0")).join("");
}

export default function CasesPage() {
  const cases = useApi<Case[]>("/api/cases");
  const [open, setOpen] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>eDiscovery</h1>
          <div className="sub">Cases keep their custodians' backups on legal hold, keep their searches, and export items with a manifest of each one's SHA-256.</div>
        </div>
        <button className="btn primary" onClick={() => setCreating(true)}><Briefcase size={15} /> New case</button>
      </div>
      {cases.data?.length === 0 && <div className="card"><Empty icon={<Briefcase size={24} />} title="No cases">Open a case to hold and search the backups of the people or machines involved.</Empty></div>}
      {!!cases.data?.length && (
        <div className="card table-wrap">
          <table className="table">
            <thead><tr><th>Case</th><th>Status</th><th>Custodians</th><th style={{ textAlign: "right" }}>Held backups</th><th>Opened</th></tr></thead>
            <tbody>{cases.data.map((c) => (
              <tr key={c.id} className="clickable" onClick={() => setOpen(c.id)}>
                <td><b>{c.name}</b>{c.matter && <div className="faint small">{c.matter}</div>}</td>
                <td><Pill tone={c.status === "open" ? "warn" : "neutral"}>{c.status}</Pill></td>
                <td className="small">{c.custodians.map((x) => x.label).join(", ")}</td>
                <td style={{ textAlign: "right" }}>{c.held_backups}</td>
                <td className="small">{when(c.created)}</td>
              </tr>))}
            </tbody>
          </table>
        </div>
      )}
      {creating && <CaseEditor onClose={() => { setCreating(false); cases.reload(); }} />}
      {open && <CaseDetail id={open} onClose={() => { setOpen(null); cases.reload(); }} />}
    </div>
  );
}

function CaseEditor({ initial, onClose }: { initial?: Case; onClose: () => void }) {
  const toast = useToast();
  const images = useApi<Image[]>("/api/images");
  const machines = useMemo(() => {
    const m = new Map<string, string>();
    for (const i of images.data ?? []) if (!m.has(i.machine_id)) m.set(i.machine_id, i.vm_name ?? i.hostname);
    return [...m.entries()].sort((a, b) => a[1].localeCompare(b[1]));
  }, [images.data]);
  const [f, setF] = useState({ name: initial?.name ?? "", matter: initial?.matter ?? "", description: initial?.description ?? "", hold_new: initial?.hold_new ?? true });
  const [cust, setCust] = useState<Custodian[]>(initial?.custodians ?? []);
  const [err, setErr] = useState<string | null>(null);
  const save = async () => {
    try {
      if (initial) await api.patch(`/api/cases/${initial.id}`, { description: f.description, hold_new: f.hold_new, custodians: cust });
      else await api.post("/api/cases", { ...f, custodians: cust });
      toast("ok", initial ? "Case updated" : "Case opened: the custodians' backups are on hold");
      onClose();
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <Modal title={initial ? `Custodians of ${initial.name}` : "New eDiscovery case"} onClose={onClose}
      foot={<button className="btn primary" disabled={!initial && f.name.trim().length < 3} onClick={save}>{initial ? "Save" : "Open case"}</button>}>
      {err && <Notice tone="bad">{err}</Notice>}
      {!initial && <Field label="Name"><input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="Smith v Acme" /></Field>}
      {!initial && <Field label="Matter reference"><input className="input" value={f.matter} onChange={(e) => setF({ ...f, matter: e.target.value })} /></Field>}
      <Field label="Description"><textarea className="input" rows={2} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
      <label className="check" style={{ margin: "8px 0" }}><input type="checkbox" checked={f.hold_new} onChange={(e) => setF({ ...f, hold_new: e.target.checked })} /> Also hold backups taken while the case is open</label>
      <h4>Custodians</h4>
      {machines.map(([id, name]) => {
        const c = cust.find((x) => x.machine_id === id);
        return (
          <div key={id} style={{ marginBottom: 6 }}>
            <label className="check"><input type="checkbox" checked={!!c} onChange={() => setCust(c ? cust.filter((x) => x.machine_id !== id) : [...cust, { machine_id: id, label: name, accounts: [] }])} /> {name} <span className="faint small">{id.startsWith("saas:") ? "cloud tenant" : "machine"}</span></label>
            {c && id.startsWith("saas:") && <input className="input small" style={{ marginLeft: 24, width: "85%" }} placeholder="Only these accounts, comma-separated (empty: the whole tenant)" value={c.accounts.join(", ")}
              onChange={(e) => setCust(cust.map((x) => x.machine_id === id ? { ...x, accounts: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) } : x))} />}
          </div>
        );
      })}
    </Modal>
  );
}

function CaseDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const toast = useToast();
  const c = useApi<Case>(`/api/cases/${id}`);
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [editing, setEditing] = useState(false);
  const [closing, setClosing] = useState(false);
  const [password, setPassword] = useState("");
  if (!c.data) return null;
  const cs = c.data;
  const last = cs.searches?.[cs.searches.length - 1];
  const hits = last?.hits ?? [];
  const run = async (what: string, fn: () => Promise<void>) => {
    setBusy(what);
    setErr(null);
    try {
      await fn();
      c.reload();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  };
  const search = () => run("Searching on the machines that keep the backups…", async () => {
    const r = await api.post<{ jobs: string[] }>(`/api/cases/${id}/search`, { query: query.trim() });
    setSelected(new Set());
    await Promise.all(r.jobs.map((j) => waitFast(j, undefined, 900)));
  });
  const exportSelected = () => run("Starting exports…", async () => {
    const groups = new Map<string, Hit[]>();
    for (const i of selected) {
      const h = hits[i];
      const k = `${h.image_id}|${h.volume ? `${h.volume.disk}:${h.volume.partition}` : ""}`;
      groups.set(k, [...(groups.get(k) ?? []), h]);
    }
    for (const g of groups.values()) {
      const k = await downloadKey();
      const h0 = g[0];
      const body = h0.account
        ? { image_id: h0.image_id, accounts: [...new Set(g.map((h) => h.account))], items: g.map((h) => h.path), recipient: k.publicB64 }
        : { image_id: h0.image_id, disk: h0.volume?.disk, partition: h0.volume?.partition, paths: g.map((h) => h.path), recipient: k.publicB64 };
      const r = await api.post<{ id: string }>(`/api/cases/${id}/export`, body);
      keys.set(r.id, k);
    }
    setSelected(new Set());
    toast("ok", "Export started: download it below when it is ready");
  });
  const save = (e: Export) => run("Downloading and decrypting…", async () => {
    const k = keys.get(e.id);
    if (!k) throw new Error("This export was started in another browser or before a reload: only that browser's key opens it. Export again here.");
    const job = await waitFast(e.job_id, undefined, 24 * 3600);
    const header = (job.result as { download: { sealed_key: import("../seal").Sealed; file_name: string } }).download;
    const resp = await fetch(`/api/jobs/${e.job_id}/download`, { credentials: "same-origin" });
    if (!resp.ok) throw new Error(`download failed (${resp.status})`);
    const plain = await k.decrypt(header, await resp.arrayBuffer());
    const sha = await sha256Hex(plain);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([plain], { type: "application/x-tar" }));
    a.download = header.file_name || `ediscovery-${e.id}.tar`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
    await api.post(`/api/cases/${id}/exports/${e.id}/receipt`, { sha256: sha, bytes: plain.length });
    toast("ok", `Saved ${a.download}; its SHA-256 is recorded with the case`);
  });
  return (
    <Modal wide title={<>{cs.name}{cs.matter && <span className="faint"> · {cs.matter}</span>}</>} onClose={onClose}
      sub={<><Pill tone={cs.status === "open" ? "warn" : "neutral"}>{cs.status}</Pill> {cs.held_backups} backups held · {cs.custodians.map((x) => `${x.label}${x.accounts.length ? ` (${x.accounts.join(", ")})` : ""}`).join("; ")}</>}
      foot={<>
        <a className="btn" href={`/api/cases/${id}/manifest`}><FileJson size={14} /> Chain-of-custody manifest</a>
        {cs.status === "open" && <button className="btn" onClick={() => setEditing(true)}>Custodians…</button>}
        {cs.status === "open" && <button className="btn danger" onClick={() => setClosing(true)}>Close case</button>}
      </>}>
      {err && <Notice tone="bad">{err}</Notice>}
      {busy && <div className="small muted" style={{ margin: "6px 0" }}>{busy}</div>}
      {cs.status === "open" && <div className="row" style={{ gap: 8 }}>
        <input className="input" style={{ minWidth: 300 }} value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => e.key === "Enter" && query.trim() && search()} placeholder="Words, *.xlsx, a subject or a path" />
        <button className="btn primary" disabled={!query.trim() || !!busy} onClick={search}><SearchIcon size={14} /> Search custodians</button>
      </div>}
      {last && <>
        <p className="small" style={{ marginTop: 10 }}>"{last.query}" by {last.by}, {when(last.at)}: {last.state === "done" ? `${hits.length} matches` : "running…"}{last.truncated ? " (first 5,000 kept)" : ""}</p>
        {hits.length > 0 && <div className="table-wrap" style={{ maxHeight: 280, overflowY: "auto" }}>
          <table className="table small">
            <thead><tr><th /><th>Item</th><th>Where</th></tr></thead>
            <tbody>{hits.map((h, i) => (
              <tr key={i}>
                <td><input type="checkbox" disabled={!!h.folder && !h.account} checked={selected.has(i)} onChange={() => { const s = new Set(selected); if (s.has(i)) s.delete(i); else s.add(i); setSelected(s); }} /></td>
                <td className={h.account ? "" : "mono"}>{h.path}</td>
                <td>{h.account ? `${h.kind} · ${h.account}` : h.image_id.slice(0, 8)}</td>
              </tr>))}
            </tbody>
          </table>
        </div>}
        {cs.status === "open" && <button className="btn primary" style={{ marginTop: 8 }} disabled={!selected.size || !!busy} onClick={exportSelected}><Download size={14} /> Export {selected.size || ""} selected</button>}
      </>}
      <h4 style={{ marginTop: 14 }}>Exports</h4>
      {!cs.exports?.length ? <div className="faint small">No exports yet.</div> : (
        <table className="table small">
          <thead><tr><th>What</th><th>State</th><th>Hashes</th><th /></tr></thead>
          <tbody>{cs.exports.map((e) => (
            <tr key={e.id}>
              <td>{e.what} of {e.machine}<div className="faint">{e.by}, {when(e.at)}</div></td>
              <td><Pill tone={e.state === "succeeded" ? "ok" : e.state === "failed" ? "bad" : "info"}>{e.state}</Pill></td>
              <td className="mono">{e.manifest_sha256 ? `manifest ${e.manifest_sha256.slice(0, 12)}… (${e.manifest_entries})` : ""}{e.receipts?.length ? <div>saved {e.receipts[e.receipts.length - 1].sha256.slice(0, 12)}…</div> : null}</td>
              <td>{keys.has(e.id) && e.state !== "failed" && <button className="btn sm" onClick={() => save(e)}>Download</button>}</td>
            </tr>))}
          </tbody>
        </table>
      )}
      {editing && <CaseEditor initial={cs} onClose={() => { setEditing(false); c.reload(); }} />}
      {closing && (
        <Modal title="Close the case" onClose={() => setClosing(false)}
          foot={<button className="btn danger" disabled={!password} onClick={() => run("Closing…", async () => { await api.post(`/api/cases/${id}/close`, { password }); setClosing(false); toast("ok", "Case closed: its holds are released"); })}>Close case</button>}>
          <p className="small">The holds this case placed are released, so retention can delete those backups again. Holds placed by hand or by other cases stay.</p>
          <Field label="Your password"><input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
        </Modal>
      )}
    </Modal>
  );
}
