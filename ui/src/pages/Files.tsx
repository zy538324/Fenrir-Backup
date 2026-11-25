// File-level restore: browse the files inside a backup and restore chosen files or folders, without restoring the
// disk. A machine with access to the repository reads the backup with the key it was given; this server only relays
// folder listings (kept a day) and never sees file contents.
import { useEffect, useMemo, useState } from "react";
import { Download, File, Folder, FolderOpen, Link2, Loader2, RotateCcw } from "lucide-react";
import { downloadKey } from "../seal";
import { api, guardInfected, type Agent, type Image, type Job, type Repository } from "../api";
import { bytes, when } from "../format";
import { Field, Modal, Notice, useApi, useToast } from "../ui";

interface Volume { disk: number; partition: number; filesystem: string; size: number; mount_points: string[]; name: string; browsable: boolean; note?: string }
interface Entry { name: string; kind: "file" | "dir" | "link" | "other"; size: number; modified?: number; hidden: boolean }
interface Listing { path: string; entries: Entry[]; truncated: boolean; total: number }

const FINAL = ["succeeded", "warning", "failed", "cancelled"];
const FS: Record<string, string> = { ntfs: "NTFS", ext: "ext4", fat32: "FAT32", exfat: "exFAT", xfs: "XFS", btrfs: "Btrfs", refs: "ReFS", bitlocker: "BitLocker", luks: "LUKS", swap: "swap" };
const label = (v: Volume) => v.mount_points[0] || v.name || `Disk ${v.disk + 1}, partition ${v.partition}`;
const join = (dir: string, name: string) => `${dir.replace(/\/+$/, "")}/${name}`;

/** Poll a job quickly: browsing is interactive (the machine polls every second meanwhile). */
export async function waitFast(id: string, onProgress?: (j: Job) => void, seconds = 180, base = "/api"): Promise<Job> {
  const until = Date.now() + seconds * 1000;
  while (Date.now() < until) {
    await new Promise((r) => setTimeout(r, 700));
    const j = await api.get<Job>(`${base}/jobs/${id}`);
    if (FINAL.includes(j.state)) {
      if (j.state === "failed" || j.state === "cancelled") throw new Error(j.error || `the job was ${j.state}`);
      return j;
    }
    onProgress?.(j);
  }
  throw new Error("The machine did not answer in time. Is it online, or busy with another job (see Activity)?");
}

/**
 * Browse a backup's files. `selfService`: a restore user's view (their own
 * machines' backups, through /api/self): files can only be downloaded here.
 */
export function FileBrowser({ image, onClose, selfService }: { image: Image; onClose: () => void; selfService?: boolean }) {
  const base = selfService ? "/api/self" : "/api";
  const toast = useToast();
  const [agentId, setAgentId] = useState<string | undefined>();
  const [agentName, setAgentName] = useState("");
  const [volumes, setVolumes] = useState<Volume[] | null>(null);
  const [volume, setVolume] = useState<Volume | null>(null);
  const [listing, setListing] = useState<Listing | null>(null);
  const [busy, setBusy] = useState<string | null>("Opening the backup…");
  const [err, setErr] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [hidden, setHidden] = useState(false);
  const [filter, setFilter] = useState("");
  const [restoring, setRestoring] = useState(false);

  const request = async (body: Record<string, unknown>, what: string) => {
    setBusy(what);
    setErr(null);
    try {
      const r = await api.post<{ id: string; agent_id: string; agent_name: string; agent_online: boolean }>(`${base}/images/${image.image_id}/browse`, { ...body, agent_id: selfService ? null : agentId });
      setAgentId(r.agent_id);
      setAgentName(r.agent_name);
      if (!r.agent_online) setBusy(`${what} ${r.agent_name} is offline; waiting for it…`);
      return (await waitFast(r.id, undefined, 180, base)).result as { volumes?: Volume[]; listing?: Listing };
    } catch (e) {
      setErr((e as Error).message);
      return null;
    } finally {
      setBusy(null);
    }
  };
  const open = async (v: Volume, path = "/") => {
    const res = await request({ disk: v.disk, partition: v.partition, path }, `Reading ${path === "/" ? label(v) : path}…`);
    if (res?.listing) {
      setVolume(v);
      setListing(res.listing);
      setFilter("");
    }
  };
  useEffect(() => {
    (async () => {
      const res = await request({}, "Opening the backup…");
      if (!res?.volumes) return;
      setVolumes(res.volumes);
      const ok = res.volumes.filter((v) => v.browsable);
      const pick = ok.length === 1 ? ok[0] : ok.find((v) => v.mount_points.some((m) => /^c:\\?$/i.test(m)));
      if (pick) await open(pick);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const path = listing?.path ?? "/";
  const crumbs = path.split("/").filter(Boolean);
  const rows = (listing?.entries ?? []).filter((e) => (hidden || !e.hidden) && (!filter || e.name.toLowerCase().includes(filter.toLowerCase())));
  const here = rows.filter((e) => e.kind === "file" || e.kind === "dir").map((e) => join(path, e.name));
  const all = here.length > 0 && here.every((p) => selected.has(p));
  const toggle = (p: string) => setSelected((s) => { const n = new Set(s); if (n.has(p)) n.delete(p); else n.add(p); return n; });

  return (
    <Modal wide title={`Files in ${image.vm_name ?? image.hostname}`} sub={`Backup from ${when(image.created)} · read by ${agentName || "a machine with access"}; nothing is changed until you restore`} onClose={onClose}
      foot={volume && <>
        <span className="faint small grow">{selected.size ? `${selected.size} selected` : "Tick files or folders to restore them"}</span>
        {selected.size > 0 && <button className="btn" onClick={() => setSelected(new Set())}>Clear</button>}
        {selfService
          ? <button className="btn primary" disabled={!selected.size || !!busy} onClick={async () => {
              if (!volume) return;
              setBusy("Preparing the download…");
              setErr(null);
              try {
                const name = await downloadToBrowser(base, image, volume, [...selected].sort(), (m) => setBusy(m));
                if (name) toast("ok", `Downloaded ${name}`);
              } catch (e) {
                setErr((e as Error).message);
              } finally {
                setBusy(null);
              }
            }}><Download size={14} /> Download {selected.size || ""}</button>
          : <button className="btn primary" disabled={!selected.size} onClick={() => setRestoring(true)}><RotateCcw size={14} /> Restore {selected.size || ""}…</button>}
      </>}>
      {err && <Notice tone="bad">{err}</Notice>}
      {busy && <div className="row small muted" style={{ gap: 6, margin: "6px 0" }}><Loader2 size={14} className="spin" /> {busy}</div>}
      {volumes && (
        <div className="row wrap" style={{ gap: 6, marginBottom: 10 }}>
          {volumes.map((v) => (
            <button key={`${v.disk}-${v.partition}`} className={`btn sm${volume === v ? " primary" : ""}`} disabled={!v.browsable || !!busy} title={v.note ?? ""} onClick={() => { setSelected(new Set()); open(v); }}>
              {label(v)} <span className="faint">{FS[v.filesystem] ?? v.filesystem} · {bytes(v.size)}</span>
            </button>
          ))}
        </div>
      )}
      {volumes && !volume && !busy && <div className="faint small">{volumes.some((v) => v.browsable) ? "Choose a volume." : `None of these volumes can be browsed. ${volumes.find((v) => v.note)?.note ?? ""}`}</div>}
      {volume && listing && (
        <>
          <div className="row wrap" style={{ gap: 4, marginBottom: 8 }}>
            <button className="btn sm ghost" disabled={!!busy} onClick={() => open(volume, "/")}>{label(volume)}</button>
            {crumbs.map((c, i) => <span key={i} className="row" style={{ gap: 4 }}>› <button className="btn sm ghost" disabled={!!busy || i === crumbs.length - 1} onClick={() => open(volume, "/" + crumbs.slice(0, i + 1).join("/"))}>{c}</button></span>)}
            <span className="grow" />
            <input className="input" style={{ width: 180 }} placeholder="Filter this folder" value={filter} onChange={(e) => setFilter(e.target.value)} />
            <label className="row small" style={{ gap: 4 }}><input type="checkbox" checked={hidden} onChange={(e) => setHidden(e.target.checked)} /> Hidden and system</label>
          </div>
          <div className="table-wrap" style={{ maxHeight: 420, overflowY: "auto" }}>
            <table className="table">
              <thead><tr>
                <th style={{ width: 28 }}><input type="checkbox" aria-label="Select all in this folder" checked={all} onChange={() => setSelected((s) => { const n = new Set(s); here.forEach((p) => (all ? n.delete(p) : n.add(p))); return n; })} /></th>
                <th>Name</th><th style={{ textAlign: "right" }}>Size</th><th>Modified</th>
              </tr></thead>
              <tbody>
                {path !== "/" && <tr style={{ cursor: "pointer" }} onClick={() => !busy && open(volume, "/" + crumbs.slice(0, -1).join("/"))}><td /><td><FolderOpen size={14} /> ..</td><td /><td /></tr>}
                {rows.map((e) => {
                  const full = join(path, e.name);
                  return (
                    <tr key={e.name} style={{ cursor: e.kind === "dir" ? "pointer" : undefined, opacity: e.hidden ? 0.65 : 1 }} onClick={() => e.kind === "dir" && !busy && open(volume, full)}>
                      <td onClick={(ev) => ev.stopPropagation()}>{(e.kind === "file" || e.kind === "dir") && <input type="checkbox" aria-label={`Select ${e.name}`} checked={selected.has(full)} onChange={() => toggle(full)} />}</td>
                      <td>{e.kind === "dir" ? <Folder size={14} /> : e.kind === "link" ? <Link2 size={14} /> : <File size={14} />} {e.name}</td>
                      <td style={{ textAlign: "right" }} className="small">{e.kind === "dir" ? "" : bytes(e.size)}</td>
                      <td className="small nowrap">{e.modified ? when(e.modified) : "—"}</td>
                    </tr>
                  );
                })}
                {rows.length === 0 && <tr><td colSpan={4} className="faint small">{filter ? "Nothing matches." : "Empty folder."}</td></tr>}
              </tbody>
            </table>
          </div>
          {listing.truncated && <div className="faint small">Showing the first {listing.entries.length} of {listing.total}; use the filter to find others.</div>}
        </>
      )}
      {restoring && volume && <RestoreFiles image={image} volume={volume} paths={[...selected].sort()} reader={agentId} onClose={(done) => { setRestoring(false); if (done) setSelected(new Set()); }} />}
    </Modal>
  );
}

/** Files from a backup, encrypted by the machine for a key made in this browser, saved as a .tar. */
async function downloadToBrowser(base: string, image: Image, volume: Volume, paths: string[], progress: (m: string) => void): Promise<string | null> {
  const k = await downloadKey();
  const r = await guardInfected((allow_infected) => api.post<{ id: string }>(`${base}/images/${image.image_id}/download-files`, {
    agent_id: null, disk: volume.disk, partition: volume.partition, paths, recipient: k.publicB64, allow_infected,
  }));
  if (r === null) return null;
  const job = await waitFast(r.id, (j) => progress(j.progress ? `${j.progress.phase} ${j.progress.message ?? ""}` : "Preparing…"), 24 * 3600, base);
  const header = (job.result as { download: { sealed_key: import("../seal").Sealed; file_name: string } }).download;
  progress("Downloading and decrypting…");
  const resp = await fetch(`${base}/jobs/${r.id}/download`, { credentials: "same-origin" });
  if (!resp.ok) throw new Error(`download failed (${resp.status})`);
  const plain = await k.decrypt(header, await resp.arrayBuffer());
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([plain], { type: "application/x-tar" }));
  a.download = header.file_name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
  return header.file_name;
}

interface Report { target: string; files: number; bytes: number; skipped: number; renamed: number; failed: { path: string; error: string }[]; failed_total: number }

function RestoreFiles({ image, volume, paths, reader, onClose }: { image: Image; volume: Volume; paths: string[]; reader?: string; onClose: (done: boolean) => void }) {
  const toast = useToast();
  const agents = useApi<Agent[]>("/api/agents");
  const repos = useApi<Repository[]>("/api/repositories");
  const repo = repos.data?.find((r) => r.id === image.repository_id);
  const pool = useMemo(() => (agents.data ?? []).filter((a) => repo?.agents.some((x) => x.id === a.id) && a.capabilities.includes("restore_files")), [agents.data, repo]);
  const [agentId, setAgentId] = useState("");
  const agent = pool.find((a) => a.id === (agentId || image.agent_id || reader)) ?? pool[0];
  const original = volume.mount_points[0];
  // A Hyper-V VM's image belongs to its host's agent: "original location" would be the host, not the VM.
  const same = agent && agent.id === image.agent_id && !image.vm_name;
  const [where, setWhere] = useState<"folder" | "original">("folder");
  const stamp = new Date(image.created * 1000).toISOString().slice(0, 10);
  const fallback = agent?.os.family === "windows" ? `C:\\Restored\\${stamp}` : `/var/tmp/restored/${stamp}`;
  const [folder, setFolder] = useState("");
  const [keep, setKeep] = useState(true);
  const [conflict, setConflict] = useState<"rename" | "skip" | "overwrite">("rename");
  const [state, setState] = useState<{ busy?: boolean; job?: Job; err?: string; progress?: string }>({});
  const target = where === "original" ? original : folder.trim() || fallback;
  const go = async () => {
    setState({ busy: true });
    try {
      const r = await guardInfected((allow_infected) => api.post<{ id: string }>(`/api/images/${image.image_id}/restore-files`, {
        agent_id: agent!.id, disk: volume.disk, partition: volume.partition, paths, target,
        keep_structure: where === "original" ? true : keep, conflict, allow_infected,
      }));
      if (r === null) return setState({});
      const { id } = r;
      const job = await waitFast(id, (j) => setState({ busy: true, progress: j.progress?.message }), 24 * 3600);
      setState({ job });
      toast("ok", "Files restored");
    } catch (e) {
      setState({ err: (e as Error).message });
    }
  };
  // Download to this browser: the machine encrypts the files for a key made here; the server relays ciphertext.
  const download = async () => {
    setState({ busy: true, progress: "Preparing…" });
    try {
      const k = await downloadKey();
      const r = await guardInfected((allow_infected) => api.post<{ id: string }>(`/api/images/${image.image_id}/download-files`, {
        agent_id: agent!.id, disk: volume.disk, partition: volume.partition, paths, recipient: k.publicB64, allow_infected,
      }));
      if (r === null) return setState({});
      const { id } = r;
      const job = await waitFast(id, (j) => setState({ busy: true, progress: j.progress ? `${j.progress.phase} ${j.progress.message ?? ""}` : undefined }), 24 * 3600);
      if (job.state !== "succeeded" && job.state !== "warning") throw new Error(job.error || "the machine could not prepare the files");
      const header = (job.result as { download: { sealed_key: import("../seal").Sealed; file_name: string } }).download;
      setState({ busy: true, progress: "Downloading and decrypting…" });
      const resp = await fetch(`/api/jobs/${id}/download`, { credentials: "same-origin" });
      if (!resp.ok) throw new Error(`download failed (${resp.status})`);
      const plain = await k.decrypt(header, await resp.arrayBuffer());
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([plain], { type: "application/x-tar" }));
      a.download = header.file_name;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
      setState({});
      toast("ok", `Downloaded ${header.file_name}`);
    } catch (e) {
      setState({ err: (e as Error).message });
    }
  };
  const r = state.job?.result as Report | undefined;
  return (
    <Modal title={`Restore ${paths.length} item${paths.length === 1 ? "" : "s"}`} onClose={() => onClose(!!state.job)}
      foot={state.job ? <button className="btn primary" onClick={() => onClose(true)}>Done</button>
        : <>
          <button className="btn" disabled={!agent || state.busy} onClick={download} title="The machine encrypts the files for this browser; the server only relays them (up to 4 GiB, as a .tar)"><Download size={14} /> Download here</button>
          <button className={`btn ${conflict === "overwrite" ? "danger" : "primary"}`} disabled={!agent || state.busy || !target} onClick={go}>{state.busy ? <Loader2 size={14} className="spin" /> : <RotateCcw size={14} />} Restore</button>
        </>}>
      <div className="mono small" style={{ maxHeight: 90, overflowY: "auto", marginBottom: 10 }}>{paths.map((p) => <div key={p}>{p}</div>)}</div>
      {!state.job && (
        <div className="stack tight">
          <Field label="Restore on">
            <select className="input" value={agent?.id ?? ""} onChange={(e) => { setAgentId(e.target.value); setWhere("folder"); }}>
              {pool.length === 0 && <option value="">No machine with access can restore files</option>}
              {pool.map((a) => <option key={a.id} value={a.id}>{a.name}{a.id === image.agent_id ? " (where the backup came from)" : ""}{a.online ? "" : " (offline)"}</option>)}
            </select>
          </Field>
          <Field label="To">
            <select className="input" value={where} onChange={(e) => setWhere(e.target.value as "folder" | "original")}>
              <option value="folder">A folder</option>
              {original && same && <option value="original">Original location ({original})</option>}
            </select>
          </Field>
          {where === "folder" && <Field label={`Folder on ${agent?.name ?? "the machine"}`}><input className="input" value={folder} placeholder={fallback} onChange={(e) => setFolder(e.target.value)} /></Field>}
          <Field label="If a file already exists">
            <select className="input" value={conflict} onChange={(e) => setConflict(e.target.value as "rename" | "skip" | "overwrite")}>
              <option value="rename">Keep both (the backup copy gets “(restored)”)</option>
              <option value="skip">Skip it</option>
              <option value="overwrite">Replace it with the backup copy</option>
            </select>
          </Field>
          {where === "folder" && <label className="row small" style={{ gap: 6 }}><input type="checkbox" checked={keep} onChange={(e) => setKeep(e.target.checked)} /> Recreate the original folders inside it</label>}
        </div>
      )}
      {state.busy && <div className="small muted" style={{ marginTop: 8 }}>{state.progress || `Waiting for ${agent?.name}…`}</div>}
      {state.err && <Notice tone="bad">{state.err}</Notice>}
      {state.job && r && (
        <Notice tone={state.job.state === "succeeded" ? "ok" : "warn"}>
          {r.files} file{r.files === 1 ? "" : "s"} ({bytes(r.bytes)}) restored to <span className="mono">{r.target}</span> on {agent?.name}.
          {r.renamed > 0 && ` ${r.renamed} written beside an existing file.`}{r.skipped > 0 && ` ${r.skipped} skipped.`}
          {r.failed_total > 0 && <div className="small" style={{ marginTop: 6 }}><b>{r.failed_total} could not be restored:</b>{r.failed.map((f, i) => <div key={i}><span className="mono">{f.path}</span>: {f.error}</div>)}</div>}
        </Notice>
      )}
    </Modal>
  );
}
