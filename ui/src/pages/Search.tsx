// Search across backups (docs/design/search.md): each repository's job runs
// on a machine with access, over the file catalogues it keeps; only the
// matching names come back.
import { useMemo, useState } from "react";
import { FolderOpen, Search as SearchIcon } from "lucide-react";
import { api, type Image, type Job } from "../api";
import { bytes, when } from "../format";
import { Empty, Field, Notice, useApi } from "../ui";
import { FileBrowser } from "./Files";

interface Hit { image_id: string; volume: string; path: string; size: number; modified: number | null; folder: boolean }
interface SearchJob { id: string; agent_name: string; agent_online: boolean; images: number }

const FINAL = ["succeeded", "warning", "failed", "cancelled"];

export default function SearchPage() {
  const images = useApi<Image[]>("/api/images");
  const machines = useMemo(() => {
    const m = new Map<string, string>();
    for (const i of images.data ?? []) if (!m.has(i.machine_id)) m.set(i.machine_id, i.vm_name ?? i.hostname);
    return [...m.entries()].sort((a, b) => a[1].localeCompare(b[1]));
  }, [images.data]);
  const byId = useMemo(() => new Map((images.data ?? []).map((i) => [i.image_id, i])), [images.data]);
  const [query, setQuery] = useState("");
  const [machine, setMachine] = useState("");
  const [running, setRunning] = useState<SearchJob[]>([]);
  const [hits, setHits] = useState<Hit[] | null>(null);
  const [notes, setNotes] = useState<string[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<Image | null>(null);

  const go = async () => {
    setErr(null);
    setHits(null);
    setNotes([]);
    try {
      const r = await api.post<{ jobs: SearchJob[] }>("/api/search", { query: query.trim(), machine_id: machine || null });
      setRunning(r.jobs);
      const found: Hit[] = [];
      const extra: string[] = [];
      await Promise.all(r.jobs.map(async (sj) => {
        for (let n = 0; n < 400; n++) {
          const j = await api.get<Job>(`/api/jobs/${sj.id}`);
          if (FINAL.includes(j.state)) {
            const res = j.result as { hits?: Hit[]; not_indexed?: number; truncated?: boolean } | null;
            found.push(...(res?.hits ?? []));
            if (j.error) extra.push(`${sj.agent_name}: ${j.error}`);
            if (res?.not_indexed) extra.push(`${res.not_indexed} backups were not indexed in time and were not searched; search again shortly.`);
            if (res?.truncated) extra.push("Only the first 500 matches are shown: narrow the search.");
            break;
          }
          await new Promise((ok) => setTimeout(ok, 1500));
        }
      }));
      found.sort((a, b) => (byId.get(b.image_id)?.created ?? 0) - (byId.get(a.image_id)?.created ?? 0));
      setHits(found);
      setNotes(extra);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setRunning([]);
    }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Search backups</h1>
          <div className="sub">Find a file or folder by name across a machine's backups, then restore it.</div>
        </div>
      </div>
      <div className="card card-body">
        <div className="row wrap" style={{ gap: 12, alignItems: "flex-start" }}>
          <Field label="Name or pattern" hint="Part of a name, or a pattern such as *.xlsx or budget*2026*.">
            <input className="input" value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => e.key === "Enter" && query.trim() && go()} style={{ minWidth: 280 }} />
          </Field>
          <Field label="In">
            <select className="input" value={machine} onChange={(e) => setMachine(e.target.value)}>
              <option value="">Every machine</option>
              {machines.map(([id, name]) => <option key={id} value={id}>{name}</option>)}
            </select>
          </Field>
          <button className="btn primary" style={{ marginTop: 24 }} disabled={!query.trim() || running.length > 0} onClick={go}><SearchIcon size={15} /> Search</button>
        </div>
        {running.length > 0 && <div className="muted small" style={{ marginTop: 10 }}>Searching on {running.map((r) => `${r.agent_name}${r.agent_online ? "" : " (offline: waits for it)"}`).join(", ")}…</div>}
      </div>
      {err && <Notice tone="bad">{err}</Notice>}
      {notes.map((n, i) => <Notice key={i} tone="warn">{n}</Notice>)}
      {hits && (hits.length === 0 ? <div className="card"><Empty icon={<SearchIcon size={24} />} title="Nothing found">No file or folder in these backups matches.</Empty></div> : (
        <div className="card table-wrap">
          <table className="table">
            <thead><tr><th>Name</th><th>Backup</th><th style={{ textAlign: "right" }}>Size</th><th /></tr></thead>
            <tbody>
              {hits.map((h, i) => {
                const im = byId.get(h.image_id);
                return (
                  <tr key={i}>
                    <td><span className="mono small">{h.volume} {h.path}</span>{h.folder && <span className="faint small"> (folder)</span>}</td>
                    <td className="nowrap">{im ? <>{im.vm_name ?? im.hostname}<div className="faint small">{when(im.created)}</div></> : h.image_id.slice(0, 8)}</td>
                    <td style={{ textAlign: "right" }}>{h.folder ? "" : bytes(h.size)}</td>
                    <td style={{ textAlign: "right" }}>{im && <button className="btn sm" onClick={() => setOpen(im)}><FolderOpen size={13} /> Open</button>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ))}
      {open && <FileBrowser image={open} onClose={() => setOpen(null)} />}
    </div>
  );
}
