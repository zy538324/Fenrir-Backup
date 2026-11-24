// The detection content malware scans of backups use: YARA rules and
// SHA-256 hashes of known malicious files, kept by the administrator.
import { useEffect, useState } from "react";
import { Plus, Save, ShieldCheck, Trash2 } from "lucide-react";
import { api } from "../api";
import { Field, Loading, Notice, Switch, useApi, useToast } from "../ui";

interface Rule { name: string; source: string; enabled: boolean }
interface Content { rules: Rule[]; indicators: string[] }

export function ScanContentCard() {
  const c = useApi<Content>("/api/scan-content");
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [hashes, setHashes] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const toast = useToast();
  useEffect(() => {
    if (c.data && rules === null) {
      setRules(c.data.rules);
      setHashes(c.data.indicators.join("\n"));
    }
  }, [c.data, rules]);
  if (!rules) return <div className="card"><Loading /></div>;
  const save = async () => {
    setBusy(true);
    setErr(null);
    try {
      const r = await api.req<{ rules: number; indicators: number }>("PUT", "/api/scan-content", {
        rules,
        indicators: hashes.split(/[\s,]+/).map((h) => h.trim()).filter(Boolean),
      });
      toast("ok", `Saved: ${r.rules} rules, ${r.indicators} hashes`);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="card">
      <div className="card-head"><ShieldCheck size={17} /><h2>Malware scans of backups</h2></div>
      <div className="card-body stack">
      <div className="muted small">
        Scans check the files inside backups against these YARA rules and SHA-256 hashes, on a machine with access to the repository. Paste rules from your own threat intelligence or a trusted rule set; nothing is downloaded automatically.
      </div>
      {err && <Notice tone="bad">{err}</Notice>}
      {rules.map((r, i) => (
        <div key={i} className="card" style={{ padding: 12 }}>
          <div className="row" style={{ gap: 8 }}>
            <input className="input" value={r.name} placeholder="Rule file name" onChange={(e) => setRules(rules.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)))} style={{ maxWidth: 300 }} />
            <Switch on={r.enabled} label={`Use ${r.name}`} onChange={(v) => setRules(rules.map((x, j) => (j === i ? { ...x, enabled: v } : x)))} />
            <button className="icon-btn right" aria-label="Remove rule" onClick={() => setRules(rules.filter((_, j) => j !== i))}><Trash2 size={15} /></button>
          </div>
          <textarea className="input mono" rows={6} value={r.source} onChange={(e) => setRules(rules.map((x, j) => (j === i ? { ...x, source: e.target.value } : x)))} placeholder={"rule example {\n  strings: $a = \"...\"\n  condition: $a\n}"} style={{ marginTop: 8 }} />
        </div>
      ))}
      <button className="btn" style={{ alignSelf: "flex-start" }} onClick={() => setRules([...rules, { name: `rules-${rules.length + 1}`, source: "", enabled: true }])}><Plus size={15} /> Add YARA rules</button>
      <Field label="Known malicious files (SHA-256)" hint="One hash per line.">
        <textarea className="input mono" rows={5} value={hashes} onChange={(e) => setHashes(e.target.value)} />
      </Field>
      <button className="btn primary" style={{ alignSelf: "flex-start" }} disabled={busy} onClick={save}><Save size={15} /> Save scan content</button>
      </div>
    </div>
  );
}
