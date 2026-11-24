import { useEffect, useState } from "react";
import { BellRing, CheckCircle2, Mail, RefreshCw, Save, Send, Webhook, XCircle, Download } from "lucide-react";
import { api, type Delivery, type EmailSettings, type NotifySettings, type Settings, type WebhookSettings } from "../api";
import { when } from "../format";
import { Field, Loading, Notice, Switch, useApi, useToast } from "../ui";
import { ScanContentCard } from "./ScanContent";

const EMPTY_EMAIL: EmailSettings = { host: "", port: 587, security: "starttls", username: "", password: "", from: "", to: [] };
const EMPTY_HOOK: WebhookSettings = { url: "", format: "generic" };

export default function SettingsPage() {
  const s = useApi<Settings>("/api/settings");
  const log = useApi<Delivery[]>("/api/notifications", 10000);
  const [n, setN] = useState<NotifySettings | null>(null);
  const [emailOn, setEmailOn] = useState(false);
  const [hookOn, setHookOn] = useState(false);
  const [toText, setToText] = useState("");
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<{ channel: string; ok: boolean; error: string | null }[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const toast = useToast();

  useEffect(() => {
    if (s.data && !n) {
      const v = s.data.notifications;
      setN({ ...v, email: v.email ?? EMPTY_EMAIL, webhook: v.webhook ?? EMPTY_HOOK });
      setEmailOn(!!v.email);
      setHookOn(!!v.webhook);
      setToText((v.email?.to ?? []).join(", "));
    }
  }, [s.data, n]);

  if (!s.data || !n) return <div className="page"><Loading /></div>;
  const email = n.email!;
  const hook = n.webhook!;
  const setEmail = (e: Partial<EmailSettings>) => setN({ ...n, email: { ...email, ...e } });
  const setHook = (h: Partial<WebhookSettings>) => setN({ ...n, webhook: { ...hook, ...h } });

  const save = async () => {
    setBusy(true);
    setErr(null);
    try {
      await api.req("PUT", "/api/settings", {
        notifications: {
          ...n,
          email: emailOn ? { ...email, to: toText.split(/[,;\s]+/).filter(Boolean) } : null,
          webhook: hookOn ? hook : null,
        },
      });
      toast("ok", "Settings saved");
      s.reload();
      return true;
    } catch (e) {
      setErr((e as Error).message);
      return false;
    } finally {
      setBusy(false);
    }
  };

  const test = async () => {
    if (!(await save())) return;
    setResults(null);
    try {
      const r = await api.post<{ results: { channel: string; ok: boolean; error: string | null }[] }>("/api/settings/test-notification");
      setResults(r.results);
      log.reload();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <div className="sub">Alerts, and how agents are kept up to date.</div>
        </div>
      </div>
      {err && <Notice tone="bad">{err}</Notice>}

      <div className="card">
        <div className="card-head"><BellRing size={17} /><h2>Alerts</h2></div>
        <div className="card-body stack">
          <div className="muted">You are alerted when a backup fails, when a backup looks like ransomware, when a machine goes offline, and when a machine has no recent backup.</div>
          <div className="grid cols-3">
            <label className="check">
              <input type="checkbox" checked={n.on_warning} onChange={(e) => setN({ ...n, on_warning: e.target.checked })} />
              <span>Also alert on backups that finished with warnings</span>
            </label>
            <Field label="Machine offline after" hint="0 turns this alert off.">
              <div className="row"><input className="input" type="number" min={0} style={{ width: 90 }} value={n.offline_hours} onChange={(e) => setN({ ...n, offline_hours: Math.max(0, Number(e.target.value)) })} /><span className="muted">hours</span></div>
            </Field>
            <Field label="Backup overdue after" hint="For machines with an active plan. 0 turns this off.">
              <div className="row"><input className="input" type="number" min={0} style={{ width: 90 }} value={n.overdue_days} onChange={(e) => setN({ ...n, overdue_days: Math.max(0, Number(e.target.value)) })} /><span className="muted">days</span></div>
            </Field>
          </div>
        </div>
      </div>

      <div className="grid cols-2" style={{ alignItems: "start" }}>
        <div className="card">
          <div className="card-head"><Mail size={17} /><h2>Email</h2><span className="right"><Switch on={emailOn} onChange={setEmailOn} label="Email alerts" /></span></div>
          {emailOn && (
            <div className="card-body stack">
              <div className="grid" style={{ gridTemplateColumns: "1fr 100px" }}>
                <Field label="SMTP server"><input className="input" value={email.host} onChange={(e) => setEmail({ host: e.target.value })} placeholder="smtp.office365.com" /></Field>
                <Field label="Port"><input className="input" type="number" value={email.port} onChange={(e) => setEmail({ port: Number(e.target.value) })} /></Field>
              </div>
              <Field label="Encryption">
                <div className="seg" style={{ alignSelf: "flex-start" }}>
                  {(["starttls", "tls", "none"] as const).map((x) => (
                    <button key={x} className={email.security === x || (!email.security && x === "starttls") ? "on" : ""} onClick={() => setEmail({ security: x, port: x === "tls" ? 465 : x === "starttls" ? 587 : 25 })}>
                      {x === "starttls" ? "STARTTLS (587)" : x === "tls" ? "TLS (465)" : "None"}
                    </button>
                  ))}
                </div>
              </Field>
              <div className="grid cols-2">
                <Field label="Username"><input className="input" autoComplete="off" value={email.username} onChange={(e) => setEmail({ username: e.target.value })} /></Field>
                <Field label="Password" hint={email.has_password ? "Saved. Leave empty to keep it." : undefined}>
                  <input className="input" type="password" autoComplete="new-password" value={email.password} onChange={(e) => setEmail({ password: e.target.value })} />
                </Field>
              </div>
              <Field label="From"><input className="input" value={email.from} onChange={(e) => setEmail({ from: e.target.value })} placeholder="Fenrir-Backup <backup@example.com>" /></Field>
              <Field label="Send to" hint="Separate several addresses with commas."><input className="input" value={toText} onChange={(e) => setToText(e.target.value)} placeholder="it@example.com" /></Field>
            </div>
          )}
        </div>
        <div className="card">
          <div className="card-head"><Webhook size={17} /><h2>Webhook</h2><span className="right"><Switch on={hookOn} onChange={setHookOn} label="Webhook alerts" /></span></div>
          {hookOn && (
            <div className="card-body stack">
              <Field label="Format">
                <div className="seg" style={{ alignSelf: "flex-start" }}>
                  {(["slack", "teams", "generic"] as const).map((x) => (
                    <button key={x} className={hook.format === x ? "on" : ""} onClick={() => setHook({ format: x })}>{x === "generic" ? "JSON" : x === "slack" ? "Slack" : "Teams"}</button>
                  ))}
                </div>
              </Field>
              <Field label="URL" hint={hook.format === "generic" ? "Receives a JSON POST with severity, subject, body and link." : "The incoming-webhook URL from Slack or Teams."}>
                <input className="input mono" value={hook.url} onChange={(e) => setHook({ url: e.target.value })} placeholder="https://hooks.slack.com/services/…" />
              </Field>
            </div>
          )}
        </div>
      </div>

      <div className="row">
        <button className="btn primary" onClick={save} disabled={busy}><Save size={15} /> Save</button>
        <button className="btn" onClick={test} disabled={busy || (!emailOn && !hookOn)}><Send size={15} /> Save and send a test</button>
        {results?.map((r) => (
          <span key={r.channel} className={`pill ${r.ok ? "ok" : "bad"}`} title={r.error ?? ""}>
            {r.ok ? <CheckCircle2 size={13} /> : <XCircle size={13} />} {r.channel}: {r.ok ? "sent" : r.error}
          </span>
        ))}
      </div>

      <div className="card">
        <div className="card-head"><Download size={17} /><h2>Move to Fenrir Cloud</h2></div>
        <div className="card-body stack tight">
          <div className="muted small">Download the repositories and plans (no passphrases or sign-ins: those are only ever encrypted for machines). In Fenrir Cloud, add each repository as existing with its passphrase, then import this file to recreate the plans.</div>
          <div><button className="btn" onClick={async () => {
            const data = await api.get<unknown>("/api/export");
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
            const a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = "fenrir-backup-export.json";
            a.click();
            URL.revokeObjectURL(a.href);
          }}><Download size={15} /> Download export</button></div>
        </div>
      </div>
      <div className="card">
        <div className="card-head"><RefreshCw size={17} /><h2>Agent updates</h2><span className="right"><Switch on={s.data.auto_update} label="Automatic agent updates" onChange={async (v) => { await api.req("PUT", "/api/settings", { auto_update: v }); s.reload(); }} /></span></div>
        <div className="card-body muted">
          {s.data.auto_update
            ? "Agents install the build this server carries when it differs from theirs, between jobs, after checking its SHA-256. Upgrading the server upgrades every machine."
            : "Agents keep their current build. Reinstall them to upgrade."}
        </div>
      </div>

      {log.data && log.data.length > 0 && (
        <div className="card table-wrap">
          <div className="card-head"><h2>Recent alerts</h2></div>
          <table className="table">
            <thead><tr><th>When</th><th>Channel</th><th>Subject</th><th>Result</th></tr></thead>
            <tbody>
              {log.data.slice(0, 20).map((d, i) => (
                <tr key={i}>
                  <td className="nowrap">{when(d.at)}</td>
                  <td>{d.channel}</td>
                  <td>{d.subject}</td>
                  <td>{d.ok ? <span className="pill ok">sent</span> : <span className="pill bad" title={d.error ?? ""}>{d.error}</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <ScanContentCard />
    </div>
  );
}
