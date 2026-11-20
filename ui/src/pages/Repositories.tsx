import { useMemo, useState } from "react";
import { Database, Download, KeyRound, Lock, Plus, ShieldCheck, Trash2, UserPlus, X } from "lucide-react";
import { api, type Agent, type Repository } from "../api";
import { ago, bytes, passwordStrength } from "../format";
import { newRecoveryKey, seal, sealSupported } from "../seal";
import { Empty, Field, Loading, Modal, Notice, Pill, useApi, useToast } from "../ui";

export default function RepositoriesPage() {
  const repos = useApi<Repository[]>("/api/repositories", 5000);
  const agents = useApi<Agent[]>("/api/agents");
  const [creating, setCreating] = useState(false);
  const [granting, setGranting] = useState<Repository | null>(null);
  const toast = useToast();

  if (!repos.data || !agents.data) return <div className="page"><Loading /></div>;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Repositories</h1>
          <div className="sub">Where backups are stored. Data is encrypted on each machine before it is written.</div>
        </div>
        <button className="btn primary right" onClick={() => setCreating(true)} disabled={agents.data.length === 0}>
          <Plus size={16} /> New repository
        </button>
      </div>

      {repos.data.length === 0 ? (
        <div className="card">
          <Empty
            icon={<Database size={26} />}
            title="No repositories yet"
            action={agents.data.length === 0 ? <span className="muted small">Add a machine first: a machine creates the repository.</span> : <button className="btn primary" onClick={() => setCreating(true)}>Create a repository</button>}
          >
            A repository is a folder on a NAS share, a USB disk or a backup server. Many machines can share one, and identical data is stored only once.
          </Empty>
        </div>
      ) : (
        <div className="grid cols-2">
          {repos.data.map((r) => (
            <div key={r.id} className="card">
              <div className="card-head">
                <div className="hero-icon info" style={{ width: 36, height: 36, borderRadius: 10 }}><Database size={18} /></div>
                <div className="grow">
                  <h2 className="ellipsis">{r.name}</h2>
                  <div className="mono faint ellipsis">{r.path}</div>
                </div>
                {r.status === "ready" ? <Pill tone="ok">Ready</Pill> : r.status === "pending" ? <Pill tone="info" pulse>Creating…</Pill> : <Pill tone="bad">Failed</Pill>}
              </div>
              <div className="card-body stack">
                {r.status === "failed" && <Notice tone="bad">{r.status_message ?? "The machine could not create the repository."}</Notice>}
                <div className="grid cols-3" style={{ gap: 10 }}>
                  <div><div className="faint small">Images</div><div style={{ fontWeight: 650, fontSize: 18 }}>{r.images}</div></div>
                  <div><div className="faint small">Stored</div><div style={{ fontWeight: 650, fontSize: 18 }}>{bytes(r.stored_bytes)}</div></div>
                  <div><div className="faint small">Last backup</div><div style={{ fontWeight: 650, fontSize: 18 }}>{ago(r.last_image)}</div></div>
                </div>
                <div>
                  <div className="faint small" style={{ marginBottom: 6 }}>Machines with access</div>
                  <div className="chips">
                    {r.agents.map((a) => (
                      <span key={a.id} className="chip on" style={{ cursor: "default", display: "inline-flex", alignItems: "center", gap: 4 }}>
                        {a.name}
                        <button
                          className="icon-btn"
                          style={{ padding: 0 }}
                          aria-label={`Remove access for ${a.name}`}
                          onClick={async () => {
                            if (!confirm(`Remove ${a.name}'s access to ${r.name}? Its plans for this repository are paused.`)) return;
                            await api.del(`/api/repositories/${r.id}/access/${a.id}`);
                            repos.reload();
                          }}
                        >
                          <X size={12} />
                        </button>
                      </span>
                    ))}
                    <button className="chip" onClick={() => setGranting(r)}><UserPlus size={12} style={{ verticalAlign: -1 }} /> Give access</button>
                  </div>
                </div>
                <div className="row">
                  <span className="faint small mono">ID {r.repo_uuid.slice(0, 8)}</span>
                  <button
                    className="btn sm ghost danger right"
                    onClick={async () => {
                      if (!confirm(`Forget ${r.name}? The server stops using it. The data in ${r.path} is not deleted.`)) return;
                      try {
                        await api.del(`/api/repositories/${r.id}`);
                        repos.reload();
                      } catch (e) {
                        toast("bad", (e as Error).message);
                      }
                    }}
                  >
                    <Trash2 size={13} /> Forget
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {creating && <CreateWizard agents={agents.data} onClose={() => setCreating(false)} onDone={() => { setCreating(false); repos.reload(); }} />}
      {granting && <GrantDialog repo={granting} agents={agents.data} onClose={() => setGranting(null)} onDone={() => { setGranting(null); repos.reload(); }} />}
    </div>
  );
}

function PassphraseFields({ value, onChange, confirm, onConfirm }: { value: string; onChange: (v: string) => void; confirm: string; onConfirm: (v: string) => void }) {
  const s = passwordStrength(value);
  return (
    <>
      <Field label="Repository passphrase" hint="At least 12 characters. Every machine using this repository needs it; you type it here only.">
        <input className="input" type="password" autoComplete="new-password" value={value} onChange={(e) => onChange(e.target.value)} />
        <div className={`meter s${s}`} aria-hidden="true"><span /><span /><span /><span /></div>
      </Field>
      <Field label="Confirm passphrase">
        <input className={`input${confirm && confirm !== value ? " invalid" : ""}`} type="password" autoComplete="new-password" value={confirm} onChange={(e) => onConfirm(e.target.value)} />
      </Field>
    </>
  );
}

function CreateWizard({ agents, onClose, onDone }: { agents: Agent[]; onClose: () => void; onDone: () => void }) {
  const [step, setStep] = useState(1);
  const [name, setName] = useState("Main backups");
  const [path, setPath] = useState("");
  const [creator, setCreator] = useState(agents.find((a) => a.online)?.id ?? agents[0]?.id ?? "");
  const [others, setOthers] = useState<string[]>([]);
  const [pass, setPass] = useState("");
  const [pass2, setPass2] = useState("");
  const [saved, setSaved] = useState(false);
  const [downloaded, setDownloaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const recovery = useMemo(() => newRecoveryKey(), []);
  const creatorAgent = agents.find((a) => a.id === creator);
  const winPath = creatorAgent?.os.family === "windows";

  const download = () => {
    const blob = new Blob([recovery.fileContents], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `fenrir-recovery-${name.replace(/[^\w-]+/g, "-").toLowerCase()}-${recovery.repoId.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    setDownloaded(true);
  };

  const create = async () => {
    setBusy(true);
    setErr(null);
    try {
      if (!sealSupported()) throw new Error("This browser cannot encrypt secrets (WebCrypto unavailable). Open the server over HTTPS in a current browser.");
      const ids = [creator, ...others.filter((o) => o !== creator)];
      const access = await Promise.all(
        ids.map(async (id) => {
          const a = agents.find((x) => x.id === id)!;
          const secret = JSON.stringify({ passphrase: pass, recovery_key: id === creator ? recovery.fileContents : null });
          return { agent_id: id, sealed: await seal(a.public_key, secret) };
        }),
      );
      await api.post("/api/repositories", { name, path, repo_uuid: recovery.repoId, init_agent_id: creator, access });
      onDone();
    } catch (e) {
      const m = (e as Error).message;
      setErr(m.includes("X25519") || m.includes("Algorithm") ? "This browser does not support X25519 encryption yet. Use a current Chrome, Edge, Firefox or Safari." : m);
    } finally {
      setBusy(false);
    }
  };

  const steps = ["Location", "Passphrase", "Recovery key"];
  return (
    <Modal
      wide
      title="New repository"
      sub={
        <div className="row" style={{ gap: 6, marginTop: 6 }}>
          {steps.map((s, i) => (
            <span key={s} className={`pill ${i + 1 === step ? "info" : i + 1 < step ? "ok" : "neutral"}`}>{i + 1}. {s}</span>
          ))}
        </div>
      }
      onClose={onClose}
      foot={
        <>
          {step > 1 && <button className="btn" onClick={() => setStep(step - 1)}>Back</button>}
          <span className="grow" />
          {step === 1 && <button className="btn primary" disabled={!name.trim() || !path.trim() || !creator} onClick={() => setStep(2)}>Continue</button>}
          {step === 2 && <button className="btn primary" disabled={pass.length < 12 || pass !== pass2} onClick={() => setStep(3)}>Continue</button>}
          {step === 3 && <button className="btn primary" disabled={!saved || busy} onClick={create}><Lock size={15} /> {busy ? "Encrypting…" : "Create repository"}</button>}
        </>
      }
    >
      {err && <Notice tone="bad">{err}</Notice>}
      {step === 1 && (
        <>
          <Field label="Name"><input className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={60} /></Field>
          <Field label="Created by" hint="This machine creates the repository folder and must be able to write to it.">
            <select className="input" value={creator} onChange={(e) => setCreator(e.target.value)}>
              {agents.map((a) => <option key={a.id} value={a.id}>{a.name}{a.online ? "" : " (offline)"}</option>)}
            </select>
          </Field>
          <Field label="Folder" hint={winPath ? "As this machine sees it: a local folder like D:\\Backups\\Fenrir or a share like \\\\nas\\backups\\fenrir. The folder must be new or empty." : "As this machine sees it, e.g. /mnt/nas/fenrir. The folder must be new or empty."}>
            <input className="input mono" placeholder={winPath ? "\\\\nas\\backups\\fenrir" : "/mnt/backups/fenrir"} value={path} onChange={(e) => setPath(e.target.value)} />
          </Field>
          {agents.length > 1 && (
            <Field label="Other machines that back up here" hint="You can add more later.">
              <div className="chips">
                {agents.filter((a) => a.id !== creator).map((a) => (
                  <button key={a.id} className={`chip${others.includes(a.id) ? " on" : ""}`} onClick={() => setOthers(others.includes(a.id) ? others.filter((x) => x !== a.id) : [...others, a.id])}>
                    {a.name}
                  </button>
                ))}
              </div>
            </Field>
          )}
        </>
      )}
      {step === 2 && (
        <>
          <Notice tone="info">
            The passphrase is encrypted in this browser for each chosen machine, so only those machines can read it. The Fenrir-Backup server stores only the encrypted copies and can never open your backups.
          </Notice>
          <PassphraseFields value={pass} onChange={setPass} confirm={pass2} onConfirm={setPass2} />
        </>
      )}
      {step === 3 && (
        <>
          <div className="row" style={{ alignItems: "flex-start", gap: 14 }}>
            <div className="hero-icon warn"><KeyRound size={24} /></div>
            <div className="grow stack tight">
              <h3 style={{ fontSize: 15 }}>Save your recovery key</h3>
              <div className="muted">If the passphrase is ever lost, this file is the only other way into the repository. It was made in this browser and has not been sent anywhere. Keep it offline, away from the backed-up machines: a USB stick in a drawer, or your password manager.</div>
            </div>
          </div>
          <button className="btn lg" onClick={download}><Download size={17} /> Download recovery key</button>
          {downloaded && <Notice tone="ok">Downloaded. Move it somewhere safe that is not on this network.</Notice>}
          <label className="check">
            <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
            <span>I have stored the recovery key safely. I understand that without the passphrase or this key, nobody can restore these backups.</span>
          </label>
        </>
      )}
    </Modal>
  );
}

function GrantDialog({ repo, agents, onClose, onDone }: { repo: Repository; agents: Agent[]; onClose: () => void; onDone: () => void }) {
  const candidates = agents.filter((a) => !repo.agents.some((x) => x.id === a.id));
  const [agent, setAgent] = useState(candidates[0]?.id ?? "");
  const [pass, setPass] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const toast = useToast();
  return (
    <Modal
      title={`Give a machine access to ${repo.name}`}
      onClose={onClose}
      foot={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button
            className="btn primary"
            disabled={!agent || !pass}
            onClick={async () => {
              try {
                const a = agents.find((x) => x.id === agent)!;
                const sealed = await seal(a.public_key, JSON.stringify({ passphrase: pass, recovery_key: null }));
                await api.post(`/api/repositories/${repo.id}/access`, { agent_id: agent, sealed });
                toast("ok", `${a.name} can now use ${repo.name}`);
                onDone();
              } catch (e) {
                setErr((e as Error).message);
              }
            }}
          >
            <ShieldCheck size={15} /> Give access
          </button>
        </>
      }
    >
      {err && <Notice tone="bad">{err}</Notice>}
      {candidates.length === 0 ? (
        <Notice tone="info">Every machine already has access.</Notice>
      ) : (
        <>
          <Field label="Machine">
            <select className="input" value={agent} onChange={(e) => setAgent(e.target.value)}>
              {candidates.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
            </select>
          </Field>
          <Field label="Repository passphrase" hint="Encrypted here for that machine only. If it is wrong, the machine's first backup reports it.">
            <input className="input" type="password" autoComplete="off" value={pass} onChange={(e) => setPass(e.target.value)} />
          </Field>
          <div className="muted small">The machine must be able to reach <span className="mono">{repo.path}</span>.</div>
        </>
      )}
    </Modal>
  );
}
