import { useMemo, useState } from "react";
import { Database, Download, KeyRound, Lock, PauseCircle, Plus, ShieldAlert, ShieldCheck, Sparkles, Trash2, UserPlus, X, Network } from "lucide-react";
import { api, type Agent, type Repository } from "../api";
import { ago, bytes, passwordStrength, when } from "../format";
import { newRecoveryKey, seal, sealSupported } from "../seal";
import { Empty, Field, Loading, Modal, Notice, Pill, useApi, useToast } from "../ui";
import { BootVerification } from "./Boot";
import { emptyS3, s3Complete, S3Fields, s3Path, s3Settings, s3Signin, type S3Form } from "./S3";
import { emptySignin, isSharePath, sealSignin, ShareFields, ShareSigninRow, signinComplete, signinDisplay, signinFromDisplay, TestConnection, type ShareSignin } from "./Share";

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
                {r.hold && <HoldBanner repo={r} onChange={repos.reload} />}
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
                  {r.status === "ready" && <Maintenance repo={r} agents={agents.data!} onChange={repos.reload} />}
                </div>
                <ShareSigninRow repo={r} agents={agents.data!} onSaved={repos.reload} />
                {r.status === "ready" && <GatewayRow repo={r} agents={agents.data!} onSaved={repos.reload} />}
                {r.status === "ready" && <BootVerification repo={r} agents={agents.data!} onSaved={repos.reload} />}
                <div className="row">
                  <span className="faint small mono">ID {r.repo_uuid.slice(0, 8)}</span>
                  {!r.hold && r.status === "ready" && (
                    <button
                      className="btn sm ghost"
                      title="Stop all automatic deletion in this repository, e.g. during an investigation or for legal reasons"
                      onClick={async () => {
                        const reason = prompt("Why is this repository being placed on hold? (shown to other administrators)", "Legal hold");
                        if (reason === null) return;
                        await api.post(`/api/repositories/${r.id}/hold`, { hold: true, reason });
                        repos.reload();
                      }}
                    >
                      <PauseCircle size={13} /> Hold deletions
                    </button>
                  )}
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
  const [signin, setSignin] = useState<ShareSignin>(emptySignin());
  const [kind, setKind] = useState<"folder" | "s3">("folder");
  const [s3, setS3] = useState<S3Form>(emptyS3());
  const [saved, setSaved] = useState(false);
  // Add a repository that already exists (moved from another server): no new recovery key.
  const [existing, setExisting] = useState(false);
  const [downloaded, setDownloaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const recovery = useMemo(() => newRecoveryKey(), []);
  const creatorAgent = agents.find((a) => a.id === creator);
  const winPath = creatorAgent?.os.family === "windows";
  const isS3 = kind === "s3";
  const share = !isS3 && isSharePath(path);
  const location = isS3 ? s3Path(s3) : path;
  const chosen = agents.filter((a) => a.id === creator || others.includes(a.id));

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
          const secret = JSON.stringify({ passphrase: pass, recovery_key: id === creator && !existing ? recovery.fileContents : null });
          const sealed_share = isS3 ? await sealSignin(a, s3Signin(s3)) : share && signin.mode === "password" ? await sealSignin(a, signin) : null;
          return { agent_id: id, sealed: await seal(a.public_key, secret), sealed_share };
        }),
      );
      await api.post("/api/repositories", {
        name, path: location, ...(existing ? { existing: true } : { repo_uuid: recovery.repoId }), init_agent_id: creator, access,
        share_auth: isS3 ? "password" : share ? signin.mode : "none",
        share_user: isS3 ? s3.access_key.trim() : share && signin.mode === "password" ? signinDisplay(signin) : null,
        s3: isS3 ? s3Settings(s3) : null,
      });
      onDone();
    } catch (e) {
      const m = (e as Error).message;
      setErr(m.includes("X25519") || m.includes("Algorithm") ? "This browser does not support X25519 encryption yet. Use a current Chrome, Edge, Firefox or Safari." : m);
    } finally {
      setBusy(false);
    }
  };

  const steps = existing ? ["Location", "Passphrase"] : ["Location", "Passphrase", "Recovery key"];
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
          {step === 1 && <button className="btn primary" disabled={!name.trim() || !creator || (isS3 ? !s3Complete(s3) : !path.trim() || (share && !signinComplete(signin)))} onClick={() => setStep(2)}>Continue</button>}
          {step === 2 && !existing && <button className="btn primary" disabled={pass.length < 12 || pass !== pass2} onClick={() => setStep(3)}>Continue</button>}
          {step === 2 && existing && <button className="btn primary" disabled={!pass || pass !== pass2 || busy} onClick={create}><Lock size={15} /> {busy ? "Encrypting…" : "Add repository"}</button>}
          {step === 3 && <button className="btn primary" disabled={!saved || busy} onClick={create}><Lock size={15} /> {busy ? "Encrypting…" : "Create repository"}</button>}
        </>
      }
    >
      {err && <Notice tone="bad">{err}</Notice>}
      {step === 1 && (
        <>
          <Field label="Name"><input className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={60} /></Field>
          <label className="check">
            <input type="checkbox" checked={existing} onChange={(e) => setExisting(e.target.checked)} />
            <span>It already exists<div className="faint small">A repository moved from another Fenrir-Backup server, or added again: its backups and their history are listed, nothing is created. You need its passphrase.</div></span>
          </label>
          <Field label={existing ? "Opened by" : "Created by"} hint="This machine creates the repository folder and must be able to write to it.">
            <select className="input" value={creator} onChange={(e) => setCreator(e.target.value)}>
              {agents.map((a) => <option key={a.id} value={a.id}>{a.name}{a.online ? "" : " (offline)"}</option>)}
            </select>
          </Field>
          <Field label="Where">
            <div className="seg" style={{ alignSelf: "flex-start" }}>
              <button className={!isS3 ? "on" : ""} onClick={() => setKind("folder")}>Folder or network share</button>
              <button className={isS3 ? "on" : ""} onClick={() => setKind("s3")}>S3 object storage</button>
            </div>
          </Field>
          {isS3 && <S3Fields value={s3} onChange={setS3} />}
          {isS3 && s3Complete(s3) && <TestConnection agent={creatorAgent} path={location} signin={s3Signin(s3)} s3={s3Settings(s3)} />}
          {!isS3 && <Field label="Folder" hint={<>A local folder (<span className="mono">{winPath ? "D:\\Backups\\Fenrir" : "/srv/backups/fenrir"}</span>) or a network share (<span className="mono">{"\\\\backup-server\\backups\\fenrir"}</span>). The folder must be new or empty; it is created if missing.</>}>
            <input className="input mono" placeholder={"\\\\backup-server\\backups\\fenrir"} value={path} onChange={(e) => setPath(e.target.value)} />
          </Field>}
          {share && (
            <Field label="Sign-in to the share">
              <ShareFields value={signin} onChange={setSignin} machines={chosen} />
            </Field>
          )}
          {!isS3 && path.trim() && <TestConnection agent={creatorAgent} path={path} signin={share ? signin : null} />}
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
      {step === 2 && existing && (
        <Notice tone="info">Enter the repository's existing passphrase. It is encrypted in this browser for each chosen machine; the first one opens the repository and lists its backups.</Notice>
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
  const [via, setVia] = useState(!!repo.gateway);
  const needsSignin = repo.share_auth === "password" && !via;
  const [signin, setSignin] = useState<ShareSignin>(() => signinFromDisplay(repo.share_user));
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
            disabled={!agent || !pass || (needsSignin && !signin.password)}
            onClick={async () => {
              try {
                const a = agents.find((x) => x.id === agent)!;
                const sealed = await seal(a.public_key, JSON.stringify({ passphrase: pass, recovery_key: null }));
                const sealed_share = needsSignin ? await sealSignin(a, signin) : null;
                await api.post(`/api/repositories/${repo.id}/access`, { agent_id: agent, sealed, sealed_share, via_gateway: via });
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
          {needsSignin && (
            <Field label={repo.s3 ? `Secret access key for ${repo.share_user}` : `Share password for ${repo.share_user}`} hint="Encrypted here for that machine only.">
              <input className="input" type="password" autoComplete="off" value={signin.password} onChange={(e) => setSignin({ ...signin, password: e.target.value })} />
            </Field>
          )}
          {repo.gateway && (
            <label className="check">
              <input type="checkbox" checked={via} onChange={(e) => setVia(e.target.checked)} />
              <span>
                Through the gateway ({repo.gateway.name})
                <div className="faint small">For machines outside the network that cannot reach {repo.path} themselves. They can add backups and restore, but never delete: old backups are removed only by the gateway's retention.</div>
              </span>
            </label>
          )}
          {!via && repo.share_auth === "machine" && agents.find((x) => x.id === agent)?.os.family !== "windows" && (
            <Notice tone="warn">This repository uses the Windows computer account to reach the share; this machine is not Windows. Switch the repository to a username and password first (Change sign-in).</Notice>
          )}
          {!via && <div className="muted small">The machine must be able to reach <span className="mono">{repo.path}</span>.</div>}
          {!via && <TestConnection agent={agents.find((x) => x.id === agent)} path={repo.path} s3={repo.s3} signin={(repo.s3 || isSharePath(repo.path)) && repo.share_auth !== "none" ? { ...signin, mode: repo.share_auth === "machine" ? "machine" : "password" } : null} />}
        </>
      )}
    </Modal>
  );
}

function HoldBanner({ repo, onChange }: { repo: Repository; onChange: () => void }) {
  const [typed, setTyped] = useState("");
  const [open, setOpen] = useState(false);
  const ransomware = (repo.hold_reason ?? "").toLowerCase().includes("ransomware");
  return (
    <div className="notice bad" style={{ flexDirection: "column", gap: 10 }}>
      <div className="row" style={{ alignItems: "flex-start" }}>
        <ShieldAlert size={18} style={{ flex: "none", color: "var(--bad)" }} />
        <div className="grow">
          <strong>{ransomware ? "Deletions on hold: possible ransomware" : "Deletions on hold"}</strong>
          <div className="small" style={{ marginTop: 2 }}>{repo.hold_reason}</div>
          <div className="small muted" style={{ marginTop: 4 }}>
            Since {when(repo.hold_since)}. Backups keep running; no backup is deleted and no space is reclaimed until the hold is released.
            {ransomware && " Check the machine before releasing: the images from before the event are your clean copies."}
          </div>
        </div>
        {!open && <button className="btn sm" onClick={() => setOpen(true)}>Release…</button>}
      </div>
      {open && (
        <div className="row wrap">
          <span className="small">Type <strong>release</strong> to allow deletions again:</span>
          <input className="input" style={{ width: 140, height: 32 }} value={typed} onChange={(e) => setTyped(e.target.value)} autoFocus />
          <button
            className="btn sm danger solid"
            disabled={typed.trim().toLowerCase() !== "release"}
            onClick={async () => {
              await api.post(`/api/repositories/${repo.id}/hold`, { hold: false });
              onChange();
            }}
          >
            Release hold
          </button>
          <button className="btn sm ghost" onClick={() => setOpen(false)}>Cancel</button>
        </div>
      )}
    </div>
  );
}

function Maintenance({ repo, agents, onChange }: { repo: Repository; agents: Agent[]; onChange: () => void }) {
  const toast = useToast();
  const members = agents.filter((a) => repo.agents.some((x) => x.id === a.id) && a.capabilities.includes("maintenance"));
  return (
    <details className="small" style={{ marginTop: 4 }}>
      <summary style={{ cursor: "pointer", fontWeight: 600 }}>
        Space reclamation · {repo.prune_every_days ? `every ${repo.prune_every_days} days` : "off"} · last run {ago(repo.last_prune)}
      </summary>
      <div className="stack" style={{ marginTop: 10 }}>
        <div className="muted">Removes data that no kept backup uses any more. It locks the repository briefly; backups wait until it finishes.</div>
        <div className="row wrap" style={{ gap: 12 }}>
          <label className="field">
            <span className="faint small">Run on</span>
            <select
              className="input"
              style={{ width: 200 }}
              value={repo.maintenance_agent_id ?? ""}
              onChange={async (e) => {
                await api.post(`/api/repositories/${repo.id}/maintenance`, { agent_id: e.target.value });
                onChange();
              }}
            >
              {!repo.maintenance_agent_id && <option value="">Choose a machine</option>}
              {members.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
            </select>
          </label>
          <label className="field">
            <span className="faint small">Every</span>
            <select
              className="input"
              style={{ width: 130 }}
              value={repo.prune_every_days}
              onChange={async (e) => {
                await api.post(`/api/repositories/${repo.id}/maintenance`, { prune_every_days: Number(e.target.value) });
                onChange();
              }}
            >
              <option value={1}>day</option>
              <option value={7}>week</option>
              <option value={30}>month</option>
              <option value={0}>never</option>
            </select>
          </label>
          <button
            className="btn sm"
            style={{ alignSelf: "flex-end" }}
            disabled={repo.hold || !repo.maintenance_agent_id}
            onClick={async () => {
              try {
                await api.post(`/api/repositories/${repo.id}/prune`, { dry_run: false });
                toast("ok", "Space reclamation queued");
              } catch (e) {
                toast("bad", (e as Error).message);
              }
            }}
          >
            <Sparkles size={13} /> Reclaim now
          </button>
        </div>
      </div>
    </details>
  );
}

/** NAS gateway: one machine next to the repository serves it to machines elsewhere. */
function GatewayRow({ repo, agents, onSaved }: { repo: Repository; agents: Agent[]; onSaved: () => void }) {
  const [open, setOpen] = useState(false);
  const g = repo.gateway;
  const users = repo.agents.filter((a) => a.via_gateway).map((a) => a.name);
  return (
    <div className="row wrap" style={{ gap: 8 }}>
      <Network size={15} style={{ color: "var(--text-2)" }} />
      <span className="small">
        {g ? (
          <>Gateway: <strong>{g.name}</strong>{!g.online && <> (offline)</>} serves it to {users.join(", ") || "no machines yet"} · {g.port ? `direct on ${g.addresses.join(", ") || `port ${g.port}`}, otherwise relayed` : "relayed through this server"}</>
        ) : (
          <>Machines outside this network can back up here through a gateway.</>
        )}
      </span>
      <button className="btn sm ghost" onClick={() => setOpen(true)}>{g ? "Gateway settings" : "Serve through a gateway"}</button>
      {open && <GatewayDialog repo={repo} agents={agents} onClose={() => setOpen(false)} onSaved={() => { setOpen(false); onSaved(); }} />}
    </div>
  );
}

function GatewayDialog({ repo, agents, onClose, onSaved }: { repo: Repository; agents: Agent[]; onClose: () => void; onSaved: () => void }) {
  const pool = agents.filter((a) => repo.agents.some((x) => x.id === a.id && !x.via_gateway) && a.capabilities.includes("gateway"));
  const [id, setId] = useState(repo.gateway?.agent_id ?? pool[0]?.id ?? "");
  const [direct, setDirect] = useState(repo.gateway ? repo.gateway.port > 0 : true);
  const [port, setPort] = useState(repo.gateway?.port || 8475);
  const [address, setAddress] = useState(repo.gateway?.address ?? "");
  const [err, setErr] = useState<string | null>(null);
  const toast = useToast();
  const save = async (body: Record<string, unknown>, msg: string) => {
    try {
      await api.post(`/api/repositories/${repo.id}/gateway`, body);
      toast("ok", msg);
      onSaved();
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <Modal wide title={`Serve ${repo.name} through a gateway`} onClose={onClose}
      foot={<>
        {repo.gateway && <button className="btn danger" onClick={() => save({}, "Gateway removed")}>Stop serving</button>}
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" disabled={!id} onClick={() => save({ agent_id: id, port: direct ? port : 0, address: address.trim() || null }, "Gateway saved")}>Save</button>
      </>}>
      {err && <Notice tone="bad">{err}</Notice>}
      <div className="muted">
        One machine inside the network where the NAS is serves this repository to machines you choose elsewhere: laptops at home, a branch office.
        They connect to it directly when they can reach it (same network, VPN or a forwarded port), and through this server otherwise, so no port has to be opened.
      </div>
      <Notice tone="info">
        Everything is encrypted between the two machines; this server only passes on what it cannot read. Machines that use the gateway can add backups and
        restore, but cannot delete them, so ransomware on a laptop cannot erase its history. Retention and space reclamation run on the gateway.
      </Notice>
      {pool.length === 0 ? (
        <Notice tone="warn">No machine with direct access to <span className="mono">{repo.path}</span> can be a gateway yet. Give the machine next to the NAS access first (and let its agent update).</Notice>
      ) : (
        <>
          <Field label="Gateway machine">
            <select className="input" value={id} onChange={(e) => setId(e.target.value)}>
              {pool.map((a) => <option key={a.id} value={a.id}>{a.name}{a.online ? "" : " (offline)"}</option>)}
            </select>
          </Field>
          <label className="check">
            <input type="checkbox" checked={direct} onChange={(e) => setDirect(e.target.checked)} />
            <span>Accept direct connections on port <input className="input" type="number" min={1024} max={65535} value={port} disabled={!direct} style={{ width: 100, display: "inline-block" }} onChange={(e) => setPort(Number(e.target.value))} />
              <div className="faint small">On Windows the agent adds a firewall rule for Domain and Private networks. Without it, or from anywhere else, machines use the relay.</div>
            </span>
          </label>
          <Field label="Address from outside (optional)" hint="host:port reachable from the other machines, e.g. a forwarded port or VPN address.">
            <input className="input" value={address} placeholder="backup.example.com:8475" onChange={(e) => setAddress(e.target.value)} />
          </Field>
          <div className="faint small">Then give each remote machine access with “Through the gateway” ticked.</div>
        </>
      )}
    </Modal>
  );
}
