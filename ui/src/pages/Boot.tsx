import { useMemo, useState } from "react";
import { Camera, MonitorPlay, Power, Rocket } from "lucide-react";
import { api, type Agent, type BootCheck, type Image, type Repository, type RunningVm } from "../api";
import { accelLabel, ago, bootLabel, when } from "../format";
import { seal } from "../seal";
import { Field, Modal, Notice, Pill, useApi, useRoute, useToast } from "../ui";

export const canBoot = (a: Agent) => a.capabilities.includes("boot_kvm") || a.capabilities.includes("boot_hyperv");

/** Machines that can boot images (Hyper-V or QEMU), those with access to `repositoryId` first. */
export function useBootHosts(repositoryId: string | null) {
  const agents = useApi<Agent[]>("/api/agents");
  const repos = useApi<Repository[]>("/api/repositories");
  const repo = repos.data?.find((r) => r.id === repositoryId);
  const hasAccess = (id: string) => !!repo?.agents.some((x) => x.id === id);
  const hosts = useMemo(
    () => (agents.data ?? []).filter(canBoot).sort((a, b) => Number(!!repo?.agents.some((x) => x.id === b.id)) - Number(!!repo?.agents.some((x) => x.id === a.id))),
    [agents.data, repo],
  );
  return { hosts, repo, hasAccess, loading: agents.loading || repos.loading };
}

export function BootPill({ check, onClick }: { check: BootCheck | null; onClick?: () => void }) {
  if (!check) return <span className="faint small">not tested</span>;
  const l = bootLabel(check.outcome);
  return (
    <button className="link-btn" onClick={onClick} title={`${check.message} · ${when(check.at)}`}>
      <Pill tone={l.tone}>{l.text}</Pill>
      <div className="faint small">{ago(check.at)}</div>
    </button>
  );
}

export function BootCheckDialog({ image, onClose }: { image: Image; onClose: () => void }) {
  const { hosts, repo, hasAccess, loading } = useBootHosts(image.repository_id);
  const [hostId, setHostId] = useState("");
  const host = hosts.find((h) => h.id === hostId) ?? hosts.find((h) => h.id === image.agent_id && hasAccess(h.id)) ?? hosts[0];
  const kvm = !!host?.capabilities.includes("boot_kvm");
  const needsAccess = !!host && !hasAccess(host.id);
  const shareSignin = repo?.share_auth === "password";
  const [pass, setPass] = useState("");
  const [folder, setFolder] = useState("");
  const [keep, setKeep] = useState(false);
  const [memory, setMemory] = useState(4096);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const toast = useToast();
  const { go } = useRoute();

  const submit = async () => {
    if (!host) return;
    setBusy(true);
    setErr(null);
    try {
      if (needsAccess) {
        // Sealed in this browser for that host only; the server never sees the passphrase.
        const sealed = await seal(host.public_key, JSON.stringify({ passphrase: pass, recovery_key: null }));
        await api.post(`/api/repositories/${image.repository_id}/access`, { agent_id: host.id, sealed });
      }
      await api.post(`/api/images/${image.image_id}/boot-check`, { agent_id: host.id, keep_running: keep, memory_mb: memory, directory: !kvm && folder.trim() ? folder.trim() : null });
      toast("ok", `Boot test queued on ${host.name}`);
      onClose();
      go(`/machines/${host.id}`);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={`Test-boot ${image.vm_name ?? image.hostname}`}
      sub={`Image from ${when(image.created)} · ${image.repository_name}`}
      onClose={onClose}
      foot={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" disabled={!host || busy || (needsAccess && (!pass || shareSignin))} onClick={submit}><Rocket size={15} /> {needsAccess ? "Give access and start" : keep ? (kvm ? "Boot and keep running" : "Boot and keep the VM") : "Start boot test"}</button>
        </>
      }
    >
      {err && <Notice tone="bad">{err}</Notice>}
      <div className="muted">
        The image starts as a virtual machine with <strong>no connection to your network</strong>. The backup itself is never changed: everything the VM writes is thrown away afterwards.
        The result and a screenshot are kept with the image.
      </div>
      {!loading && hosts.length === 0 ? (
        <Notice tone="warn">
          No machine can run VMs yet. Install the agent on a Windows machine with Hyper-V (it is detected by itself) or a Linux machine with QEMU (packages <span className="mono">qemu-system-x86 qemu-utils ovmf</span>).
        </Notice>
      ) : (
        <>
          <Field label="Run on" hint={kvm ? "Boots straight from the repository, nothing is copied first." : host ? "Hyper-V hosts copy the image to a scratch folder first, so this takes about as long as a restore." : undefined}>
            <select className="input" value={host?.id} onChange={(e) => setHostId(e.target.value)}>
              {hosts.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} — {a.capabilities.includes("boot_kvm") ? "QEMU/KVM" : "Hyper-V"}{hasAccess(a.id) ? "" : " — no access yet"}{a.online ? "" : " (offline)"}
                </option>
              ))}
            </select>
          </Field>
          {needsAccess && (shareSignin ? (
            <Notice tone="warn">{host?.name} has no access to {image.repository_name}, which is on a network share with a password: give it access on the Repositories page (with the share sign-in), then come back.</Notice>
          ) : (
            <Field label={`Repository passphrase (gives ${host?.name} access to ${image.repository_name})`} hint="Encrypted in this browser for that machine only.">
              <input className="input" type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="off" />
            </Field>
          ))}
          {!kvm && host && (
            <Field label="Folder on the host for the VM's disks" hint="Optional. The VM's disks need about as much free space as the data in the backup. Default: the agent's folder on C:.">
              <input className="input" value={folder} placeholder="D:\\Fenrir checks" onChange={(e) => setFolder(e.target.value)} />
            </Field>
          )}
          <Field label="Memory">
            <select className="input" value={memory} onChange={(e) => setMemory(Number(e.target.value))}>
              {[1024, 2048, 4096, 8192, 16384].map((m) => <option key={m} value={m}>{m / 1024} GB</option>)}
            </select>
          </Field>
          {host && (
            <label className="check">
              <input type="checkbox" checked={keep} onChange={(e) => setKeep(e.target.checked)} />
              {kvm ? (
                <span>
                  Keep it running afterwards
                  <div className="faint small">Reach its screen, RDP or SSH through the host (loopback only, over an SSH tunnel). It stops automatically after 8 hours and can be stopped from the host's page.</div>
                </span>
              ) : (
                <span>
                  Keep the VM afterwards so I can log in and check it
                  <div className="faint small">It stays in Hyper-V Manager on {host.name} (network disconnected) until you stop it from the host's page, which deletes the VM and its disks.</div>
                </span>
              )}
            </label>
          )}
        </>
      )}
    </Modal>
  );
}

export function BootResultDialog({ image, onClose }: { image: Image; onClose: () => void }) {
  const hist = useApi<BootCheck[]>(`/api/images/${image.image_id}/boot-checks`);
  const [sel, setSel] = useState<number | null>(null);
  const list = hist.data ?? [];
  const c = list.find((x) => x.id === sel) ?? list[0] ?? image.boot_check;
  return (
    <Modal wide title={`Boot tests of ${image.vm_name ?? image.hostname}`} sub={`Image from ${when(image.created)}`} onClose={onClose} foot={<button className="btn" onClick={onClose}>Close</button>}>
      {!c ? (
        <div className="muted">This image has not been test-booted yet.</div>
      ) : (
        <>
          <div className="row wrap" style={{ gap: 8 }}>
            <Pill tone={bootLabel(c.outcome).tone}>{bootLabel(c.outcome).text}</Pill>
            <span className="muted">{c.message}</span>
          </div>
          <div className="faint small">
            {when(c.at)} · {c.seconds}s · {c.firmware.toUpperCase()} · {accelLabel(c.accel)} · decided by {c.method}
            {c.agent_name ? ` · on ${c.agent_name}` : ""}
          </div>
          {c.has_screenshot ? (
            <img className="screenshot" src={`/api/boot-checks/${c.id}/screenshot.png`} alt="The VM's screen at the end of the boot test" />
          ) : (
            <div className="muted small row"><Camera size={14} /> No screenshot was taken.</div>
          )}
          {c.restore_test && <RestoreTestFacts t={c.restore_test} />}
          {c.outcome === "screen" && (
            <Notice tone="warn">The VM reached a steady screen but nothing inside it answered. Look at the screenshot: a login screen means it booted; an error or a blue screen means it did not.</Notice>
          )}
          {list.length > 1 && (
            <div className="chips">
              {list.map((x) => (
                <button key={x.id} className={`chip${x.id === c.id ? " on" : ""}`} onClick={() => setSel(x.id)}>
                  {bootLabel(x.outcome).text} · {ago(x.at)}
                </button>
              ))}
            </div>
          )}
        </>
      )}
    </Modal>
  );
}

export function RunningVmsCard({ agent, vms, images }: { agent: Agent; vms: RunningVm[]; images: Image[] }) {
  const toast = useToast();
  if (vms.length === 0) return null;
  return (
    <div className="card">
      <div className="card-head"><MonitorPlay size={17} /><h2>VMs running from backups</h2><span className="faint small">{vms.length}</span></div>
      <div className="timeline">
        {vms.map((v) => {
          const im = images.find((i) => i.image_id === v.image_id);
          const tunnels = [`-L ${v.vnc_port}:127.0.0.1:${v.vnc_port}`, ...Object.entries(v.forwards).map(([, p]) => `-L ${p}:127.0.0.1:${p}`)].join(" ");
          return (
            <div key={v.session_id} className="tl-item">
              <div className="tl-icon ok"><MonitorPlay size={15} /></div>
              <div className="grow stack tight">
                <div><strong>{im ? im.vm_name ?? im.hostname : v.image_id.slice(0, 8)}</strong> <span className="muted">· started {ago(v.started_unix)} · isolated network</span></div>
                {v.vnc_port ? (
                  <>
                    <div className="small muted">
                      Screen: VNC on <span className="mono">127.0.0.1:{v.vnc_port}</span>
                      {Object.entries(v.forwards).map(([k, p]) => <span key={k}> · {k} on <span className="mono">127.0.0.1:{p}</span></span>)}
                    </div>
                    <div className="small faint">From your computer: <span className="mono">ssh {tunnels} {agent.hostname}</span>, then connect to the same ports on localhost.</div>
                  </>
                ) : (
                  <div className="small muted">In Hyper-V Manager on {agent.name} as “Fenrir check …”: open it there to log in. Stop deletes the VM and its disks.</div>
                )}
              </div>
              <button
                className="btn sm danger"
                onClick={async () => {
                  try {
                    await api.post(`/api/agents/${agent.id}/vms/${v.session_id}/stop`);
                    toast("ok", "Power-off queued");
                  } catch (e) {
                    toast("bad", (e as Error).message);
                  }
                }}
              >
                <Power size={13} /> Stop
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}

const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

function gib(n: number): string {
  return n >= 1 << 30 ? `${(n / (1 << 30)).toFixed(1)} GiB` : `${Math.round(n / (1 << 20))} MiB`;
}

/** What a restore test did around the boot: the full restore, its read-back, and the deletion of the VM. */
function RestoreTestFacts({ t }: { t: NonNullable<BootCheck["restore_test"]> }) {
  return (
    <div className="small">
      <div>
        Restore test: {gib(t.bytes_restored)} restored as {t.format.toUpperCase()} in {t.restore_seconds}s
        {t.chunks_checked ? `, ${t.chunks_checked} chunks read back${t.mismatches ? `, ${t.mismatches} did not match` : " and matched"}` : " (this format is not read back; the data was authenticated as it was read from the backup)"}.
      </div>
      {t.vm_removed
        ? <div className="faint">The test VM and its restored disks were deleted {when(t.removed_unix)}.</div>
        : <Notice tone="warn">The test VM or its restored disks could not be deleted: {t.removal_error || "unknown error"}. Remove them on the host.</Notice>}
    </div>
  );
}

/** Repository setting: test-boot the newest image of each machine regularly. */
export function BootVerification({ repo, agents, onSaved }: { repo: Repository; agents: Agent[]; onSaved: () => void }) {
  const hosts = agents.filter((a) => canBoot(a) && repo.agents.some((x) => x.id === a.id));
  const [agentId, setAgentId] = useState(repo.boot_agent_id ?? "");
  const [days, setDays] = useState(repo.boot_every_days || 7);
  const [full, setFull] = useState(!!repo.boot_full_restore);
  const [weekday, setWeekday] = useState<number | null>(repo.boot_weekday ?? null);
  const toast = useToast();
  const save = async (id: string, d: number, f = full, w = weekday) => {
    try {
      await api.post(`/api/repositories/${repo.id}/boot-verification`, { agent_id: id || null, every_days: d, full_restore: f, weekday: w });
      toast("ok", id ? "Boot verification saved" : "Boot verification turned off");
      onSaved();
    } catch (e) {
      toast("bad", (e as Error).message);
    }
  };
  return (
    <div className="stack tight">
      <div className="row wrap" style={{ gap: 8 }}>
        <strong className="small">Boot verification</strong>
        {repo.last_verified_boot ? <span className="faint small">last verified boot {ago(repo.last_verified_boot)}</span> : <span className="faint small">never</span>}
      </div>
      {hosts.length === 0 ? (
        <div className="faint small">Give a Linux machine with QEMU, or a Hyper-V host, access to this repository to test-boot its backups automatically.</div>
      ) : (
        <div className="row wrap" style={{ gap: 8 }}>
          <select className="input" style={{ width: "auto" }} value={agentId} onChange={(e) => { setAgentId(e.target.value); save(e.target.value, days); }}>
            <option value="">Off</option>
            {hosts.map((h) => <option key={h.id} value={h.id}>on {h.name}</option>)}
          </select>
          {agentId && (
            <select className="input" style={{ width: "auto" }} value={days} onChange={(e) => { const d = Number(e.target.value); setDays(d); save(agentId, d); }}>
              {[1, 7, 14, 30].map((d) => <option key={d} value={d}>{d === 1 ? "daily" : d === 7 ? "weekly" : `every ${d} days`}</option>)}
            </select>
          )}
          {agentId && (
            <select className="input" style={{ width: "auto" }} value={weekday ?? ""} onChange={(e) => { const w = e.target.value === "" ? null : Number(e.target.value); setWeekday(w); save(agentId, days, full, w); }}>
              <option value="">any day</option>
              {WEEKDAYS.map((n, i) => <option key={n} value={i}>on {n}s (UTC)</option>)}
            </select>
          )}
          {agentId && (
            <label className="check small"><input type="checkbox" checked={full} onChange={(e) => { setFull(e.target.checked); save(agentId, days, e.target.checked); }} />
              <span>Full restore test<div className="faint small">Restore each image completely, boot the VM from the restored disks and screenshot it, then delete the VM and its disks. Needs free space on the host for the largest machine.</div></span></label>
          )}
        </div>
      )}
    </div>
  );
}
