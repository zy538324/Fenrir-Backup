import { useMemo, useState } from "react";
import { Camera, MonitorPlay, Power, Rocket } from "lucide-react";
import { api, type Agent, type BootCheck, type Image, type Repository, type RunningVm } from "../api";
import { accelLabel, ago, bootLabel, when } from "../format";
import { Field, Modal, Notice, Pill, useApi, useRoute, useToast } from "../ui";

export const canBoot = (a: Agent) => a.capabilities.includes("boot_kvm") || a.capabilities.includes("boot_hyperv");

/** Machines that can boot images from `repositoryId`. */
export function useBootHosts(repositoryId: string | null) {
  const agents = useApi<Agent[]>("/api/agents");
  const repos = useApi<Repository[]>("/api/repositories");
  const repo = repos.data?.find((r) => r.id === repositoryId);
  const hosts = useMemo(() => (agents.data ?? []).filter((a) => canBoot(a) && repo?.agents.some((x) => x.id === a.id)), [agents.data, repo]);
  return { hosts, loading: agents.loading || repos.loading };
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
  const { hosts, loading } = useBootHosts(image.repository_id);
  const [hostId, setHostId] = useState("");
  const host = hosts.find((h) => h.id === hostId) ?? hosts.find((h) => h.id === image.agent_id) ?? hosts[0];
  const kvm = !!host?.capabilities.includes("boot_kvm");
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
      await api.post(`/api/images/${image.image_id}/boot-check`, { agent_id: host.id, keep_running: kvm && keep, memory_mb: memory });
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
          <button className="btn primary" disabled={!host || busy} onClick={submit}><Rocket size={15} /> {keep && kvm ? "Boot and keep running" : "Start boot test"}</button>
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
          No machine with access to {image.repository_name} can run VMs. Use a Linux machine with QEMU installed (packages <span className="mono">qemu-system-x86 qemu-utils ovmf</span>) or a Hyper-V host, and give it access on the Repositories page.
        </Notice>
      ) : (
        <>
          <Field label="Run on" hint={kvm ? "Boots straight from the repository, nothing is copied first." : host ? "Hyper-V hosts copy the image to a scratch folder first, so this takes about as long as a restore." : undefined}>
            <select className="input" value={host?.id} onChange={(e) => setHostId(e.target.value)}>
              {hosts.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} — {a.capabilities.includes("boot_kvm") ? "QEMU/KVM" : "Hyper-V"}{a.online ? "" : " (offline)"}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Memory">
            <select className="input" value={memory} onChange={(e) => setMemory(Number(e.target.value))}>
              {[1024, 2048, 4096, 8192, 16384].map((m) => <option key={m} value={m}>{m / 1024} GB</option>)}
            </select>
          </Field>
          {kvm && (
            <label className="check">
              <input type="checkbox" checked={keep} onChange={(e) => setKeep(e.target.checked)} />
              <span>
                Keep it running afterwards
                <div className="faint small">Reach its screen, RDP or SSH through the host (loopback only, over an SSH tunnel). It stops automatically after 8 hours and can be stopped from the host's page.</div>
              </span>
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
                <div className="small muted">
                  Screen: VNC on <span className="mono">127.0.0.1:{v.vnc_port}</span>
                  {Object.entries(v.forwards).map(([k, p]) => <span key={k}> · {k} on <span className="mono">127.0.0.1:{p}</span></span>)}
                </div>
                <div className="small faint">From your computer: <span className="mono">ssh {tunnels} {agent.hostname}</span>, then connect to the same ports on localhost.</div>
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

/** Repository setting: test-boot the newest image of each machine regularly. */
export function BootVerification({ repo, agents, onSaved }: { repo: Repository; agents: Agent[]; onSaved: () => void }) {
  const hosts = agents.filter((a) => canBoot(a) && repo.agents.some((x) => x.id === a.id));
  const [agentId, setAgentId] = useState(repo.boot_agent_id ?? "");
  const [days, setDays] = useState(repo.boot_every_days || 7);
  const toast = useToast();
  const save = async (id: string, d: number) => {
    try {
      await api.post(`/api/repositories/${repo.id}/boot-verification`, { agent_id: id || null, every_days: d });
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
        </div>
      )}
    </div>
  );
}
