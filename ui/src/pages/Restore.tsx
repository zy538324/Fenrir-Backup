import { useMemo, useState } from "react";
import { HardDrive, Layers, RotateCcw, Server } from "lucide-react";
import { api, type Agent, type AgentDetail, type Image, type Repository, type RestoreTarget } from "../api";
import { bytes, when } from "../format";
import { Field, Modal, Notice, useApi, useRoute, useToast } from "../ui";

type Kind = "vhdx" | "hyperv_vm" | "disk";

const KINDS: { id: Kind; cap: string; title: string; text: string; icon: React.ReactNode }[] = [
  {
    id: "vhdx",
    cap: "restore_vhdx",
    title: "As a virtual disk (VHDX)",
    text: "Writes a .vhdx file per disk. Double-click it in Windows to browse and copy files, or attach it to a VM. Nothing existing is touched.",
    icon: <HardDrive size={18} />,
  },
  {
    id: "hyperv_vm",
    cap: "restore_hyperv",
    title: "As a new Hyper-V VM",
    text: "Writes the disks on a Hyper-V host and creates a new VM with the original generation, CPUs, memory and disk layout.",
    icon: <Layers size={18} />,
  },
  {
    id: "disk",
    cap: "restore_disk",
    title: "Onto a disk",
    text: "Overwrites a whole disk or image file on the chosen machine. Everything on it is replaced.",
    icon: <Server size={18} />,
  },
];

export function RestoreDialog({ image, onClose }: { image: Image; onClose: () => void }) {
  const agents = useApi<Agent[]>("/api/agents");
  const repos = useApi<Repository[]>("/api/repositories");
  const repo = repos.data?.find((r) => r.id === image.repository_id);
  const candidates = useMemo(
    () => (agents.data ?? []).filter((a) => repo?.agents.some((x) => x.id === a.id) && a.capabilities.some((c) => c.startsWith("restore_"))),
    [agents.data, repo],
  );
  const [agentId, setAgentId] = useState("");
  const agent = candidates.find((a) => a.id === agentId) ?? candidates.find((a) => a.id === image.agent_id) ?? candidates[0];
  const detail = useApi<AgentDetail>(agent ? `/api/agents/${agent.id}` : null);
  const kinds = KINDS.filter((k) => agent?.capabilities.includes(k.cap));
  const [kindSel, setKind] = useState<Kind | null>(null);
  const kind: Kind | undefined = kindSel && kinds.some((k) => k.id === kindSel) ? kindSel : kinds[0]?.id;

  const isWin = agent?.os.family === "windows";
  const [dir, setDir] = useState("");
  const directory = dir || (isWin ? "D:\\Fenrir-Restores" : "/var/tmp/fenrir-restores");
  const baseName = (image.vm_name ?? image.hostname).replace(/\s+/g, "-");
  const [vmName, setVmName] = useState(`${baseName}-restored`);
  const [sw, setSw] = useState("");
  const [start, setStart] = useState(false);
  const [disk, setDisk] = useState(0);
  const [device, setDevice] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const toast = useToast();
  const { go } = useRoute();

  const target: RestoreTarget | null =
    kind === "vhdx"
      ? { type: "vhdx", directory }
      : kind === "hyperv_vm"
        ? { type: "hyperv_vm", name: vmName.trim(), directory, switch: sw.trim() || null, start }
        : kind === "disk"
          ? { type: "disk", device: device.trim(), disk, confirm: confirm.trim() }
          : null;
  const ready =
    !!agent && !!target &&
    (target.type !== "disk" || (target.device !== "" && target.confirm === target.device)) &&
    (target.type !== "hyperv_vm" || target.name !== "");

  const submit = async () => {
    if (!agent || !target) return;
    setBusy(true);
    setErr(null);
    try {
      await api.post("/api/restores", { image_id: image.image_id, agent_id: agent.id, target, disks: [] });
      toast("ok", `Restore queued on ${agent.name}`);
      onClose();
      go(`/machines/${agent.id}`);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const disks = detail.data?.inventory?.disks ?? [];
  return (
    <Modal
      wide
      title={`Restore ${image.vm_name ?? image.hostname}`}
      sub={`Image from ${when(image.created)} · ${bytes(image.captured_bytes)} · ${image.repository_name}`}
      onClose={onClose}
      foot={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className={`btn ${kind === "disk" ? "danger solid" : "primary"}`} disabled={!ready || busy} onClick={submit}>
            <RotateCcw size={15} /> {kind === "disk" ? "Overwrite and restore" : "Start restore"}
          </button>
        </>
      }
    >
      {err && <Notice tone="bad">{err}</Notice>}
      {image.anomaly && <Notice tone="warn">This image was flagged as a possible ransomware event. Restore an earlier image unless you are sure.</Notice>}
      {candidates.length === 0 ? (
        <Notice tone="warn">No machine with access to {image.repository_name} can restore. Give a machine access on the Repositories page.</Notice>
      ) : (
        <>
          <Field label="Restore on" hint="The machine that reads the backup and writes the result. It needs access to the repository.">
            <select className="input" value={agent?.id} onChange={(e) => { setAgentId(e.target.value); setKind(null); setDir(""); }}>
              {candidates.map((a) => <option key={a.id} value={a.id}>{a.name}{a.online ? "" : " (offline)"}</option>)}
            </select>
          </Field>
          <div className="stack tight">
            {kinds.map((k) => (
              <label key={k.id} className="check card" style={{ padding: "12px 14px", borderColor: kind === k.id ? "var(--accent)" : undefined }}>
                <input type="radio" name="kind" checked={kind === k.id} onChange={() => setKind(k.id)} />
                <span className="row" style={{ alignItems: "flex-start" }}>
                  <span style={{ color: "var(--text-2)", marginTop: 1 }}>{k.icon}</span>
                  <span><strong>{k.title}</strong><div className="muted small">{k.text}</div></span>
                </span>
              </label>
            ))}
          </div>
          {(kind === "vhdx" || kind === "hyperv_vm") && (
            <Field label={kind === "vhdx" ? "Folder" : "Folder on the host"} hint="Created if missing. Existing files are never overwritten.">
              <input className="input mono" value={directory} onChange={(e) => setDir(e.target.value)} />
            </Field>
          )}
          {kind === "hyperv_vm" && (
            <div className="grid cols-2">
              <Field label="New VM name" hint="Must not exist on the host. The original VM is never touched.">
                <input className="input" value={vmName} onChange={(e) => setVmName(e.target.value)} maxLength={100} />
              </Field>
              <Field label="Virtual switch" hint="Leave empty to use the original switch name, if it exists.">
                <input className="input" value={sw} onChange={(e) => setSw(e.target.value)} placeholder="e.g. LAN" />
              </Field>
              <label className="check">
                <input type="checkbox" checked={start} onChange={(e) => setStart(e.target.checked)} />
                <span>Start the VM afterwards<div className="faint small">Leave off if the original may still be running on the same network.</div></span>
              </label>
            </div>
          )}
          {kind === "disk" && (
            <>
              {image.disks.length > 1 && (
                <Field label="Image disk">
                  <select className="input" value={disk} onChange={(e) => setDisk(Number(e.target.value))}>
                    {image.disks.map((size, i) => <option key={i} value={i}>Disk {i} · {bytes(size)}</option>)}
                  </select>
                </Field>
              )}
              <Field label="Target device or image file" hint={`Must be at least ${bytes(image.disks[disk] ?? 0)}, not in use and not the running system's disk.`}>
                <input className="input mono" list="target-disks" value={device} onChange={(e) => setDevice(e.target.value)} placeholder="/dev/sdc" />
                <datalist id="target-disks">
                  {disks.filter((d) => !d.system).map((d) => <option key={d.path} value={d.path}>{`${d.model} ${bytes(d.size)}`}</option>)}
                </datalist>
              </Field>
              <Notice tone="bad">
                Everything on <span className="mono">{device || "the target"}</span> will be permanently replaced. Type the device path again to confirm.
              </Notice>
              <input className={`input mono${confirm && confirm !== device ? " invalid" : ""}`} value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder={device || "/dev/sdc"} aria-label="Confirm target device" />
            </>
          )}
        </>
      )}
    </Modal>
  );
}
