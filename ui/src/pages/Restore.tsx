import { useMemo, useState } from "react";
import { Cloud, HardDrive, Layers, Monitor, RotateCcw, Server } from "lucide-react";
import { api, guardInfected, type Agent, type AgentDetail, type Image, type Repository, type RestoreTarget } from "../api";
import { bytes, when } from "../format";
import { seal } from "../seal";
import { Field, Modal, Notice, useApi, useRoute, useToast } from "../ui";

type Kind = "vhdx" | "hyperv_vm" | "vm_files" | "azure" | "aws" | "disk";

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
    id: "vm_files",
    cap: "restore_vm_files",
    title: "As a VM for QEMU/KVM, VirtualBox or VMware",
    text: "Writes the disks as qcow2, VDI or VMDK files in a new folder, with a VM definition (a start script, a registration script or a .vmx) next to them.",
    icon: <Monitor size={18} />,
  },
  {
    id: "azure",
    cap: "restore_cloud",
    title: "To Azure",
    text: "Uploads each disk as a fixed VHD page blob to your storage container, ready to become a managed disk and a VM there.",
    icon: <Cloud size={18} />,
  },
  {
    id: "aws",
    cap: "restore_cloud",
    title: "To AWS",
    text: "Uploads each disk as a VHDX to your S3 bucket for VM Import. The files are staged on the restoring machine first.",
    icon: <Cloud size={18} />,
  },
  {
    id: "disk",
    cap: "restore_disk",
    title: "Onto a disk",
    text: "Overwrites a whole disk or image file on the chosen machine. Everything on it is replaced.",
    icon: <Server size={18} />,
  },
];

export function RestoreDialog({ image, preferAgent, onClose }: { image: Image; preferAgent?: string; onClose: () => void }) {
  const agents = useApi<Agent[]>("/api/agents");
  const repos = useApi<Repository[]>("/api/repositories");
  const repo = repos.data?.find((r) => r.id === image.repository_id);
  const candidates = useMemo(
    // Any machine that can restore; those with access first. One without access is given it here.
    () => (agents.data ?? []).filter((a) => a.capabilities.some((c) => c.startsWith("restore_")))
      .sort((a, b) => Number(!!repo?.agents.some((x) => x.id === b.id)) - Number(!!repo?.agents.some((x) => x.id === a.id))),
    [agents.data, repo],
  );
  const hasAccess = (id: string) => !!repo?.agents.some((x) => x.id === id);
  const [agentId, setAgentId] = useState("");
  const agent = candidates.find((a) => a.id === agentId) ?? candidates.find((a) => a.id === preferAgent) ?? candidates.find((a) => a.id === image.agent_id) ?? candidates[0];
  const needsAccess = !!agent && !hasAccess(agent.id);
  const shareSignin = repo?.share_auth === "password";
  const [pass, setPass] = useState("");
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
  const [grow, setGrow] = useState(true);
  const [format, setFormat] = useState<"qcow2" | "vdi" | "vmdk">("qcow2");
  const [location, setLocation] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [region, setRegion] = useState("");
  const [account, setAccount] = useState("");
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const toast = useToast();
  const { go } = useRoute();

  const cloudName = vmName.trim().replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 64);
  // Cloud keys are sealed when the restore starts; this is only the shape.
  const target: Exclude<RestoreTarget, { type: "azure" | "aws" }> | null =
    kind === "vhdx"
      ? { type: "vhdx", directory }
      : kind === "hyperv_vm"
        ? { type: "hyperv_vm", name: vmName.trim(), directory, switch: sw.trim() || null, start }
        : kind === "vm_files"
          ? { type: "vm_files", format, name: vmName.trim(), directory }
          : kind === "disk"
            ? { type: "disk", device: device.trim(), disk, confirm: confirm.trim(), grow }
            : null;
  const cloudReady = (kind === "azure" && /^azure:\/\/[a-z0-9-]{3,63}(\/.*)?$/.test(location.trim()))
    || (kind === "aws" && /^s3:\/\/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9](\/.*)?$/.test(location.trim()));
  const ready =
    !!agent && (cloudReady ? !!cloudName && !!account.trim() && !!secret : !!target) &&
    (target?.type !== "disk" || (target.device !== "" && target.confirm === target.device)) &&
    ((target?.type !== "hyperv_vm" && target?.type !== "vm_files") || target.name !== "");

  const submit = async () => {
    if (!agent || !target) return;
    setBusy(true);
    setErr(null);
    try {
      if (needsAccess) {
        const sealed = await seal(agent.public_key, JSON.stringify({ passphrase: pass, recovery_key: null }));
        await api.post(`/api/repositories/${image.repository_id}/access`, { agent_id: agent.id, sealed });
      }
      let t: RestoreTarget | null = target as RestoreTarget | null;
      if (kind === "azure" || kind === "aws") {
        // The storage key goes to the restoring machine only, sealed here.
        const sealed = await seal(agent.public_key, JSON.stringify({ username: account.trim(), password: secret }));
        t = kind === "azure"
          ? { type: "azure", location: location.trim(), endpoint: endpoint.trim(), name: cloudName, sealed }
          : { type: "aws", location: location.trim(), endpoint: endpoint.trim(), region: region.trim(), name: cloudName, staging: directory, sealed };
      }
      const done = await guardInfected((allow_infected) => api.post("/api/restores", { image_id: image.image_id, agent_id: agent.id, target: t, disks: [], allow_infected }));
      if (done === null) return;
      toast("ok", `Restore queued on ${agent.name}`);
      onClose();
      go(`/machines/${agent.id}`);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const free = (detail.data?.inventory?.disks ?? []).filter((d) => !d.system && !d.in_use);
  return (
    <Modal
      wide
      title={`Restore ${image.vm_name ?? image.hostname}`}
      sub={`Image from ${when(image.created)} · ${bytes(image.captured_bytes)} · ${image.repository_name}`}
      onClose={onClose}
      foot={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className={`btn ${kind === "disk" ? "danger solid" : "primary"}`} disabled={!ready || busy || (needsAccess && (!pass || shareSignin))} onClick={submit}>
            <RotateCcw size={15} /> {kind === "disk" ? "Overwrite and restore" : "Start restore"}
          </button>
        </>
      }
    >
      {err && <Notice tone="bad">{err}</Notice>}
      {image.anomaly && <Notice tone="warn">This image was flagged as a possible ransomware event. Restore an earlier image unless you are sure.</Notice>}
      {candidates.length === 0 ? (
        <Notice tone="warn">No machine can restore yet: install the backup agent on the machine to restore to.</Notice>
      ) : (
        <>
          <Field label="Restore on" hint="The machine that reads the backup and writes the result.">
            <select className="input" value={agent?.id} onChange={(e) => { setAgentId(e.target.value); setKind(null); setDir(""); }}>
              {candidates.map((a) => <option key={a.id} value={a.id}>{a.name}{a.capabilities.includes("restore_hyperv") ? " — Hyper-V" : ""}{a.role === "recovery" ? " — recovery session" : ""}{hasAccess(a.id) ? "" : " — no access yet"}{a.online ? "" : " (offline)"}</option>)}
            </select>
          </Field>
          {needsAccess && (shareSignin ? (
            <Notice tone="warn">{agent?.name} has no access to {image.repository_name}, which is on a network share with a password: give it access on the Repositories page (with the share sign-in) first.</Notice>
          ) : (
            <Field label={`Repository passphrase (gives ${agent?.name} access to ${image.repository_name})`} hint="Encrypted in this browser for that machine only.">
              <input className="input" type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="off" />
            </Field>
          ))}
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
          {kind === "vm_files" && (
            <div className="grid cols-2">
              <Field label="Format">
                <select className="input" value={format} onChange={(e) => setFormat(e.target.value as "qcow2" | "vdi" | "vmdk")}>
                  <option value="qcow2">QEMU/KVM (qcow2)</option>
                  <option value="vdi">VirtualBox (VDI)</option>
                  <option value="vmdk">VMware (VMDK)</option>
                </select>
              </Field>
              <Field label="VM name" hint="The folder and the VM get this name.">
                <input className="input" value={vmName} onChange={(e) => setVmName(e.target.value)} maxLength={80} />
              </Field>
            </div>
          )}
          {(kind === "azure" || kind === "aws") && (
            <>
              <div className="grid cols-2">
                <Field label={kind === "azure" ? "Container" : "Bucket"} hint={kind === "azure" ? "azure://container/folder" : "s3://bucket/folder"}>
                  <input className="input mono" value={location} onChange={(e) => setLocation(e.target.value)} placeholder={kind === "azure" ? "azure://restores/web01" : "s3://my-restores/web01"} />
                </Field>
                <Field label="Disk names start with"><input className="input" value={vmName} onChange={(e) => setVmName(e.target.value)} maxLength={64} /></Field>
                <Field label={kind === "azure" ? "Storage account" : "Access key ID"}><input className="input" value={account} onChange={(e) => setAccount(e.target.value)} autoComplete="off" /></Field>
                <Field label={kind === "azure" ? "Account key or SAS token" : "Secret access key"} hint="Encrypted in this browser for the restoring machine only.">
                  <input className="input" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="off" />
                </Field>
                {kind === "aws" && <Field label="Region" hint="Empty: us-east-1."><input className="input" value={region} onChange={(e) => setRegion(e.target.value)} placeholder="eu-west-2" /></Field>}
                <Field label="Endpoint" hint="Empty for the public cloud; an https:// address otherwise."><input className="input" value={endpoint} onChange={(e) => setEndpoint(e.target.value)} /></Field>
              </div>
              {kind === "aws" && (
                <Field label="Staging folder" hint="On the restoring machine, with room for the disk files; they are removed after the upload.">
                  <input className="input mono" value={directory} onChange={(e) => setDir(e.target.value)} />
                </Field>
              )}
            </>
          )}
          {(kind === "vhdx" || kind === "hyperv_vm" || kind === "vm_files") && (
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
              {detail.data?.inventory?.firmware && agent?.role === "recovery" && (
                <div className="muted small">
                  {agent.name} started in {detail.data.inventory.firmware === "uefi" ? "UEFI mode" : "legacy BIOS mode"}. A system backed up from a {detail.data.inventory.firmware === "uefi" ? "BIOS" : "UEFI"} machine needs that mode switched in the firmware settings before it starts; the restore says so if it does.
                </div>
              )}
              {free.length > 0 && (
                <Field label="Disk to overwrite" hint={`The image disk is ${bytes(image.disks[disk] ?? 0)}. A larger disk keeps the extra space unallocated; a smaller one works if the partitions fit. Disks in use (system disk, recovery medium) are not offered.`}>
                  <div className="stack tight">
                    {free.map((d) => (
                      <label key={d.path} className="check card" style={{ padding: "10px 12px", borderColor: device === d.path ? "var(--danger, var(--accent))" : undefined }}>
                        <input type="radio" name="target-disk" checked={device === d.path} onChange={() => { setDevice(d.path); setConfirm(""); }} />
                        <span><span className="mono">{d.path}</span> · {bytes(d.size)}{d.model && <> · {d.model}</>}{d.serial && <span className="faint small"> · {d.serial}</span>}</span>
                      </label>
                    ))}
                  </div>
                </Field>
              )}
              <Field label={free.length > 0 ? "Or another device or image file" : "Target device or image file"} hint="Not in use and not the running system's disk.">
                <input className="input mono" value={device} onChange={(e) => { setDevice(e.target.value); setConfirm(""); }} placeholder={isWin ? "\\\\.\\PhysicalDrive1" : "/dev/sdc"} />
              </Field>
              <label className="check">
                <input type="checkbox" checked={grow} onChange={(e) => setGrow(e.target.checked)} />
                <span>Use the whole disk<div className="faint small">On a larger disk, the last partition gets the extra space and its file system is grown (NTFS, ext4, LVM; XFS and Btrfs grow once mounted).</div></span>
              </label>
              <Notice tone="bad">
                Everything on <span className="mono">{device || "the target"}</span> will be permanently replaced. Type the device path again to confirm.
              </Notice>
              <input className={`input mono${confirm && confirm !== device ? " invalid" : ""}`} value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder={device || (isWin ? "\\\\.\\PhysicalDrive1" : "/dev/sdc")} aria-label="Confirm target device" />
            </>
          )}
        </>
      )}
    </Modal>
  );
}
