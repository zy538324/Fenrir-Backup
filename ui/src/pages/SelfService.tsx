// What a restore user sees: the backups of the machines they were given, to
// browse and download files from. Nothing else.
import { useState } from "react";
import { FolderOpen, LogOut } from "lucide-react";
import { api, type Image } from "../api";
import { bytes, when } from "../format";
import { Empty, Loading, Logo, useApi } from "../ui";
import { FileBrowser } from "./Files";

interface Me { username: string; machines: { id: string; name: string }[] }
interface SelfImage { image_id: string; created: number; source: "files" | "disks"; name: string; label: string | null; bytes: number; agent_id: string }

export default function SelfServicePage({ onSignOut }: { onSignOut: () => void }) {
  const me = useApi<Me>("/api/self");
  const images = useApi<SelfImage[]>("/api/self/images", 30000);
  const [open, setOpen] = useState<SelfImage | null>(null);
  return (
    <div className="page" style={{ maxWidth: 960, margin: "0 auto" }}>
      <div className="page-head">
        <div className="row" style={{ gap: 10 }}>
          <Logo />
          <div>
            <h1>My backups</h1>
            <div className="sub">{me.data ? `${me.data.username} · ${me.data.machines.map((m) => m.name).join(", ")}` : ""}</div>
          </div>
        </div>
        <button className="btn right" onClick={async () => { await api.post("/api/logout").catch(() => {}); onSignOut(); }}><LogOut size={15} /> Sign out</button>
      </div>
      <div className="muted small">Open a backup, tick the files or folders you need and download them. They are encrypted for this browser by the machine that reads the backup.</div>
      {!images.data ? <Loading /> : images.data.length === 0 ? (
        <div className="card"><Empty icon={<FolderOpen size={24} />} title="No backups yet">Backups of your machines appear here.</Empty></div>
      ) : (
        <div className="card table-wrap">
          <table className="table">
            <thead><tr><th>Taken</th><th>Machine</th><th>Kind</th><th style={{ textAlign: "right" }}>Size</th><th /></tr></thead>
            <tbody>
              {images.data.map((i) => (
                <tr key={i.image_id}>
                  <td className="nowrap">{when(i.created)}</td>
                  <td>{i.name}{i.label && <div className="faint small">{i.label}</div>}</td>
                  <td>{i.source === "files" ? "Files and folders" : "Whole machine"}</td>
                  <td style={{ textAlign: "right" }}>{bytes(i.bytes)}</td>
                  <td style={{ textAlign: "right" }}><button className="btn sm" onClick={() => setOpen(i)}><FolderOpen size={13} /> Open</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {open && (
        <FileBrowser
          selfService
          image={{ image_id: open.image_id, created: open.created, hostname: open.name, vm_name: null, agent_id: open.agent_id, repository_id: "", machine_id: "" } as unknown as Image}
          onClose={() => setOpen(null)}
        />
      )}
    </div>
  );
}
