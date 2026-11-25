// Restore users (self-service): each sees only the backups of the machines
// chosen here, to browse and download files from.
import { useState } from "react";
import { Trash2, UserPlus, Users } from "lucide-react";
import { api, type Agent } from "../api";
import { Field, Notice, useApi, useToast } from "../ui";

interface User { id: number; username: string; role: string; machines: string[] }

export function UsersCard() {
  const users = useApi<User[]>("/api/users");
  const agents = useApi<Agent[]>("/api/agents");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [machines, setMachines] = useState<string[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const toast = useToast();
  const names = new Map((agents.data ?? []).map((a) => [a.id, a.name]));
  const add = async () => {
    setErr(null);
    try {
      await api.post("/api/users", { username: name.trim(), password, machines });
      toast("ok", `${name.trim()} can now restore from ${machines.length} machine${machines.length === 1 ? "" : "s"}`);
      setName("");
      setPassword("");
      setMachines([]);
      users.reload();
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <div className="card">
      <div className="card-head"><Users size={17} /><h2>Self-service restores</h2></div>
      <div className="card-body stack">
        <div className="muted small">A restore user signs in here and sees only the backups of the machines given to them: they can open those backups and download files, nothing else. Downloads are encrypted for their browser by the machine that reads the backup.</div>
        {err && <Notice tone="bad">{err}</Notice>}
        {(users.data ?? []).filter((u) => u.role === "restore").map((u) => (
          <div key={u.id} className="row" style={{ gap: 8 }}>
            <strong>{u.username}</strong>
            <span className="faint small grow">{u.machines.map((m) => names.get(m) ?? m.slice(0, 8)).join(", ")}</span>
            <button className="icon-btn" aria-label={`Remove ${u.username}`} onClick={async () => { if (confirm(`Remove ${u.username}?`)) { await api.del(`/api/users/${u.id}`); users.reload(); } }}><Trash2 size={15} /></button>
          </div>
        ))}
        <div className="grid cols-2">
          <Field label="Username"><input className="input" value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" /></Field>
          <Field label="Password" hint="At least 10 characters; give it to them yourself."><input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" /></Field>
        </div>
        <Field label="Machines whose backups they may restore from">
          <div className="chips">
            {(agents.data ?? []).filter((a) => a.role !== "recovery").map((a) => (
              <button key={a.id} className={`chip${machines.includes(a.id) ? " on" : ""}`} onClick={() => setMachines(machines.includes(a.id) ? machines.filter((x) => x !== a.id) : [...machines, a.id])}>{a.name}</button>
            ))}
          </div>
        </Field>
        <button className="btn primary" style={{ alignSelf: "flex-start" }} disabled={!name.trim() || password.length < 10 || machines.length === 0} onClick={add}><UserPlus size={15} /> Add restore user</button>
      </div>
    </div>
  );
}
