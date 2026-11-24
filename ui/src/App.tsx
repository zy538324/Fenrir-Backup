import { useEffect, useState, type ReactNode } from "react";
import { Activity, Settings2, CalendarClock, Database, LayoutDashboard, LogOut, Menu, Moon, MonitorSmartphone, PlusCircle, ShieldCheck, Sun, Lock, Server, Cloud } from "lucide-react";
import { api, type Overview, type Status } from "./api";
import { Field, Link, Logo, Notice, useApi, useRoute } from "./ui";
import { passwordStrength } from "./format";
import OverviewPage from "./pages/Overview";
import MachinesPage from "./pages/Machines";
import MachinePage from "./pages/Machine";
import RepositoriesPage from "./pages/Repositories";
import PlansPage from "./pages/Plans";
import SourcesPage from "./pages/Sources";
import ActivityPage from "./pages/Activity";
import AddMachinePage from "./pages/AddMachine";
import SettingsPage from "./pages/Settings";

export default function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const refresh = () =>
    api
      .get<Status>("/api/status")
      .then(setStatus)
      .catch((e) => setErr(String(e.message)));
  useEffect(() => {
    refresh();
    const out = () => refresh();
    window.addEventListener("fenrir:signed-out", out);
    return () => window.removeEventListener("fenrir:signed-out", out);
  }, []);

  if (err) return <div className="page"><Notice tone="bad">Cannot reach the Fenrir-Backup server: {err}</Notice></div>;
  if (!status) return null;
  if (status.setup_required) return <AuthScreen mode="setup" onDone={refresh} />;
  if (!status.user) return <AuthScreen mode="login" onDone={refresh} />;
  return <Shell user={status.user.username} version={status.version} onSignOut={refresh} />;
}

function AuthScreen({ mode, onDone }: { mode: "setup" | "login"; onDone: () => void }) {
  const [username, setUsername] = useState(mode === "setup" ? "admin" : "");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const strength = passwordStrength(password);
  const setupInvalid = mode === "setup" && (password.length < 10 || password !== confirm);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post(mode === "setup" ? "/api/setup" : "/api/login", { username, password });
      onDone();
    } catch (x) {
      setError((x as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth">
      <div className="auth-art">
        <div className="row" style={{ gap: 12 }}>
          <Logo size={38} />
          <div>
            <div style={{ fontWeight: 700, fontSize: 18, color: "#fff" }}>Fenrir-Backup</div>
            <div style={{ fontSize: 12, color: "#94a3b8" }}>Disk imaging and recovery</div>
          </div>
        </div>
        <div>
          <h1>Every machine backed up. Every backup proven.</h1>
          <p>Images of Windows, Linux and Mac machines and of whole Hyper-V hosts, encrypted before they leave the machine.</p>
          <div className="auth-points">
            <div><Lock size={18} /><span>End-to-end encrypted: this server never sees your repository keys.</span></div>
            <div><Server size={18} /><span>Install one agent on a Hyper-V host to protect every VM on it.</span></div>
            <div><ShieldCheck size={18} /><span>Signed, deduplicated images with built-in verification.</span></div>
          </div>
        </div>
        <div style={{ fontSize: 12, color: "#64748b" }}>Open source · clean-room implementation</div>
      </div>
      <div className="auth-form">
        <form className="auth-card" onSubmit={submit}>
          <div>
            <h1>{mode === "setup" ? "Welcome" : "Sign in"}</h1>
            <div className="muted" style={{ marginTop: 6 }}>
              {mode === "setup" ? "Create the administrator account for this server. You only do this once." : "Sign in to manage your backups."}
            </div>
          </div>
          {error && <Notice tone="bad">{error}</Notice>}
          <Field label="Username">
            <input className="input" autoFocus={mode === "login"} autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
          </Field>
          <Field label="Password" hint={mode === "setup" ? "At least 10 characters. A short sentence is easy to remember and hard to guess." : undefined}>
            <input className="input" type="password" autoFocus={mode === "setup"} autoComplete={mode === "setup" ? "new-password" : "current-password"} value={password} onChange={(e) => setPassword(e.target.value)} required />
            {mode === "setup" && (
              <div className={`meter s${strength}`} aria-hidden="true">
                <span /><span /><span /><span />
              </div>
            )}
          </Field>
          {mode === "setup" && (
            <Field label="Confirm password">
              <input className={`input${confirm && confirm !== password ? " invalid" : ""}`} type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
            </Field>
          )}
          <button className="btn primary lg block" disabled={busy || !username || !password || setupInvalid}>
            {busy ? "Please wait…" : mode === "setup" ? "Create account and continue" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}

function NavItem({ to, icon, children, badge }: { to: string; icon: ReactNode; children: ReactNode; badge?: number }) {
  const { path } = useRoute();
  const active = to === "/" ? path === "/" : path.startsWith(to);
  return (
    <Link to={to} className={`nav-item${active ? " active" : ""}`}>
      {icon}
      <span>{children}</span>
      {badge ? <span className="count">{badge}</span> : null}
    </Link>
  );
}

function ThemeToggle() {
  const [theme, setTheme] = useState<string>(document.documentElement.dataset.theme ?? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
  const flip = () => {
    const t = theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = t;
    try {
      localStorage.setItem("fenrir-theme", t);
    } catch {
      /* ignore */
    }
    setTheme(t);
  };
  return (
    <button className="nav-item" onClick={flip}>
      {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
      <span>{theme === "dark" ? "Light mode" : "Dark mode"}</span>
    </button>
  );
}

function Shell({ user, version, onSignOut }: { user: string; version: string; onSignOut: () => void }) {
  const { path } = useRoute();
  const [open, setOpen] = useState(false);
  const ov = useApi<Overview>("/api/overview", 15000);
  useEffect(() => setOpen(false), [path]);

  let page: ReactNode;
  const m = path.match(/^\/machines\/([0-9a-f-]{36})$/);
  if (m) page = <MachinePage id={m[1]} />;
  else if (path.startsWith("/machines")) page = <MachinesPage />;
  else if (path.startsWith("/repositories")) page = <RepositoriesPage />;
  else if (path.startsWith("/plans")) page = <PlansPage />;
  else if (path.startsWith("/apps")) page = <SourcesPage />;
  else if (path.startsWith("/activity")) page = <ActivityPage />;
  else if (path.startsWith("/add")) page = <AddMachinePage />;
  else if (path.startsWith("/settings")) page = <SettingsPage />;
  else page = <OverviewPage />;

  return (
    <div className="shell">
      <aside className={`side${open ? " open" : ""}`}>
        <div className="brand">
          <Logo />
          <div>
            <div className="brand-name">Fenrir-Backup</div>
            <div className="brand-sub">v{version}</div>
          </div>
        </div>
        <NavItem to="/" icon={<LayoutDashboard size={17} />}>Overview</NavItem>
        <NavItem to="/machines" icon={<MonitorSmartphone size={17} />} badge={ov.data?.machines.attention}>Machines</NavItem>
        <NavItem to="/plans" icon={<CalendarClock size={17} />}>Backup plans</NavItem>
        <NavItem to="/apps" icon={<Cloud size={17} />}>Apps & clusters</NavItem>
        <NavItem to="/repositories" icon={<Database size={17} />}>Repositories</NavItem>
        <NavItem to="/activity" icon={<Activity size={17} />}>Activity</NavItem>
        <div className="nav-sep" />
        <NavItem to="/add" icon={<PlusCircle size={17} />}>Add machines</NavItem>
        <NavItem to="/settings" icon={<Settings2 size={17} />}>Settings</NavItem>
        <div className="side-foot">
          <ThemeToggle />
          <button
            className="nav-item"
            onClick={async () => {
              await api.post("/api/logout").catch(() => {});
              onSignOut();
            }}
          >
            <LogOut size={17} />
            <span>Sign out {user}</span>
          </button>
        </div>
      </aside>
      <div className="main">
        <div className="topbar">
          <button className="icon-btn" onClick={() => setOpen(!open)} aria-label="Menu">
            <Menu size={20} />
          </button>
          <Logo size={24} />
          <strong>Fenrir-Backup</strong>
        </div>
        {page}
      </div>
    </div>
  );
}
