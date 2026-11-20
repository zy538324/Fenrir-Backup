import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { AlertTriangle, Apple, Check, CheckCircle2, Copy, Info, Layers, Monitor, Server, Terminal, X, XCircle } from "lucide-react";
import { api, type JobState } from "./api";
import { JOB_STATE_TEXT, jobTone, type Tone } from "./format";

// ---------- routing ----------

const RouteCtx = createContext<{ path: string; go: (p: string) => void }>({ path: "/", go: () => {} });

export function Router({ children }: { children: ReactNode }) {
  const [path, setPath] = useState(window.location.pathname);
  useEffect(() => {
    const on = () => setPath(window.location.pathname);
    window.addEventListener("popstate", on);
    return () => window.removeEventListener("popstate", on);
  }, []);
  const go = useCallback((p: string) => {
    if (p !== window.location.pathname) window.history.pushState({}, "", p);
    setPath(p);
    window.scrollTo(0, 0);
  }, []);
  return <RouteCtx.Provider value={{ path, go }}>{children}</RouteCtx.Provider>;
}

export const useRoute = () => useContext(RouteCtx);

export function Link({ to, children, className }: { to: string; children: ReactNode; className?: string }) {
  const { go } = useRoute();
  return (
    <a
      href={to}
      className={className}
      onClick={(e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
        e.preventDefault();
        go(to);
      }}
    >
      {children}
    </a>
  );
}

// ---------- data ----------

/** GET `path`, refreshing every `every` ms while the tab is visible. */
export function useApi<T>(path: string | null, every = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  useEffect(() => {
    if (!path) return;
    let alive = true;
    const load = () =>
      api
        .get<T>(path)
        .then((d) => alive && (setData(d), setError(null)))
        .catch((e) => alive && setError(String(e.message ?? e)));
    load();
    const id = every ? window.setInterval(() => document.visibilityState === "visible" && load(), every) : 0;
    return () => {
      alive = false;
      if (id) window.clearInterval(id);
    };
  }, [path, every, tick]);
  return { data, error, reload, loading: data === null && error === null };
}

// ---------- toasts ----------

type ToastT = { id: number; tone: "ok" | "bad"; text: string };
const ToastCtx = createContext<(tone: "ok" | "bad", text: string) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

export function Toasts({ children }: { children: ReactNode }) {
  const [list, setList] = useState<ToastT[]>([]);
  const n = useRef(0);
  const push = useCallback((tone: "ok" | "bad", text: string) => {
    const id = ++n.current;
    setList((l) => [...l, { id, tone, text }]);
    window.setTimeout(() => setList((l) => l.filter((t) => t.id !== id)), tone === "bad" ? 7000 : 3500);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {list.map((t) => (
          <div key={t.id} className={`toast ${t.tone}`}>
            {t.tone === "ok" ? <CheckCircle2 size={18} /> : <XCircle size={18} />}
            <div className="grow">{t.text}</div>
            <button className="icon-btn" aria-label="Dismiss" onClick={() => setList((l) => l.filter((x) => x.id !== t.id))}>
              <X size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

// ---------- pieces ----------

export function Logo({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
      <rect width="64" height="64" rx="15" fill="#122038" />
      <path d="M14 18l9 7 9-9 9 9 9-7-3 22-15 12-15-12z" fill="#2dd4bf" />
      <path d="M25 33l4 3 3-2 3 2 4-3" stroke="#122038" strokeWidth="3" fill="none" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Pill({ tone, children, pulse }: { tone: Tone; children: ReactNode; pulse?: boolean }) {
  return (
    <span className={`pill ${tone}${pulse ? " pulse" : ""}`}>
      <span className="dot" />
      {children}
    </span>
  );
}

export function StatePill({ state }: { state: JobState }) {
  return (
    <Pill tone={jobTone(state)} pulse={state === "running" || state === "dispatched"}>
      {JOB_STATE_TEXT[state]}
    </Pill>
  );
}

export function ProgressBar({ done, total }: { done?: number; total?: number }) {
  const known = total && total > 0;
  const pct = known ? Math.min(100, (100 * (done ?? 0)) / total!) : 0;
  return (
    <div className={`progress${known ? "" : " indet"}`} role="progressbar" aria-valuenow={known ? Math.round(pct) : undefined}>
      <div style={{ width: `${pct}%` }} />
    </div>
  );
}

export function OsBadge({ role, family, size = 20 }: { role?: string; family?: string; size?: number }) {
  const kind = role === "hyperv" ? "hyperv" : family === "windows" ? "windows" : family === "macos" ? "macos" : family === "linux" ? "linux" : "";
  const Icon = kind === "hyperv" ? Layers : kind === "windows" ? Monitor : kind === "macos" ? Apple : kind === "linux" ? Terminal : Server;
  return (
    <div className={`os-badge ${kind}`}>
      <Icon size={size} />
    </div>
  );
}

export function Modal({ title, sub, onClose, children, foot, wide }: { title: ReactNode; sub?: ReactNode; onClose: () => void; children: ReactNode; foot?: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal${wide ? " wide" : ""}`} role="dialog" aria-modal="true">
        <div className="modal-head">
          <div className="grow">
            <h2>{title}</h2>
            {sub && <div className="muted small" style={{ marginTop: 4 }}>{sub}</div>}
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {foot && <div className="modal-foot">{foot}</div>}
      </div>
    </div>
  );
}

export function Notice({ tone, children }: { tone: "info" | "warn" | "bad" | "ok"; children: ReactNode }) {
  const Icon = tone === "ok" ? CheckCircle2 : tone === "info" ? Info : tone === "bad" ? XCircle : AlertTriangle;
  return (
    <div className={`notice ${tone}`}>
      <Icon size={17} />
      <div className="grow">{children}</div>
    </div>
  );
}

export function Empty({ icon, title, children, action }: { icon: ReactNode; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <div className="em-icon">{icon}</div>
      <h3>{title}</h3>
      {children && <div style={{ maxWidth: 440 }}>{children}</div>}
      {action && <div style={{ marginTop: 8 }}>{action}</div>}
    </div>
  );
}

export function Command({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="cmd">
      <code>{text}</code>
      <button
        onClick={() => {
          navigator.clipboard?.writeText(text).then(() => {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1600);
          });
        }}
      >
        {copied ? <Check size={14} /> : <Copy size={14} />}
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="field">
      <label>{label}</label>
      {children}
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

export function Switch({ on, onChange, label }: { on: boolean; onChange: (v: boolean) => void; label: string }) {
  return <button className={`switch${on ? " on" : ""}`} role="switch" aria-checked={on} aria-label={label} onClick={() => onChange(!on)} />;
}

export function Skeleton({ h = 18, w = "100%" }: { h?: number; w?: number | string }) {
  return <div className="skeleton" style={{ height: h, width: w }} />;
}

export function Loading() {
  return (
    <div className="stack" style={{ padding: 4 }}>
      <Skeleton h={28} w={240} />
      <div className="grid cols-4">
        {[0, 1, 2, 3].map((i) => (
          <Skeleton key={i} h={96} />
        ))}
      </div>
      <Skeleton h={220} />
    </div>
  );
}
