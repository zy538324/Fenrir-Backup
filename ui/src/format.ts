import type { Agent, JobKind, JobState, Retention, Schedule } from "./api";

/** "12 MB/s · 4 min left · 300 MB new" for a running job's progress. */
export function progressDetail(p: { rate?: number; eta_seconds?: number | null; stored?: number } | null | undefined): string {
  if (!p) return "";
  const parts: string[] = [];
  if (p.rate) parts.push(`${bytes(p.rate)}/s`);
  if (p.eta_seconds != null && p.rate) {
    const s = p.eta_seconds;
    parts.push(s < 60 ? "under a minute left" : s < 3600 ? `${Math.ceil(s / 60)} min left` : `${Math.floor(s / 3600)} h ${Math.ceil((s % 3600) / 60)} min left`);
  }
  if (p.stored) parts.push(`${bytes(p.stored)} new`);
  return parts.join(" · ");
}

export function bytes(n: number | null | undefined): string {
  if (n == null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB", "PB"];
  let v = n;
  let i = 0;
  while (v >= 1000 && i < u.length - 1) {
    v /= 1000;
    i++;
  }
  return i === 0 ? `${n} B` : `${v < 10 ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
}

export const now = () => Math.floor(Date.now() / 1000);

export function ago(t: number | null | undefined): string {
  if (!t) return "never";
  const d = now() - t;
  if (d < 45) return "just now";
  if (d < 3600) return `${Math.round(d / 60)} min ago`;
  if (d < 86400) return `${Math.round(d / 3600)} h ago`;
  if (d < 86400 * 30) return `${Math.round(d / 86400)} d ago`;
  return new Date(t * 1000).toLocaleDateString();
}

export function until(t: number | null | undefined): string {
  if (!t) return "—";
  const d = t - now();
  if (d <= 0) return "due now";
  if (d < 3600) return `in ${Math.max(1, Math.round(d / 60))} min`;
  if (d < 86400) return `in ${Math.round(d / 3600)} h`;
  return `in ${Math.round(d / 86400)} d`;
}

export function when(t: number | null | undefined): string {
  if (!t) return "—";
  return new Date(t * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function duration(a: number | null, b: number | null): string {
  if (!a) return "—";
  const s = (b ?? now()) - a;
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
export const DAY_NAMES = DAYS;

export function scheduleText(s: Schedule): string {
  switch (s.type) {
    case "interval": {
      const m = s.minutes ?? 0;
      if (m) return s.hours ? `Every ${s.hours} h ${m} min` : `Every ${m} minutes`;
      return s.hours === 1 ? "Every hour" : s.hours % 24 === 0 ? `Every ${s.hours / 24} day${s.hours === 24 ? "" : "s"}` : `Every ${s.hours} hours`;
    }
    case "manual":
      return "Only when started by hand";
    case "daily": {
      const local = s.time;
      const days =
        s.days.length === 0 || s.days.length === 7
          ? "Every day"
          : s.days.length === 5 && [0, 1, 2, 3, 4].every((d) => s.days.includes(d))
            ? "Weekdays"
            : s.days.map((d) => DAYS[d]).join(", ");
      return `${days} at ${local}`;
    }
  }
}

export function jobWhat(k: JobKind): string {
  switch (k.type) {
    case "backup_system":
      return "Whole system";
    case "backup_disks":
      return k.paths.join(", ");
    case "backup_hyperv":
      return k.vm_ids.length === 0 ? "All virtual machines" : `${k.vm_ids.length} virtual machine${k.vm_ids.length === 1 ? "" : "s"}`;
    case "verify":
      return k.level === "full" ? "Full verification" : k.level === "sample" ? `Spot check (${k.sample_percent ?? 5}%)` : "Quick check";
    case "init_repository":
      return "Create repository";
    case "backup_files":
      return k.paths.join(", ");
    case "scan_image":
      return "Malware scan";
    case "index_image":
      return "File catalogue for search";
    case "search_files":
      return `Search: ${k.query}`;
    case "restore_application":
      return `${k.component} to ${k.directory}${k.attach_as ? ` as ${k.attach_as}` : ""}`;
    case "backup_kubernetes":
      return `Kubernetes ${k.cluster.name}: ${k.cluster.namespaces.join(", ")}`;
    case "restore_kubernetes":
      return `Into ${k.cluster.name}${k.rename_to ? ` as ${k.rename_to}` : ""}`;
    case "backup_saas":
      return `${k.tenant.service} ${k.tenant.tenant}`;
    case "restore_saas":
      return `${k.account}${k.to_account ? ` into ${k.to_account}` : ""}`;
    case "list_images":
      return "Refresh image list";
    case "copy_images":
      return k.images?.length ? `Copy ${k.images.length} image${k.images.length === 1 ? "" : "s"} off-site` : "Copy new images off-site";
    case "apply_retention":
      return `Retention: ${retentionText(k.retention)}`;
    case "prune":
      return k.dry_run ? "Check reclaimable space" : "Delete data no backup uses";
    case "restore":
      switch (k.target.type) {
        case "vhdx":
          return `As virtual disk to ${k.target.directory}`;
        case "hyperv_vm":
          return `As Hyper-V VM “${k.target.name}”${k.target.replace ? " (standby)" : ""}`;
        case "vm_files":
          return `As ${k.target.format} VM “${k.target.name}” in ${k.target.directory}${k.target.replace ? " (standby)" : ""}`;
        case "azure":
          return `To Azure ${k.target.location}`;
        case "aws":
          return `To AWS ${k.target.location}`;
        default:
          return `To ${k.target.device}`;
      }
    case "boot_check":
      return k.keep_running ? "Boot as VM and keep running" : "Boot test in an isolated VM";
    case "stop_vm":
      return "Power off a VM";
    case "check_access":
      return `Test connection to ${k.path}`;
    case "browse_files":
      return k.volume ? `Browse ${k.path}` : "Open a backup to browse its files";
    case "restore_files":
      return `${k.paths.length} item${k.paths.length === 1 ? "" : "s"} to ${k.target}`;
  }
}

export type Tone = "ok" | "warn" | "bad" | "info" | "neutral";

export function jobTone(s: JobState): Tone {
  switch (s) {
    case "succeeded":
      return "ok";
    case "warning":
      return "warn";
    case "failed":
      return "bad";
    case "running":
    case "dispatched":
      return "info";
    default:
      return "neutral";
  }
}

export const JOB_STATE_TEXT: Record<JobState, string> = {
  queued: "Queued",
  dispatched: "Starting",
  running: "Running",
  succeeded: "Succeeded",
  warning: "Completed with warnings",
  failed: "Failed",
  cancelled: "Cancelled",
};

/** Health of a machine as one word for the UI. */
export function health(a: Agent): { tone: Tone; text: string } {
  if (a.role === "recovery") {
    if (a.running_job) return { tone: "info", text: a.running_job.label };
    return a.online ? { tone: "info", text: "Ready to restore" } : { tone: "neutral", text: "Ended" };
  }
  if (a.running_job) return { tone: "info", text: "Backing up" };
  if (!a.online) return { tone: "neutral", text: "Offline" };
  if (!a.last_backup) return { tone: "warn", text: "No backup yet" };
  if (a.last_backup.state === "failed") return { tone: "bad", text: "Last backup failed" };
  if (now() - a.last_backup.at > 3 * 86400) return { tone: "warn", text: "Backup overdue" };
  if (a.last_backup.state === "warning") return { tone: "warn", text: "Protected, with warnings" };
  return { tone: "ok", text: "Protected" };
}

export function osLabel(a: { role: string; os: { family: string; name: string; version: string } }): string {
  if (a.role === "hyperv") return `Hyper-V host · ${a.os.name || "Windows"}`;
  if (a.role === "recovery") return "Booted from recovery media";
  return [a.os.name || a.os.family, a.os.version].filter(Boolean).join(" ");
}

export function passwordStrength(p: string): 0 | 1 | 2 | 3 | 4 {
  if (!p) return 0;
  let s = 0;
  if (p.length >= 10) s++;
  if (p.length >= 14) s++;
  if (/[a-z]/.test(p) && /[A-Z]/.test(p)) s++;
  if (/\d/.test(p) || /[^\w\s]/.test(p) || p.includes(" ")) s++;
  return Math.min(4, s) as 0 | 1 | 2 | 3 | 4;
}

export function consistencyLabel(c: string): { tone: Tone; text: string } {
  switch (c) {
    case "application":
      return { tone: "ok", text: "App-consistent" };
    case "offline":
      return { tone: "ok", text: "Offline copy" };
    case "crash":
      return { tone: "warn", text: "Crash-consistent" };
    default:
      return { tone: "bad", text: "Inconsistent" };
  }
}

export const RETENTION_PRESETS: { id: string; label: string; r: Retention | null; text: string }[] = [
  { id: "all", label: "Keep everything", r: null, text: "Never delete backups automatically" },
  { id: "frequent", label: "Frequent", r: { keep_hourly: 24, keep_daily: 14, keep_weekly: 8, keep_monthly: 12 }, text: "24 hourly, 14 daily, 8 weekly, 12 monthly (for backups every few minutes)" },
  { id: "standard", label: "Standard", r: { keep_daily: 14, keep_weekly: 8, keep_monthly: 12, keep_yearly: 3 }, text: "14 daily, 8 weekly, 12 monthly, 3 yearly" },
  { id: "short", label: "Short", r: { keep_daily: 7, keep_weekly: 4 }, text: "7 daily, 4 weekly" },
  { id: "long", label: "Long", r: { keep_daily: 30, keep_weekly: 12, keep_monthly: 24, keep_yearly: 7 }, text: "30 daily, 12 weekly, 24 monthly, 7 yearly" },
];

export function retentionText(r: Retention | null | undefined): string {
  if (!r) return "keep everything";
  const parts: string[] = [];
  if (r.keep_last) parts.push(`last ${r.keep_last}`);
  if (r.keep_hourly) parts.push(`${r.keep_hourly} hourly`);
  if (r.keep_daily) parts.push(`${r.keep_daily} daily`);
  if (r.keep_weekly) parts.push(`${r.keep_weekly} weekly`);
  if (r.keep_monthly) parts.push(`${r.keep_monthly} monthly`);
  if (r.keep_yearly) parts.push(`${r.keep_yearly} yearly`);
  return parts.length ? parts.join(", ") : "keep everything";
}

export function bootLabel(o: string): { text: string; tone: "ok" | "warn" | "bad" } {
  return o === "verified" ? { text: "Boots", tone: "ok" } : o === "screen" ? { text: "Check screenshot", tone: "warn" } : { text: "Did not boot", tone: "bad" };
}

export function accelLabel(a: string): string {
  return a === "kvm" ? "KVM" : a === "tcg" ? "software emulation" : a === "hyperv" ? "Hyper-V" : a;
}
