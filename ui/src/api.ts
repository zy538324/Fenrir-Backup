// Typed client for the fenrir-server API.

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-Fenrir-Csrf"] = "1";
  const r = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await r.text();
  const data = text ? JSON.parse(text) : null;
  if (!r.ok) {
    if (r.status === 401 && path !== "/api/login") window.dispatchEvent(new Event("fenrir:signed-out"));
    throw new ApiError(r.status, data?.error ?? `${r.status} ${r.statusText}`);
  }
  return data as T;
}

export const api = {
  req: <T,>(method: string, p: string, b?: unknown) => call<T>(method, p, b),
  get: <T,>(p: string) => call<T>("GET", p),
  post: <T,>(p: string, b: unknown = {}) => call<T>("POST", p, b),
  patch: <T,>(p: string, b: unknown) => call<T>("PATCH", p, b),
  del: <T,>(p: string) => call<T>("DELETE", p),
};

export interface Status {
  setup_required: boolean;
  version: string;
  user: { username: string } | null;
  tls: { pinned: boolean; cert_sha256: string } | null;
}

export interface OsSummary { family: string; name: string; version: string; arch: string }

export interface Progress { phase: string; done: number; total: number; message: string }

export interface Agent {
  id: string;
  name: string;
  hostname: string;
  role: "workstation" | "server" | "hyperv" | "recovery";
  os: OsSummary;
  agent_version: string;
  enrolled: number;
  last_seen: number | null;
  online: boolean;
  public_key: string;
  capabilities: string[];
  vm_count: number;
  last_backup: { job_id: string; state: string; at: number; error: string | null } | null;
  running_job: { id: string; label: string; state: string; progress: Progress | null } | null;
}

export interface Vm { id: string; name: string; state: string; generation: number; disk_bytes: number; disks: string[] }
export interface Disk { path: string; size: number; model: string; system: boolean; serial?: string; sector_size?: number; in_use?: boolean }
export interface RunningVm { session_id: string; image_id: string; started_unix: number; vnc_port: number; forwards: Record<string, number> }
export interface Inventory { hostname: string; os: OsSummary; capabilities: string[]; disks: Disk[]; vms: Vm[]; notes: string[]; agent_version: string; running_vms?: RunningVm[]; firmware?: "uefi" | "bios"; secure_boot?: boolean }

export type JobKind =
  | { type: "init_repository" }
  | { type: "backup_system"; settings?: BackupSettings }
  | { type: "backup_disks"; paths: string[]; settings?: BackupSettings }
  | { type: "backup_hyperv"; vm_ids: string[]; settings?: BackupSettings }
  | { type: "verify"; level: "quick" | "sample" | "full"; sample_percent?: number }
  | { type: "list_images" }
  | { type: "apply_retention"; machine_ids: string[]; retention: Retention; dry_run?: boolean }
  | { type: "prune"; dry_run?: boolean }
  | { type: "restore"; image_id: string; disks: number[]; target: RestoreTarget }
  | { type: "boot_check"; image_id: string; keep_running?: boolean; memory_mb?: number | null; cpus?: number | null; directory?: string | null }
  | { type: "stop_vm"; session_id: string }
  | { type: "check_access"; path: string }
  | { type: "browse_files"; image_id: string; volume: { disk: number; partition: number } | null; path: string }
  | { type: "restore_files"; image_id: string; volume: { disk: number; partition: number }; paths: string[]; target: string; keep_structure?: boolean; conflict?: string };

export type BootOutcome = "verified" | "screen" | "failed";
export interface BootCheck {
  id: number;
  at: number;
  outcome: BootOutcome;
  method: string;
  seconds: number;
  firmware: string;
  accel: string;
  message: string;
  has_screenshot: boolean;
  agent_name?: string | null;
}

export interface Retention { keep_last?: number; keep_daily?: number; keep_weekly?: number; keep_monthly?: number; keep_yearly?: number }

export type RestoreTarget =
  | { type: "vhdx"; directory: string }
  | { type: "hyperv_vm"; name: string; directory: string; switch?: string | null; start: boolean }
  | { type: "disk"; device: string; disk: number; confirm: string };

export interface BackupSettings { label?: string | null; rate_limit_mib?: number; vss_full?: boolean; verify_sample_percent?: number | null }

export type JobState = "queued" | "dispatched" | "running" | "succeeded" | "warning" | "failed" | "cancelled";

export interface Job {
  id: string;
  agent_id: string;
  agent_name: string;
  repository_id: string | null;
  repository_name: string | null;
  kind: JobKind;
  label: string;
  state: JobState;
  created: number;
  started: number | null;
  finished: number | null;
  progress: Progress | null;
  result: unknown;
  error: string | null;
  warnings: string[];
  requested_by: string | null;
  plan_id: string | null;
}

export interface Image {
  image_id: string;
  repository_id: string;
  repository_name: string;
  agent_id: string | null;
  machine_id: string;
  hostname: string;
  created: number;
  kind: string;
  consistency: string;
  captured_bytes: number;
  stored_new_bytes: number;
  disks: number[];
  label: string | null;
  vm_name: string | null;
  anomaly: string | null;
  chunks_total: number;
  chunks_new: number;
  boot_check: BootCheck | null;
}

export interface Repository {
  id: string;
  name: string;
  path: string;
  repo_uuid: string;
  status: "pending" | "ready" | "failed";
  status_message: string | null;
  created: number;
  images: number;
  stored_bytes: number;
  last_image: number | null;
  agents: { id: string; name: string; via_gateway?: boolean }[];
  gateway: { agent_id: string; name: string; online: boolean; port: number; address: string | null; addresses: string[] } | null;
  hold: boolean;
  hold_reason: string | null;
  hold_since: number | null;
  maintenance_agent_id: string | null;
  prune_every_days: number;
  last_prune: number | null;
  anomalies: number;
  boot_agent_id: string | null;
  boot_every_days: number;
  last_verified_boot: number | null;
  share_auth: "none" | "machine" | "password";
  share_user: string | null;
}

export type Schedule =
  | { type: "interval"; hours: number }
  | { type: "daily"; time: string; days: number[]; utc_offset_minutes: number }
  | { type: "manual" };

export interface Plan {
  id: string;
  name: string;
  agent_id: string;
  agent_name: string;
  repository_id: string;
  repository_name: string;
  job: JobKind;
  schedule: Schedule;
  enabled: boolean;
  last_run: number | null;
  next_run: number | null;
  retention: Retention | null;
}

export interface Overview {
  boot: { verified_30d: number; screen_30d: number; failed_30d: number; last_verified: { at: number; hostname: string | null; vm_name: string | null; id: number; seconds: number } | null };
  machines: { total: number; online: number; attention: number };
  last_24h: { succeeded: number; warning: number; failed: number };
  running: number;
  storage: { images: number; stored_bytes: number; protected_bytes: number };
  repositories: number;
  plans: number;
  agents: Agent[];
  recent_jobs: Job[];
}

export interface AgentDetail {
  agent: Agent;
  inventory: Inventory | null;
  jobs: Job[];
  images: Image[];
  plans: Plan[];
  repositories: { id: string; name: string; status: string }[];
}

export interface PlatformTarget { triple: string; arch: string; available: boolean; sha256: string | null; size: number | null }
export interface Platform {
  id: "windows" | "hyperv" | "linux" | "macos";
  name: string;
  summary: string;
  available: boolean;
  targets: PlatformTarget[];
  script_name: string;
  script_url: string | null;
  command: string | null;
  /** Windows / Hyper-V: per-enrollment setup program. */
  setup_name: string | null;
  setup_url: string | null;
  uninstall_url: string;
}
export interface RecoveryMedia { available: boolean; size: number | null; iso_url: string | null; settings_url: string | null }
export interface Downloads { server_url: string; pinned: boolean; cert_sha256: string | null; platforms: Platform[]; recovery: RecoveryMedia }
export interface EnrollmentToken { id: string; token: string; label: string; role: string; expires: number }
export interface AuditEntry { at: number; actor: string; action: string; detail: string }

export interface EmailSettings { host: string; port: number; security: "starttls" | "tls" | "none"; username: string; password: string; from: string; to: string[]; has_password?: boolean }
export interface WebhookSettings { url: string; format: "generic" | "slack" | "teams" }
export interface NotifySettings { email: EmailSettings | null; webhook: WebhookSettings | null; on_warning: boolean; offline_hours: number; overdue_days: number }
export interface Settings { notifications: NotifySettings; auto_update: boolean }
export interface Delivery { at: number; channel: string; subject: string; ok: boolean; error: string | null }
