import type { Sealed } from "./seal";
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

export interface Progress { phase: string; done: number; total: number; message: string; rate?: number; eta_seconds?: number | null; stored?: number }

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
export interface LocalRecoveryInfo { disk: number; partition: number; size: number; built_unix: number; agent_version: string; expires: number; auto_start: boolean }
export interface Inventory { hostname: string; os: OsSummary; capabilities: string[]; disks: Disk[]; vms: Vm[]; notes: string[]; agent_version: string; running_vms?: RunningVm[]; firmware?: "uefi" | "bios"; secure_boot?: boolean; local_recovery?: LocalRecoveryInfo | null }

export type JobKind =
  | { type: "init_repository" }
  | { type: "backup_system"; settings?: BackupSettings }
  | { type: "backup_disks"; paths: string[]; settings?: BackupSettings }
  | { type: "backup_hyperv"; vm_ids: string[]; settings?: BackupSettings }
  | { type: "verify"; level: "quick" | "sample" | "full"; sample_percent?: number }
  | { type: "list_images" }
  | { type: "copy_images"; target_repository_id: string; images?: string[]; full_verify?: boolean }
  | { type: "apply_retention"; machine_ids: string[]; retention: Retention; dry_run?: boolean }
  | { type: "prune"; dry_run?: boolean }
  | { type: "restore"; image_id: string; disks: number[]; target: RestoreTarget }
  | { type: "boot_check"; image_id: string; keep_running?: boolean; memory_mb?: number | null; cpus?: number | null; directory?: string | null }
  | { type: "stop_vm"; session_id: string }
  | { type: "check_access"; path: string }
  | { type: "browse_files"; image_id: string; volume: { disk: number; partition: number } | null; path: string }
  | { type: "restore_files"; image_id: string; volume: { disk: number; partition: number }; paths: string[]; target: string; keep_structure?: boolean; conflict?: string }
  | { type: "backup_kubernetes"; cluster: K8sCluster; sealed_token: Sealed }
  | { type: "restore_kubernetes"; image_id: string; cluster: K8sCluster; sealed_token: Sealed; namespaces: string[]; rename_to?: string | null; replace?: boolean }
  | { type: "backup_saas"; tenant: SaasTenant; sealed_secret: Sealed }
  | { type: "backup_files"; paths: string[]; excludes?: string[]; settings?: BackupSettings }
  | { type: "scan_image"; image_id: string; selection?: string }
  | { type: "index_image"; image_id: string }
  | { type: "search_files"; query: string; images: string[] }
  | { type: "restore_application"; image_id: string; component: string; directory: string; attach_as?: string | null; sql_instance?: string }
  | { type: "restore_saas"; image_id: string; tenant: SaasTenant; sealed_secret: Sealed; account: string; to_account?: string | null; kind?: string | null; path?: string | null; overwrite?: boolean };

export interface K8sCluster { name: string; api_server: string; ca_pem: string; namespaces: string[]; volume_image: string }
export interface SaasTenant { service: string; tenant: string; client_id: string; domain_url: string; admin: string; users: string[]; objects: string[]; mail: boolean; files: boolean; sites?: boolean; teams?: boolean; directory?: boolean }

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

export interface Retention { keep_last?: number; keep_hourly?: number; keep_daily?: number; keep_weekly?: number; keep_monthly?: number; keep_yearly?: number }

export type RestoreTarget =
  | { type: "vhdx"; directory: string }
  | { type: "hyperv_vm"; name: string; directory: string; switch?: string | null; start: boolean; replace?: boolean }
  | { type: "disk"; device: string; disk: number; confirm: string; grow?: boolean }
  | { type: "vm_files"; format: "qcow2" | "vdi" | "vmdk"; name: string; directory: string; replace?: boolean }
  | { type: "azure"; location: string; endpoint: string; name: string; sealed: Sealed }
  | { type: "aws"; location: string; endpoint: string; region: string; name: string; staging: string; sealed: Sealed };

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
  applications?: ImageApplication[];
  /** "files" for a backup of chosen files and folders (nothing to restore as disks or boot). */
  source?: "files" | "disks";
  legal_hold?: { reason: string; by: string; at: number } | null;
  last_scan?: { state: "clean" | "infected" | "incomplete"; findings: number; files_scanned: number; at: number } | null;
}

/** An application component (VSS writer) the backup was coordinated with. */
export interface ImageApplication { writer: string; component: string; caption?: string; included: boolean; note?: string | null; file_sets?: number }

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
  s3: S3Settings | null;
  /** Daily check of the storage with a machine's credentials. */
  storage_checked_at?: number | null;
  storage_error?: string | null;
  /** Offline media set (rotated removable drives) this repository belongs to. */
  media_set?: string | null;
}

export interface S3Settings { endpoint: string; region: string; path_style: boolean; lock_mode: "governance" | "compliance" | null; lock_days: number; storage_class?: string | null }

export type Schedule =
  | { type: "interval"; hours: number; minutes?: number }
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
  copy_to_repository_id?: string | null;
  copy_to_repository_name?: string | null;
  scan_after_backup?: boolean;
  standby?: Standby | null;
}

export interface Standby { agent_id: string; type: "hyperv_vm" | "vm_files"; format?: "qcow2" | "vdi" | "vmdk" | null; name: string; directory: string }

/**
 * Run a restore; when the server refuses because the latest malware scan
 * found infected files in it, show which and ask before running it again
 * with `allow_infected`.
 */
export async function guardInfected<T>(run: (allowInfected: boolean) => Promise<T>): Promise<T | null> {
  try {
    return await run(false);
  } catch (e) {
    if (e instanceof ApiError && e.status === 409 && e.message.startsWith("infected:")) {
      if (!window.confirm(`${e.message.slice("infected:".length).trim()}\n\nRestore anyway?`)) return null;
      return await run(true);
    }
    throw e;
  }
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
