import { Field, Notice } from "../ui";
import type { S3Settings } from "../api";

/** What the S3 part of "New repository" holds; the keys stay in the browser until sealed per machine. */
export interface S3Form {
  provider: string;
  endpoint: string;
  region: string;
  bucket: string;
  prefix: string;
  path_style: boolean;
  lock_mode: "none" | "governance" | "compliance";
  lock_days: number;
  access_key: string;
  secret_key: string;
}

export const emptyS3 = (): S3Form => ({
  provider: "aws",
  endpoint: "https://s3.eu-west-2.amazonaws.com",
  region: "eu-west-2",
  bucket: "",
  prefix: "fenrir",
  path_style: false,
  lock_mode: "compliance",
  lock_days: 30,
  access_key: "",
  secret_key: "",
});

const PROVIDERS: { id: string; name: string; endpoint: (region: string) => string; region: string; path_style: boolean; regionHint?: string }[] = [
  { id: "aws", name: "Amazon S3", endpoint: (r) => `https://s3.${r}.amazonaws.com`, region: "eu-west-2", path_style: false, regionHint: "e.g. eu-west-2, us-east-1" },
  { id: "wasabi", name: "Wasabi", endpoint: (r) => `https://s3.${r}.wasabisys.com`, region: "eu-west-1", path_style: false, regionHint: "e.g. eu-west-1, us-east-1" },
  { id: "b2", name: "Backblaze B2", endpoint: (r) => `https://s3.${r}.backblazeb2.com`, region: "eu-central-003", path_style: false, regionHint: "from the bucket's endpoint, e.g. eu-central-003" },
  { id: "r2", name: "Cloudflare R2", endpoint: () => "https://<account-id>.r2.cloudflarestorage.com", region: "auto", path_style: true },
  { id: "other", name: "MinIO or other S3-compatible", endpoint: () => "https://minio.example.lan:9000", region: "us-east-1", path_style: true },
];

export const s3Path = (f: S3Form) => `s3://${f.bucket.trim()}${f.prefix.trim() ? "/" + f.prefix.trim().replace(/^\/+|\/+$/g, "") : ""}`;

export const s3Settings = (f: S3Form): S3Settings => ({
  endpoint: f.endpoint.trim().replace(/\/+$/, ""),
  region: f.region.trim() || "us-east-1",
  path_style: f.path_style,
  lock_mode: f.lock_mode === "none" ? null : f.lock_mode,
  lock_days: f.lock_mode === "none" ? 0 : f.lock_days,
});

export const s3Complete = (f: S3Form) =>
  /^https?:\/\/[^/\s<>]+$/.test(f.endpoint.trim().replace(/\/+$/, "")) &&
  /^[a-z0-9.-]{3,63}$/.test(f.bucket.trim()) &&
  f.access_key.trim() !== "" && f.secret_key !== "" &&
  (f.lock_mode === "none" || (f.lock_days > 7 && f.lock_days <= 36500));

/** The access key as a share sign-in, so it is sealed to each machine the same way. */
export const s3Signin = (f: S3Form) => ({ mode: "password" as const, domain: "", username: f.access_key.trim(), password: f.secret_key });

export function S3Fields({ value: f, onChange }: { value: S3Form; onChange: (f: S3Form) => void }) {
  const set = (p: Partial<S3Form>) => onChange({ ...f, ...p });
  const prov = PROVIDERS.find((p) => p.id === f.provider) ?? PROVIDERS[PROVIDERS.length - 1];
  return (
    <div className="stack">
      <div className="grid cols-2">
        <Field label="Provider">
          <select className="input" value={f.provider} onChange={(e) => {
            const p = PROVIDERS.find((x) => x.id === e.target.value)!;
            set({ provider: p.id, region: p.region, endpoint: p.endpoint(p.region), path_style: p.path_style });
          }}>
            {PROVIDERS.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </Field>
        <Field label="Region" hint={prov.regionHint}>
          <input className="input mono" value={f.region} onChange={(e) => set({ region: e.target.value, endpoint: prov.id === "aws" || prov.id === "wasabi" || prov.id === "b2" ? prov.endpoint(e.target.value.trim()) : f.endpoint })} />
        </Field>
      </div>
      <Field label="Endpoint" hint="https://host (or http://host:port on a private network), without a path.">
        <input className="input mono" value={f.endpoint} onChange={(e) => set({ endpoint: e.target.value })} />
      </Field>
      <div className="grid cols-2">
        <Field label="Bucket" hint="It must exist. For Object Lock it must have been created with Object Lock enabled.">
          <input className="input mono" value={f.bucket} onChange={(e) => set({ bucket: e.target.value.toLowerCase() })} placeholder="company-backups" />
        </Field>
        <Field label="Folder in the bucket" hint="Must be empty; several repositories can share a bucket.">
          <input className="input mono" value={f.prefix} onChange={(e) => set({ prefix: e.target.value })} placeholder="fenrir" />
        </Field>
      </div>
      <label className="check">
        <input type="checkbox" checked={f.path_style} onChange={(e) => set({ path_style: e.target.checked })} />
        <span>Path-style addresses<div className="faint small">https://host/bucket instead of https://bucket.host. Needed by MinIO and most self-hosted storage.</div></span>
      </label>
      <div className="grid cols-2">
        <Field label="Access key ID"><input className="input mono" value={f.access_key} onChange={(e) => set({ access_key: e.target.value })} autoComplete="off" /></Field>
        <Field label="Secret access key" hint="Encrypted in this browser for each machine; the server never sees it.">
          <input className="input mono" type="password" value={f.secret_key} onChange={(e) => set({ secret_key: e.target.value })} autoComplete="off" />
        </Field>
      </div>
      <div className="grid cols-2">
        <Field label="Immutable backups (Object Lock)">
          <select className="input" value={f.lock_mode} onChange={(e) => set({ lock_mode: e.target.value as S3Form["lock_mode"] })}>
            <option value="compliance">Compliance: nobody can delete a backup early</option>
            <option value="governance">Governance: only special admin rights can</option>
            <option value="none">Off</option>
          </select>
        </Field>
        {f.lock_mode !== "none" && (
          <Field label="Keep each backup locked for (days)" hint="More than 7 (maintenance renews locks weekly).">
            <input className="input" type="number" min={8} max={36500} value={f.lock_days} onChange={(e) => set({ lock_days: Number(e.target.value) })} />
          </Field>
        )}
      </div>
      {f.lock_mode === "compliance" && (
        <Notice tone="info">
          Every backup stays undeletable for at least {f.lock_days} days: not by ransomware with these keys, not by the storage account owner, not by Fenrir-Backup. Old backups are removed only after their lock ends, so storage use is at least {f.lock_days} days of changes. Locks of backups still in use are renewed by maintenance.
        </Notice>
      )}
    </div>
  );
}
