# Kubernetes backup

Kubernetes workloads are described by API objects (Deployments, Services, ConfigMaps, Secrets...) and keep their
data on PersistentVolumes. Fenrir-Backup backs up both into the same repositories as disk images, encrypted and
deduplicated the same way, and restores them on the same cluster or another.

Stage 1 (this note): the API objects of chosen namespaces. Stage 2: the data of their PersistentVolumeClaims
through CSI volume snapshots (below).

## Access

The `k8s` crate talks to the API server over HTTPS with a bearer token, checking the server against the cluster's CA:
in a pod, its service account (`/var/run/secrets/kubernetes.io/serviceaccount`); outside, `--api-server`,
`--token-file` and `--ca-file`. Backing up needs `get` and `list` on the namespaces' objects; restoring needs
`create` (and `update` with `--replace`).

## What is backed up

Discovery lists every namespaced resource type that can be listed and created (core and every API group, including
custom resources; a group whose API service is down is skipped with a warning). Of each type, every object of the
chosen namespaces, except what Kubernetes recreates or keeps for itself:

* objects owned by another (a Deployment's ReplicaSets and their Pods, a CronJob's Jobs): their owner recreates them;
* events, endpoints, endpoint slices, leases, controller revisions;
* `kube-root-ca.crt`, the `default` service account, service-account token secrets.

Each object is cleaned so it can be created again: no uid, resourceVersion, generation, timestamps, managed fields,
owner references or status; a Service loses its allocated cluster IP and node ports (a headless one stays headless);
a claim loses the volume it was bound to; a Job loses its generated selector.

The objects (with their resource type and the namespaces' labels) are one JSON document, stored as a disk of an
image (a 512-byte header with a magic and length, the JSON, zero padding) whose machine is the cluster
(`k8s:<cluster>`) and OS family `kubernetes`. Retention, verification, off-site copies and immutability work as for
any image.

## Restore

`fenrir-backup k8s restore --image ID [--namespace N [--to-namespace M]] [--replace]`: the namespaces are created
(with their labels), then the objects in dependency order (service accounts, secrets and config maps, quotas and
network policies, claims, roles and bindings, services, other kinds, workloads, then autoscalers, disruption budgets
and ingresses). An object that exists is left alone unless `--replace`. Restored under another name, RoleBinding
subjects naming the namespace's service accounts follow it.

## Commands

* `fenrir-backup k8s backup --namespace shop [--namespace ...] [--cluster NAME] [--api-server ... --token-file ... --ca-file ...]`
* `fenrir-backup k8s show IMAGE`: the objects in a backup.
* `fenrir-backup k8s restore --image IMAGE ...`

Run in the cluster, the CLI is a CronJob with a service account and the repository on a mounted volume or S3.

## Stage 2: volume data

For each PersistentVolumeClaim of a backed-up namespace whose CSI driver has a VolumeSnapshotClass: snapshot it,
create a temporary claim from the snapshot, mount it read-only in a short-lived reader pod running the Fenrir-Backup
image, and store the volume (a raw block device, or the file system's files as a stream) as another disk of the
same image; restore creates the claim and writes the data back through a pod the same way. This needs a container
image of the CLI and is being built next.

## Tests

* Unit tests: discovery filtering, what is skipped, cleaning, restore order, the archive format.
* `ci/e2e-kubernetes.sh` (CI job `kubernetes`, a kind cluster): a namespace with a Deployment, Service, ConfigMap,
  Secret, ServiceAccount, Role, RoleBinding, claim and CronJob is backed up, deleted and restored (data equal, the
  Deployment available again, generated objects never in the backup), restored again as another namespace, and a
  third restore over existing objects changes nothing.
