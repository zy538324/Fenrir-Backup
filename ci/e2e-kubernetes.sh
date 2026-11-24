#!/bin/bash
# Kubernetes backup and restore (design: docs/design/kubernetes.md) on a real cluster (kind).
#
# A namespace with a Deployment, Service, ConfigMap, Secret, ServiceAccount, Role, RoleBinding, PersistentVolumeClaim
# and CronJob is backed up with `fenrir-backup k8s backup`, deleted, and restored: every object is back with its data,
# the Deployment becomes available again, objects Kubernetes generates (ReplicaSets, Pods, Endpoints, events) were not
# in the backup. Then it is restored once more as another namespace, with its RoleBinding following it.
#
#   ci/e2e-kubernetes.sh WORK path/to/fenrir-backup
set -euo pipefail
W=$1
CLI=$(realpath "$2")
rm -rf "$W" && mkdir -p "$W"
export FENRIR_PASSPHRASE="k8s e2e passphrase"
B() { local rc=0; "$CLI" --repo "$W/repo" "$@" || rc=$?; [ "$rc" = 0 ] || [ "$rc" = 10 ] || { echo "fenrir-backup $* failed ($rc)" >&2; return "$rc"; }; }
check() { if eval "$1"; then echo "  ok: $2"; else echo "FAILED: $2"; exit 1; fi; }

kind get clusters | grep -qx fenrir || kind create cluster --name fenrir --wait 120s
kubectl config use-context kind-fenrir >/dev/null
kubectl delete namespace shop shop-copy --ignore-not-found --wait=true >/dev/null

kubectl create namespace shop
kubectl label namespace shop team=web
kubectl -n shop apply -f - <<'Y'
apiVersion: v1
kind: ConfigMap
metadata: { name: settings }
data: { greeting: "hello from the backup" }
---
apiVersion: v1
kind: Secret
metadata: { name: db }
type: Opaque
stringData: { password: "s3cret-value" }
---
apiVersion: v1
kind: ServiceAccount
metadata: { name: shop-app }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: read-config }
rules: [{ apiGroups: [""], resources: ["configmaps"], verbs: ["get", "list"] }]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: shop-app-reads }
subjects: [{ kind: ServiceAccount, name: shop-app, namespace: shop }]
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: read-config }
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: { name: data }
spec: { accessModes: [ReadWriteOnce], resources: { requests: { storage: 64Mi } } }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: web }
spec:
  replicas: 1
  selector: { matchLabels: { app: web } }
  template:
    metadata: { labels: { app: web } }
    spec:
      serviceAccountName: shop-app
      containers:
        - name: web
          image: registry.k8s.io/pause:3.9
          env: [{ name: GREETING, valueFrom: { configMapKeyRef: { name: settings, key: greeting } } }]
          volumeMounts: [{ name: data, mountPath: /data }]
      volumes: [{ name: data, persistentVolumeClaim: { claimName: data } }]
---
apiVersion: v1
kind: Service
metadata: { name: web }
spec: { selector: { app: web }, ports: [{ port: 80, targetPort: 8080 }] }
---
apiVersion: batch/v1
kind: CronJob
metadata: { name: nightly }
spec:
  schedule: "0 3 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers: [{ name: n, image: registry.k8s.io/pause:3.9 }]
Y
kubectl -n shop rollout status deployment/web --timeout=180s

# A service account for Fenrir-Backup, and how to reach the API from here.
kubectl -n kube-system create serviceaccount fenrir-backup --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create clusterrolebinding fenrir-backup --clusterrole=cluster-admin --serviceaccount=kube-system:fenrir-backup --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n kube-system create token fenrir-backup --duration=2h > "$W/token"
kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "$W/ca.crt"
SERVER=$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')
K=(--api-server "$SERVER" --token-file "$W/token" --ca-file "$W/ca.crt")

B repo init --recovery-key-out "$W/rk.json" >/dev/null
B --json k8s backup "${K[@]}" --namespace shop --cluster kind-fenrir > "$W/backup.json"
cat "$W/backup.json"
IMAGE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["result"]["image_id"])' "$W/backup.json")
B --json k8s show "$IMAGE" > "$W/show.json"
python3 - "$W/show.json" <<'PY'
import json, sys
objs = json.load(open(sys.argv[1]))["result"]["objects"]
print("\n".join(objs))
want = ["shop/Deployment web", "shop/Service web", "shop/ConfigMap settings", "shop/Secret db", "shop/ServiceAccount shop-app",
        "shop/Role read-config", "shop/RoleBinding shop-app-reads", "shop/PersistentVolumeClaim data", "shop/CronJob nightly"]
for w in want:
    assert w in objs, f"missing {w}"
for k in ("ReplicaSet", "Pod ", "Endpoints", "EndpointSlice", "Event", "ConfigMap kube-root-ca.crt", "ServiceAccount default"):
    assert not any(k in o for o in objs), f"{k} should not be backed up"
print("  ok: the backup holds the namespace's own objects only")
PY

kubectl delete namespace shop --wait=true
check '! kubectl get namespace shop >/dev/null 2>&1' "the namespace is gone"
B --json k8s restore "${K[@]}" --image "$IMAGE" > "$W/restore.json"
cat "$W/restore.json"
kubectl -n shop rollout status deployment/web --timeout=180s
check '[ "$(kubectl get namespace shop -o jsonpath={.metadata.labels.team})" = web ]' "the namespace is back with its labels"
check '[ "$(kubectl -n shop get configmap settings -o jsonpath={.data.greeting})" = "hello from the backup" ]' "the ConfigMap's data"
check '[ "$(kubectl -n shop get secret db -o jsonpath={.data.password} | base64 -d)" = "s3cret-value" ]' "the Secret's data"
check 'kubectl -n shop get service web -o jsonpath={.spec.clusterIP} | grep -q .' "the Service, with a new cluster IP"
check 'kubectl -n shop get pvc data >/dev/null && kubectl -n shop get cronjob nightly >/dev/null && kubectl -n shop get rolebinding shop-app-reads >/dev/null' "the claim, the CronJob and the RoleBinding"
check '[ "$(kubectl -n shop get deployment web -o jsonpath={.status.availableReplicas})" = 1 ]' "the Deployment runs again"

# Once more, as another namespace.
B --json k8s restore "${K[@]}" --image "$IMAGE" --namespace shop --to-namespace shop-copy > "$W/copy.json"
kubectl -n shop-copy rollout status deployment/web --timeout=180s
check '[ "$(kubectl -n shop-copy get rolebinding shop-app-reads -o jsonpath={.subjects[0].namespace})" = shop-copy ]' "the RoleBinding follows the renamed namespace"
check '[ "$(kubectl -n shop-copy get configmap settings -o jsonpath={.data.greeting})" = "hello from the backup" ]' "the copy has the data"
# Restoring over what exists leaves it unless asked.
B --json k8s restore "${K[@]}" --image "$IMAGE" > "$W/again.json"
check 'python3 -c "import json,sys; r=json.load(open(sys.argv[1]))[\"result\"]; assert r[\"created\"]==0 and r[\"existing\"]>=9, r" "$W/again.json"' "existing objects are left alone"
echo "E2E KUBERNETES OK"
