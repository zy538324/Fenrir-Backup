#!/bin/sh
# Pull the latest Fenrir-Backup from GitHub and, if anything changed,
# rebuild and restart the server container. Run by fenrir-sync.timer.
#
# Local settings belong in compose.override.yaml next to compose.yaml
# (git-ignored, picked up by docker compose automatically): this script
# discards any edits to tracked files.
set -eu

REPO_DIR="${FENRIR_REPO_DIR:-/opt/fenrir-backup}"
STATE="${FENRIR_SYNC_STATE:-/var/lib/fenrir-sync}"
cd "$REPO_DIR"
mkdir -p "$STATE"

# One run at a time (a build can take longer than the timer interval).
exec 9>"$STATE/lock"
if ! flock -n 9; then
    echo "another sync is running; skipping"
    exit 0
fi

BRANCH="${FENRIR_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"
git fetch --quiet origin "$BRANCH"
REMOTE="$(git rev-parse FETCH_HEAD)"
DEPLOYED="$(cat "$STATE/deployed" 2>/dev/null || true)"
FAILED="$(cat "$STATE/failed" 2>/dev/null || true)"

if [ "$REMOTE" = "$DEPLOYED" ] && [ "${1:-}" != "--force" ]; then
    exit 0
fi
if [ "$REMOTE" = "$FAILED" ] && [ "${1:-}" != "--force" ]; then
    echo "commit ${REMOTE} failed to build before; waiting for a newer one (run with --force to retry)"
    exit 0
fi

echo "updating to ${REMOTE} (${BRANCH})"
git checkout --quiet -B "$BRANCH" "$REMOTE"
git reset --quiet --hard "$REMOTE"

# Build first; the running server keeps going if the build fails.
if docker compose build --pull && docker compose up -d --remove-orphans; then
    echo "$REMOTE" > "$STATE/deployed"
    rm -f "$STATE/failed"
    docker image prune -f >/dev/null 2>&1 || true
    echo "deployed ${REMOTE}"
else
    echo "$REMOTE" > "$STATE/failed"
    echo "build or start failed for ${REMOTE}; the previous version is still running" >&2
    exit 1
fi
