#!/bin/sh
# Keep a Fenrir-Backup server current with GitHub. Run by fenrir-sync.timer.
#
# 1. Code: when the followed branch has a new commit, rebuild the image and
#    restart the container (the data volume is kept).
# 2. macOS agents: CI builds them on a Mac and publishes them to the
#    `agent-builds` branch; they are checked against SHA256SUMS and placed
#    in ./agents/<target>/, which compose.yaml mounts into the container.
#
# Local settings belong in compose.override.yaml next to compose.yaml
# (git-ignored, picked up by docker compose automatically): this script
# discards any edits to tracked files.
set -eu

REPO_DIR="${FENRIR_REPO_DIR:-/opt/fenrir-backup}"
STATE="${FENRIR_SYNC_STATE:-/var/lib/fenrir-sync}"
MAC_TARGETS="aarch64-apple-darwin x86_64-apple-darwin"
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1
cd "$REPO_DIR"
mkdir -p "$STATE"

# One run at a time (a build can take longer than the timer interval).
exec 9>"$STATE/lock"
if ! flock -n 9; then
    echo "another sync is running; skipping"
    exit 0
fi

sync_code() {
    BRANCH="${FENRIR_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"
    git fetch --quiet origin "$BRANCH"
    REMOTE="$(git rev-parse FETCH_HEAD)"
    DEPLOYED="$(cat "$STATE/deployed" 2>/dev/null || true)"
    FAILED="$(cat "$STATE/failed" 2>/dev/null || true)"
    if [ "$REMOTE" = "$DEPLOYED" ] && [ $FORCE = 0 ]; then
        return 0
    fi
    if [ "$REMOTE" = "$FAILED" ] && [ $FORCE = 0 ]; then
        echo "commit ${REMOTE} failed to build before; waiting for a newer one (run with --force to retry)"
        return 0
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
        return 1
    fi
}

sync_agents() {
    if ! git fetch --quiet origin agent-builds 2>/dev/null; then
        return 0 # not published yet (CI has not finished a run)
    fi
    REV="$(git rev-parse FETCH_HEAD)"
    if [ "$REV" = "$(cat "$STATE/agents" 2>/dev/null || true)" ] && [ $FORCE = 0 ]; then
        return 0
    fi
    TMP="$(mktemp -d "$STATE/agents.XXXXXX")"
    git archive FETCH_HEAD | tar -x -C "$TMP"
    if ! (cd "$TMP" && sha256sum -c --quiet SHA256SUMS); then
        echo "agent-builds ${REV}: checksum mismatch; not installed" >&2
        rm -rf "$TMP"
        return 1
    fi
    for t in $MAC_TARGETS; do
        # Builds from before the rename are named fenrir-agent.
        src="$TMP/$t/fenrir-backup-agent"
        [ -f "$src" ] || src="$TMP/$t/fenrir-agent"
        [ -f "$src" ] || continue
        mkdir -p "agents/$t"
        # Replace the file inside the mounted directory (keeps the mount).
        cp "$src" "agents/$t/.fenrir-backup-agent.new"
        chmod 755 "agents/$t/.fenrir-backup-agent.new"
        mv -f "agents/$t/.fenrir-backup-agent.new" "agents/$t/fenrir-backup-agent"
    done
    rm -rf "$TMP"
    echo "$REV" > "$STATE/agents"
    echo "installed macOS agents from agent-builds ${REV}"
}

rc=0
sync_code || rc=1
sync_agents || rc=1
exit $rc
