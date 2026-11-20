#!/bin/sh
# Install the auto-update timer. Run as root from the clone:
#   sudo sh scripts/server-sync/install.sh
set -eu
DIR="$(cd "$(dirname "$0")/../.." && pwd)"
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }
command -v docker >/dev/null || { echo "install Docker first"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "install the Docker Compose plugin first"; exit 1; }
chmod +x "$DIR/scripts/server-sync/fenrir-sync.sh"
sed "s#/opt/fenrir-backup#$DIR#g" "$DIR/scripts/server-sync/fenrir-sync.service" > /etc/systemd/system/fenrir-sync.service
cp "$DIR/scripts/server-sync/fenrir-sync.timer" /etc/systemd/system/fenrir-sync.timer
# git refuses repositories owned by another user unless trusted.
git config --system --add safe.directory "$DIR" 2>/dev/null || true
systemctl daemon-reload
systemctl enable --now fenrir-sync.timer
echo "Installed. First build starts now; follow it with: journalctl -fu fenrir-sync"
systemctl start --no-block fenrir-sync.service
