#!/bin/bash
# Application-aware live images on Linux (design: docs/design/app-aware-linux.md), with real databases.
#
# A loop disk with an LVM volume holds a running PostgreSQL cluster and a running MySQL server, each with a writer
# inserting rows during the backup, and a freeze/thaw hook in /etc/fenrir-backup/hooks.d. The image must be
# application-consistent and list PostgreSQL, MySQL and the hook as coordinated; the hook ran freeze then thaw.
# The image is restored to another loop disk, and both databases start on the restored files: every row committed
# before the backup started is there, and their own checks (amcheck, CHECK TABLE) find nothing wrong.
#
#   sudo ci/e2e-app-aware-linux.sh WORK path/to/fenrir-backup
set -euo pipefail
W=$1
CLI=$(realpath "$2")
VG=fenrirapps
PG_BIN=$(ls -d /usr/lib/postgresql/*/bin | sort -V | tail -1)
rm -rf "$W" && mkdir -p "$W"
export FENRIR_PASSPHRASE="app-aware e2e passphrase"
B() { local rc=0; "$CLI" --repo "$W/repo" "$@" || rc=$?; [ "$rc" = 0 ] || [ "$rc" = 10 ] || { echo "fenrir-backup $* failed ($rc)" >&2; return "$rc"; }; }
SRC= DST= PGW= MYW=
MNT=/srv/fenrir-apps
PGSOCK=/tmp/fenrir-pg
MYSOCK=/tmp/fenrir-mysql.sock
pgc() { runuser -u postgres -- "$PG_BIN/psql" -X -q -A -t -h "$PGSOCK" -p 54329 -d postgres -c "$1"; }
myc() { mysql --socket="$MYSOCK" -uroot -N -B -e "$1"; }
stop_dbs() {
  [ -n "$PGW" ] && kill "$PGW" 2>/dev/null; [ -n "$MYW" ] && kill "$MYW" 2>/dev/null; PGW= MYW=
  runuser -u postgres -- "$PG_BIN/pg_ctl" -D "$MNT/pg" -m fast stop >/dev/null 2>&1 || true
  mysqladmin --socket="$MYSOCK" -uroot shutdown 2>/dev/null || true
  for _ in $(seq 1 60); do pgrep -f "datadir=$MNT/mysql" >/dev/null || break; sleep 1; done
}
cleanup() {
  set +e
  stop_dbs
  umount "$MNT" 2>/dev/null
  vgchange -an "$VG" >/dev/null 2>&1
  [ -n "$SRC" ] && losetup -d "$SRC"
  [ -n "$DST" ] && losetup -d "$DST"
  rm -rf /etc/fenrir-backup/hooks.d/10-e2e /etc/fenrir-backup/mysql.cnf
}
trap cleanup EXIT

# MySQL's AppArmor profile only allows /var/lib/mysql; this server lives elsewhere.
apparmor_parser -R /etc/apparmor.d/usr.sbin.mysqld 2>/dev/null || true

truncate -s 1500M "$W/src.img" "$W/dst.img"
SRC=$(losetup -fP --show "$W/src.img")
sfdisk -q "$SRC" <<P
label: gpt
type=E6D6D379-F507-44C2-A23C-238F2A3DF928, name=lvm
P
partprobe "$SRC" || true; udevadm settle
pvcreate -q "${SRC}p1"
vgcreate -q "$VG" "${SRC}p1"
lvcreate -q -y -L 900M -n data "$VG"
mkfs.ext4 -q -L data "/dev/$VG/data"
mkdir -p "$MNT" && mount "/dev/$VG/data" "$MNT"

# ---- PostgreSQL: a cluster on the volume, data and WAL together --------------------------------------
mkdir -p "$MNT/pg" "$PGSOCK" && chown postgres:postgres "$MNT/pg" "$PGSOCK"
runuser -u postgres -- "$PG_BIN/initdb" -D "$MNT/pg" >/dev/null
runuser -u postgres -- "$PG_BIN/pg_ctl" -D "$MNT/pg" -l /tmp/fenrir-pg.log -w \
  -o "-p 54329 -k $PGSOCK -c listen_addresses=''" start >/dev/null
pgc "CREATE TABLE t (id bigserial PRIMARY KEY, phase text, pad text); CREATE EXTENSION amcheck;"
pgc "INSERT INTO t (phase, pad) SELECT 'before', repeat('x', 200) FROM generate_series(1, 20000);"

# ---- MySQL: a second server with its data folder on the volume ---------------------------------------
mkdir -p "$MNT/mysql" && chown mysql:mysql "$MNT/mysql"
mysqld --no-defaults --initialize-insecure --user=mysql --datadir="$MNT/mysql" 2> "$W/mysql-init.log"
mysqld --no-defaults --user=mysql --datadir="$MNT/mysql" --socket="$MYSOCK" --port=33069 \
  --pid-file=/tmp/fenrir-mysql.pid --mysqlx=OFF --log-error=/tmp/fenrir-mysql.log &
for _ in $(seq 1 60); do myc "SELECT 1" >/dev/null 2>&1 && break; sleep 1; done
myc "CREATE DATABASE fenrir; CREATE TABLE fenrir.t (id BIGINT AUTO_INCREMENT PRIMARY KEY, phase VARCHAR(10), pad TEXT) ENGINE=InnoDB;"
myc "INSERT INTO fenrir.t (phase, pad) SELECT 'before', REPEAT('x', 200) FROM (SELECT 1 FROM information_schema.columns LIMIT 2000) a;"
mkdir -p /etc/fenrir-backup/hooks.d && chmod 755 /etc/fenrir-backup /etc/fenrir-backup/hooks.d
printf '[client]\nuser=root\nsocket=%s\n' "$MYSOCK" > /etc/fenrir-backup/mysql.cnf
chmod 600 /etc/fenrir-backup/mysql.cnf

PG_BEFORE=$(pgc "SELECT count(*) FROM t")
MY_BEFORE=$(myc "SELECT count(*) FROM fenrir.t")

# ---- a hook: logs its phases ---------------------------------------------------------------------------
cat > /etc/fenrir-backup/hooks.d/10-e2e <<EOF
#!/bin/sh
echo "\$1 \$(date +%s%N)" >> $W/hook.log
EOF
chmod 755 /etc/fenrir-backup/hooks.d/10-e2e

# ---- writers, then the backup ---------------------------------------------------------------------------
( while true; do pgc "INSERT INTO t (phase, pad) SELECT 'during', repeat('y', 200) FROM generate_series(1, 200);" >/dev/null 2>&1 || true; done ) &
PGW=$!
( while true; do myc "INSERT INTO fenrir.t (phase, pad) VALUES ('during', REPEAT('y', 200)), ('during', REPEAT('y', 200));" >/dev/null 2>&1 || true; done ) &
MYW=$!
sleep 3

B repo init --recovery-key-out "$W/recovery.key" >/dev/null
B --json backup system --disk "$SRC" --label apps > "$W/backup.json"
cat "$W/backup.json"
IMAGE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["result"]["image_id"])' "$W/backup.json")
B --json image show "$IMAGE" > "$W/manifest.json"
python3 - "$W/manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))["result"]
apps = m.get("applications") or []
print(json.dumps(apps, indent=1))
by = {a["writer"]: a for a in apps}
assert by.get("PostgreSQL", {}).get("included"), "PostgreSQL coordinated"
assert by.get("MySQL", {}).get("included"), "MySQL coordinated"
assert any(a["writer"] == "hook" and a["component"] == "10-e2e" and a["included"] for a in apps), "hook ran"
assert m["consistency"] == "application", m["consistency"]
print("consistency:", m["consistency"])
PY
grep -q '^freeze ' "$W/hook.log" && grep -q '^thaw ' "$W/hook.log"
[ "$(head -1 "$W/hook.log" | cut -d' ' -f1)" = freeze ] && [ "$(tail -1 "$W/hook.log" | cut -d' ' -f1)" = thaw ]
echo "  ok: the hook ran freeze, then thaw"
myc "INSERT INTO fenrir.t (phase, pad) VALUES ('after', 'z');" # the lock is released

# ---- restore onto another disk and start both databases on it --------------------------------------------
stop_dbs
umount "$MNT"; vgchange -q -an "$VG" >/dev/null
losetup -d "$SRC"; SRC=
DST=$(losetup -fP --show "$W/dst.img")
B restore disk --image "$IMAGE" --disk 0 --target "$DST" --yes
partprobe "$DST" || true; udevadm settle
pvscan -q --cache >/dev/null 2>&1 || true
vgchange -q -ay "$VG" >/dev/null
e2fsck -fn "/dev/$VG/data"
mount "/dev/$VG/data" "$MNT"
rm -f "$MNT/pg/postmaster.pid"
runuser -u postgres -- "$PG_BIN/pg_ctl" -D "$MNT/pg" -l /tmp/fenrir-pg-restored.log -w \
  -o "-p 54329 -k $PGSOCK -c listen_addresses=''" start >/dev/null
PG_AFTER=$(pgc "SELECT count(*) FROM t WHERE phase = 'before'")
[ "$PG_AFTER" = "$PG_BEFORE" ] || { echo "PostgreSQL: $PG_AFTER rows from before, expected $PG_BEFORE"; exit 1; }
pgc "SELECT bt_index_check('t_pkey', true);" >/dev/null
echo "  ok: PostgreSQL starts on the restored files, all $PG_BEFORE earlier rows there, amcheck clean ($(pgc "SELECT count(*) FROM t") rows in all)"
rm -f "$MNT/mysql/"*.pid
mysqld --no-defaults --user=mysql --datadir="$MNT/mysql" --socket="$MYSOCK" --port=33069 \
  --pid-file=/tmp/fenrir-mysql.pid --mysqlx=OFF --log-error=/tmp/fenrir-mysql-restored.log &
for _ in $(seq 1 90); do myc "SELECT 1" >/dev/null 2>&1 && break; sleep 1; done
MY_AFTER=$(myc "SELECT count(*) FROM fenrir.t WHERE phase = 'before'")
[ "$MY_AFTER" = "$MY_BEFORE" ] || { echo "MySQL: $MY_AFTER rows from before, expected $MY_BEFORE"; exit 1; }
[ "$(myc "SELECT count(*) FROM fenrir.t WHERE phase = 'after'")" = 0 ] || { echo "MySQL: a row from after the backup"; exit 1; }
myc "CHECK TABLE fenrir.t" | grep -q "status	OK"
echo "  ok: MySQL starts on the restored files, all $MY_BEFORE earlier rows there, none from after, CHECK TABLE OK"
echo "E2E APP-AWARE LINUX OK"
