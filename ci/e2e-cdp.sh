#!/bin/bash
# Continuous data protection on Linux (design: docs/design/cdp.md), with the kernel's dm-log-writes.
#
# An ext4 logical volume on a loop disk gets CDP; the file system is mounted through the CDP device while
# `cdp run` marks the journal every second, swaps journals every 8 seconds and ships them. A file is written
# three times (versions 1, 2, 3) with seconds between; the last version crosses a journal swap. Restoring to the
# second after each version gives exactly that version, and a clean file system; a restore without --yes is refused.
#
#   sudo ci/e2e-cdp.sh WORK path/to/fenrir-backup
set -Eeuo pipefail
trap 'echo "e2e-cdp: line $LINENO failed: $BASH_COMMAND" >&2' ERR
W=$1
CLI=$(realpath "$2")
VG=fenrircdp
rm -rf "$W" && mkdir -p "$W"
export FENRIR_PASSPHRASE="cdp e2e passphrase" FENRIR_CDP_STATE="$W/state"
B() { local rc=0; "$CLI" --repo "$W/repo" "$@" || rc=$?; [ "$rc" = 0 ] || [ "$rc" = 10 ] || { echo "fenrir-backup $* failed ($rc)" >&2; return "$rc"; }; }
LOOP= RUN=
MNT=/srv/fenrir-cdp
cleanup() {
  set +e
  [ -n "$RUN" ] && kill "$RUN" 2>/dev/null
  umount "$MNT" /mnt/fenrir-cdp-check 2>/dev/null
  dmsetup remove fenrir-cdp-e2e 2>/dev/null
  vgchange -an "$VG" >/dev/null 2>&1
  [ -n "$LOOP" ] && losetup -d "$LOOP"
}
trap cleanup EXIT

modprobe dm-log-writes
truncate -s 1G "$W/disk.img"
LOOP=$(losetup -f --show "$W/disk.img")
pvcreate -q "$LOOP"
vgcreate -q "$VG" "$LOOP"
lvcreate -q -y -L 256M -n data "$VG"
udevadm settle
mkfs.ext4 -q -L data "/dev/$VG/data"
B repo init --recovery-key-out "$W/recovery.key" >/dev/null

B --json cdp enable --name e2e --volume "/dev/$VG/data" --journal-mb 96 > "$W/enable.json"
DEV=$(jq -r .result.device "$W/enable.json")
[ "$DEV" = /dev/mapper/fenrir-cdp-e2e ]
mkdir -p "$MNT" && mount "$DEV" "$MNT"

B --json cdp run --name e2e --mark-every 1 --rotate-every 8 --for 40 > "$W/run.json" &
RUN=$!
sleep 6   # the base image first

version() { echo "version $1 $(head -c 300000 /dev/urandom | base64 -w0)" > "$MNT/file.txt"; sync; sha256sum "$MNT/file.txt" | cut -d' ' -f1 > "$W/v$1.sha"; sleep 3; date +%s > "$W/t$1"; sleep 2; }
version 1
version 2
sleep 9   # a journal swap between versions 2 and 3
version 3
wait "$RUN"; RUN=
jq . "$W/run.json"
[ "$(jq '.result.cycles | length' "$W/run.json")" -ge 4 ] || { echo "expected several journal swaps" >&2; exit 1; }
jq -e '.result.cycles[0].base_image' "$W/run.json" >/dev/null

B --json cdp points --name e2e > "$W/points.json"
jq . "$W/points.json"
[ "$(jq '[.result.points[] | select(.kind == "cdp-base")] | length' "$W/points.json")" = 1 ]
[ "$(jq ".result.latest >= $(cat "$W/t3")" "$W/points.json")" = true ]

# Refused without --yes, and nothing written.
if "$CLI" --repo "$W/repo" cdp restore --name e2e --at "$(cat "$W/t1")" --target "$W/refused.img" 2>/dev/null; then
  echo "restore without --yes was not refused" >&2; exit 1
fi
[ ! -s "$W/refused.img" ]

mkdir -p /mnt/fenrir-cdp-check
for v in 1 2 3; do
  B --json cdp restore --name e2e --at "$(cat "$W/t$v")" --target "$W/r$v.img" --yes > "$W/restore$v.json"
  jq -c . "$W/restore$v.json"
  # Crash-consistent at that second: ext4 replays its own journal, then is clean.
  e2fsck -fy "$W/r$v.img" >/dev/null || [ $? -le 1 ]
  e2fsck -fn "$W/r$v.img" >/dev/null
  mount -o ro,loop "$W/r$v.img" /mnt/fenrir-cdp-check
  got=$(sha256sum /mnt/fenrir-cdp-check/file.txt | cut -d' ' -f1)
  head -c 9 /mnt/fenrir-cdp-check/file.txt; echo
  umount /mnt/fenrir-cdp-check
  [ "$got" = "$(cat "$W/v$v.sha")" ] || { echo "restore to t$v does not hold version $v" >&2; exit 1; }
done

umount "$MNT"
B cdp disable --name e2e --remove-journals
[ ! -e /dev/mapper/fenrir-cdp-e2e ]
[ -z "$(lvs --noheadings -o lv_name "$VG" | grep fenrir-cdp)" ]
echo "CDP: three points in time restored exactly, across a journal swap"
