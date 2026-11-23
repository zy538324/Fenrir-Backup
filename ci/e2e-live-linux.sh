#!/bin/bash
# Live image of a running Linux system (design: docs/design/phase-6.md), on a real LVM setup.
#
# A loop "disk" with a GPT: ext4 /boot (not LVM) and an LVM PV holding an ext4 root LV (with a second segment) and
# an active swap LV. Both file systems are mounted, and a writer keeps changing files during the backup. The image
# is taken with `fenrir-backup backup system --disk`, restored to another loop disk, and checked: every file system
# is clean, files from before the backup are intact, the restored volume group holds no snapshot, swap keeps its
# header, and no snapshot is left on the source.
#
#   sudo ci/e2e-live-linux.sh WORK path/to/fenrir-backup
set -euo pipefail
W=$1
CLI=$(realpath "$2")
VG=fenrirlive
rm -rf "$W" && mkdir -p "$W"
export FENRIR_PASSPHRASE="live e2e passphrase"
# Exit code 10 = succeeded with warnings.
B() { local rc=0; "$CLI" --repo "$W/repo" "$@" || rc=$?; [ "$rc" = 0 ] || [ "$rc" = 10 ] || { echo "fenrir-backup $* failed ($rc)" >&2; return "$rc"; }; }
SRC= DST= WRITER=
cleanup() {
  set +e
  [ -n "$WRITER" ] && kill "$WRITER" 2>/dev/null
  umount -R "$W/mnt" 2>/dev/null; umount -R "$W/check" 2>/dev/null
  swapoff "/dev/$VG/swap" 2>/dev/null
  vgchange -an "$VG" >/dev/null 2>&1
  [ -n "$SRC" ] && losetup -d "$SRC"
  [ -n "$DST" ] && losetup -d "$DST"
}
trap cleanup EXIT

truncate -s 1200M "$W/src.img" "$W/dst.img"
SRC=$(losetup -fP --show "$W/src.img")
sfdisk -q "$SRC" <<P
label: gpt
size=256MiB, type=linux, name=boot
type=E6D6D379-F507-44C2-A23C-238F2A3DF928, name=lvm
P
partprobe "$SRC" || true; udevadm settle
mkfs.ext4 -q -L boot "${SRC}p1"
pvcreate -q "${SRC}p2"
vgcreate -q "$VG" "${SRC}p2"
lvcreate -q -y -L 300M -n root "$VG"
lvcreate -q -y -L 64M -n swap "$VG"
lvextend -q -L +100M "$VG/root"          # a second segment, after the swap LV
mkfs.ext4 -q -L root "/dev/$VG/root"
mkswap -q -L fenrirswap "/dev/$VG/swap" >/dev/null
swapon "/dev/$VG/swap"
mkdir -p "$W/mnt"
mount "/dev/$VG/root" "$W/mnt"
mkdir -p "$W/mnt/boot" && mount "${SRC}p1" "$W/mnt/boot"
for d in "$W/mnt" "$W/mnt/boot"; do
  mkdir -p "$d/keep" "$d/churn"
  for i in $(seq 1 20); do head -c $((200000 + i * 7919)) /dev/urandom > "$d/keep/f$i"; done
done
# Files from before the backup span both segments of root.
head -c 250M /dev/urandom > "$W/mnt/keep/big"
sync
(cd "$W/mnt" && find keep -type f -exec sha256sum {} + | sort -k2) > "$W/root.sums"
(cd "$W/mnt/boot" && find keep -type f -exec sha256sum {} + | sort -k2) > "$W/boot.sums"

# Writer: keeps rewriting files in both file systems for the whole backup.
( n=0; while true; do
    n=$((n + 1))
    head -c 1M /dev/urandom > "$W/mnt/churn/w$((n % 40))"
    head -c 256K /dev/urandom > "$W/mnt/boot/churn/w$((n % 20))"
    rm -f "$W/mnt/churn/w$(((n + 7) % 40))"
    sync -f "$W/mnt/churn" 2>/dev/null || true
  done ) &
WRITER=$!
sleep 2

B repo init --recovery-key-out "$W/recovery.key" >/dev/null
B --json backup system --disk "$SRC" --label live > "$W/backup.json"
cat "$W/backup.json"
kill "$WRITER"; wait "$WRITER" 2>/dev/null || true; WRITER=
IMAGE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["result"]["image_id"])' "$W/backup.json")
B --json image show "$IMAGE" > "$W/manifest.json"
python3 - "$W/manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))["result"]
assert m["consistency"] == "crash", m["consistency"]
assert m["os"]["family"] == "linux", m["os"]
print("consistency:", m["consistency"], "| os:", m["os"]["name"], "| warnings:", m.get("warnings"))
PY
if lvs --noheadings -o lv_name "$VG" | grep -q fenrir-snap; then echo "snapshot left behind"; lvs "$VG"; exit 1; fi
echo "no snapshot left on the source"

# A crashed run leaves a recorded snapshot: the next run removes it (and only it).
lvcreate -q -y -s -L 64M -n fenrir-snap-root-dead "$VG/root" >/dev/null
lvcreate -q -y -s -L 64M -n someone-elses "$VG/root" >/dev/null
mkdir -p /var/lib/fenrir-backup
echo "[\"$VG/fenrir-snap-root-dead\"]" > /var/lib/fenrir-backup/linux-snapshots.json
B --json backup system --disk "$SRC" --dry-run > /dev/null 2> "$W/dry.err" || { cat "$W/dry.err"; exit 1; }
grep -q "removed leftover snapshot $VG/fenrir-snap-root-dead" "$W/dry.err"
lvs --noheadings -o lv_name "$VG" | grep -q someone-elses
! lvs --noheadings -o lv_name "$VG" | grep -q fenrir-snap
lvremove -q -y "$VG/someone-elses" >/dev/null
echo "leftover snapshot removed, another tool's snapshot kept"

# Take the source away (same VG and PV UUIDs as the restored copy), then restore.
umount -R "$W/mnt"; swapoff "/dev/$VG/swap"; vgchange -q -an "$VG" >/dev/null
losetup -d "$SRC"; SRC=
DST=$(losetup -fP --show "$W/dst.img")
B restore disk --image "$IMAGE" --disk 0 --target "$DST" --yes
partprobe "$DST" || true; udevadm settle
pvscan -q --cache >/dev/null 2>&1 || true
vgchange -q -ay "$VG" >/dev/null
lvs "$VG"
if lvs --noheadings -o lv_name "$VG" | grep -q fenrir-snap; then echo "restored VG holds a snapshot"; exit 1; fi
e2fsck -fn "/dev/$VG/root"
e2fsck -fn "${DST}p1"
blkid -o value -s TYPE "/dev/$VG/swap" | grep -qx swap
mkdir -p "$W/check" && mount -o ro "/dev/$VG/root" "$W/check" && mount -o ro "${DST}p1" "$W/check/boot"
(cd "$W/check" && find keep -type f -exec sha256sum {} + | sort -k2) | diff - "$W/root.sums"
(cd "$W/check/boot" && find keep -type f -exec sha256sum {} + | sort -k2) | diff - "$W/boot.sums"
echo "E2E LIVE LINUX OK"
