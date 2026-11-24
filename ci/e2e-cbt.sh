#!/bin/bash
# Changed-block tracking on Linux with dm-era (design: docs/design/cbt-physical.md).
#
# An ext4 logical volume gets tracking and is mounted through the era device. A first backup reads everything; then
# 1 MiB of a 40 MiB file is rewritten and a small file added, and the second backup must read only the changed
# blocks (read mode "changed_blocks", most of the volume taken from the first image). Restoring the second backup
# gives a clean file system with exactly the files as they were.
#
#   sudo ci/e2e-cbt.sh WORK path/to/fenrir-backup
set -Eeuo pipefail
trap 'echo "e2e-cbt: line $LINENO failed: $BASH_COMMAND" >&2' ERR
W=$1
CLI=$(realpath "$2")
VG=fenrircbt
rm -rf "$W" && mkdir -p "$W"
export FENRIR_PASSPHRASE="cbt e2e passphrase" FENRIR_CDP_STATE="$W/state"
B() { local rc=0; "$CLI" --repo "$W/repo" "$@" || rc=$?; [ "$rc" = 0 ] || [ "$rc" = 10 ] || { echo "fenrir-backup $* failed ($rc)" >&2; return "$rc"; }; }
LOOP=
MNT=/srv/fenrir-cbt
cleanup() {
  set +e
  umount "$MNT" /mnt/fenrir-cbt-check 2>/dev/null
  dmsetup remove fenrir-era-e2e 2>/dev/null
  vgchange -an "$VG" >/dev/null 2>&1
  [ -n "$LOOP" ] && losetup -d "$LOOP"
}
trap cleanup EXIT

modprobe dm-era
truncate -s 1G "$W/disk.img"
LOOP=$(losetup -f --show "$W/disk.img")
pvcreate -q "$LOOP"
vgcreate -q "$VG" "$LOOP"
lvcreate -q -y -L 256M -n data "$VG"
mkfs.ext4 -q -L data "/dev/$VG/data"
B repo init --recovery-key-out "$W/recovery.key" >/dev/null

B --json cbt enable --name e2e --volume "/dev/$VG/data" --block-kib 64 > "$W/enable.json"
DEV=$(jq -r .result.device "$W/enable.json")
mkdir -p "$MNT" && mount "$DEV" "$MNT"
head -c 40M /dev/urandom > "$MNT/big.bin"
mkdir -p "$MNT/docs" && seq 1 20000 > "$MNT/docs/list.txt"
sync

B --json cbt backup --name e2e > "$W/b1.json"
jq -c .result "$W/b1.json"
[ "$(jq -r .result.read_mode "$W/b1.json")" = full ]

dd if=/dev/urandom of="$MNT/big.bin" bs=1M seek=12 count=1 conv=notrunc status=none
echo "added after the first backup" > "$MNT/docs/new.txt"
sync
sha256sum "$MNT/big.bin" "$MNT/docs/list.txt" "$MNT/docs/new.txt" | sed "s|$MNT/||" > "$W/expected.sha"

B --json cbt backup --name e2e > "$W/b2.json"
jq -c .result "$W/b2.json"
[ "$(jq -r .result.read_mode "$W/b2.json")" = changed_blocks ] || { echo "the second backup did not use the tracking" >&2; exit 1; }
unchanged=$(jq -r .result.bytes_unchanged "$W/b2.json")
[ "$unchanged" -gt $((30 << 20)) ] || { echo "only $unchanged bytes were taken from the first image" >&2; exit 1; }
B --json cbt status --name e2e | jq -c .result

# The second image, restored: a clean file system with exactly those files.
IMAGE=$(jq -r .result.image_id "$W/b2.json")
B restore disk --image "$IMAGE" --disk 0 --target "$W/restored.img" --yes
e2fsck -fn "$W/restored.img"
mkdir -p /mnt/fenrir-cbt-check
mount -o ro,loop "$W/restored.img" /mnt/fenrir-cbt-check
(cd /mnt/fenrir-cbt-check && sha256sum -c "$W/expected.sha")
umount /mnt/fenrir-cbt-check

umount "$MNT"
B cbt disable --name e2e
[ ! -e /dev/mapper/fenrir-era-e2e ]
echo "CBT: the second backup read only the changed blocks and restores exactly"
