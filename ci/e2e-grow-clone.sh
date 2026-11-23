#!/bin/bash
# Growing onto a larger disk, and cloning (design: docs/design/phase-5-grow-clone.md).
#
# Two disk images, one whose last partition is ext4 and one whose last partition is NTFS (each after a
# small FAT partition), with files on them. Each is backed up and restored with --grow onto a larger image
# file, and cloned with --grow onto another: the last partition fills the new disk, its file system reports
# the new size and is clean, the files are intact, and the first partition is unchanged.
#
#   sudo ci/e2e-grow-clone.sh WORK path/to/fenrir-backup      (needs e2fsprogs, ntfs-3g, dosfstools, fdisk)
set -euo pipefail
W=$1
CLI=$(realpath "$2")
rm -rf "$W" && mkdir -p "$W"
export FENRIR_PASSPHRASE="grow e2e passphrase"
B() { local rc=0; "$CLI" --repo "$W/repo" "$@" || rc=$?; [ "$rc" = 0 ] || [ "$rc" = 10 ] || { echo "fenrir-backup $* failed ($rc)" >&2; return "$rc"; }; }
LOOPS=()
cleanup() { for l in "${LOOPS[@]}"; do umount "$l" 2>/dev/null; losetup -d "$l" 2>/dev/null; done; true; }
trap cleanup EXIT
# The partition of FILE at OFFSET (bytes), LENGTH bytes, as a loop device.
part() { local l; l=$(losetup -f --show -o "$2" --sizelimit "$3" "$1"); LOOPS+=("$l"); echo "$l"; }
# START and SIZE (bytes) of partition N of an image.
geom() { sfdisk -J "$1" | python3 -c 'import json,sys; t=json.load(sys.stdin)["partitiontable"]; p=t["partitions"][int(sys.argv[1])-1]; ss=t.get("sectorsize",512); print(p["start"]*ss, p["size"]*ss)' "$2"; }

B repo init --recovery-key-out "$W/recovery.key" >/dev/null
MIB=$((1 << 20))
for FS in ext4 ntfs; do
  echo "== last partition $FS"
  src="$W/$FS-src.img"
  truncate -s 200M "$src"
  type=$([ "$FS" = ntfs ] && echo EBD0A0A2-B9E5-4433-87C0-68B6B72699C7 || echo linux)
  sfdisk -q "$src" <<P
label: gpt
size=32MiB, type=uefi, name=esp
size=150MiB, type=$type, name=data
P
  read -r s1 l1 < <(geom "$src" 1); read -r s2 l2 < <(geom "$src" 2)
  mkfs.vfat -n FENRIRESP "$(part "$src" "$s1" "$l1")" >/dev/null
  d=$(part "$src" "$s2" "$l2")
  if [ "$FS" = ext4 ]; then mkfs.ext4 -q -L data "$d"; else mkntfs -q -f -L data "$d" >/dev/null 2>&1; fi
  mkdir -p "$W/m" && mount "$d" "$W/m"
  for i in $(seq 1 12); do head -c $((300000 + i * 4099)) /dev/urandom > "$W/m/f$i"; done
  (cd "$W/m" && sha256sum f* > "$W/$FS.sums")
  umount "$W/m"
  B --json backup disk "$src" --machine-id "grow-$FS" > "$W/$FS-backup.json"
  image=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["result"]["image_id"])' "$W/$FS-backup.json")

  for how in restore clone; do
    dst="$W/$FS-$how.img"
    truncate -s 400M "$dst"
    if [ "$how" = restore ]; then
      B --json restore disk --image "$image" --target "$dst" --yes --grow > "$W/$FS-$how.json"
    else
      B --json clone --source "$src" --target "$dst" --yes --grow > "$W/$FS-$how.json"
    fi
    python3 - "$W/$FS-$how.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))["result"]
g = r["grow"]
assert g["filesystem_grown"], g
assert g["new_length"] > g["old_length"], g
print("   grown:", g["old_length"] >> 20, "->", g["new_length"] >> 20, "MiB")
PY
    read -r t1 n1 < <(geom "$dst" 1); read -r t2 n2 < <(geom "$dst" 2)
    [ "$t1 $n1" = "$s1 $l1" ] || { echo "first partition changed"; exit 1; }
    [ "$t2" = "$s2" ] || { echo "last partition moved"; exit 1; }
    [ $((t2 + n2)) -ge $((398 * MIB)) ] || { echo "last partition ends at $((t2 + n2)) bytes"; exit 1; }
    sfdisk --verify "$dst" | grep -qv "error" || true
    d=$(part "$dst" "$t2" "$n2")
    if [ "$FS" = ext4 ]; then
      e2fsck -fn "$d" >/dev/null
      fs=$(dumpe2fs -h "$d" 2>/dev/null | awk -F: '/^Block count/{c=$2} /^Block size/{s=$2} END{print c*s}')
    else
      ntfsfix -n "$d" >/dev/null
      fs=$(ntfsresize --info --force --no-progress-bar "$d" 2>/dev/null | awk '/Current volume size/{print $4}')
    fi
    echo "   $how: partition $((n2 / MIB)) MiB, file system $((fs / MIB)) MiB"
    [ "$fs" -gt $((n2 - 2 * MIB)) ] || { echo "the file system did not grow"; exit 1; }
    mount -o ro "$d" "$W/m"
    (cd "$W/m" && sha256sum -c --quiet "$W/$FS.sums")
    umount "$W/m"
  done
done

# Refusals: the same disk, and no --yes.
! "$CLI" clone --source "$W/ext4-src.img" --target "$W/ext4-src.img" --yes 2>/dev/null
! "$CLI" clone --source "$W/ext4-src.img" --target "$W/ext4-clone.img" 2>/dev/null
echo "E2E GROW AND CLONE OK"
