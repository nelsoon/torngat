#!/usr/bin/env bash
# Storage test for the host image: LVM, LUKS2 and, if the image was built with --zfs, ZFS.
#
#   SSH_KEY=KEY CERT=FILE image/test/storage.sh IMAGE
#
# 1. LVM sees only volume groups made on this machine, not those of other disks or inside volumes,
#    and nothing is activated by itself.
# 2. A LUKS2 volume on LVM keeps its data over a power cut.
# 3. ZFS: the module loads only with our signature, pools are not imported by themselves nor when they
#    belong to another machine, and a LUKS2 volume on a zvol keeps its data over a power cut.
#
# Same environment as secure-boot.sh.
set -euo pipefail
img=${1:?usage: storage.sh IMAGE}
: "${SSH_KEY:?set SSH_KEY to the private key of the image root user}"
here=$(cd "$(dirname "$0")" && pwd)
cert=$(realpath "${CERT:?set CERT to the certificate the image is signed with}")
port=${SSH_PORT:-2222}
. "$here/lib.sh"

for d in own foreign pool; do
  truncate -s 2G "$work/$d.raw"
  # cache=none: what the guest did not flush is lost with QEMU only if the guest kept it.
  qemu_args+=(-drive "file=$work/$d.raw,if=none,id=$d,format=raw,cache=none" -device "virtio-blk-pci,drive=$d,serial=$d")
done
# By serial number: the order of the disks is not fixed.
id() { echo "/dev/disk/by-id/virtio-$1"; }
power_cut() {
  kill -9 "$(cat "$dir/qemu.pid")"
  stop
  REUSE=1 start node "$work/ours.fd"
  expect_up "after a power cut"
}
run() { guest "set -eu; $1" >"$work/out" 2>&1 || { cat "$work/out" >&2; fail "$2"; }; }
refuse() { # COMMAND MESSAGE WHAT
  if guest "$1" >"$work/out" 2>&1; then fail "$3: not refused"; fi
  grep -qE "$2" "$work/out" || { cat "$work/out" >&2; fail "$3: unexpected refusal"; }
}
expect_vgs() { # NAMES [VGS OPTIONS]
  local found
  found=$(guest "vgs --noheadings -o vg_name ${2:-}") || fail "vgs"
  [ "$(xargs -n1 <<<"$found" | sort | xargs)" = "$1" ] || fail "visible volume groups: $found"
}
expect_hostid() {
  hostid=$(guest 'test "$(stat -c %s /etc/hostid)" = 4 && od -An -tx1 /etc/hostid') || fail "no host ID"
}
not_loaded() { guest 'test ! -e /sys/module/zfs' || fail "the ZFS module is loaded by itself"; }
key='head -c 64 /dev/zero'
make_luks() { # DEVICE NAME [MB]
  run "$key | cryptsetup luksFormat -q --type luks2 --pbkdf pbkdf2 --key-file - $1
    $key | cryptsetup open --key-file - $1 $2
    dd if=/dev/urandom of=/root/$2 bs=1M count=${3:-64} status=none
    dd if=/root/$2 of=/dev/mapper/$2 bs=1M oflag=direct conv=fsync status=none; sync /root/$2" "LUKS on $1"
}
check_luks() { # DEVICE NAME
  run "$key | cryptsetup open --key-file - $1 $2; cmp -n $((64 << 20)) /root/$2 /dev/mapper/$2" "LUKS on $1 after a power cut"
}

only_trusts "$cert" "$work/ours.fd"
start node "$work/ours.fd"
expect_up "first boot"
expect_enforced
no_failed_units
mappings=$(guest ls /dev/mapper)

run "vgcreate --devicesfile '' foreign $(id foreign) && lvcreate --devicesfile '' -y -n lv -L 100M foreign" "another machine's volume group"
expect_vgs foreign "--devicesfile ''"
expect_vgs ""
run "vgcreate own $(id own) && lvcreate -y -n lv -L 500M own" "volume group"
make_luks /dev/own/lv lvdata
# What an instance's volume looks like to the host.
run "lvcreate -y -n guest -L 100M own" "guest volume"
make_luks /dev/own/guest guestdata 16
run "vgcreate --devicesfile '' guestvg /dev/mapper/guestdata" "a volume group in an instance's volume"
expect_vgs "foreign guestvg own" "--devicesfile ''"
expect_vgs own
guest 'test ! -e /usr/lib/udev/rules.d/64-btrfs.rules' || fail "udev gives btrfs to the kernel"

if guest test -e /usr/sbin/zpool; then zfs=1; else zfs=; fi
if [ -n "$zfs" ]; then
  not_loaded
  # The modules' two last parts: 12 bytes of structure, 28 of marker.
  run 'cp "$(modinfo -n spl)" /root/spl.ko
    strings=$(tail -c 28 /root/spl.ko); [ "$strings" = "~Module signature appended~" ]
    head -c -28 /root/spl.ko >/root/unsigned.ko
    printf x | dd of=/root/spl.ko bs=1 seek=4096 conv=notrunc status=none' "module copies"
  refuse 'insmod /root/unsigned.ko' 'Key was rejected|not permitted|Required key' "unsigned module"
  refuse 'insmod /root/spl.ko' 'Key was rejected|not permitted|Required key' "changed module"
  run "modprobe zfs; zpool create -O mountpoint=none tank $(id pool)
    zfs create -s -V 500M tank/vol; udevadm settle" "pool"
  versions=$(guest zfs version | sed 's/^zfs-\(kmod-\)\?//') || fail "zfs version"
  [ "$(wc -l <<<"$versions") $(sort -u <<<"$versions" | wc -l)" = "2 1" ] || fail "the module and the tools differ"
  make_luks /dev/zvol/tank/vol zdata
  expect_hostid
fi

power_cut
no_failed_units
expect_vgs own
[ "$(guest ls /dev/mapper)" = "$mappings" ] || fail "activated by itself: $(guest ls /dev/mapper | xargs)"
run "vgchange -qq -ay own; udevadm settle" "activation"
check_luks /dev/own/lv lvdata
run "$key | cryptsetup open --key-file - /dev/own/guest guestdata; udevadm settle" "guest volume"
expect_vgs "foreign guestvg own" "--devicesfile ''"
expect_vgs own
echo "ok: LVM and LUKS2"

if [ -n "$zfs" ]; then
  not_loaded
  first=$hostid
  expect_hostid
  [ "$hostid" = "$first" ] || fail "the host ID changed"
  guest 'test -s /etc/zfs/zpool.cache' || fail "no pool cache: the next check would not say anything"
  pools=$(guest zpool list -H -o name) || fail "zpool list"
  [ -z "$pools" ] || fail "imported by itself: $pools"
  units=$(guest "systemctl list-unit-files --no-legend 'zfs*' 'lvm2*' blk-availability.service 'dm-event*'") || fail "list-unit-files"
  grep -q '^zfs-import-cache.service' <<<"$units" || fail "no ZFS units listed"
  enabled=$(awk '$2 == "enabled"' <<<"$units")
  [ -z "$enabled" ] || fail "enabled units: $enabled"
  run "cp /etc/hostid /root/hostid; zgenhostid -f" "another host ID"
  refuse 'zpool import -N tank' 'in use from another system' "another machine's pool"
  run "cp /root/hostid /etc/hostid; zpool import -N tank; udevadm settle" "import"
  check_luks /dev/zvol/tank/vol zdata
  run "cryptsetup close zdata; zpool scrub -w tank; zpool status -x tank | grep -q healthy; zpool export tank" "scrub"
fi
run "cryptsetup close lvdata; cryptsetup close guestdata; vgchange -qq -an own" "closing"
shut_down

if [ -n "$zfs" ]; then
  start other "$work/ours.fd"
  expect_up "another machine"
  first=$hostid
  expect_hostid
  [ "$hostid" != "$first" ] || fail "two machines have the same host ID"
  echo "ok: ZFS"
else
  echo "no ZFS in this image"
fi
echo PASS
