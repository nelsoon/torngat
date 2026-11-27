#!/usr/bin/env bash
# Storage pools on the host image, through the API: torngatd marks an LVM volume group made by the
# operator, reports its size, and removes its mark when the pool is deleted, from inside its
# service's sandbox. An instance boots from a volume of it (its boot disk, encrypted, handed to
# QEMU by torngatd).
#
#   SSH_KEY=KEY image/test/pools.sh IMAGE
#
# Same host and environment as instances.sh.
set -euo pipefail

img=$(realpath "${1:?usage: pools.sh IMAGE}")
: "${SSH_KEY:?set SSH_KEY to the private key of the image root user}"
NAME=pools
. "$(dirname "$0")/api.sh"

truncate -s 2G "$work/data.raw"
qemu_args+=(-drive "file=$work/data.raw,if=none,id=data,format=raw" -device "virtio-blk-pci,drive=data,serial=data")
boot_node

echo "== pool"
guest vgcreate --yes data /dev/disk/by-id/virtio-data >/dev/null
call POST "/v1/platform/storagePools?storage_pool_id=n1-data" \
  '{"spec": {"node": "n1", "driver": "lvm", "source": "data"}}' >/dev/null
pool() { call GET /v1/platform/storagePools/n1-data; }
ready() { [ "$(pool | jq -r .status.ready)" = true ]; }
for _ in $(seq 60); do ready && break; sleep 1; done
ready || {
  pool | jq -c .status >&2
  guest journalctl -u torngatd --no-pager -b | grep -iE "lvm|pool|storage" | tail -n 20 >&2
  fail "pool not ready"
}
p=$(pool)
uid=$(jq -r .metadata.uid <<<"$p")
[ "$(jq -r .status.allocation_unit_bytes <<<"$p")" = $((4 << 20)) ] || fail "allocation unit: $p"
cap=$(jq -r .status.capacity_bytes <<<"$p")
[ "$cap" -gt $((1900 << 20)) ] && [ "$cap" -le $((2 << 30)) ] || fail "capacity: $p"
tags=$(guest vgs --noheadings -o vg_tags data | tr -d ' ')
[[ "$tags" = torngat:*:"$uid" ]] || fail "mark: $tags"
echo "ok: marked and reported ($cap bytes)"

echo "== boot disk"
call POST "/v1/platform/volumeTypes?volume_type_id=fast" '{"spec": {"pools": ["n1-data"]}}' >/dev/null
base=/v1/orgs/acme/projects/web
call POST "$base/instances?instance_id=vm" \
  '{"spec": {"vcpus": 1, "memory_mib": 128, "boot_disk": {"volume_type": "fast", "size_gib": 1}}}' >/dev/null
vol() { call GET "$base/volumes/vm-boot"; }
vm() { call GET "$base/instances/vm"; }
opened() { [ "$(vol 2>/dev/null | jq -r .status.open)" = true ]; }
for _ in $(seq 120); do opened && break; sleep 1; done
opened || {
  vol | jq -c .status >&2
  vm | jq -c .status >&2
  guest journalctl -u torngatd --no-pager -b | tail -n 30 >&2
  fail "boot disk not open"
}
vuid=$(vol | jq -r .metadata.uid)
iuid=$(vm | jq -r .metadata.uid)
phase_is() { [ "$(vm | jq -r .status.phase)" = "$1" ]; }
power() { # STATE
  call PATCH "$base/instances/vm" "$(vm | jq -c --arg p "$1" '{etag: .metadata.etag, spec: (.spec + {power_state: $p})}')" >/dev/null
}
# Its disk is blank: it boots nothing. Stopped, it keeps its disk open on the node.
until_true "running" 60 phase_is running
power stopped
until_true "stopped" 60 phase_is stopped
# What an image would hold: a boot sector that writes to the serial port (see
# crates/agent/tests/qemu_units.rs).
sector='\061\300\216\330\374\276\027\174\272\370\003\254\204\300\164\003\356\353\370\372\364\353\375TORNGAT-BOOT-OK\r\n\000'
guest "printf '$sector' | dd of=/dev/mapper/torngat-vol-$vuid bs=512 conv=notrunc,fsync status=none &&
  printf '\125\252' | dd of=/dev/mapper/torngat-vol-$vuid bs=1 seek=510 conv=notrunc,fsync status=none"
opened || fail "the boot disk was closed"
power running
booted() { guest grep -q TORNGAT-BOOT-OK "/var/lib/torngat-vm/$iuid/console.log" 2>/dev/null; }
until_true "boots from its disk" 60 booted
[ "$(vm | jq -r .status.phase)" = running ] || fail "instance: $(vm | jq -c .status)"
echo "ok: booted from its encrypted boot disk"
call DELETE "$base/instances/vm" >/dev/null
vol_gone() { [ "$(code "$(api GET "$base/volumes/vm-boot")")" = 404 ]; }
until_true "boot disk deleted with it" 120 vol_gone
[ -z "$(guest lvs --noheadings -o lv_name data)" ] || fail "volumes left: $(guest lvs data)"
call DELETE /v1/platform/volumeTypes/fast >/dev/null
echo "ok: deleted with the instance"

echo "== deleted"
call DELETE /v1/platform/storagePools/n1-data >/dev/null
gone() { [ "$(code "$(api GET /v1/platform/storagePools/n1-data)")" = 404 ]; }
until_true "pool gone" 60 gone
[ -z "$(guest vgs --noheadings -o vg_tags data | tr -d ' ')" ] || fail "the mark is still there"
guest vgs data >/dev/null || fail "the volume group was touched"
bad=$(guest journalctl -u torngatd --no-pager -b | grep -iE "lvm.*(fail|error|read-only)" || true)
[ -z "$bad" ] || fail "LVM complained: $bad"
failed=$(guest systemctl --failed --no-legend)
[ -z "$failed" ] || fail "failed units: $failed"
echo "ok: mark removed, group kept"
ok=1
echo PASS
