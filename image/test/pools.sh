#!/usr/bin/env bash
# Storage pools on the host image, through the API: torngatd marks an LVM volume group made by the
# operator, reports its size, and removes its mark when the pool is deleted, from inside its
# service's sandbox.
#
#   SSH_KEY=KEY image/test/pools.sh IMAGE
#
# Same host and environment as instances.sh.
set -euo pipefail

img=$(realpath "${1:?usage: pools.sh IMAGE}")
: "${SSH_KEY:?set SSH_KEY to the private key of the image root user}"
NAME=pools
. "$(dirname "$0")/api.sh"

truncate -s 1G "$work/data.raw"
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
[ "$cap" -gt $((900 << 20)) ] && [ "$cap" -le $((1 << 30)) ] || fail "capacity: $p"
tags=$(guest vgs --noheadings -o vg_tags data | tr -d ' ')
[[ "$tags" = torngat:*:"$uid" ]] || fail "mark: $tags"
echo "ok: marked and reported ($cap bytes)"

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
