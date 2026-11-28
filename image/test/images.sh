#!/usr/bin/env bash
# Image imports on the host image, through the API: a platform image is downloaded from the
# internet (the Debian 13 cloud image, its checksum taken from Debian's SHA512SUMS), checked, read
# by qemu-img in its sandbox and copied into its encrypted volume. A project image with a wrong
# checksum fails, and one on a private address is never fetched. An instance boots Debian from a boot
# disk made from the image, and its kernel sees a disk added and grown while it runs.
#
#   SSH_KEY=KEY image/test/images.sh IMAGE
#
# Same host and environment as instances.sh, with internet access.
set -euo pipefail

img=$(realpath "${1:?usage: images.sh IMAGE}")
: "${SSH_KEY:?set SSH_KEY to the private key of the image root user}"
NAME=images
. "$(dirname "$0")/api.sh"

base=https://cloud.debian.org/images/cloud/trixie/latest
file=debian-13-genericcloud-amd64.qcow2
sha=$(curl -fsS "$base/SHA512SUMS" | awk -v f="$file" '$2 == f {print $1}')
[ "${#sha}" = 128 ] || fail "no checksum for $file"

truncate -s 10G "$work/data.raw"
qemu_args+=(-drive "file=$work/data.raw,if=none,id=data,format=raw" -device "virtio-blk-pci,drive=data,serial=data")
boot_node

echo "== pool"
guest vgcreate --yes data /dev/disk/by-id/virtio-data >/dev/null
call POST "/v1/platform/storagePools?storage_pool_id=n1-data" \
  '{"spec": {"node": "n1", "driver": "lvm", "source": "data"}}' >/dev/null
ready() { [ "$(call GET /v1/platform/storagePools/n1-data | jq -r .status.ready)" = true ]; }
until_true "pool ready" 60 ready
call POST "/v1/platform/volumeTypes?volume_type_id=fast" '{"spec": {"pools": ["n1-data"]}}' >/dev/null

image() { # PATH NAME URL CHECKSUM-JSON; an empty URL: uploaded
  local url=
  [ -n "$3" ] && url="\"url\": \"$3\", "
  call POST "$1?image_id=$2" "{\"spec\": {\"source\": {$url\"checksum\": $4}, \"volume_type\": \"fast\"}}" >/dev/null
}
phase() { call GET "$1/$2" | jq -r .status.phase; }
is() { [ "$(phase "$1" "$2")" = "$3" ]; }
show() { call GET "$1/$2" | jq -c .status >&2; guest journalctl -u torngatd --no-pager -b | grep -iE "image|qemu-img" | tail -n 20 >&2; }

echo "== refused"
project=/v1/orgs/acme/projects/web/images
image "$project" bad "$base/$file" "{\"sha512\": \"$(printf '0%.0s' $(seq 128))\"}"
image "$project" private "https://10.0.2.2/x.qcow2" "{\"sha256\": \"$(printf '0%.0s' $(seq 64))\"}"
for _ in $(seq 120); do is "$project" private failed && break; sleep 1; done
is "$project" private failed || { show "$project" private; fail "a private address was not refused"; }
msg=$(call GET "$project/private" | jq -r .status.message)
[[ "$msg" = *"cannot be reached"* ]] || fail "private: $msg"
echo "ok: a private address is refused ($msg)"

echo "== import"
platform=/v1/platform/images
image "$platform" debian "$base/$file" "{\"sha512\": \"$sha\"}"
for _ in $(seq 900); do
  p=$(phase "$platform" debian)
  [ "$p" = ready ] || [ "$p" = failed ] && break
  sleep 1
done
is "$platform" debian ready || { show "$platform" debian; fail "not imported"; }
s=$(call GET "$platform/debian" | jq -c .status)
[ "$(jq -r .format <<<"$s")" = qcow2 ] || fail "format: $s"
size=$(jq -r .size_bytes <<<"$s")
[ "$size" -ge $((2 << 30)) ] || fail "size: $s"
echo "ok: imported ($size bytes, qcow2)"
until_true "bad failed" 300 is "$project" bad failed
msg=$(call GET "$project/bad" | jq -r .status.message)
[[ "$msg" = *checksum* ]] || fail "bad: $msg"
echo "ok: a wrong checksum fails"

echo "== volume"
lvs_count() { guest lvs --noheadings -o lv_name data | tr -d ' ' | grep -c '^torngat-' || true; }
one_left() { [ "$(lvs_count)" = 1 ]; }
until_true "the staging volumes deleted" 120 one_left
closed() { [ "$(guest sh -c 'ls /dev/mapper/ | grep -c torngat-vol- || true')" = 0 ]; }
until_true "volumes closed" 60 closed
echo "ok: one volume left, closed"

echo "== boot from it"
base=/v1/orgs/acme/projects/web
call POST "$base/instances?instance_id=vm" '{"spec": {"vcpus": 2, "memory_mib": 1024,
  "boot_disk": {"volume_type": "fast", "size_gib": 3, "image": {"name": "debian", "platform": true}}}}' >/dev/null
vm() { call GET "$base/instances/vm"; }
running() { [ "$(vm | jq -r .status.phase)" = running ]; }
for _ in $(seq 300); do running && break; sleep 1; done
running || { vm | jq -c .status >&2; show "$platform" debian; fail "not started from the image"; }
[ "$(call GET "$base/volumes/vm-boot" | jq -r .status.filled)" = true ] || fail "boot disk not filled"
log=/var/lib/torngat-vm/$(vm | jq -r .metadata.uid)/console.log
seen() { guest "grep -aqE '$1' $log"; }
kernel() { seen 'Linux version'; }
until_true "the guest's kernel" 180 kernel
login() { seen 'login:'; }
until_true "the guest's login prompt" 300 login
echo "ok: Debian boots from a boot disk made from the image"
# The guest sees a disk added while it runs, and its growth.
call POST "$base/volumes?volume_id=data-1" '{"spec": {"volume_type": "fast", "size_gib": 1}}' >/dev/null
call PATCH "$base/instances/vm" "$(vm | jq -c '{etag: .metadata.etag, spec: (.spec + {disks: [{volume: "data-1"}]})}')" >/dev/null
vdb() { seen '\[vdb\]'; }
until_true "the guest sees the added disk" 180 vdb
d=$(call GET "$base/volumes/data-1")
call PATCH "$base/volumes/data-1" "$(jq -c '{etag: .metadata.etag, spec: (.spec + {size_gib: 2})}' <<<"$d")" >/dev/null
grown() { seen 'vdb.*capacity change'; }
for _ in $(seq 180); do grown && break; sleep 1; done
grown || {
  call GET "$base/volumes/data-1" | jq -c .status >&2
  guest "grep -a vdb $log" | tail -n 5 >&2
  fail "the guest did not see the disk grow"
}
echo "ok: the guest sees a disk added and grown while it runs"
call DELETE "$base/instances/vm" >/dev/null
boot_gone() { [ "$(code "$(api GET "$base/volumes/vm-boot")")" = 404 ]; }
until_true "boot disk deleted" 120 boot_gone
data_free() { [ "$(call GET "$base/volumes/data-1" | jq -r '.status.attached_to // empty')" = "" ]; }
until_true "data volume released" 60 data_free
call DELETE "$base/volumes/data-1" >/dev/null

echo "== upload"
# A small raw disk, in two parts, the second first.
head -c 3000000 /dev/urandom >"$work/up.raw"
sum=$(sha256sum "$work/up.raw" | cut -d' ' -f1)
image "$project" up "" "{\"sha256\": \"$sum\"}"
upload() { # PART FILE
  curl -s -m 60 -X PUT -o /dev/null -w '%{http_code}' --config <(printf 'header = "Authorization: Bearer %s"\n' "$token") \
    --data-binary "@$2" "http://127.0.0.1:$api_port$project/up/upload/parts/$1"
}
head -c 2000000 "$work/up.raw" >"$work/p1"
tail -c 1000000 "$work/up.raw" >"$work/p2"
[ "$(upload 2 "$work/p2")" = 200 ] && [ "$(upload 1 "$work/p1")" = 200 ] || fail "parts refused"
call POST "$project/up/upload:finish" >/dev/null
until_true "uploaded image imported" 300 is "$project" up ready
[ "$(call GET "$project/up" | jq -r .status.size_bytes)" = 3000000 ] || fail "upload size"
echo "ok: an uploaded image is imported"
call DELETE "$project/up" >/dev/null

echo "== deleted"
call DELETE "$platform/debian" >/dev/null
gone() { [ "$(code "$(api GET "$platform/debian")")" = 404 ]; }
until_true "image gone" 120 gone
none_left() { [ "$(lvs_count)" = 0 ]; }
until_true "its volume deleted" 120 none_left
echo "ok: deleted with its volume"
ok=1
echo PASS
