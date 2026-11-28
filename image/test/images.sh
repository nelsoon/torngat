#!/usr/bin/env bash
# Image imports on the host image, through the API: a platform image is downloaded from the
# internet (the Debian 13 cloud image, its checksum taken from Debian's SHA512SUMS), checked, read
# by qemu-img in its sandbox and copied into its encrypted volume. A project image with a wrong
# checksum fails, and one on a private address is never fetched.
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

truncate -s 8G "$work/data.raw"
qemu_args+=(-drive "file=$work/data.raw,if=none,id=data,format=raw" -device "virtio-blk-pci,drive=data,serial=data")
boot_node

echo "== pool"
guest vgcreate --yes data /dev/disk/by-id/virtio-data >/dev/null
call POST "/v1/platform/storagePools?storage_pool_id=n1-data" \
  '{"spec": {"node": "n1", "driver": "lvm", "source": "data"}}' >/dev/null
ready() { [ "$(call GET /v1/platform/storagePools/n1-data | jq -r .status.ready)" = true ]; }
until_true "pool ready" 60 ready
call POST "/v1/platform/volumeTypes?volume_type_id=fast" '{"spec": {"pools": ["n1-data"]}}' >/dev/null

image() { # PATH NAME URL CHECKSUM-JSON
  call POST "$1?image_id=$2" "{\"spec\": {\"source\": {\"url\": \"$3\", \"checksum\": $4}, \"volume_type\": \"fast\"}}" >/dev/null
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

echo "== deleted"
call DELETE "$platform/debian" >/dev/null
gone() { [ "$(code "$(api GET "$platform/debian")")" = 404 ]; }
until_true "image gone" 120 gone
none_left() { [ "$(lvs_count)" = 0 ]; }
until_true "its volume deleted" 120 none_left
echo "ok: deleted with its volume"
ok=1
echo PASS
