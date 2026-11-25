#!/usr/bin/env bash
# Test of the host image on a machine without a TPM.
#
#   SSH_KEY=KEY CERT=FILE image/test/no-tpm.sh IMAGE
#
# 1. First boot: the root is encrypted with a key on the boot partition. A node can only be set up with
#    that accepted, and it shows.
# 2. It boots again by itself. It cannot be sealed, also with Secure Boot on.
# 3. Without the key file the root stays locked, and the image does not make another one.
# 4. A TPM added later changes nothing to an existing root: it does not use the key file.
# 5. Enrollment makes the root anew. Two attached copies of the image are refused.
#
# Needs and environment: see secure-boot.sh.
set -euo pipefail
img=${1:?usage: no-tpm.sh IMAGE}
: "${SSH_KEY:?set SSH_KEY to the private key of the image root user}"
here=$(cd "$(dirname "$0")" && pwd)
cert=$(realpath "${CERT:?set CERT to the certificate the image is signed with}")
port=${SSH_PORT:-2222}
. "$here/lib.sh"
export NO_TPM=1

start node /usr/share/OVMF/OVMF_VARS_4M.fd
expect_up "first boot"
[ "$(guest findmnt -no SOURCE /)" = /dev/mapper/root ] || fail "root is not on the encrypted volume"
[ "$(slots)" = password ] || fail "slots: $(slots)"
guest "test -e /var/lib/torngat-seal/unprotected && test ! -e $prov" || fail "markers"
[ -z "$(guest systemctl --failed --no-legend)" ] || fail "failed units: $(guest systemctl --failed --no-legend)"
if guest torngatd init --name n1 --tpm optional >"$work/out" 2>&1; then fail "init on an unprotected root"; fi
grep -q 'key on the boot partition' "$work/out" || { cat "$work/out" >&2; fail "unexpected init refusal"; }
if guest torngatd init --name n1 --allow-unsealed-root >"$work/out" 2>&1; then fail "init without a TPM"; fi
grep -q 'no TPM answers' "$work/out" || { cat "$work/out" >&2; fail "unexpected init refusal"; }
shut_down

only_trusts "$cert" "$work/ours.fd"
cp "$work/ours.fd" "$work/node/vars.fd"
REUSE=1 start node "$work/ours.fd"
expect_up "second boot, Secure Boot on"
expect_enforced
if guest torngat-seal-root >"$work/out" 2>&1; then fail "sealed without a TPM"; fi
grep -q 'made without a TPM' "$work/out" || { cat "$work/out" >&2; fail "unexpected seal refusal"; }
guest torngatd init --name n1 --tpm optional --allow-unsealed-root >"$work/out" 2>&1 || { tail -3 "$work/out" >&2; fail "init"; }
guest systemctl start torngatd
for _ in $(seq 30); do
  # The token stays in the guest.
  guest 'exec 3<>/dev/tcp/127.0.0.1/8080
    printf "GET /v1/platform/nodes HTTP/1.0\r\nHost: localhost\r\nAuthorization: Bearer %s\r\n\r\n" "$(cat /var/lib/torngat/admin-token)" >&3
    cat <&3' >"$work/nodes" 2>/dev/null || true
  grep -q disk-not-protected "$work/nodes" && break
  sleep 1
done
grep -q disk-not-protected "$work/nodes" || fail "the node does not show that its disk is not protected"
shut_down
echo "ok: runs without a TPM, accepted explicitly and shown"

esp=$(/usr/sbin/sfdisk -J "$work/node/disk.raw" | jq '.partitiontable.partitions[0].start * 512')
mcopy -n -i "$work/node/disk.raw@@$esp" ::/torngat/root.key "$work/root.key"
mdel -i "$work/node/disk.raw@@$esp" ::/torngat/root.key
REUSE=1 start node "$work/ours.fd"
expect_locked "no key file"
stop
mdir -b -i "$work/node/disk.raw@@$esp" ::/torngat >"$work/files" || fail "the directory is gone"
if grep -q root.key "$work/files"; then fail "another key was made"; fi
printf x | mcopy -i "$work/node/disk.raw@@$esp" - ::/torngat/root.key
REUSE=1 start node "$work/ours.fd"
for _ in $(seq 60); do
  alive
  if grep -aqs 'root.key on the boot partition is damaged' "$dir/serial.log"; then break; fi
  sleep 2
done
grep -aqs 'root.key on the boot partition is damaged' "$dir/serial.log" || fail "a damaged key file was accepted"
stop
[ "$(mtype -i "$work/node/disk.raw@@$esp" ::/torngat/root.key)" = x ] || fail "the damaged key file was written over"
mcopy -o -i "$work/node/disk.raw@@$esp" "$work/root.key" ::/torngat/root.key
REUSE=1 start node "$work/ours.fd"
expect_up "key file back"
guest test -e /var/lib/torngat/node.json || fail "state lost"
shut_down
echo "ok: locked without the key file, nothing written over"

mkdir -p "$work/node/tpm"
swtpm_setup --tpm2 --tpmstate "$work/node/tpm" --create-ek-cert --overwrite \
  --config "${XDG_CONFIG_HOME:-$HOME/.config}/swtpm_setup.conf" >"$work/swtpm.log" 2>&1
NO_TPM='' REUSE=1 start node "$work/ours.fd"
expect_locked "a TPM added to an unprotected root"
stop
REUSE=1 start node "$work/ours.fd"
expect_up "TPM removed again"
guest test -e /var/lib/torngat/node.json || fail "state lost"
done_with

# Enrollment: the root is made anew with the same key file.
virt-fw-vars -i /usr/share/OVMF/OVMF_VARS_4M.ms.fd -o "$work/setup.fd" -d PK >"$work/vars.log" 2>&1
start enroll "$work/setup.fd"
expect_up "Setup Mode"
uuid=$(guest "cryptsetup luksUUID $dev")
guest torngat-enroll-secure-boot >"$work/out" 2>&1 || { cat "$work/out" >&2; fail "enrollment"; }
shut_down
REUSE=1 start enroll "$work/setup.fd"
expect_up "after enrollment"
expect_enforced
[ "$(guest "cryptsetup luksUUID $dev")" != "$uuid" ] || fail "enrollment did not make the root anew"
guest 'test ! -e /sys/firmware/efi/efivars/FactoryReset-*' || fail "the factory reset request is still there"
done_with
echo "ok: enrollment"

# Two copies of the image attached: refused, with or without a TPM, until one is removed.
cp --sparse=always "$img" "$work/copy.raw"
for NO_TPM in 1 ''; do
  export NO_TPM
  qemu_args=(-drive "file=$work/copy.raw,if=virtio,format=raw")
  start "two$NO_TPM" /usr/share/OVMF/OVMF_VARS_4M.fd
  for _ in $(seq 60); do
    alive
    if guest true 2>/dev/null; then fail "booted with two copies of the image"; fi
    if grep -aqs 'two copies of this image' "$dir/serial.log"; then break; fi
    sleep 2
  done
  grep -aqs 'two copies of this image' "$dir/serial.log" || fail "two copies: no message (see $dir/serial.log)"
  stop
  qemu_args=()
  REUSE=1 start "two$NO_TPM" /usr/share/OVMF/OVMF_VARS_4M.fd
  expect_up "copy removed"
  done_with
done
cmp -s "$img" "$work/copy.raw" || fail "the copy was written to"
rm "$work/copy.raw"
echo "ok: refused with two copies of the image"
echo "PASS"
