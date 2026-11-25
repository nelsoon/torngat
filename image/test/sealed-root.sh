#!/usr/bin/env bash
# Encrypted root test for the host image.
#
#   SSH_KEY=KEY CERT=FILE image/test/sealed-root.sh IMAGE
#
# 1. First boot in Setup Mode: the root is encrypted; a node cannot be set up, nor the root sealed.
# 2. Enrolling our key makes the root anew. It can then be sealed: the recovery key and the TPM are the
#    only ways in.
# 3. The sealed root unlocks by itself, but the running system cannot unseal its key, and the initrd
#    does not act on the root's fstab.
# 4. With Secure Boot in another state the TPM refuses; the recovery key on the console opens it, and
#    --reseal accepts the new state.
#    A different UKI signed with the same keys (an upgrade) unlocks; one whose TPM policy is signed with
#    another key does not.
# 5. Another machine's TPM does not unlock it, until it is resealed there. Nor does a kernel command
#    line extended by the firmware.
# 6. An unencrypted file system in place of the root is not booted.
# 7. A power cut during the first boot leaves an image that still boots.
#
# Run it as a normal user. Needs what secure-boot.sh needs, plus python3, systemd-ukify, systemd-boot-efi and binutils. Environment: see there, and
#   KEYS      directory with readable copies of the dev image's dev-signing.* and dev-pcr.* (required)
set -euo pipefail
img=${1:?usage: sealed-root.sh IMAGE}
: "${SSH_KEY:?set SSH_KEY to the private key of the image root user}"
here=$(cd "$(dirname "$0")" && pwd)
cert=$(realpath "${CERT:?set CERT to the certificate the image is signed with}")
keys=$(realpath "${KEYS:?set KEYS to a directory with the dev signing keys}")
port=${SSH_PORT:-2222}
. "$here/lib.sh"

virt-fw-vars -i /usr/share/OVMF/OVMF_VARS_4M.ms.fd -o "$work/setup.fd" -d PK \
  >"$work/vars.log" 2>&1 || { cat "$work/vars.log" >&2; fail "virt-fw-vars"; }
start node "$work/setup.fd"
expect_up "first boot"
[ "$(guest findmnt -no SOURCE /)" = /dev/mapper/root ] || fail "root is not on the encrypted volume"
[ "$(guest "stat -c %a $prov")" = 600 ] || fail "provisional key mode"
[ "$(guest "stat -c %a / /etc /mnt /var/lib/torngat-seal" | xargs)" = "755 755 755 700" ] || fail "directory modes"
[ "$(slots)" = "password tpm2" ] || fail "provisional slots: $(slots)"
no_failed_units
if guest torngatd init --name n1 >"$work/out" 2>&1; then fail "init on an unsealed root"; fi
grep -q 'not sealed' "$work/out" || { cat "$work/out" >&2; fail "unexpected init refusal"; }
if guest torngat-seal-root >"$work/out" 2>&1; then fail "sealed without Secure Boot"; fi
grep -q 'Secure Boot is not on' "$work/out" || { cat "$work/out" >&2; fail "unexpected seal refusal"; }
echo "ok: first boot: encrypted, init and sealing refused"

uuid=$(guest "cryptsetup luksUUID $dev")
guest torngat-enroll-secure-boot >"$work/out" 2>&1 || { cat "$work/out" >&2; fail "enrollment"; }
shut_down
REUSE=1 start node "$work/setup.fd"
expect_up "after enrollment"
expect_enforced
[ "$(guest "cryptsetup luksUUID $dev")" != "$uuid" ] || fail "enrollment did not make the root anew"
guest 'test ! -e /sys/firmware/efi/efivars/FactoryReset-*' || fail "the factory reset request is still there"
# A foreign slot, hidden from --wipe-slot=password by a token of its own.
guest "echo -n hidden | cryptsetup luksAddKey --pbkdf pbkdf2 --key-file $prov --new-key-slot 7 $dev - &&
  echo '{\"type\":\"other\",\"keyslots\":[\"7\"]}' | cryptsetup token import --token-id 9 $dev" || fail "adding a slot"
if guest torngat-seal-root >"$work/out" 2>&1; then fail "sealed with a foreign key slot"; fi
grep -q 'unexpected key slots' "$work/out" || { cat "$work/out" >&2; fail "unexpected seal refusal"; }
guest "cryptsetup token remove --token-id 9 $dev && cryptsetup luksKillSlot -q $dev 7" || fail "removing the slot"
recovery=$(guest torngat-seal-root 2>"$work/seal.err") || { cat "$work/seal.err" >&2; fail "sealing"; }
recovery=$(grep -oE '[a-z]{8}(-[a-z]{8}){7}' <<<"$recovery") || fail "no recovery key shown"
[ "$(slots)" = "recovery tpm2" ] || fail "slots after sealing: $(slots)"
if guest test -e "$prov"; then fail "the provisional key is still there"; fi
if guest torngat-seal-root >"$work/out" 2>&1; then fail "sealed twice"; fi
guest "echo 'tmpfs /probe tmpfs x-initrd.mount,nofail 0 0' >>/etc/fstab" || fail "fstab"
guest torngatd init --name n1 >"$work/init.log" 2>&1 || { tail -5 "$work/init.log" >&2; fail "init after sealing"; }
echo "ok: sealed, node set up"

shut_down
REUSE=1 start node "$work/setup.fd"
expect_up "sealed"
guest test -e /var/lib/torngat/node.json || fail "state lost"
if guest "SYSTEMD_LOG_LEVEL=debug systemd-cryptenroll --unlock-tpm2-device=auto --recovery-key $dev" </dev/null >/dev/null 2>"$work/out"; then
  fail "the running system can unseal the root key"
fi
[ "$(guest findmnt -no FSTYPE /probe)" = tmpfs ] || fail "the fstab probe is wrong"
# The initrd's checker sees the entry (so the journal is complete), but nothing mounts it.
guest journalctl --flush
guest journalctl -b -o cat >"$work/journal"
grep -q '/sysroot/probe should be mounted in the initrd' "$work/journal" || fail "no trace of the initrd in the journal"
if grep -q 'Mount.* sysroot-probe.mount' "$work/journal"; then fail "the initrd acted on the root's fstab"; fi
# What was measured into PCR 15, in order (the journal may not have the initrd's messages yet).
measured=$(guest cat /run/log/systemd/tpm2-measure.log | tr '\036' '\n' | grep -o 'cryptsetup:root\|torngat:root-opened' | xargs)
[ "$measured" = "cryptsetup:root torngat:root-opened" ] || fail "no barrier in the initrd: $measured"
[ "$(guest cat /sys/class/tpm/tpm0/pcr-sha256/12 | tr -d 0)" = "" ] || fail "PCR 12 is not zero"
# Refused by the policy, not by some other error.
grep -q "Couldn't find signature" "$work/out" || { cat "$work/out" >&2; fail "unexpected unseal error"; }
echo "ok: unlocks by itself; the running system cannot unseal"
shut_down

# Another PCR 7: the same machine with only our key enrolled, no vendor keys.
cp "$work/node/vars.fd" "$work/enrolled.fd"
only_trusts "$cert" "$work/ours.fd"
cp "$work/ours.fd" "$work/node/vars.fd"
REUSE=1 start node "$work/setup.fd"
expect_locked "changed Secure Boot state"
printf %s "$recovery" | type_line
expect_up "recovery key"
guest "PASSWORD=\$(cat) torngat-seal-root --reseal" <<<"$recovery" >"$work/out" 2>&1 || { cat "$work/out" >&2; fail "reseal"; }
[ "$(slots)" = "recovery tpm2" ] || fail "slots after resealing: $(slots)"
shut_down
REUSE=1 start node "$work/setup.fd"
expect_up "resealed"
shut_down
echo "ok: recovery key and resealing"
cp "$work/enrolled.fd" "$work/node/vars.fd"
REUSE=1 start node "$work/setup.fd"
expect_locked "the previous Secure Boot state after resealing"
stop
cp "$work/ours.fd" "$work/node/vars.fd"

# Upgrade: another UKI, as the firmware and the TPM see it (changed command line and initrd).
esp=$(/usr/sbin/sfdisk -J "$work/node/disk.raw" | jq '.partitiontable.partitions[0].start * 512')
disk=$work/node/disk.raw@@$esp
uki=$(mdir -b -i "$disk" ::/EFI/Linux | grep -m1 '\.efi')
mcopy -n -i "$disk" "$uki" "$work/uki.efi"
for s in linux initrd osrel uname cmdline; do
  objcopy -O binary --only-section=".$s" "$work/uki.efi" "$work/uki.$s"
done
for s in osrel uname cmdline; do tr -d '\0' <"$work/uki.$s" >"$work/uki.tmp"; mv "$work/uki.tmp" "$work/uki.$s"; done
printf ' torngat.test=1' >>"$work/uki.cmdline"
(cd "$work" && echo upgrade >upgraded && echo upgraded | cpio -o -H newc --quiet) >"$work/extra.cpio"
make_uki() { # PCR-KEY OUTPUT
  /usr/lib/systemd/ukify build --linux "$work/uki.linux" --initrd "$work/uki.initrd" --initrd "$work/extra.cpio" \
    --cmdline "@$work/uki.cmdline" --os-release "@$work/uki.osrel" --uname "$(cat "$work/uki.uname")" \
    --pcr-private-key "$1" --phases enter-initrd --pcr-banks sha256 --no-sign-kernel \
    --secureboot-private-key "$keys/dev-signing.key" --secureboot-certificate "$keys/dev-signing.crt" \
    --output "$2" >"$work/ukify.log" 2>&1 || { tail -5 "$work/ukify.log" >&2; fail "ukify"; }
}
make_uki "$keys/dev-pcr.key" "$work/upgrade.efi"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work/other-pcr.key" 2>/dev/null
make_uki "$work/other-pcr.key" "$work/other.efi"
mcopy -o -i "$disk" "$work/upgrade.efi" "$uki"
REUSE=1 start node "$work/setup.fd"
expect_up "another UKI, same keys"
guest grep -q torngat.test=1 /proc/cmdline || fail "the other UKI was not booted"
shut_down
mcopy -o -i "$disk" "$work/other.efi" "$uki"
REUSE=1 start node "$work/setup.fd"
expect_locked "a UKI with a TPM policy signed by another key"
stop
mcopy -o -i "$disk" "$work/uki.efi" "$uki"
echo "ok: upgrade"

# The disk in another machine: same firmware state, new TPM.
mkdir "$work/thief"
cp --sparse=always "$work/node/disk.raw" "$work/thief/disk.raw"
cp "$work/ours.fd" "$work/thief/vars.fd"
mkdir "$work/thief/tpm"
swtpm_setup --tpm2 --tpmstate "$work/thief/tpm" --create-ek-cert --overwrite \
  --config "${XDG_CONFIG_HOME:-$HOME/.config}/swtpm_setup.conf" >"$work/thief/swtpm.log" 2>&1
REUSE=1 start thief "$work/setup.fd"
expect_locked "another TPM"
printf %s "$recovery" | type_line
expect_up "recovery key with another TPM"
guest "PASSWORD=\$(cat) torngat-seal-root --reseal" <<<"$recovery" >"$work/out" 2>&1 || { cat "$work/out" >&2; fail "reseal on another TPM"; }
shut_down
REUSE=1 start thief "$work/setup.fd"
expect_up "resealed on another TPM"
shut_down
rm "$work/thief/disk.raw"
echo "ok: resealed on another TPM"

# The TPM turned off, and a key file planted where a machine without a TPM has it.
esp=$(/usr/sbin/sfdisk -J "$work/node/disk.raw" | jq '.partitiontable.partitions[0].start * 512')
mmd -i "$work/node/disk.raw@@$esp" ::/torngat
printf '%064d' 0 | mcopy -i "$work/node/disk.raw@@$esp" - ::/torngat/root.key
NO_TPM=1 REUSE=1 start node "$work/setup.fd"
expect_locked "the TPM turned off"
printf %s "$recovery" | type_line
expect_up "recovery key with the TPM turned off"
guest test -e /var/lib/torngat/node.json || fail "state lost"
shut_down
REUSE=1 start node "$work/setup.fd"
expect_up "the TPM turned on again"
shut_down
mdeltree -i "$work/node/disk.raw@@$esp" ::/torngat

qemu_args=(-smbios "type=11,value=io.systemd.stub.kernel-cmdline-extra=rd.systemd.debug_shell=1")
REUSE=1 start node "$work/setup.fd"
expect_locked "a kernel command line extended by the firmware"
stop
qemu_args=()

# A plain file system of the attacker's in place of the root, in the genuine machine.
read -r first count < <(/usr/sbin/sfdisk -J "$work/node/disk.raw" |
  jq -r '.partitiontable.partitions[] | select(.type == "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709") | "\(.start) \(.size)"')
truncate -s "$((count * 512))" "$work/plain.raw"
/usr/sbin/mkfs.ext4 -q "$work/plain.raw"
# More than the LUKS header: the start of a file system is enough to be recognized.
dd if="$work/plain.raw" of="$work/node/disk.raw" bs=1M count=32 oflag=seek_bytes seek="$((first * 512))" \
  conv=notrunc status=none
rm "$work/plain.raw"
REUSE=1 start node "$work/setup.fd"
refused=
for _ in $(seq 90); do
  alive
  if guest true 2>/dev/null; then fail "a plain root was booted"; fi
  if grep -aqs 'root account is locked' "$dir/serial.log"; then refused=1; break; fi
  sleep 2
done
if grep -aqi 'switching root\|switch root' "$dir/serial.log"; then fail "a plain root was booted"; fi
grep -aq 'missing or not encrypted' "$dir/serial.log" || fail "plain root: not refused by make-root"
[ -n "$refused" ] || fail "plain root: no locked emergency mode (see $dir/serial.log)"
done_with
echo "ok: an unencrypted root is refused, the emergency shell is locked"

# The partition table is written at the end: cut before and after that (4 and 5 partitions).
before=0
after=0
# How long it takes depends on the host: go on until two cuts were after it.
for delay in $(seq 5 3 59); do
  start cut "$work/ours.fd"
  until [ -s "$dir/qemu.pid" ]; do alive; sleep 0.2; done
  sleep "$delay"
  kill -9 "$(cat "$dir/qemu.pid")"
  stop
  n=$(/usr/sbin/sfdisk -J "$dir/disk.raw" 2>/dev/null | jq '.partitiontable.partitions | length')
  echo "cut after $delay s: $n partitions"
  if [ "$n" = 4 ]; then before=$((before + 1)); else after=$((after + 1)); fi
  REUSE=1 start cut "$work/ours.fd"
  expect_up "power cut after $delay s of the first boot"
  guest test -s "$prov" || fail "no provisional key after a power cut"
  done_with
  rm -rf "$work/cut"
  [ "$after" -lt 2 ] || break
done
[ "$before" -gt 0 ] && [ "$after" -gt 1 ] || fail "the cuts were not spread around the creation of the root"
echo "ok: power cuts during the first boot"
echo "PASS"
