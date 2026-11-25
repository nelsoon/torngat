#!/usr/bin/env bash
# Encrypted root test for the host image.
#
#   SSH_KEY=KEY CERT=FILE image/test/sealed-root.sh IMAGE
#
# 1. First boot in Setup Mode: the root is encrypted; a node cannot be set up, nor the root sealed.
# 2. After enrolling our key the root still unlocks and can be sealed: the recovery key and the TPM
#    are then the only ways in.
# 3. The sealed root unlocks by itself, but the running system cannot unseal its key.
# 4. With Secure Boot in another state the TPM refuses; the recovery key on the console opens it, and
#    --reseal accepts the new state.
# 5. Another machine's TPM does not unlock it.
# 6. An unencrypted file system in place of the root is not booted.
# 7. A power cut during the first boot leaves an image that still boots.
#
# Run it as a normal user. Needs what secure-boot.sh needs, plus python3. Environment: see there.
set -euo pipefail
img=${1:?usage: sealed-root.sh IMAGE}
: "${SSH_KEY:?set SSH_KEY to the private key of the image root user}"
here=$(cd "$(dirname "$0")" && pwd)
cert=$(realpath "${CERT:?set CERT to the certificate the image is signed with}")
port=${SSH_PORT:-2222}
. "$here/lib.sh"

prov=/var/lib/torngat-seal/provisional.key
dev='$(cryptsetup status root | sed -n "s/^ *device: *//p")'
slots() { guest "systemd-cryptenroll $dev" | awk 'NR > 1 { print $2 }' | sort | xargs; }
expect_locked() { # WHAT
  for _ in $(seq 60); do
    alive
    if grep -aqi 'enter recovery key\|enter passphrase' "$dir/serial.log" 2>/dev/null; then
      echo "ok: locked: $1"
      return
    fi
    if guest true 2>/dev/null; then fail "$1: the root was unlocked"; fi
    sleep 2
  done
  fail "$1: no recovery key prompt (see $dir/serial.log)"
}
# Types a line on the console. The key only goes through a pipe.
type_line() {
  python3 -c 'import socket, sys, time
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(sys.stdin.buffer.read() + b"\r"); time.sleep(2)' "$dir/console.sock"
}

virt-fw-vars -i /usr/share/OVMF/OVMF_VARS_4M.ms.fd -o "$work/setup.fd" -d PK \
  >"$work/vars.log" 2>&1 || { cat "$work/vars.log" >&2; fail "virt-fw-vars"; }
start node "$work/setup.fd"
expect_up "first boot"
[ "$(guest findmnt -no SOURCE /)" = /dev/mapper/root ] || fail "root is not on the encrypted volume"
[ "$(guest "stat -c %a $prov")" = 600 ] || fail "provisional key mode"
[ "$(guest "stat -c %a / /etc /mnt /var/lib/torngat-seal" | xargs)" = "755 755 755 700" ] || fail "directory modes"
[ "$(slots)" = "password tpm2" ] || fail "provisional slots: $(slots)"
[ -z "$(guest systemctl --failed --no-legend)" ] || fail "failed units: $(guest systemctl --failed --no-legend)"
if guest torngatd init --name n1 >"$work/out" 2>&1; then fail "init on an unsealed root"; fi
grep -q 'not sealed' "$work/out" || { cat "$work/out" >&2; fail "unexpected init refusal"; }
if guest torngat-seal-root >"$work/out" 2>&1; then fail "sealed without Secure Boot"; fi
grep -q 'Secure Boot is not on' "$work/out" || { cat "$work/out" >&2; fail "unexpected seal refusal"; }
echo "ok: first boot: encrypted, init and sealing refused"

guest torngat-enroll-secure-boot >"$work/out" 2>&1 || { cat "$work/out" >&2; fail "enrollment"; }
shut_down
REUSE=1 start node "$work/setup.fd"
expect_up "after enrollment"
expect_enforced
recovery=$(guest torngat-seal-root 2>"$work/seal.err") || { cat "$work/seal.err" >&2; fail "sealing"; }
recovery=$(grep -oE '[a-z]{8}(-[a-z]{8}){7}' <<<"$recovery") || fail "no recovery key shown"
[ "$(slots)" = "recovery tpm2" ] || fail "slots after sealing: $(slots)"
if guest test -e "$prov"; then fail "the provisional key is still there"; fi
if guest torngat-seal-root >"$work/out" 2>&1; then fail "sealed twice"; fi
guest torngatd init --name n1 >"$work/init.log" 2>&1 || { tail -5 "$work/init.log" >&2; fail "init after sealing"; }
echo "ok: sealed, node set up"

shut_down
REUSE=1 start node "$work/setup.fd"
expect_up "sealed"
guest test -e /var/lib/torngat/node.json || fail "state lost"
if guest "systemd-cryptenroll --unlock-tpm2-device=auto --recovery-key $dev" </dev/null >/dev/null 2>"$work/out"; then
  fail "the running system can unseal the root key"
fi
# Refused by the policy, not by some other error.
grep -qi 'signature\|policy' "$work/out" || { cat "$work/out" >&2; fail "unexpected unseal error"; }
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

# The disk in another machine: same firmware state, new TPM.
mkdir "$work/thief"
cp --sparse=always "$work/node/disk.raw" "$work/thief/disk.raw"
cp "$work/ours.fd" "$work/thief/vars.fd"
mkdir "$work/thief/tpm"
swtpm_setup --tpm2 --tpmstate "$work/thief/tpm" --create-ek-cert --overwrite \
  --config "${XDG_CONFIG_HOME:-$HOME/.config}/swtpm_setup.conf" >"$work/thief/swtpm.log" 2>&1
REUSE=1 start thief "$work/setup.fd"
expect_locked "another TPM"
stop

# A plain file system of the attacker's in place of the root, in the genuine machine.
read -r first count < <(/usr/sbin/sfdisk -J "$work/node/disk.raw" |
  jq -r '.partitiontable.partitions[] | select(.type == "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709") | "\(.start) \(.size)"')
truncate -s "$((count * 512))" "$work/plain.raw"
/usr/sbin/mkfs.ext4 -q "$work/plain.raw"
dd if="$work/plain.raw" of="$work/node/disk.raw" bs=1M oflag=seek_bytes seek="$((first * 512))" \
  conv=notrunc,sparse status=none
# Sparse writing skips zeroes, so the LUKS header's magic must go explicitly.
dd if="$work/plain.raw" of="$work/node/disk.raw" bs=1M count=17 oflag=seek_bytes seek="$((first * 512))" \
  conv=notrunc status=none
rm "$work/plain.raw"
REUSE=1 start node "$work/setup.fd"
refused=
for _ in $(seq 90); do
  alive
  if guest true 2>/dev/null; then fail "a plain root was booted"; fi
  if grep -aq 'root account is locked' "$dir/serial.log"; then refused=1; break; fi
  sleep 2
done
[ -n "$refused" ] || fail "plain root: no locked emergency mode (see $dir/serial.log)"
done_with
echo "ok: an unencrypted root is refused, the emergency shell is locked"

# About 5 to 20 s: the partition is created in the middle of it (5 partitions once it exists).
for delay in 6 8 10 12 14 16 18 20; do
  start cut "$work/ours.fd"
  sleep "$delay"
  kill -9 "$(cat "$dir/qemu.pid")" 2>/dev/null || true
  stop
  echo "cut after $delay s: $(/usr/sbin/sfdisk -J "$dir/disk.raw" 2>/dev/null | jq '.partitiontable.partitions | length') partitions"
  REUSE=1 start cut "$work/ours.fd"
  expect_up "power cut after $delay s of the first boot"
  guest test -s "$prov" || fail "no provisional key after a power cut"
  done_with
  rm -rf "$work/cut"
done
echo "ok: power cuts during the first boot"
echo "PASS"
