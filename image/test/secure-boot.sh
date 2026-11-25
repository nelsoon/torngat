#!/usr/bin/env bash
# Secure Boot test for the host image.
#
#   SSH_KEY=KEY CERT=FILE image/test/secure-boot.sh IMAGE
#
# 1. Firmware trusting only our certificate: the image boots, Secure Boot is on and the kernel is
#    locked down.
# 2. Firmware trusting only an unrelated certificate: the firmware refuses the image.
# 3. A changed kernel command line in the UKI is refused.
# 4. Setup Mode without vendor keys: enrollment is refused.
# 5. Setup Mode with vendor keys: enrollment keeps them, and after a reboot Secure Boot is on.
#
# Run it as a normal user (swtpm_setup refuses per-user configuration as root).
# Needs KVM, qemu, swtpm, OVMF, python3-virt-firmware, openssl, mtools, jq, fdisk, and an image built with KEY
# authorized. Environment:
#   SSH_KEY   private key whose public half is the image's root authorized key (required)
#   CERT      certificate the image is signed with (required: image/keys is readable by root
#             only; dev-signing.crt for a --dev image)
#   SSH_PORT  guest SSH on localhost (default 2222)
set -euo pipefail
img=${1:?usage: secure-boot.sh IMAGE}
: "${SSH_KEY:?set SSH_KEY to the private key of the image root user}"
here=$(cd "$(dirname "$0")" && pwd)
cert=$(realpath "${CERT:?set CERT to the certificate the image is signed with}")
port=${SSH_PORT:-2222}
. "$here/lib.sh"

expect_refused() { # WHAT
  for _ in $(seq 60); do
    alive
    if refused; then done_with; echo "ok: refused: $1"; return; fi
    if guest true 2>/dev/null; then fail "$1: the image boots"; fi
    sleep 2
  done
  fail "$1: the firmware did not refuse the image (see $dir/serial.log)"
}
only_trusts "$cert" "$work/ours.fd"
start ours "$work/ours.fd"
expect_up "our certificate"
expect_enforced
done_with
echo "ok: boots with our certificate, Secure Boot on, kernel locked down"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=unrelated \
  -keyout "$work/other.key" -out "$work/other.crt" 2>/dev/null
only_trusts "$work/other.crt" "$work/other.fd"
start other "$work/other.fd"
expect_refused "unrelated certificate"

# The ESP is the first partition.
esp=$(/usr/sbin/sfdisk -J "$img" | jq '.partitiontable.partitions[0].start * 512')
cp --sparse=always "$img" "$work/tampered.raw"
uki=$(mdir -b -i "$img@@$esp" ::/EFI/Linux | grep -m1 '\.efi')
mcopy -n -i "$img@@$esp" "$uki" "$work/uki.efi"
cp "$work/uki.efi" "$work/uki.orig"
sed -i 's/systemd.firstboot=no/systemd.firstboot=ya/' "$work/uki.efi"
! cmp -s "$work/uki.efi" "$work/uki.orig" || fail "the command line to change was not found in the UKI"
mcopy -o -i "$work/tampered.raw@@$esp" "$work/uki.efi" "$uki"
start tampered "$work/ours.fd" "$work/tampered.raw"
expect_refused "changed kernel command line"
rm -f "$work/tampered.raw" "$work/uki.efi" "$work/uki.orig"

start setup-empty /usr/share/OVMF/OVMF_VARS_4M.fd
expect_up "Setup Mode"
if guest torngat-enroll-secure-boot >"$work/enroll.log" 2>&1; then fail "enrolled without vendor keys"; fi
grep -q 'no db entries' "$work/enroll.log" || { cat "$work/enroll.log" >&2; fail "unexpected refusal"; }
done_with
echo "ok: enrollment without vendor keys refused"

# The firmware's factory keys, without the platform key.
virt-fw-vars -i /usr/share/OVMF/OVMF_VARS_4M.ms.fd -o "$work/setup.fd" -d PK \
  >"$work/vars.log" 2>&1 || { cat "$work/vars.log" >&2; fail "virt-fw-vars"; }
start setup "$work/setup.fd"
expect_up "Setup Mode with vendor keys"
db='/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f'
guest "cat $db | tail -c +5" >"$work/db.before"
guest torngat-enroll-secure-boot || fail "enrollment"
shut_down
REUSE=1 start setup "$work/setup.fd"
expect_up "after enrollment"
expect_enforced
guest "cat $db | tail -c +5" >"$work/db.after"
[ "$(stat -c %s "$work/db.after")" -gt "$(stat -c %s "$work/db.before")" ] || fail "db did not grow"
cmp -s -n "$(stat -c %s "$work/db.before")" "$work/db.before" "$work/db.after" || fail "vendor keys changed"
if guest torngat-enroll-secure-boot >"$work/enroll.log" 2>&1; then fail "enrolled outside Setup Mode"; fi
grep -q 'not in Setup Mode' "$work/enroll.log" || { cat "$work/enroll.log" >&2; fail "unexpected refusal"; }
stop
echo "ok: enrollment keeps vendor keys, Secure Boot on after a reboot"
echo "PASS"
