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
# Needs KVM, qemu, swtpm, OVMF, python3-virt-firmware, openssl, mtools, jq, and an image built with KEY
# authorized. Environment:
#   SSH_KEY   private key whose public half is the image's root authorized key (required)
#   CERT      certificate the image is signed with (required: image/keys is readable by root only)
#   SSH_PORT  guest SSH on localhost (default 2222)
set -euo pipefail
img=${1:?usage: secure-boot.sh IMAGE}
: "${SSH_KEY:?set SSH_KEY to the private key of the image root user}"
here=$(cd "$(dirname "$0")" && pwd)
cert=$(realpath "${CERT:?set CERT to the certificate the image is signed with}")
port=${SSH_PORT:-2222}
work=$(mktemp -d /tmp/torngat-secure-boot.XXXXXX)
boot_pid=

guest() {
  ssh -i "$SSH_KEY" -p "$port" -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR root@127.0.0.1 "$@"
}
stop() {
  [ -n "$boot_pid" ] || return 0
  # boot.sh may still be copying the disk: give QEMU time to appear rather than leave it running.
  for _ in $(seq 60); do
    [ -s "$dir/qemu.pid" ] && break
    kill -0 "$boot_pid" 2>/dev/null || break
    sleep 1
  done
  kill "$(cat "$dir/qemu.pid" 2>/dev/null)" 2>/dev/null || true
  wait "$boot_pid" 2>/dev/null || true
  boot_pid=
}
cleanup() {
  local rc=$?
  set +e
  stop
  if [ "$rc" = 0 ]; then rm -rf "$work"; else echo "workdir kept: $work" >&2; fi
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# The VM must not be confused with something else on the port.
if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then fail "port $port is in use"; fi

start() { # NAME VARS [IMAGE]; with REUSE=1 boots NAME again as it is
  dir=$work/$1
  mkdir -p "$dir"
  rm -f "$dir/qemu.pid" "$dir/serial.log"
  SECURE_BOOT_VARS=$2 SERIAL="$dir/serial.log" SSH_PORT=$port \
    "$here/../boot.sh" "${3:-$img}" "$dir" -- -pidfile "$dir/qemu.pid" >"$dir/boot.log" 2>&1 &
  boot_pid=$!
}
alive() { kill -0 "$boot_pid" 2>/dev/null || { cat "$dir/boot.log" >&2; fail "boot.sh exited"; }; }
refused() { grep -aqi 'access denied' "$dir/serial.log" 2>/dev/null; }
expect_up() { # WHAT
  for _ in $(seq 60); do
    alive
    if guest true 2>/dev/null; then return; fi
    if refused; then fail "$1: the firmware refused the image"; fi
    sleep 2
  done
  fail "$1: no SSH (see $dir/serial.log)"
}
expect_refused() { # WHAT
  for _ in $(seq 60); do
    alive
    if refused; then stop; echo "ok: refused: $1"; return; fi
    if guest true 2>/dev/null; then fail "$1: the image boots"; fi
    sleep 2
  done
  fail "$1: the firmware did not refuse the image (see $dir/serial.log)"
}
# The byte after the variable's 4 bytes of attributes is 1 when Secure Boot is enforced.
expect_enforced() {
  local sb
  sb=$(guest 'od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c' | tr -d ' ')
  [ "$sb" = 1 ] || fail "Secure Boot is not on in the guest"
  guest grep -q '\[integrity\]' /sys/kernel/security/lockdown || fail "the kernel is not locked down"
}
only_trusts() { # CERT VARS
  local owner=7a3f2c1e-5d0b-4f6a-9c38-1b2e4d6f8a90
  virt-fw-vars -i /usr/share/OVMF/OVMF_VARS_4M.fd -o "$2" --secure-boot --set-pk "$owner" "$1" \
    --add-kek "$owner" "$1" --add-db "$owner" "$1" >"$work/vars.log" 2>&1 ||
    { cat "$work/vars.log" >&2; fail "virt-fw-vars"; }
}

only_trusts "$cert" "$work/ours.fd"
start ours "$work/ours.fd"
expect_up "our certificate"
expect_enforced
stop
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
sed -i 's/systemd.firstboot=no/systemd.firstboot=ya/' "$work/uki.efi"
mcopy -o -i "$work/tampered.raw@@$esp" "$work/uki.efi" "$uki"
start tampered "$work/ours.fd" "$work/tampered.raw"
expect_refused "changed kernel command line"
rm -f "$work/tampered.raw" "$work/uki.efi"

start setup-empty /usr/share/OVMF/OVMF_VARS_4M.fd
expect_up "Setup Mode"
if guest torngat-enroll-secure-boot >"$work/enroll.log" 2>&1; then fail "enrolled without vendor keys"; fi
grep -q 'no db entries' "$work/enroll.log" || { cat "$work/enroll.log" >&2; fail "unexpected refusal"; }
stop
echo "ok: enrollment without vendor keys refused"

# The firmware's factory keys, without the platform key.
virt-fw-vars -i /usr/share/OVMF/OVMF_VARS_4M.ms.fd -o "$work/setup.fd" -d PK >"$work/vars.log" 2>&1
start setup "$work/setup.fd"
expect_up "Setup Mode with vendor keys"
db='/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f'
guest "cat $db | tail -c +5" >"$work/db.before"
guest torngat-enroll-secure-boot || fail "enrollment"
guest systemctl poweroff || true
wait "$boot_pid" || true
boot_pid=
REUSE=1 start setup "$work/setup.fd"
expect_up "after enrollment"
expect_enforced
guest "cat $db | tail -c +5" >"$work/db.after"
[ "$(stat -c %s "$work/db.after")" -gt "$(stat -c %s "$work/db.before")" ] || fail "db did not grow"
cmp -s -n "$(stat -c %s "$work/db.before")" "$work/db.before" "$work/db.after" || fail "vendor keys changed"
if guest torngat-enroll-secure-boot 2>/dev/null; then fail "enrolled outside Setup Mode"; fi
stop
echo "ok: enrollment keeps vendor keys, Secure Boot on after a reboot"
echo "PASS"
