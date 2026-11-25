#!/usr/bin/env bash
# Secure Boot test for the host image.
#
#   SSH_KEY=KEY CERT=FILE image/test/secure-boot.sh IMAGE
#
# 1. Firmware trusting only our certificate: the image boots, Secure Boot is on and the kernel is
#    locked down.
# 2. Firmware trusting only an unrelated certificate: the firmware refuses the image.
#
# Run it as a normal user (swtpm_setup refuses per-user configuration as root).
# Needs KVM, qemu, swtpm, OVMF, python3-virt-firmware, openssl, and an image built with KEY
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

# The unrelated VM must not be answered by something else on the port.
if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then fail "port $port is in use"; fi

start() { # NAME CERT
  dir=$work/$1
  mkdir "$dir"
  SECURE_BOOT_CERT=$2 SERIAL="$dir/serial.log" SSH_PORT=$port \
    "$here/../boot.sh" "$img" "$dir" -- -pidfile "$dir/qemu.pid" >"$dir/boot.log" 2>&1 &
  boot_pid=$!
}
alive() { kill -0 "$boot_pid" 2>/dev/null || { cat "$dir/boot.log" >&2; fail "boot.sh exited"; }; }

start ours "$cert"
up=
for _ in $(seq 60); do
  alive
  if guest true 2>/dev/null; then up=1; break; fi
  grep -aq 'Access Denied' "$dir/serial.log" 2>/dev/null &&
    fail "the firmware refused the image: not signed with $cert?"
  sleep 2
done
[ -n "$up" ] || fail "no SSH with our certificate enrolled (see $dir/serial.log)"
# The last byte of the SecureBoot variable (after 4 bytes of attributes) is 1 when it is enforced.
sb=$(guest 'od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c' | tr -d ' ')
[ "$sb" = 1 ] || fail "Secure Boot is not on in the guest"
guest grep -q '\[integrity\]' /sys/kernel/security/lockdown || fail "the kernel is not locked down"
stop
echo "ok: boots with our certificate, Secure Boot on, kernel locked down"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=unrelated \
  -keyout "$work/other.key" -out "$work/other.crt" 2>/dev/null
start other "$work/other.crt"
refused=
for _ in $(seq 60); do
  alive
  if grep -aq 'Access Denied' "$dir/serial.log" 2>/dev/null; then refused=1; break; fi
  if guest true 2>/dev/null; then fail "the image boots with an unrelated certificate enrolled"; fi
  sleep 2
done
[ -n "$refused" ] || fail "the firmware did not refuse the image (see $dir/serial.log)"
stop
echo "ok: refused with an unrelated certificate"
echo "PASS"
