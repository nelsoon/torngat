# Helpers for the tests that boot the image with Secure Boot. Sourced, not run; needs img, here, port
# and SSH_KEY set.
work=$(mktemp -d "${TMPDIR:-/var/tmp}/torngat-$(basename "$0" .sh).XXXXXX")
boot_pid=
qemu_args=() # more arguments for QEMU

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
  # swtpm exits a little after QEMU: the next boot must not race it for the state directory.
  local tpm
  tpm=$(cat "$dir/swtpm.pid" 2>/dev/null) || return 0
  for _ in $(seq 50); do kill -0 "$tpm" 2>/dev/null || return 0; sleep 0.1; done
  echo "swtpm did not exit" >&2
}
done_with() { stop; rm -f "$dir/disk.raw"; }
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
  # The console is a socket, so that a test can type into it.
  SECURE_BOOT_VARS=$2 SERIAL=chardev:console SSH_PORT=$port \
    "$here/../boot.sh" "${3:-$img}" "$dir" -- -pidfile "$dir/qemu.pid" \
    -chardev "socket,id=console,path=$dir/console.sock,server=on,wait=off,logfile=$dir/serial.log" "${qemu_args[@]}" >"$dir/boot.log" 2>&1 &
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

shut_down() { # cleanly, unlike stop
  guest systemctl poweroff || true
  for _ in $(seq 60); do kill -0 "$boot_pid" 2>/dev/null || break; sleep 1; done
  ! kill -0 "$boot_pid" 2>/dev/null || fail "the guest did not power off"
  stop
}

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
no_failed_units() {
  local failed
  failed=$(guest systemctl --failed --no-legend) || fail "systemctl --failed"
  [ -z "$failed" ] || fail "failed units: $failed"
}
