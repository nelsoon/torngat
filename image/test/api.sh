# Helpers for the tests that boot the image without Secure Boot and use the API: a single node,
# set up with `torngatd init`. Sourced, not run; needs img, SSH_KEY and NAME (for the work directory)
# set, and `qemu_args` for more QEMU arguments.
#
# The admin token is read from the guest into a shell variable and handed to curl through a pipe,
# never a file or the command line; it is not printed.
ssh_port=${SSH_PORT:-2222}
api_port=${API_PORT:-18080}
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/var/tmp}/torngat-$NAME.XXXXXX")
boot_pid= fwd_pid= token= ok=0
qemu_args=()

ssh_opts=(-i "$SSH_KEY" -p "$ssh_port" -o BatchMode=yes -o ConnectTimeout=3
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
guest() { ssh "${ssh_opts[@]}" root@127.0.0.1 "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
cleanup() {
  set +e
  [ -n "$fwd_pid" ] && kill "$fwd_pid" 2>/dev/null
  kill "$(cat "$work/qemu.pid" 2>/dev/null)" 2>/dev/null
  [ -n "$boot_pid" ] && wait "$boot_pid" 2>/dev/null
  if [ "$ok" = 1 ]; then rm -rf "$work"; else echo "workdir kept: $work" >&2; fi
}
trap cleanup EXIT

if (exec 3<>"/dev/tcp/127.0.0.1/$ssh_port") 2>/dev/null; then fail "port $ssh_port is in use"; fi

# The bearer header goes through a process substitution (a pipe).
api() { # METHOD PATH [JSON]; prints the body, then the status code on its own line
  local m=$1 p=$2
  shift 2
  curl -s -m 10 -X "$m" -w '\n%{http_code}' --config <(printf 'header = "Authorization: Bearer %s"\n' "$token") \
    ${1:+-H 'Content-Type: application/json' --data "$1"} "http://127.0.0.1:$api_port$p"
}
body() { printf '%s' "${1%$'\n'*}"; }
code() { printf '%s' "${1##*$'\n'}"; }
# Fails unless the request answers 200; prints the body.
call() { # METHOD PATH [JSON]
  local out
  out=$(api "$@")
  [ "$(code "$out")" = 200 ] || fail "$1 $2: $(body "$out")"
  body "$out"
}

until_true() { # WHAT SECONDS COMMAND...
  local what=$1 n=$2
  shift 2
  for _ in $(seq "$n"); do
    if "$@"; then return 0; fi
    sleep 1
  done
  fail "never: $what"
}

# Boots the image, makes it a cluster of one (n1), and waits until the node is active.
boot_node() {
  echo "== boot"
  SERIAL="$work/serial.log" SSH_PORT=$ssh_port "$here/../boot.sh" "$img" "$work" -- -pidfile "$work/qemu.pid" \
    "${qemu_args[@]}" >"$work/boot.log" 2>&1 &
  boot_pid=$!
  up() { guest true 2>/dev/null; }
  until_true "SSH" 120 up
  guest torngatd init --allow-unsealed-root --name n1 >"$work/init.log" 2>&1 ||
    { tail -n 10 "$work/init.log" >&2; fail "torngatd init"; }
  guest systemctl start torngatd
  ssh "${ssh_opts[@]}" -N -L "127.0.0.1:$api_port:127.0.0.1:8080" -o ExitOnForwardFailure=yes root@127.0.0.1 \
    2>>"$work/forward.log" &
  fwd_pid=$!
  token=$(guest cat /var/lib/torngat/admin-token)
  until_true "API" 60 api_up
  node_active() { [ "$(jq -r .status.phase <<<"$(call GET /v1/platform/nodes/n1)")" = active ]; }
  until_true "node active" 60 node_active
}
api_up() { [ "$(code "$(api GET /v1/platform/nodes/n1 2>/dev/null)")" = 200 ]; }
