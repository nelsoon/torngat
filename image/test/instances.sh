#!/usr/bin/env bash
# Instances on the host image: each runs in a systemd unit of its own, under a user of its own, and
# keeps running when torngatd restarts.
#
#   SSH_KEY=KEY image/test/instances.sh IMAGE
#
# Run it on a Debian build host with KVM (nested), qemu, swtpm, OVMF and jq, and an image built
# with KEY authorized. Environment:
#   SSH_KEY   private key whose public half is the image's root authorized key (required)
#   SSH_PORT  guest SSH on localhost (default 2222)      API_PORT  local end of the API forward (18080)
#
# The admin token is read from the guest into a shell variable and handed to curl through a pipe,
# never a file or the command line; it is not printed.
set -euo pipefail

img=$(realpath "${1:?usage: instances.sh IMAGE}")
: "${SSH_KEY:?set SSH_KEY to the private key of the image root user}"
ssh_port=${SSH_PORT:-2222}
api_port=${API_PORT:-18080}
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/var/tmp}/torngat-instances.XXXXXX")
boot_pid= fwd_pid= token= ok=0

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

until_true() { # WHAT SECONDS COMMAND...
  local what=$1 n=$2
  shift 2
  for _ in $(seq "$n"); do
    if "$@"; then return 0; fi
    sleep 1
  done
  fail "never: $what"
}

base=/v1/orgs/acme/projects/web/instances
phase() { # NAME
  local out
  out=$(api GET "$base/$1") || return 1
  [ "$(code "$out")" = 200 ] || return 1
  jq -r '.status.phase // empty' <<<"$(body "$out")"
}
phase_is() { [ "$(phase "$1")" = "$2" ]; }
uid_of() { jq -r .metadata.uid <<<"$(body "$(api GET "$base/$1")")"; }
unit_state() { guest systemctl show --property=ActiveState --value "torngat-vm-$1.service"; }
main_pid() { guest systemctl show --property=MainPID --value "torngat-vm-$1.service"; }
unit_gone() { [ "$(guest systemctl show --property=LoadState --value "torngat-vm-$1.service")" = not-found ]; }

echo "== boot"
SERIAL="$work/serial.log" SSH_PORT=$ssh_port "$here/../boot.sh" "$img" "$work" -- -pidfile "$work/qemu.pid" \
  >"$work/boot.log" 2>&1 &
boot_pid=$!
until_true "SSH" 120 guest true
guest torngatd init --allow-unsealed-root --name n1 >"$work/init.log" 2>&1 ||
  { tail -n 10 "$work/init.log" >&2; fail "torngatd init"; }
guest systemctl start torngatd
ssh "${ssh_opts[@]}" -N -L "127.0.0.1:$api_port:127.0.0.1:8080" -o ExitOnForwardFailure=yes root@127.0.0.1 \
  2>>"$work/forward.log" &
fwd_pid=$!
token=$(guest cat /var/lib/torngat/admin-token)
api_up() { [ "$(code "$(api GET /v1/platform/nodes/n1 2>/dev/null)")" = 200 ]; }
until_true "API" 60 api_up
node_active() { [ "$(jq -r .status.phase <<<"$(body "$(api GET /v1/platform/nodes/n1)")")" = active ]; }
until_true "node active" 60 node_active

echo "== two instances"
for n in vm-a vm-b; do
  out=$(api POST "$base?instance_id=$n" '{"spec": {"vcpus": 1, "memory_mib": 128}}')
  [ "$(code "$out")" = 200 ] || fail "create $n: $(body "$out")"
done
until_true "vm-a running" 60 phase_is vm-a running
until_true "vm-b running" 60 phase_is vm-b running
a=$(uid_of vm-a)
b=$(uid_of vm-b)
users=()
for u in "$a" "$b"; do
  [ "$(unit_state "$u")" = active ] || fail "unit of $u is not active"
  pid=$(main_pid "$u")
  user=$(guest ps -o uid= -p "$pid" | tr -d ' ')
  [ -n "$user" ] && [ "$user" != 0 ] || fail "instance $u runs as root"
  users+=("$user")
  guest test -e "/var/lib/torngat-vm/$u/console.log" || fail "no console log for $u"
done
[ "${users[0]}" != "${users[1]}" ] || fail "both instances run as user ${users[0]}"
echo "ok: two units, users ${users[*]}"

echo "== torngatd restarts"
before=$(main_pid "$a")
guest systemctl restart torngatd
until_true "API after restart" 60 api_up
sleep 5
[ "$(main_pid "$a")" = "$before" ] || fail "the instance was restarted with torngatd"
phase_is vm-a running || fail "vm-a not running after the restart"
echo "ok: instances kept running"

echo "== stop and delete"
etag=$(jq -r .metadata.etag <<<"$(body "$(api GET "$base/vm-a")")")
out=$(api PATCH "$base/vm-a" "{\"etag\": \"$etag\", \"spec\": {\"vcpus\": 1, \"memory_mib\": 128, \"power_state\": \"stopped\"}}")
[ "$(code "$out")" = 200 ] || fail "stop vm-a: $(body "$out")"
until_true "vm-a stopped" 60 phase_is vm-a stopped
until_true "unit of vm-a gone" 30 unit_gone "$a"
out=$(api DELETE "$base/vm-b")
[ "$(code "$out")" = 200 ] || fail "delete vm-b: $(body "$out")"
until_true "unit of vm-b gone" 60 unit_gone "$b"
failed=$(guest systemctl --failed --no-legend)
[ -z "$failed" ] || fail "failed units: $failed"
echo "ok: stopped and deleted"
ok=1
echo PASS
