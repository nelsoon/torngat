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
set -euo pipefail

img=$(realpath "${1:?usage: instances.sh IMAGE}")
: "${SSH_KEY:?set SSH_KEY to the private key of the image root user}"
NAME=instances
. "$(dirname "$0")/api.sh"
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

boot_node

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
stop=$(jq -c '{etag: .metadata.etag, spec: (.spec + {power_state: "stopped"})}' <<<"$(body "$(api GET "$base/vm-a")")")
out=$(api PATCH "$base/vm-a" "$stop")
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
