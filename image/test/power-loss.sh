#!/usr/bin/env bash
# Power-loss test for the host image: write through torngatd's API, cut the "power", reboot the same
# disk and check that no acknowledged write was lost.
#
#   image/test/power-loss.sh IMAGE [CYCLES]        (CYCLES defaults to 10)
#
# Run it on a Debian build host with KVM, qemu, swtpm and jq, and a built image (build.sh --dev
# --authorized-keys KEY.pub). Environment:
#   SSH_KEY   private key whose public half is the image's root authorized key (required)
#   SSH_PORT  guest SSH on localhost (default 2222)      API_PORT  local end of the API forward (18080)
#   WORKDIR   scratch directory (default: mktemp -d); kept on failure or with KEEP=1
#   SEED      seed for the kill delays (default: $RANDOM); printed, so a run can be replayed
#
# How the cut works: `kill -9` of the QEMU process is a power cut as far as the guest is concerned.
# Everything in the guest's memory (page cache, dirty buffers, torngatd state) vanishes at once and
# nothing is shut down or unmounted, while every write the guest had already sent (and flushed) to
# the virtual disk stays in the disk image, as QEMU has already handed it to the host kernel. So
# this tests the guest's side of durability: fsync discipline in the store (raft log and fjall),
# ext4 journal recovery, and torngatd restarting by itself on the recovered state.
#
# NOT covered: loss of the HOST's cache (the data sits in the host page cache and survives a QEMU
# kill; a host crash or real disk with a volatile write cache is another test), torn or reordered
# sector writes (the virtual disk never does a half write), a TPM that sees the power cut (swtpm
# is shut down cleanly after the kill), and firmware or boot loader behaviour mid-update.
#
# The writes are POST /v1/platform/joinTokens with a unique description: a small durable record
# without side effects. The response holds the token secret; only the id field is read from it, and
# nothing of it is printed or stored. The admin token is read from the guest into a shell variable
# and handed to curl through a pipe, never a file or the command line.
#
# Exit status: 0 = all cycles passed; 1 = a failure (lost acked write, corruption, node or unit
# unhealthy, boot failure); the WORKDIR is kept for inspection.
set -euo pipefail

img=${1:?usage: power-loss.sh IMAGE [CYCLES]}
cycles=${2:-10}
: "${SSH_KEY:?set SSH_KEY to the private key of the image root user}"
ssh_port=${SSH_PORT:-2222}
api_port=${API_PORT:-18080}
here=$(cd "$(dirname "$0")" && pwd)
boot=$here/../boot.sh
[ -f "$img" ] || { echo "no such image: $img" >&2; exit 2; }
img=$(realpath "$img")
work=${WORKDIR:-$(mktemp -d /tmp/torngat-power-loss.XXXXXX)}
mkdir -p "$work"
work=$(cd "$work" && pwd)
seed=${SEED:-$RANDOM}
RANDOM=$seed
echo "seed=$seed workdir=$work cycles=$cycles"

attempted=$work/attempted.log # "id": written before the request is sent
acked=$work/acked.log         # "id token-id": written only after a 2xx response
: >"$attempted"
: >"$acked"

ssh_opts=(-i "$SSH_KEY" -p "$ssh_port" -o BatchMode=yes -o ConnectTimeout=3
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
guest() { ssh "${ssh_opts[@]}" root@127.0.0.1 "$@"; }

boot_pid= fwd_pid= ok=0 token=
writer_pids=()
now() { date +%s.%N; }
elapsed() { awk -v a="$1" -v b="$(now)" 'BEGIN { printf "%.1f", b - a }'; }

fail() {
  echo "FAIL: $*" >&2
  echo "workdir kept: $work (seed=$seed)" >&2
  exit 1
}

stop_writers() {
  local p
  for p in "${writer_pids[@]}"; do kill "$p" 2>/dev/null || true; done
  for p in "${writer_pids[@]}"; do wait "$p" 2>/dev/null || true; done
  writer_pids=()
}

power_cut() {
  local pid
  pid=$(cat "$work/qemu.pid" 2>/dev/null) || return 0
  kill -9 "$pid" 2>/dev/null || true
  # boot.sh sees QEMU die and stops swtpm by itself (its EXIT trap).
  [ -n "$boot_pid" ] && wait "$boot_pid" 2>/dev/null || true
  boot_pid=
  rm -f "$work/qemu.pid"
}

cleanup() {
  set +e
  stop_writers
  [ -n "$fwd_pid" ] && kill "$fwd_pid" 2>/dev/null
  power_cut
  # swtpm normally exits with boot.sh; make sure (AppArmor may refuse a plain kill).
  swtpm_ioctl -s --unix "$work/swtpm.sock" 2>/dev/null
  local p
  p=$(cat "$work/swtpm.pid" 2>/dev/null) && kill "$p" 2>/dev/null
  if [ "$ok" = 1 ] && [ -z "${KEEP:-}" ]; then rm -rf "$work"; fi
}
trap cleanup EXIT

# Starts (REUSE=1 for a reboot) the VM in the background and waits for SSH.
boot_vm() {
  rm -f "$work/qemu.pid"
  REUSE=$1 SERIAL="$work/serial.log" SSH_PORT=$ssh_port \
    "$boot" "$img" "$work" -- -pidfile "$work/qemu.pid" >>"$work/boot.log" 2>&1 &
  boot_pid=$!
  local t0 i
  t0=$(now)
  for i in $(seq 120); do
    kill -0 "$boot_pid" 2>/dev/null || { tail -n 20 "$work/boot.log" >&2; fail "boot.sh exited"; }
    guest true 2>/dev/null && { t_ssh=$(elapsed "$t0"); return 0; }
    sleep 1
  done
  tail -n 20 "$work/serial.log" >&2
  fail "no SSH within 120 s of boot"
}

# curl against the API through the forward. The bearer header goes through a process substitution
# (a pipe), so the token is neither on a command line nor in a file.
api() { # METHOD PATH [JSON]; prints the body, then the status code on its own line
  local m=$1 p=$2
  shift 2
  curl -s -m 10 -X "$m" -w '\n%{http_code}' --config <(printf 'header = "Authorization: Bearer %s"\n' "$token") \
    ${1:+-H 'Content-Type: application/json' --data "$1"} "http://127.0.0.1:$api_port$p"
}

# (Re)opens the API forward and reads the admin token; waits until the API answers.
connect_api() {
  [ -n "$fwd_pid" ] && kill "$fwd_pid" 2>/dev/null || true
  ssh "${ssh_opts[@]}" -N -L "127.0.0.1:$api_port:127.0.0.1:8080" -o ExitOnForwardFailure=yes root@127.0.0.1 2>>"$work/forward.log" &
  fwd_pid=$!
  local t0 out
  t0=$(now)
  token=
  for _ in $(seq 120); do
    [ -n "$token" ] || token=$(guest cat /var/lib/torngat/admin-token 2>/dev/null) || token=
    if [ -n "$token" ]; then
      out=$(api GET /v1/platform/nodes 2>/dev/null) || out=
      [ "${out##*$'\n'}" = 200 ] && { t_api=$(elapsed "$t0"); return 0; }
    fi
    sleep 1
  done
  guest journalctl -u torngatd --no-pager -n 20 >&2 || true
  # A key without noDA is locked out by the TPM after a few power cuts in a row (each counts as a
  # failed authorization); the node keys are created noDA, so name it if it happens anyway.
  if guest "journalctl -u torngatd -b --no-pager -n 40 | grep -q 'DA lockout'" 2>/dev/null; then
    fail "torngatd cannot start: the TPM is in dictionary-attack lockout after the power cut"
  fi
  fail "API not up within 120 s (torngatd should start by itself)"
}

wait_node_active() {
  local i out
  for i in $(seq 60); do
    out=$(api GET /v1/platform/nodes/n1 2>/dev/null) || out=
    [ "${out##*$'\n'}" = 200 ] && [ "$(jq -r '.status.phase // empty' <<<"${out%$'\n'*}")" = active ] && return 0
    sleep 1
  done
  echo "${out%$'\n'*}" | jq -c '{name, phase: .status.phase}' >&2 || true
  fail "node n1 not active within 60 s"
}

# One writer: unique ids, each logged as attempted before the request and as acked only after a 2xx.
writer() { # CYCLE WRITER
  local c=$1 w=$2 n=0 id out code body name
  while :; do
    n=$((n + 1))
    id=c$c-w$w-$n
    echo "$id" >>"$attempted"
    out=$(api POST /v1/platform/joinTokens "{\"description\":\"$id\"}") || { sleep 0.2; continue; }
    code=${out##*$'\n'}
    case $code in
      2??)
        body=${out%$'\n'*}
        name=$(jq -r '.name // empty' <<<"$body")
        [ -n "$name" ] && echo "$id $name" >>"$acked"
        ;;
    esac
  done
}

# All join token records as "description id" lines (the list never contains the secrets).
list_tokens() {
  local tok= out q
  while :; do
    q="/v1/platform/joinTokens?page_size=1000${tok:+&page_token=$tok}"
    out=$(api GET "$q") || return 1
    [ "${out##*$'\n'}" = 200 ] || return 1
    jq -r '.items[] | "\(.description) \(.name)"' <<<"${out%$'\n'*}"
    tok=$(jq -r '.next_page_token // empty' <<<"${out%$'\n'*}")
    [ -n "$tok" ] || return 0
  done
}

verify() { # CYCLE
  local c=$1 seen=$work/seen.log bad
  list_tokens | sort >"$seen" || fail "cycle $c: listing join tokens failed"
  sort "$acked" >"$work/acked.sorted"
  sort -u "$attempted" >"$work/attempted.sorted"
  # Every acked write must exist, under the id the server returned.
  comm -23 "$work/acked.sorted" "$seen" >"$work/lost.log"
  if [ -s "$work/lost.log" ]; then
    echo "LOST ACKED WRITES in cycle $c (seed=$seed), first 10 of $(wc -l <"$work/lost.log"):" >&2
    head -n 10 "$work/lost.log" >&2
    fail "acknowledged writes are missing after power loss"
  fi
  # The records made before the first cycle (e.g. the token `torngatd init` creates) must survive too.
  [ "$(comm -23 "$work/baseline.sorted" "$seen" | wc -l)" = 0 ] || fail "cycle $c: a pre-existing record is gone"
  # Everything else present must have been attempted (nothing invented or mangled).
  comm -13 "$work/baseline.sorted" "$seen" | cut -d' ' -f1 | sort >"$work/seen.ids"
  bad=$(comm -13 "$work/attempted.sorted" "$work/seen.ids" | head -n 5)
  [ -z "$bad" ] || { echo "$bad" >&2; fail "cycle $c: records exist that were never attempted (corruption)"; }
  [ "$(uniq -d "$work/seen.ids" | wc -l)" = 0 ] || fail "cycle $c: duplicate records"
  # This cycle's attempted writes that were never acked: did they land anyway?
  { grep "^c$c-" "$attempted" || true; } | sort -u >"$work/c.attempted"
  cut -d" " -f1 "$acked" | { grep "^c$c-" || true; } | sort -u >"$work/c.acked"
  n_att=$(wc -l <"$work/c.attempted")
  n_ack=$(wc -l <"$work/c.acked")
  comm -23 "$work/c.attempted" "$work/c.acked" >"$work/c.unacked"
  n_unacked_present=$(comm -12 "$work/c.unacked" "$work/seen.ids" | wc -l)
  n_unacked_missing=$(comm -23 "$work/c.unacked" "$work/seen.ids" | wc -l)
}

check_guest() {
  local failed kl bad
  wait_node_active
  failed=$(guest systemctl --failed --no-legend --plain 2>&1) || true
  [ -z "$failed" ] || { echo "$failed" >&2; fail "failed systemd units after reboot"; }
  kl=$work/kernel.log
  guest journalctl -k -b --no-pager >"$kl"
  recov=$(grep -ciE 'recover' "$kl" || true)
  fsl=$(grep -ciE 'ext4|erofs|verity' "$kl" || true)
  # "verity: Root hash verification failed (-ENOKEY)" (and its audit record) is expected today: the kernel keyring does not
  # hold the image certificate (README, "Not done yet"), so systemd checks the extension's signature
  # itself (the extension then mounts anyway). It is not a power-loss effect.
  bad=$(grep -vE "verification failed \(-ENOKEY\)|module=verity op=(ctr|dtr).*error_msg='(Root hash verification failed|success)'" "$kl" | grep -iE 'EXT4-fs.*(error|warning|corrupt)|erofs.*(error|corrupt)|verity.*(corrupt|error|fail)|I/O error|Buffer I/O|journal.*(abort|error)|remount.*read-only' | head -n 5 || true)
  [ -z "$bad" ] || { echo "$bad" >&2; fail "filesystem errors in the kernel log"; }
}

# ---- fresh boot, cluster init ----
t_ssh=0 t_api=0
echo "== first boot"
boot_vm ""
guest torngatd init --name n1 >"$work/init.log" 2>&1 || { tail -n 10 "$work/init.log" >&2; fail "torngatd init failed"; }
guest systemctl start torngatd || fail "starting torngatd failed"
connect_api
wait_node_active
list_tokens | sort >"$work/baseline.sorted" || fail "listing join tokens failed"
echo "first boot: $(wc -l <"$work/baseline.sorted") records from init; ssh ${t_ssh}s, api ${t_api}s"

printf '%-5s %-7s %-6s %-8s %-15s %-17s %-6s %s\n' cycle writers delay acked unacked-present unacked-missing boot-s "recovery-lines/fs-lines"
for c in $(seq "$cycles"); do
  # Writers: 1 sequential, then 2-4 parallel, rotating.
  nw=$(((c - 1) % 4 + 1))
  delay=$((3 + RANDOM % 18)) # 3..20 s
  writer_pids=()
  for w in $(seq "$nw"); do
    writer "$c" "$w" &
    writer_pids+=("$!")
  done
  sleep "$delay"
  power_cut # kill -9 QEMU: the power goes away mid-write
  stop_writers

  t0=$(now)
  boot_vm 1
  connect_api
  t_boot=$(elapsed "$t0")
  check_guest
  verify "$c"
  printf '%-5s %-7s %-6s %-8s %-15s %-17s %-6s %s\n' "$c" "$nw" "${delay}s" "$n_ack" "$n_unacked_present" \
    "$n_unacked_missing" "$t_boot" "$recov/$fsl (ssh ${t_ssh}s, api ${t_api}s, attempted $n_att)"
done

ok=1
echo "PASS: $cycles power cuts, $(wc -l <"$acked") acknowledged writes in total, none lost (seed=$seed)"
