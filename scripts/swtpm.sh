#!/usr/bin/env bash
# Starts a throwaway software TPM (swtpm) with an endorsement key certificate, for the TPM tests.
#   eval "$(scripts/swtpm.sh start)"   # exports TORNGAT_TEST_TCTI and TORNGAT_TEST_EK_CA
#   scripts/swtpm.sh stop
set -euo pipefail
cd "$(dirname "$0")/.."
port=${SWTPM_PORT:-2321}
dir=$(pwd)/target/swtpm-$port
cfg=${XDG_CONFIG_HOME:-$HOME/.config}
case "${1:-}" in
start)
  "$0" stop >/dev/null 2>&1 || true
  rm -rf "$dir" && mkdir -p "$dir/state"
  # Per-user swtpm CA (creates ~/.config/swtpm* once; never touches system files).
  [ -f "$cfg/swtpm_setup.conf" ] ||
    swtpm_setup --create-config-files >/dev/null
  swtpm_setup --tpm2 --tpmstate "$dir/state" --create-ek-cert --overwrite \
    --config "$cfg/swtpm_setup.conf" >"$dir/setup.log" 2>&1
  ca=$(grep -h '^statedir' "$cfg/swtpm-localca.conf" | sed 's/.*= *//')
  swtpm socket --tpm2 --tpmstate dir="$dir/state" --flags not-need-init,startup-clear \
    --server type=tcp,port="$port" --ctrl type=tcp,port=$((port + 1)) \
    --pid file="$dir/pid" --daemon
  echo "export TORNGAT_TEST_TCTI='swtpm:host=127.0.0.1,port=$port'"
  echo "export TORNGAT_TEST_EK_CA='$ca/issuercert.pem'"
  ;;
stop)
  # Shut down through swtpm's control channel (its AppArmor profile may refuse signals).
  swtpm_ioctl --tcp 127.0.0.1:$((port + 1)) -s 2>/dev/null || true
  rm -f "$dir/pid"
  ;;
*) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
