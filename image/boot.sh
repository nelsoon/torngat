#!/usr/bin/env bash
# Boots a built image in a local VM, for testing: UEFI (OVMF), a software TPM with an endorsement
# certificate, nested KVM, user-mode networking with SSH on localhost:SSH_PORT (default 2222).
#
#   image/boot.sh IMAGE [WORKDIR] [-- extra qemu args]
#
# The image is copied (the original stays pristine) and the copy grown to DISK_SIZE (default 8G)
# for the root. The serial console is on stdio unless SERIAL is set to a
# file (or to chardev:ID, with that chardev among the extra qemu args).
# SECURE_BOOT_VARS=FILE uses firmware with Secure Boot and starts from that variable store (see
# test/secure-boot.sh for making one); set it again when reusing the WORKDIR.
# DISK (default virtio-blk-pci) and NIC (default virtio-net-pci) are the QEMU devices of the disk and the
# network card; a controller the disk needs goes into the extra qemu args.
# With NO_TPM=1 the machine has no TPM.
# With REUSE=1 an existing WORKDIR (disk, UEFI variables, TPM state) is booted again as it is, e.g.
# to test a reboot or an update.
set -euo pipefail
img=${1:?usage: boot.sh IMAGE [WORKDIR] [-- qemu args]}
shift
work=${XDG_RUNTIME_DIR:-/tmp}/torngat-boot
if [ $# -gt 0 ] && [ "$1" != -- ]; then work=$1; shift; fi
[ "${1:-}" = -- ] && shift
work=$(mkdir -p "$work" && cd "$work" && pwd)
code=/usr/share/OVMF/OVMF_CODE_4M.fd
machine=q35
extra=()
if [ -n "${SECURE_BOOT_VARS:-}" ]; then
  code=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd
  machine=q35,smm=on
  extra=(-global driver=cfi.pflash01,property=secure,value=on)
fi
if [ -z "${REUSE:-}" ]; then
  cp "${SECURE_BOOT_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}" "$work/vars.fd"
  cp --sparse=always "$img" "$work/disk.raw"
  truncate -s "${DISK_SIZE:-8G}" "$work/disk.raw"

  rm -rf "$work/tpm" && mkdir -p "$work/tpm"
  # Per-user swtpm CA (creates ~/.config/swtpm* once; never touches system files).
  cfg=${XDG_CONFIG_HOME:-$HOME/.config}
  [ -f "$cfg/swtpm_setup.conf" ] || swtpm_setup --create-config-files >/dev/null
  swtpm_setup --tpm2 --tpmstate "$work/tpm" --create-ek-cert --overwrite \
    --config "$cfg/swtpm_setup.conf" >"$work/swtpm-setup.log" 2>&1
fi
tpm=()
if [ -z "${NO_TPM:-}" ]; then
  swtpm socket --tpm2 --tpmstate dir="$work/tpm" --ctrl type=unixio,path="$work/swtpm.sock" \
    --daemon --pid file="$work/swtpm.pid"
  trap 'swtpm_ioctl -s --unix "$work/swtpm.sock" 2>/dev/null || true' EXIT
  tpm=(-chardev "socket,id=chrtpm,path=$work/swtpm.sock" -tpmdev emulator,id=tpm0,chardev=chrtpm
    -device tpm-tis,tpmdev=tpm0)
fi

serial=stdio
case ${SERIAL:-} in
  '') ;;
  chardev:*) serial=$SERIAL ;;
  *) serial=file:$SERIAL ;;
esac
qemu-system-x86_64 -enable-kvm -machine "$machine" -cpu host -smp "${SMP:-2}" -m "${MEM:-3072}" "${extra[@]}" \
  -drive if=pflash,format=raw,readonly=on,file="$code" \
  -drive if=pflash,format=raw,file="$work/vars.fd" \
  -drive file="$work/disk.raw",if=none,id=root,format=raw,discard=unmap \
  "${tpm[@]}" \
  -nic user,model="${NIC:-virtio-net-pci}",hostfwd=tcp:127.0.0.1:"${SSH_PORT:-2222}"-:22 \
  -display none -monitor none -serial "$serial" "$@" \
  -device "${DISK:-virtio-blk-pci},drive=root"
