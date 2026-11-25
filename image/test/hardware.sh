#!/usr/bin/env bash
# Boots the host image on emulated server hardware: disk controllers, network cards, USB keyboard.
#
#   SSH_KEY=KEY CERT=FILE image/test/hardware.sh IMAGE
#
# 1. With Secure Boot, each disk controller and network card.
# 2. A passphrase for the root typed on a USB keyboard, the only one.
# 3. Firmware files for cards that cannot be emulated are there, and the microcode is in the UKI.
#
# Same environment as secure-boot.sh, plus python3 and cpio.
set -euo pipefail
img=${1:?usage: hardware.sh IMAGE}
: "${SSH_KEY:?set SSH_KEY to the private key of the image root user}"
here=$(cd "$(dirname "$0")" && pwd)
cert=$(realpath "${CERT:?set CERT to the certificate the image is signed with}")
port=${SSH_PORT:-2222}
. "$here/lib.sh"
only_trusts "$cert" "$work/ours.fd"

machine() { # NAME DISK DRIVER NIC DRIVER [QEMU ARGS]
  qemu_args=("${@:6}")
  DISK=$2 NIC=$4 start "$1" "$work/ours.fd"
  expect_up "$1"
  expect_enforced
  no_failed_units
  guest "test -d /sys/module/$3 && test -d /sys/module/$5" || fail "$1: not using $3 and $5"
  done_with
  echo "ok: $1"
}
machine nvme-e1000e nvme,serial=1 nvme e1000e e1000e
machine sata-igb ide-hd ahci igb igb
# The firmware in these VMs cannot boot from them: a second disk. Their drivers must be in the initrd.
truncate -s 1G "$work/second.raw"
for hba in megasas-gen2:megaraid_sas pvscsi:vmw_pvscsi virtio-scsi-pci:virtio_scsi; do
  qemu_args=(-device "${hba%:*},id=hba" -drive "file=$work/second.raw,if=none,id=second,format=raw"
    -device scsi-hd,bus=hba.0,drive=second)
  NIC=vmxnet3 start "${hba%:*}" "$work/ours.fd"
  expect_up "$hba"
  guest "test -d /sys/module/${hba#*:} && test -d /sys/module/vmxnet3 && lsblk -bdno SIZE | grep -qw 1073741824" || fail "$hba: no disk"
  guest "journalctl -b -o cat | awk '/Attached SCSI disk/ {d = 1} /Switching root/ {exit !d; s = 1}' && journalctl -b -o cat | grep -q 'Switching root'" || fail "$hba: not in the initrd"
  done_with
  echo "ok: ${hba%:*}"
done

# Without a TPM and its key file the passphrase is asked for.
qemu_args=(-machine i8042=off -device qemu-xhci -device usb-kbd -qmp "unix:$work/qmp,server=on,wait=off")
export NO_TPM=1
start keyboard "$work/ours.fd"
expect_up "USB keyboard machine"
guest 'set -e; dev=$(cryptsetup status root | sed -n "s/ *device: *//p"); mount -o ro /dev/disk/by-partlabel/esp /mnt 2>/dev/null || mount -o ro "$(blkid -t TYPE=vfat -o device | head -1)" /mnt
  echo -n usbkeyboard >/root/new; cryptsetup luksAddKey --pbkdf pbkdf2 --key-file /mnt/torngat/root.key "$dev" /root/new' || fail "adding a passphrase"
shut_down
esp=$(/usr/sbin/sfdisk -J "$work/keyboard/disk.raw" | jq '.partitiontable.partitions[0].start * 512')
mdel -i "$work/keyboard/disk.raw@@$esp" ::/torngat/root.key
REUSE=1 start keyboard "$work/ours.fd"
expect_locked "USB keyboard machine, before typing"
python3 - "$work/qmp" usbkeyboard <<'PY'
import json, socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
f = s.makefile("rw")
def call(name, **args):
    f.write(json.dumps({"execute": name, "arguments": args}) + "\n")
    f.flush()
    while True:
        answer = json.loads(f.readline())
        if "error" in answer:
            sys.exit(str(answer))
        if "return" in answer:
            return
f.readline()
call("qmp_capabilities")
for key in [*sys.argv[2], "ret"]:
    call("send-key", keys=[{"type": "qcode", "data": key}])
    time.sleep(0.2)
PY
expect_up "passphrase typed on a USB keyboard"
for f in bnx2x/bnx2x-e2-7.13.21.0.fw bnx2/bnx2-mips-09-6.2.1b.fw cxgb4/t6fw.bin intel/ice/ddp/ice.pkg \
  ql2500_fw.bin tigon/tg3.bin rtl_nic/rtl8168h-2.fw; do
  guest "ls /usr/lib/firmware/$f*" >/dev/null || fail "no firmware $f"
done
for m in ice i40e ixgbe bnxt_en bnx2x tg3 mlx5_core cxgb4 qede ena mpt3sas smartpqi megaraid_sas qla2xxx; do
  guest "modinfo -n $m" >/dev/null || fail "no driver $m"
done
for m in firewire-ohci thunderbolt bluetooth cfg80211 sctp; do
  if guest "modinfo -n $m" >/dev/null 2>&1; then fail "driver $m is there"; fi
done
[ "$(guest sysctl -n dev.tty.ldisc_autoload)" = 0 ] || fail "terminal drivers load by themselves"
guest 'ls /usr/share/doc/firmware-bnx2x/copyright /usr/share/doc/intel-microcode/copyright' >/dev/null || fail "licenses"
done_with
echo "ok: USB keyboard, firmware files"

esp=$(/usr/sbin/sfdisk -J "$img" | jq '.partitiontable.partitions[0].start * 512')
uki=$(mdir -b -i "$img@@$esp" ::/EFI/Linux | grep -m1 '\.efi')
mcopy -n -i "$img@@$esp" "$uki" "$work/uki.efi"
objcopy -O binary --only-section=.ucode "$work/uki.efi" "$work/ucode"
mkdir "$work/cpu"
(cd "$work/cpu" && cpio -idm --quiet <"$work/ucode") || fail "no microcode archive in the UKI"
for v in GenuineIntel AuthenticAMD; do
  [ -s "$work/cpu/kernel/x86/microcode/$v.bin" ] || fail "no $v microcode in the UKI"
done
[ "$(head -c 4 "$work/cpu/kernel/x86/microcode/AuthenticAMD.bin" | tr -d '\0')" = DMA ] || fail "AMD microcode header"
[ "$(od -An -tx4 -N4 "$work/cpu/kernel/x86/microcode/GenuineIntel.bin" | xargs)" = 00000001 ] || fail "Intel microcode header"
# Text in between would hide what comes after it.
if grep -aqE 'BEGIN PGP|README' "$work/cpu/kernel/x86/microcode/AuthenticAMD.bin"; then fail "text in the AMD microcode"; fi
echo "ok: microcode"
echo PASS
