#!/usr/bin/env bash
# Builds the Torngat host image (and the platform extension it ships with). Needs root (mkosi),
# mkosi 25 or later, systemd-repart 257 or later,
# systemd-ukify, sbsigntool, efitools, binutils, mtools, fdisk and jq.
#
#   sudo image/build.sh --torngatd PATH [--version V] [--authorized-keys FILE] [--zfs] [--dev]
#
#   --torngatd PATH         torngatd binary built for Debian 13 (cargo build --release -p torngatd)
#   --version V             image and extension version (default: the workspace version)
#   --authorized-keys FILE  SSH public keys allowed to log in as root
#   --zfs                   compile the ZFS kernel modules and include ZFS (see README.md: do not give
#                           such an image to others without legal advice)
#   --dev                   root autologin on the console (lab images only)
#
# Signing: keys/signing.key and keys/signing.crt (dev-signing.* with --dev) are used if present,
# otherwise a development key pair is created there. The same key signs the boot loader and the UKI
# (Secure Boot; not the kernel inside the UKI, see tools/ukify), the /usr dm-verity root hash, and the platform extension; the certificate is installed in
# /usr/lib/verity.d so the host only merges extensions signed with it.
#
# Output in out/: torngat_V.raw (write it to a disk or USB stick, or boot it in a VM) and
# torngat-platform_V.raw (the extension, also preinstalled in the image).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' "$here/../Cargo.toml")
dev=
zfs=
keys_file=
while [ $# -gt 0 ]; do
  case $1 in
    --torngatd) bin=$2; shift 2 ;;
    --version) version=$2; shift 2 ;;
    --authorized-keys) keys_file=$2; shift 2 ;;
    --zfs) zfs=1; shift ;;
    --dev) dev=1; shift ;;
    *) echo "build.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
: "${bin:?--torngatd is required}"
die() { echo "build.sh: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "build.sh: run as root (mkosi needs it)" >&2; exit 1; }
[ -z "$zfs" ] || [ "${SUDO_UID:-0}" != 0 ] || die "with --zfs, run with sudo from a normal user (who compiles ZFS)"

# Dev images let anyone log in as root: machines that trust the other key must not boot them.
name=signing
[ -n "$dev" ] && name=dev-signing
key=$here/keys/$name.key
cert=$here/keys/$name.crt
pcr_key=$here/keys/${dev:+dev-}pcr.key
pcr_cert=$here/keys/${dev:+dev-}pcr.crt
make_pair() { # KEY CERT RSA-BITS COMMON-NAME
  if [ ! -e "$1" ] && [ ! -e "$2" ]; then
    echo "build.sh: creating a development key in $1" >&2
    (umask 077 && mkdir -p "$here/keys" &&
      openssl req -new -x509 -newkey "rsa:$3" -nodes -sha256 -days 3650 -subj "/CN=$4" \
        -keyout "$1" -out "$2" 2>/dev/null)
  fi
  [ -e "$1" ] && [ -e "$2" ] || { echo "build.sh: need both $1 and $2" >&2; exit 1; }
}
if [ -z "$dev" ] && [ -e "$key" ] && [ ! -e "$pcr_key" ]; then
  echo "build.sh: $key has no PCR policy key next to it ($pcr_key)" >&2
  exit 1
fi
make_pair "$key" "$cert" 3072 "Torngat development image signing"
# The TPM checks this one's signatures: 2048 bits is what every TPM supports.
make_pair "$pcr_key" "$pcr_cert" 2048 "Torngat development PCR policy signing"

out=$here/out
sysext=$("$here/sysext/build.sh" --torngatd "$bin" --version "$version" --key "$key" \
  --cert "$cert" --out "$out")

extra=$(mktemp -d)
mkdir "$extra.initrd" "$extra.zfs" "$extra.sign"
trap 'rm -rf "$extra" "$extra.initrd" "$extra.zfs" "$extra.sign"' EXIT
# The extra tree's own modes are copied onto the image: / must stay 0755, /root 0700.
chmod 0755 "$extra"
install -D -m 0644 "$cert" "$extra/usr/lib/verity.d/torngat.crt"
install -D -m 0644 "$sysext" "$extra/var/lib/extensions/torngat-platform.raw"
# For torngat-enroll-secure-boot: db and KEK are appended (-a), the platform key is self-signed.
sb=$extra/usr/lib/torngat/secure-boot
owner=7a3f2c1e-5d0b-4f6a-9c38-1b2e4d6f8a90 # says who added an entry; any fixed GUID
install -d -m 0755 "$extra/usr/lib/torngat" "$sb"
cert-to-efi-sig-list -g "$owner" "$cert" "$sb/esl"
sign_var() { sign-efi-sig-list "${@:2}" -g "$owner" -k "$key" -c "$cert" "$1" "$sb/esl" "$sb/$1.auth" >/dev/null; }
sign_var PK
sign_var KEK -a
sign_var db -a
chmod 0644 "$sb"/*.auth
rm "$sb/esl"
# What the kernel's scripts/sign-file does. The kernel trusts modules signed by a key in the firmware's
# db, where ours is.
sign_module() { # FILE
  openssl cms -sign -binary -noattr -nocerts -md sha256 -signer "$cert" -inkey "$key" \
    -in "$1" -outform DER -out "$extra.sign/sig"
  local size
  size=$(printf %08x "$(stat -c %s "$extra.sign/sig")")
  {
    cat "$extra.sign/sig"
    # struct module_signature: PKCS#7, then the signature's size, big endian.
    printf '\0\0\2\0\0\0\0\0'
    printf "\\x${size:0:2}\\x${size:2:2}\\x${size:4:2}\\x${size:6:2}"
    printf '~Module signature appended~\n'
  } >>"$1"
}
if [ -n "$keys_file" ]; then
  install -d -m 0700 "$extra/root" "$extra/root/.ssh"
  install -m 0600 "$keys_file" "$extra/root/.ssh/authorized_keys"
fi

args=(--image-version="$version" --extra-tree="$extra"
  --secure-boot-key="$key" --secure-boot-certificate="$cert"
  --verity-key="$key" --verity-certificate="$cert"
  --sign-expected-pcr-key="$pcr_key" --sign-expected-pcr-certificate="$pcr_cert"
  --initrd="$extra.initrd/initrd")
[ -n "$dev" ] && args+=(--autologin=yes)
cd "$here"
if [ -n "$zfs" ]; then
  # Compiled as a normal user: see zfs/mkosi.conf.
  [ "$(stat -c '%u %a' "$key" "$pcr_key" | sort -u)" = "0 600" ] || die "$key and $pcr_key must be root's, mode 600"
  chown "$SUDO_UID:$SUDO_GID" "$extra.zfs"
  runuser -u "$SUDO_USER" -- env HOME="$(getent passwd "$SUDO_UID" | cut -d: -f6)" \
    mkosi --directory zfs --output-directory "$extra.zfs" --output tree -f build
  tree=$extra.zfs/tree
  zfs_kernel=$(ls "$tree/usr/lib/modules")
  [[ $zfs_kernel =~ ^[0-9][0-9A-Za-z.+-]*$ ]] || die "unexpected kernel $zfs_kernel"
  zfs_version=$(dpkg-query --admindir="$tree/var/lib/dpkg" -W -f '${Version}' zfs-dkms)
  modules=$extra/usr/lib/modules/$zfs_kernel/updates
  # Every level is copied with its mode.
  install -d -m 0755 "$extra/usr/lib/modules" "${modules%/*}" "$modules"
  for m in spl zfs; do
    xz -dc "$tree/usr/lib/modules/$zfs_kernel/updates/dkms/$m.ko.xz" >"$extra.sign/$m.ko"
    # Also drops the signature made with dkms's throwaway key.
    strip --strip-debug -o "$modules/$m.ko" "$extra.sign/$m.ko"
    sign_module "$modules/$m.ko"
    chmod 0644 "$modules/$m.ko"
  done
  args+=(--package="zfsutils-linux=$zfs_version" --postinst-script="$here/zfs/depmod.chroot")
fi
mkosi --directory initrd --output-directory "$extra.initrd" --image-version="$version" -f build
mkosi "${args[@]}" -f build

# The boot loader and UKIs must be signed with our key (mkosi silently installs a loader signed by
# someone else when there is none it can sign). Nothing else may be: a signed kernel would boot with
# any initrd and command line.
# The ESP is the first partition.
offset=$(sfdisk -J "$out/torngat_$version.raw" | jq '.partitiontable.partitions[0].start * 512')
mkdir "$extra/esp"
mcopy -s -i "$out/torngat_$version.raw@@$offset" '::/*' "$extra/esp"
signed_by_us() { sbverify --cert "$cert" "$1" >/dev/null 2>&1; }
# For what must not be signed: looks at the signature's subject, so a file whose hash does not check
# out still counts.
subject=$(openssl x509 -in "$cert" -noout -subject -nameopt compat)
subject=${subject#subject=}
mentions_us() { sbverify --list "$1" 2>&1 | grep -qF "$subject"; }
mentions_us "$extra/esp/EFI/BOOT/BOOTX64.EFI" || die "cannot read signature subjects with sbverify"
for f in EFI/BOOT/BOOTX64.EFI EFI/systemd/systemd-bootx64.efi; do
  signed_by_us "$extra/esp/$f" || die "$f on the ESP is missing or not signed with $cert"
done
ukis=("$extra"/esp/EFI/Linux/*.efi)
for f in "${ukis[@]}"; do
  signed_by_us "$f" || die "no UKI on the ESP, or not signed with $cert: ${f##*/}"
  section() { rm -f "$extra/section"; objcopy -O binary --only-section="$1" "$f" "$extra/section"; tr -d '\0' <"$extra/section"; }
  # The signed command line is what ties the UKI to this image's /usr and to the encrypted root.
  cmdline=" $(section .cmdline) "
  [[ $cmdline =~ \ usrhash=[0-9a-f]{64}\  ]] || die "no usrhash= in the command line of ${f##*/}"
  [ "$(grep -o ' root=' <<<"$cmdline" | wc -l)" = 1 ] || die "${f##*/} must have one root="
  for o in root=/dev/mapper/root systemd.gpt_auto=no systemd.import_credentials=no rd.fstab=no; do
    [[ $cmdline == *" $o "* ]] || die "no $o in the command line of ${f##*/}"
  done
  # A policy for a later phase would let a substituted root unseal the disk key.
  [ "$(section .pcrsig | jq '[.[] | length] == [1]')" = true ] ||
    die "${f##*/} must have exactly one signed PCR policy"
  [ "$(section .pcrpkey)" = "$(openssl x509 -in "$pcr_cert" -noout -pubkey)" ] ||
    die "the PCR policy key in ${f##*/} is not $pcr_cert"
  objcopy -O binary --only-section=.linux "$f" "$extra/linux"
  [ -s "$extra/linux" ] || die "no kernel in ${f##*/}"
  [ -z "$zfs" ] || [ "$(section .uname)" = "$zfs_kernel" ] ||
    die "the ZFS modules are for kernel $zfs_kernel, the image has $(section .uname)"
  ! mentions_us "$extra/linux" || die "the kernel inside ${f##*/} is signed with $cert"
done
find "$extra/esp" -type f >"$extra/files"
while IFS= read -r f; do
  case ${f#"$extra/esp/"} in
    loader/keys/* | *.addon.efi | *.cred | EFI/Linux/*/*) die "unexpected ${f#"$extra/esp/"} on the ESP" ;;
    EFI/BOOT/BOOTX64.EFI | EFI/systemd/systemd-bootx64.efi | EFI/Linux/*.efi) ;;
    *) ! mentions_us "$f" || die "${f#"$extra/esp/"} must not be signed with $cert" ;;
  esac
done <"$extra/files"
echo "build.sh: $out/torngat_$version.raw"
