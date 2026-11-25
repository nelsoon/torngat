#!/usr/bin/env bash
# Builds the Torngat host image (and the platform extension it ships with). Needs root (mkosi),
# mkosi 25 or later, systemd-repart 257 or later,
# systemd-ukify, sbsigntool, efitools and binutils.
#
#   sudo image/build.sh --torngatd PATH [--version V] [--authorized-keys FILE] [--dev]
#
#   --torngatd PATH         torngatd binary built for Debian 13 (cargo build --release -p torngatd)
#   --version V             image and extension version (default: the workspace version)
#   --authorized-keys FILE  SSH public keys allowed to log in as root
#   --dev                   root autologin on the console (lab images only)
#
# Signing: keys/signing.key and keys/signing.crt are used if present, otherwise a development key
# pair is created there. The same key signs the boot loader and kernel (Secure Boot), the /usr
# dm-verity root hash, and the platform extension; the certificate is installed in
# /usr/lib/verity.d so the host only merges extensions signed with it.
#
# Output in out/: torngat_V.raw (write it to a disk or USB stick, or boot it in a VM) and
# torngat-platform_V.raw (the extension, also preinstalled in the image).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' "$here/../Cargo.toml")
dev=
keys_file=
while [ $# -gt 0 ]; do
  case $1 in
    --torngatd) bin=$2; shift 2 ;;
    --version) version=$2; shift 2 ;;
    --authorized-keys) keys_file=$2; shift 2 ;;
    --dev) dev=1; shift ;;
    *) echo "build.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
: "${bin:?--torngatd is required}"
[ "$(id -u)" = 0 ] || { echo "build.sh: run as root (mkosi needs it)" >&2; exit 1; }

key=$here/keys/signing.key
cert=$here/keys/signing.crt
if [ ! -e "$key" ] && [ ! -e "$cert" ]; then
  echo "build.sh: creating a development signing key in $here/keys" >&2
  (umask 077 && mkdir -p "$here/keys" &&
    openssl req -new -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
      -subj "/CN=Torngat development image signing" -keyout "$key" -out "$cert" 2>/dev/null)
fi
[ -e "$key" ] && [ -e "$cert" ] || { echo "build.sh: need both $key and $cert" >&2; exit 1; }

out=$here/out
sysext=$("$here/sysext/build.sh" --torngatd "$bin" --version "$version" --key "$key" \
  --cert "$cert" --out "$out")

extra=$(mktemp -d)
trap 'rm -rf "$extra" "$extra.esl"' EXIT
# The extra tree's own modes are copied onto the image: / must stay 0755, /root 0700.
chmod 0755 "$extra"
install -D -m 0644 "$cert" "$extra/usr/lib/verity.d/torngat.crt"
install -D -m 0644 "$sysext" "$extra/var/lib/extensions/torngat-platform.raw"
# For torngat-enroll-secure-boot: db and KEK are appended (-a), the platform key is self-signed.
sb=$extra/usr/lib/torngat/secure-boot
owner=7a3f2c1e-5d0b-4f6a-9c38-1b2e4d6f8a90 # says who added an entry; any fixed GUID
install -d -m 0755 "$extra/usr/lib/torngat" "$sb"
cert-to-efi-sig-list -g "$owner" "$cert" "$extra.esl"
for v in PK KEK db; do
  append=-a
  [ "$v" = PK ] && append=
  sign-efi-sig-list ${append:+"$append"} -g "$owner" -k "$key" -c "$cert" "$v" "$extra.esl" "$sb/$v.auth" >/dev/null
  chmod 0644 "$sb/$v.auth"
done
if [ -n "$keys_file" ]; then
  install -d -m 0700 "$extra/root" "$extra/root/.ssh"
  install -m 0600 "$keys_file" "$extra/root/.ssh/authorized_keys"
fi

args=(--image-version="$version" --extra-tree="$extra"
  --secure-boot-key="$key" --secure-boot-certificate="$cert"
  --verity-key="$key" --verity-certificate="$cert")
[ -n "$dev" ] && args+=(--autologin=yes)
cd "$here"
mkosi "${args[@]}" -f build

# What boots must be signed with our key (mkosi silently installs a loader signed by someone else when
# there is none it can sign), and nothing that accepts an arbitrary initrd or command line may be.
systemd-dissect --copy-from "$out/torngat_$version.raw" /boot "$extra/esp"
signed_by_us() { sbverify --cert "$cert" "$1" >/dev/null 2>&1; }
die() { echo "build.sh: $*" >&2; exit 1; }
ukis=("$extra"/esp/EFI/Linux/*.efi)
for f in "$extra/esp/EFI/BOOT/BOOTX64.EFI" "$extra/esp/EFI/systemd/systemd-bootx64.efi" "${ukis[@]}"; do
  signed_by_us "$f" || die "${f#"$extra/esp"} on the ESP is missing or not signed with $cert"
done
for f in "${ukis[@]}"; do
  objcopy -O binary --only-section=.linux "$f" "$extra/linux"
  [ -s "$extra/linux" ] || die "no kernel in $f"
  ! signed_by_us "$extra/linux" || die "the kernel inside ${f##*/} is signed with $cert"
done
while IFS= read -r f; do
  ! signed_by_us "$f" || die "${f#"$extra/esp"}: a kernel outside a UKI is signed with $cert"
done < <(find "$extra/esp" -name 'vmlinuz*')
echo "build.sh: $out/torngat_$version.raw"
