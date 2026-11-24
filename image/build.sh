#!/usr/bin/env bash
# Builds the Torngat host image (and the platform extension it ships with). Needs root (mkosi),
# mkosi 25 or later and systemd-repart 257 or later.
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
if [ ! -e "$key" ]; then
  echo "build.sh: creating a development signing key in $here/keys" >&2
  (umask 077 && mkdir -p "$here/keys" &&
    openssl req -new -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
      -subj "/CN=Torngat development image signing" -keyout "$key" -out "$cert" 2>/dev/null)
fi

out=$here/out
sysext=$("$here/sysext/build.sh" --torngatd "$bin" --version "$version" --key "$key" \
  --cert "$cert" --out "$out")

extra=$(mktemp -d)
trap 'rm -rf "$extra"' EXIT
install -D -m 0644 "$cert" "$extra/usr/lib/verity.d/torngat.crt"
install -D -m 0644 "$sysext" "$extra/var/lib/extensions/torngat-platform.raw"
if [ -n "$keys_file" ]; then
  install -d -m 0700 "$extra/root/.ssh"
  install -m 0600 "$keys_file" "$extra/root/.ssh/authorized_keys"
fi

args=(--image-version="$version" --extra-tree="$extra"
  --secure-boot-key="$key" --secure-boot-certificate="$cert"
  --verity-key="$key" --verity-certificate="$cert")
[ -n "$dev" ] && args+=(--autologin=yes)
cd "$here"
mkosi "${args[@]}" -f build
echo "build.sh: $out/torngat_$version.raw"
