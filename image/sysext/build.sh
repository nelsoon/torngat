#!/usr/bin/env bash
# Builds the signed `torngat-platform` system extension: torngatd plus its systemd units.
#
#   sysext/build.sh --torngatd PATH --version V --key KEY --cert CERT [--out DIR]
#
# Output: DIR/torngat-platform_V.raw, an erofs image with dm-verity whose root hash is signed with
# KEY. Hosts merge it only if CERT is in their /usr/lib/verity.d. Install it on a host as
# /var/lib/extensions/torngat-platform.raw (the file name must match the extension name).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=$here/../out
while [ $# -gt 0 ]; do
  case $1 in
    --torngatd) bin=$2; shift 2 ;;
    --version) version=$2; shift 2 ;;
    --key) key=$2; shift 2 ;;
    --cert) cert=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    *) echo "sysext/build.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
: "${bin:?--torngatd is required}" "${version:?--version is required}"
: "${key:?--key is required}" "${cert:?--cert is required}"
case $version in
  *[!A-Za-z0-9.~^+-]* | '') echo "sysext/build.sh: bad version $version" >&2; exit 2 ;;
esac

tree=$(mktemp -d)
trap 'rm -rf "$tree"' EXIT
cp -a "$here/tree/." "$tree/"
install -D -m 0755 "$bin" "$tree/usr/bin/torngatd"
mkdir -p "$tree/usr/lib/extension-release.d"
# Built against Debian 13's libraries: only merge on a Debian 13 host.
cat > "$tree/usr/lib/extension-release.d/extension-release.torngat-platform" <<EOR
ID=debian
VERSION_ID=13
ARCHITECTURE=x86-64
SYSEXT_SCOPE=system
SYSEXT_ID=torngat-platform
SYSEXT_VERSION_ID=$version
EXTENSION_RELOAD_MANAGER=1
EOR

mkdir -p "$out"
img=$out/torngat-platform_$version.raw
rm -f "$img"
systemd-repart --make-ddi=sysext --copy-source="$tree" --empty=create --size=auto --seed=random \
  --private-key="$key" --certificate="$cert" --dry-run=no "$img" >&2
echo "$img"
