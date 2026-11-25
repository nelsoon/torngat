# Host image

Every Torngat node runs the same immutable host image, built with [mkosi](https://github.com/systemd/mkosi)
from Debian 13 packages:

| Partition | Contents |
|---|---|
| ESP | systemd-boot and the signed kernel image |
| `usr` (erofs, read-only) | the operating system, verified block by block by dm-verity |
| `usr-verity`, `usr-verity-sig` | the verity hash tree and its signed root hash |
| `root` (ext4, writable) | `/etc` and `/var`: node identity, state, installed extensions. Grows to fill the disk at first boot. |

The platform itself (`torngatd` and its systemd units) is not part of `/usr`. It ships as the
**`torngat-platform` system extension**: a separate signed erofs image in
`/var/lib/extensions/`, merged over `/usr` at boot by `systemd-sysext`. Updating the platform
means replacing that one file: no new OS image, no reboot.

QEMU comes from trixie-backports (pinned in `mkosi.sandbox/etc/apt/preferences.d/qemu`).

## Build

Needs Debian 13 (or newer) with mkosi 25+, systemd-repart 257+, sbsigntool and root. Build `torngatd` first on
Debian 13, so it links against the image's libraries:

```sh
cargo build --release -p torngatd --locked
sudo image/build.sh --torngatd target/release/torngatd --authorized-keys ~/.ssh/id_ed25519.pub
```

This writes `image/out/torngat_<version>.raw` (the disk image) and
`image/out/torngat-platform_<version>.raw` (the extension, also preinstalled in the image).
`--dev` adds root autologin on the console: never use it outside a lab.

### Signing keys

`image/keys/signing.{key,crt}` sign the boot loader and kernel (Secure Boot, not the boot entry or
initrd yet; `build.sh` checks both signatures), the `/usr` verity root hash and the platform
extension. If they are missing, `build.sh` creates a development pair. The certificate is installed as `/usr/lib/verity.d/torngat.crt`; the host only merges extensions
signed with it (unsigned or unprotected extensions are refused, see
`mkosi.extra/usr/lib/systemd/system/systemd-sysext.service.d/`). Keep `image/keys/` out of version
control; for releases, use a key held offline or in an HSM.

## Try it in a VM

```sh
image/boot.sh image/out/torngat_<version>.raw
```

UEFI, a software TPM with an endorsement certificate, nested KVM and SSH on `localhost:2222`.

With `SECURE_BOOT_CERT=FILE` (a readable copy of `image/keys/signing.crt`) Secure Boot is on and
that certificate is the only one the firmware trusts (needs `virt-fw-vars`, Debian package
`python3-virt-firmware`).

## Secure Boot test

`CERT=FILE SSH_KEY=KEY image/test/secure-boot.sh IMAGE` boots the image with Secure Boot on,
trusting only our certificate, and checks that Secure Boot is enabled and the kernel is locked down;
then it boots with an unrelated certificate and checks that the firmware refuses the image. Run it
as a normal user, with a readable copy of `image/keys/signing.crt` as `CERT` and an image built with
`KEY` authorized.

## Set up a node

The image boots with the platform installed but idle. On the first node:

```sh
torngatd init                 # creates the cluster; node key in the TPM
systemctl start torngatd
```

On the others, `torngatd join --controller <host> --token-file <file>` then
`systemctl start torngatd`. From then on `torngatd.service` starts at every boot.

## Update the platform

```sh
torngat-install-extension torngat-platform_<new>.raw
```

It replaces `/var/lib/extensions/torngat-platform.raw`, re-merges the extensions and restarts
`torngatd`. Running instances are separate processes and keep running while `torngatd` restarts.
If the new image does not merge (for example, it is not signed with the image's key), the previous
extension is put back. Do not copy files into `/var/lib/extensions` by hand: `systemd-sysext`
refuses the whole merge when any one image there is bad, which would leave the node without the
platform until the file is removed.

## Power-loss test

`image/test/power-loss.sh IMAGE [CYCLES]` (default 10) checks that an acknowledged write survives a
power cut. It boots the image in QEMU, creates a node, and then repeats: write join-token records
through the API (1 to 4 parallel writers, each id logged as "attempted" before the request and as
"acked" only after a 2xx), `kill -9` QEMU after 3 to 20 s, reboot the same disk, and check that
`torngatd` came back by itself, every acked record exists, nothing unknown exists, the node is
`active`, `systemctl --failed` is empty and the kernel log has no filesystem errors. Any lost acked
write exits 1 and keeps the work directory.

```sh
SSH_KEY=~/.ssh/tgimg image/test/power-loss.sh image/out/torngat_<version>.raw 10
```

It needs a Debian host with KVM, qemu, swtpm, jq, and an image built with `--authorized-keys
KEY.pub --dev`. `SEED` replays the kill delays, `KEEP=1` keeps the work directory on success.

Killing QEMU loses the guest's memory (page cache, `torngatd`) and keeps what the guest already
flushed to the virtual disk. It does not cover loss of the host's cache, torn sector writes or a
TPM that loses power; see the header of the script.

A TPM counts every unclean shutdown as a failed authorization for keys without the noDA attribute
and locks them out after a few in a row, so `torngatd` could no longer load its key. The node keys
are created noDA; a lockout fails the test.

## Not done yet

- Secure Boot key enrollment and a signed UKI carrying the `/usr` root hash.
- The image certificate in the kernel's trusted keyring, so the kernel itself, not only
  `systemd-sysext`, decides which signed extensions are trusted.
- A/B updates of the image itself (systemd-sysupdate).
