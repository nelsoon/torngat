# Host image

Every Torngat node runs the same immutable host image, built with [mkosi](https://github.com/systemd/mkosi)
from Debian 13 packages:

| Partition | Contents |
|---|---|
| ESP | systemd-boot and a signed unified kernel image (UKI): kernel, initrd and command line |
| `usr` (erofs, read-only) | the operating system, verified block by block by dm-verity |
| `usr-verity`, `usr-verity-sig` | the verity hash tree and its signed root hash |
| `root` (LUKS2 + ext4, writable) | `/etc` and `/var`: node identity, state, installed extensions. Not in the image: the initrd creates it at first boot, on the rest of the disk, from a template in `/usr`. |

The platform itself (`torngatd` and its systemd units) is not part of `/usr`. It ships as the
**`torngat-platform` system extension**: a separate signed erofs image in
`/var/lib/extensions/`, merged over `/usr` at boot by `systemd-sysext`. Updating the platform
means replacing that one file: no new OS image, no reboot.

QEMU comes from trixie-backports (pinned in `mkosi.sandbox/etc/apt/preferences.d/qemu`).

## Build

Needs Debian 13 (or newer) with mkosi 25+, systemd-repart 257+, systemd-ukify,
sbsigntool, efitools, binutils, mtools, fdisk, jq and root. Build `torngatd` first on
Debian 13, so it links against the image's libraries:

```sh
cargo build --release -p torngatd --locked
sudo image/build.sh --torngatd target/release/torngatd --authorized-keys ~/.ssh/id_ed25519.pub
```

This writes `image/out/torngat_<version>.raw` (the disk image) and
`image/out/torngat-platform_<version>.raw` (the extension, also preinstalled in the image).
`--zfs` adds ZFS (see [storage](../docs/admin/storage.md)); it also needs xz-utils and more time.
`--dev` adds root autologin on the console: never use it outside a lab.

### Signing keys

`image/keys/signing.{key,crt}` sign the boot loader and the UKI (Secure Boot), the `/usr` verity root
hash and the platform extension. The kernel inside the UKI is deliberately not signed with it: that
kernel could be booted with any initrd and command line (`tools/ukify`). `build.sh` checks both.
`keys/pcr.{key,crt}` (RSA 2048) sign the TPM policy that unlocks the root. `--dev` images let
anyone log in as root, so they use their own pairs, `dev-signing.*` and `dev-pcr.*`. If they are missing, `build.sh` creates development pairs. The certificate is installed as `/usr/lib/verity.d/torngat.crt`; the host only merges extensions
signed with it (unsigned or unprotected extensions are refused, see
`mkosi.extra/usr/lib/systemd/system/systemd-sysext.service.d/`). Keep `image/keys/` out of version
control; for releases, use a key held offline or in an HSM.

### Branding

The host says Torngat on the boot menu, the console and `hostnamectl`: `mkosi.postinst.chroot` writes
`/usr/lib/os-release` (`ID` and `VERSION_ID` stay Debian's, which the platform extension matches on).
The boot splash, a mountain ridge under the northern lights, is `tools/splash.bmp`; `tools/ukify`
puts it in the UKI, so it is signed and measured with the kernel. Make it again with
`image/branding/splash.py image/tools/splash.bmp` (needs Pillow and fonts-dejavu-core). The console
banner and login message are `mkosi.extra/etc/{issue,issue.net,motd}`.

## Try it in a VM

```sh
image/boot.sh image/out/torngat_<version>.raw
```

UEFI, a software TPM with an endorsement certificate, nested KVM and SSH on `localhost:2222`.

With `SECURE_BOOT_VARS=FILE` the firmware enforces Secure Boot with the keys in that variable store
(`virt-fw-vars`, Debian package `python3-virt-firmware`, makes one; see `test/secure-boot.sh`).

## Enroll the Secure Boot key

Clear the platform key in the firmware setup, which puts it in Setup Mode (keep the other keys), boot
the image and run:

```sh
torngat-enroll-secure-boot
reboot
```

It adds the image's certificate to the machine's keys and installs it as the platform key. The
root file system is made anew at the next boot (see below), so do this before setting up the node. The
existing keys are kept, as option ROMs of network cards and GPUs are usually signed with them; it
refuses to run if there are none, unless given `--allow-no-vendor-keys`. With vendor keys kept, the machine
still boots other systems signed by them: Secure Boot alone does not tie it to this image. Not every
firmware supports this.

Use a signing key made for this purpose and never one that signed images before the kernel was
wrapped in a UKI: those contain a signed kernel that boots with any initrd, and only a revocation
(`dbx`) would stop it. The same goes for old, vulnerable releases, as there is no rollback protection
yet. After the reboot, check that `bootctl status` says Secure Boot is enabled.

## Seal the encrypted root

Without a TPM the key of the root is a file on the boot partition (`torngat/root.key`), which protects
nothing, and it cannot be sealed. `image/test/no-tpm.sh` tests that. With a TPM 2.0, the root is encrypted from the first boot, but provisional until Secure Boot is on:
enrolling the key makes it anew, empty, at the next boot. Then:

```sh
torngat-seal-root            # shows the recovery key, once: store it away from this machine
```

The TPM unlocks the disk only with Secure Boot in this state (PCR 7), in the initrd of a UKI whose
policy we signed (PCR 11), with nothing added to its command line or extensions (PCR 12 and 13) and before any root was
opened (PCR 15). `torngatd init` and `join` refuse a root that is not sealed. When the TPM refuses
(changed Secure Boot keys, a `dbx` update, a new TPM), the recovery key is asked for on the console;
then run `torngat-seal-root --reseal`. It accepts the firmware as it is, so find out first why the TPM
refused, and be careful with a recovery key prompt that you did not expect.

`torngat-seal-root` refuses a machine whose firmware ran code signed by others, which is usual with
network cards and GPUs: another boot loader signed with the same key could then unlock the disk.
`--allow-other-signers` accepts that.

Until it is sealed, a machine must be in trusted hands. From then on this protects the disk without its machine, or with another system booted on it. It does not protect
a whole stolen machine, which boots by itself into our signed system; a TPM whose bus is tampered
with; or the integrity of the data. Old signed images can still unlock the disk. Someone with the
disk can put an encrypted root of their own in its place: the image boots it, but it cannot get at
the original.

`image/test/sealed-root.sh` tests all this; same environment as the test below.

## Secure Boot test

`CERT=FILE SSH_KEY=KEY image/test/secure-boot.sh IMAGE` boots the image in VMs with Secure Boot: it
boots with our certificate, is refused with an unrelated one or with a changed kernel command line,
and can be enrolled from Setup Mode without losing vendor keys. Run it as a normal user, with a
readable copy of the signing certificate (`dev-signing.crt` for a `--dev` image) as `CERT` and an image built with `KEY` authorized.

## Storage test

`image/test/storage.sh IMAGE`, same environment: LVM and LUKS2 over a power cut, volume groups of other
machines or inside volumes are not visible, nothing is activated by itself; with `--zfs` also module
signatures, pools of other machines, and LUKS2 on a zvol.

## Image import test

`image/test/images.sh IMAGE`, same environment, with internet access: imports the Debian 13 cloud image (checksum from
Debian's `SHA512SUMS`) through the API, and checks that a wrong checksum fails, a private address is never fetched, and
deleting the image deletes its volume. `crates/agent/tests/image_tool.rs` (as root, on a VM) checks `qemu-img` in its
sandbox on loop devices.

## Hardware test

`image/test/hardware.sh IMAGE`, same environment: boots on emulated server disk controllers and network
cards, unlocks the root with a USB keyboard, checks drivers, firmware files and microcode.

## Set up a node

The image boots with the platform installed but idle. On the first node:

```sh
torngat-enroll-secure-boot    # see above; then reboot
torngat-seal-root             # shows the recovery key
torngatd init --name n1       # creates the cluster; node key in the TPM
systemctl start torngatd
```

On the others, the same two, then `torngatd join --name <name> --controller <host> --token-file <file>` then
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

- Secure Boot key enrollment through a BMC.
- The image certificate in the kernel's trusted keyring, so the kernel itself, not only
  `systemd-sysext`, decides which signed extensions are trusted.
- A/B updates of the image itself (systemd-sysupdate).
