# Storage for instances

The image contains the tools. Torngat does not create volumes yet: this page is about the host only.

| | LVM | ZFS |
|---|---|---|
| In the image | always | only when built with `build.sh --zfs` |
| Detects corrupted data | no | yes |
| Repairs it | no | with a mirror or RAID-Z |

Use disks of their own: the system disk is all used by the image.

## Nothing is opened by itself

A disk is not used just because it is attached:

- **LVM** only looks at disks listed in `/etc/lvm/devices/system.devices`, which starts empty. `vgcreate`
  adds to it. Use disks with a serial number: LVM finds others by what is written on them, so a copy could
  be taken for the original. A volume group made elsewhere is invisible until you run `lvmdevices --adddev <disk>`.
  The list is on the root file system: after the root is made anew, add the disks again.
- **LVM volumes** are not activated at boot: `vgchange -ay <group>`.
- **ZFS pools** are not imported or mounted at boot: `zpool import -N <pool>`. `-f` is needed for a pool that was not exported
  and that another machine had, or that this one had before its root was made anew. Check first that no other machine
  uses it: two at once destroy it.

## Build an image with ZFS

```sh
sudo image/build.sh --zfs --torngatd target/release/torngatd --authorized-keys ~/.ssh/id_ed25519.pub
```

It downloads the ZFS source from Debian, compiles it for the image's kernel, and signs the modules with
the image key; with Secure Boot the kernel loads no others. It takes a few minutes more.

- **Do not give such an image to others without legal advice.** The licenses of ZFS and Linux may not allow
  distributing the compiled module. Torngat distributes only the instructions to build it.
- Whoever has the image key can load code into the kernel of your machines.
- ZFS is compiled by the user who runs `sudo`, in a user namespace, so that it cannot read the keys: run it from a
  normal user with no copy of the keys, subordinate IDs in `/etc/subuid` and `/etc/subgid`, and Debian's `uidmap` package. It can read and
  change that user's own files: for releases, use a separate user, on a machine or VM for nothing else.
- Every update of the image must be built with `--zfs` again, or the pools cannot be opened.
