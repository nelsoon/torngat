# Storage for instances

The image contains the tools. Pools, volume types and volumes can be described in the API, but
**nothing is created on the nodes yet**.

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

## Pools and volume types

You make the volume group or ZFS pool by hand. Torngat uses it and never creates or erases one.

| | Who | What |
|---|---|---|
| Storage pool | admin | one volume group or ZFS pool on one node |
| Volume type | admin | a name that tenants choose, and the pools behind it |
| Volume | tenant | a type and a size |

```
POST /v1/platform/storagePools?storage_pool_id=n1-data
{"spec": {"node": "n1", "driver": "lvm", "source": "data"}}

POST /v1/platform/volumeTypes?volume_type_id=fast
{"spec": {"pools": ["n1-data"], "description": "local disks"}}
```

- `source` is the name of the volume group or pool: lowercase letters, digits, `-` and `_`.
- The node, driver and source of a pool cannot change. `"unschedulable": true` stops new volumes.
- A pool that holds volumes or is in a type, and a type that volumes use, cannot be deleted. A pool holds at most 1024
  volumes.
- Space is never promised twice: a volume takes its full size from the pool, plus 16 MiB for encryption.
- Deleting a pool that a node uses waits until the node removed its mark from the storage. If the node is lost, the
  pool stays in deletion: there is no way to force it yet.
- A volume gets its node when an instance first uses it.

## Volume keys

Volumes do not exist on the nodes yet; each will be encrypted with its own key. Keys are made and kept by the controller, encrypted under a key
for each project, itself encrypted under the **platform key**: `/var/lib/torngat/keys/platform.key`.

- A node gets a volume's key only while it is enrolled, the volume is on it, and (once the volume has data) an
  instance uses it. The controller logs `volume key given`. A node must ask again after a reboot.
- There is no way to remove a node yet, so a stolen one can still ask for its keys.
- A minute or so after a volume is gone, its key is destroyed. Copies may remain for a while in the store's own log and
  snapshots, and in backups; reading them takes the platform key, or
  for a backup the recovery code.
- **If the platform key is lost, every volume is lost.** `torngatd` then refuses to start rather than make another.
  [Back it up](backup.md).
