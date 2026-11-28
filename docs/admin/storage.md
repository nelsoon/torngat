# Storage for instances

The image contains the tools. Pools, volume types and volumes are described in the API, and nodes look
after them ([on the node](#on-the-node)). LVM pools work; **ZFS pools have no driver yet** and show `no storage
driver on this node`. Instances cannot use volumes yet.

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
- Deleting a pool waits until its node removed its mark from the storage, and until no volume type lists it. If the node is lost,
  or no longer sees the volume group (its disks missing), the pool stays in deletion: there is no way to force it yet.
- The node opens an instance's volumes before starting it, and hands QEMU the open devices: QEMU itself cannot open any
  device but `/dev/kvm`. An instance waits (`starting`) until all its volumes are open.
- A volume gets its node when an instance first uses it (an image's, when the image gets its node). An instance's boot disk is a volume `<instance>-boot`
  whose `status.owner` names the instance; it is deleted after the instance unless the instance keeps it.
- `status.open`: the node has it open for an instance. A volume is released from its instance only once closed, so
  that two instances never have it at once. If its node is lost, it stays with its instance.

What a pool's `status` says:

| Field | Meaning |
|---|---|
| `claimed` | the node was asked to mark the storage as this pool's |
| `ready` | the node found it and marked it; volumes may go there |
| `capacity_bytes` | what volumes may use in total, as the node reported it |
| `reservations` | space promised to each volume, by uid (only when reading one pool) |

A volume's `status.phase`: `pending` (no pool yet), `placing`, `placed` (has space), `ready` (exists on the node), `deleting`.
Growing a volume first reserves the space; if there is none, it waits.

## Images

Platform images are for every project; projects can import their own (see the [user guide](../user/README.md#images)).

```
POST /v1/platform/images?image_id=debian-13
{"spec": {"source": {"url": "https://cloud.example/debian-13-genericcloud-amd64.qcow2",
                     "checksum": {"sha512": "<128 hex digits>"}},
          "volume_type": "fast"}}
```

- An image is imported on one node: the controller picks the live node with the most room in a pool of the image's volume
  type, and shows it in `status.node`. That node downloads it into the volume `<image>-staging`, the size of the download,
  and copies it into the volume `<image>-image`, the size of its disk. Both are volumes of the image's scope (platform
  images have platform volumes) with `status.owner.image`, and take space like any volume. The staging volume is deleted
  once the image is ready, or failed.
- A volume type that an image uses cannot be deleted.
- A boot disk made from an image goes on the image's node (`status.fill` names the image and its volume), and that node
  copies the image into it at its first use, with `qemu-img` in the same sandbox, before the instance starts
  (`status.filled`). Copies across nodes come later: an instance from an image runs on the image's node.
- Deleting an image deletes its volumes first; the image goes once they are gone.
- The node checks the download against its checksum as it writes it, tells qcow2 from raw by its first bytes, and copies
  it with `qemu-img` (only qcow2 images are read by `qemu-img` before that, to find their size). qcow2 images with a backing
  file or a data file are refused. `qemu-img` runs in a unit of its own, `torngat-image-<uid>`: no network, no
  capabilities, a user of its own, and no device but the two volumes (the download read-only).
- Downloads reach public addresses only: never loopback, link-local (cloud metadata), private or shared (CGNAT) ones, at
  every redirect. The node trusts the certificate authorities of its system store.
- An import with no progress for 15 minutes fails (its node is gone, or it has no room): delete the image and make it again.

```
PUT /v1/platform/settings/images
{"max_image_gib": 64, "platform_private_sources": false}
```

- `max_image_gib`: the largest download and the largest disk of an image (default 64).
- `platform_private_sources`: platform images may come from private and shared addresses, such as a mirror on your network.
  Project images never do. Loopback and link-local addresses are never reached. Add the mirror's certificate authority to
  the nodes' system store if it is your own.

## On the node

- The node marks the volume group or ZFS pool as this pool of this cluster. Storage that carries another
  mark is refused. Deleting the pool removes the mark once its volumes are gone.
- A volume is made on the node once it has space, and grown when its size grows. It is encrypted (LUKS2) when an
  instance first uses it, and only if the start of the device is blank: something else there is never
  formatted over, and a volume formatted once is never formatted again (its `message` says so).
- What an instance sees is open, as `/dev/mapper/torngat-vol-<uid>`, only while an instance on that node uses it. The host
  does not look inside it: no file system type, label or uuid in `udev`, nothing in `/dev/disk/by-*`, nothing
  activated or assembled from it. Do not open, mount or scan it by hand: the content is the tenant's.
- The node asks for a volume's key each time it opens or grows it, and forgets it right after. A key that was refused is
  asked for again after 5 s, then up to 5 min.
- Volumes on the storage that the platform does not know are never deleted: the pool's `message` counts them. Look
  at them by hand.

### LVM

- Make the volume group by hand (`vgcreate data /dev/disk/by-id/...`) and give its name as the pool's `source`.
- The node marks it with the tag `torngat:<cluster>:<pool>` (`vgs -o vg_tags`). Its volumes are thick logical volumes
  named `torngat-<uid>`, with the same tag. Torngat never changes anything else in the group: other logical
  volumes may stay there, and their size is left out of the pool's capacity.
- The allocation unit is the group's extent size; volume sizes are rounded up to it.
- A new volume has its first and last 16 MiB zeroed; the rest may hold old data, which the instance only sees
  encrypted. `torngat-zeroing` marks one whose creation is not finished yet: the node finishes it.
- A volume is active only while it is in use. Deleting it overwrites its first 16 MiB, discards its blocks where
  the disks can, then removes it. Deactivating, and so deleting, fails while something has it open.

`torngatd run --fake-storage DIR` is for tests only: every pool is a directory under `DIR`, volumes are files
attached as loop devices, and nothing keeps the file system from filling up.

## Volume keys

Each volume is encrypted with its own key. Keys are made and kept by the controller, encrypted under a key
for each project, itself encrypted under the **platform key**: `/var/lib/torngat/keys/platform.key`.

- A node gets a volume's key only while it is enrolled, the volume is on it, and an instance uses it, or the volume is an
  image's that this node imports now, or that it copies into a boot disk. The controller logs `volume key given`. A node must ask again after a reboot.
- There is no way to remove a node yet, so a stolen one can still ask for its keys.
- A minute or so after a volume is gone, its key is destroyed. Copies may remain for a while in the store's own log and
  snapshots, and in backups; reading them takes the platform key, or
  for a backup the recovery code.
- **If the platform key is lost, every volume is lost.** `torngatd` then refuses to start rather than make another.
  [Back it up](backup.md).
