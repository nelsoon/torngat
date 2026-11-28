# User guide

Pre-alpha: there is an API, no command-line client or web interface yet, and a single administrator
token. Instances have no networks yet.

The API listens on the controller's loopback interface. Through a tunnel:

```sh
ssh -N -L 8080:127.0.0.1:8080 root@<controller>
```

Every request needs the header `Authorization: Bearer <token>`. Keep the token off the command line, for
example with curl's `--config`.

## Instances

| Operation | Request |
|---|---|
| Create | `POST /v1/orgs/{org}/projects/{project}/instances?instance_id={name}` |
| List, read | `GET .../instances`, `GET .../instances/{name}` |
| Change | `PATCH .../instances/{name}` with `etag` and `spec` |
| Delete | `DELETE .../instances/{name}` |

To create one:

```json
{"spec": {"vcpus": 2, "memory_mib": 2048}}
```

To stop it, read its `metadata.etag`, then send a `PATCH`:

```json
{"etag": "<etag>", "spec": {"vcpus": 2, "memory_mib": 2048, "power_state": "stopped"}}
```

- A create answers with an operation; `GET /v1/operations/{id}` follows it. Changing and deleting answer at
  once, and the instance takes a moment to follow: `status.phase` is `pending`, `scheduled`, `starting`,
  `running`, `stopping`, `stopped` or `failed`.
- Organization, project and instance names: lowercase letters, digits and `-`, starting with a letter, at
  most 63 characters.
- `spec` is replaced as a whole by a `PATCH`. Read the object again if the `etag` is refused: someone
  else changed it.
- Memory is 64 MiB or more.

### Disks

```json
{"spec": {"vcpus": 2, "memory_mib": 2048,
          "boot_disk": {"volume_type": "fast", "size_gib": 20},
          "disks": [{"volume": "data"}]}}
```

- `boot_disk` makes the volume `<instance>-boot`, which is deleted with the instance. With `"keep": true` it stays
  and becomes a volume like any other (another instance can use it in `disks`). The instance's name must then be at most
  58 characters, and no other volume may have that name.
- `disks` are volumes of the same project, made before. They are never deleted with the instance. At most 16, each used by
  one instance at a time.
- An instance goes to the node where its volumes are, or where they fit. While it cannot run, `status.message` says why
  (for example a volume used by another instance).
- A disk can be added to `disks` while the instance runs (the guest gets it right away, as a hot-plugged PCIe disk); removing one needs it stopped. Any volume, the boot disk too, can
  grow while it runs (the guest is told the new size; the file system on it is yours to grow). The boot disk's type cannot change, and it cannot be added or removed.
- When an instance is deleted, or a disk removed from it, the volume is free again once its node has closed it.
- The guest sees them as virtio disks, the boot disk first, then `disks` in order. Each has the serial number made of the last
  20 hex digits of its volume's `uid` (without dashes), so Linux guests find it at `/dev/disk/by-id/virtio-<serial>`.
- It boots from the boot disk with UEFI firmware (no legacy BIOS): the disk needs an EFI system partition, as cloud images
  have. Its UEFI variables (boot entries) are kept across its restarts. A blank boot disk boots nothing: make it from an
  image (below). Secure Boot inside the guest is not offered yet.
- `"boot_disk": {"volume_type": "fast", "size_gib": 10, "image": {"name": "debian-13"}}` makes the boot disk from a ready
  image of the project, copied once; with `"platform": true` from the platform's image of that name. `size_gib` must hold
  the image's disk (`status.size_bytes`, rounded up to GiB). The instance starts once the copy is done; until then
  `status.message` says what it waits for. The image cannot change afterwards, and it cannot be deleted while a copy runs.
- While the instance waits for its disks to be ready on its node, it stays `starting`, and `status.message` says which.
  A start that fails is tried again every 10 seconds.

## Volumes

```
POST /v1/orgs/acme/projects/web/volumes?volume_id=data
{"spec": {"volume_type": "fast", "size_gib": 10}}
```

- A volume can grow. It cannot get smaller than the space it was given, and its type cannot change. For a smaller one, copy the data.
- `"delete_protection": true` refuses deletion until you turn it off.
- A `PATCH` replaces the whole `spec`: send `delete_protection` again, or it is turned off. Send the `etag` too.
- It is placed on a node at its first use by an instance, and stays on that node.
- A volume in an instance's `disks` cannot be deleted. Remove it from the instance (stopped) first.

## Images

An image is the content of a disk to start from, such as a cloud image. It is downloaded once and kept as a read-only,
encrypted copy. Boot disks are made from it (see [Disks](#disks)).

```
POST /v1/orgs/acme/projects/web/images?image_id=debian-13
{"spec": {"source": {"url": "https://cloud.example/debian-13-genericcloud-amd64.qcow2",
                     "checksum": {"sha512": "<128 hex digits>"}},
          "volume_type": "fast", "description": "Debian 13"}}
```

- `source.url` is an `https://` URL, without a user name, password or `#`. `checksum` is `sha256` or `sha512`, in lowercase
  hex: an image whose download does not match is refused. qcow2 and raw images are accepted, told apart by their content.
- `volume_type` is where the image is kept, and its space is counted like any volume's. The image's name must be at most 55
  characters, and the volumes `<image>-staging` (the download, while it is imported) and `<image>-image` must not exist:
  they are made for it.
- Only `description` can change. To change anything else, delete the image and make it again.
- `status.phase`: `pending`, `importing`, `ready`, `failed` (`status.message` says why) or `deleting`. `status.size_bytes` is
  the size of the disk it holds (for a raw image, its length rounded up to 512 bytes), and `status.format` what was found.
- The image's volumes are listed with the project's volumes, with `status.owner.image`. They cannot be changed, deleted or
  used in `disks`: deleting the image deletes them.
- The operator publishes platform images (`/v1/platform/images`) for every project.
- Without `source.url`, the image is uploaded instead, in parts (resumable):

  ```
  PUT  .../images/{image}/upload/parts/{n}     the bytes of part n (1 to 10000, at most 64 MiB each)
  GET  .../images/{image}/upload               the parts received
  POST .../images/{image}/upload:finish        puts parts 1 to the last together
  ```

  Parts can come in any order, and a part sent again replaces it. `upload:finish` refuses missing parts, an upload larger
  than the limit, or one that does not match `checksum`; it can then be sent again. Once finished the image is
  imported like a downloaded one. An upload not finished within a day is removed.
- The download must be reachable on a public address (not your own network), say how long it is (no compressed or
  chunked answers), and be at most the operator's limit (64 GiB by default). Up to 5 redirects are followed, to https only.
- `status.message` says how the import goes (`downloading`, `copying it into its volume`). An import that does not move on
  for 15 minutes fails.
