# User guide

Pre-alpha: there is an API, no command-line client or web interface yet, and a single administrator
token. Instances have no images or networks yet, and their disks are not handed to the guest yet.

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
- A disk can be added to `disks` while the instance runs; removing one needs it stopped. Any volume, the boot disk too, can
  grow while it runs. The boot disk's type cannot change, and it cannot be added or removed.
- When an instance is deleted, or a disk removed from it, the volume is free again once its node has closed it.

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
