# User guide

Pre-alpha: there is an API, no command-line client or web interface yet, and a single administrator
token. Instances have no disks, images or networks yet.

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

- Creating, changing and deleting take time: `status.phase` goes through `pending`, `scheduled`,
  `starting` and `running`. A create answers with an operation; `GET /v1/operations/{id}` follows it.
- `spec` is replaced as a whole by a `PATCH`. Read the object again if the `etag` is refused: someone
  else changed it.
- Memory is 64 MiB or more.
