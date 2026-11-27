# Nodes and join tokens

`torngatd init` makes the first node, the controller, and writes on it, in `/var/lib/torngat`:

- `admin-token`: full access to the API;
- `join-token`: for one node, for 24 hours.

## Names

Every node needs its own name: lowercase letters, digits and `-`, starting with a letter. A name cannot be used again, as
nodes cannot be removed yet.

## Add a node

Install and seal it, then:

```sh
torngatd join --name n2 --controller <controller> --token-file <file>
systemctl start torngatd
```

A token works for one node. By default nodes must hold their key in a TPM that the controller can
trust, in one of two ways:

- the maker's CA certificates, given to `torngatd init --tpm-ca <file>`;
- a token made for that TPM. Read its pin on the new node with `torngatd tpm-pin` and pass it as
  `ek_sha256`.

Make a token (API on the controller, through an SSH tunnel). `TOKEN` is the content of
`/var/lib/torngat/admin-token`; with `node`, only a node of that name can use the token:

```sh
curl -sS --config <(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN") \
  -H 'Content-Type: application/json' \
  --data '{"node": "n2", "ttl_seconds": 3600, "ek_sha256": "<pin>"}' \
  http://127.0.0.1:8080/v1/platform/joinTokens
```

The answer's `token` is what the node needs: write it to a file only root can read, and delete it after joining.

| Operation | Request |
|---|---|
| List nodes | `GET /v1/platform/nodes` |
| List, revoke tokens | `GET /v1/platform/joinTokens`, `DELETE /v1/platform/joinTokens/{id}` |
| Allow nodes without a TPM | `PUT /v1/platform/settings/tpm` with `{"required": false}` (weaker) |

## Instances on a node

Each instance is a systemd unit of its own, `torngat-vm-<uid>.service`, in `torngat-vms.slice`:

- It runs as a user of its own, made by systemd when it starts (`DynamicUser`): never root, never shared with
  another instance. It has no capabilities, no network yet, and `/dev/kvm` as its only device.
- Its memory is limited to the instance's plus 256 MiB and 1/16 for QEMU itself; it never makes a core dump.
- Restarting or updating `torngatd` does not touch it.
- `systemctl status torngat-vm-<uid>` and `journalctl -u torngat-vm-<uid>` show QEMU's state and messages. The
  serial console is written to `/var/lib/torngat-vm/<uid>/console.log`, which stays after the instance stops: what
  the guest writes there is the tenant's.
- Do not start or stop these units by hand: `torngatd` starts again what should run and stops what should not.

## Not there yet

- Removing a node through the API.
- Renewing node certificates: they last one year.
- Removing the console logs of deleted instances: they stay in `/var/lib/torngat-vm/`.
- More than one controller. [Back it up](backup.md), or expect to lose the cluster with it.
