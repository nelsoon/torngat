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

## Not there yet

- Removing a node through the API.
- Renewing node certificates: they last one year.
- More than one controller. Back its state up, or expect to lose the cluster with it.
