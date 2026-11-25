# Nodes and join tokens

`torngatd init` makes the first node, the controller, and writes on it, in `/var/lib/torngat`:

- `admin-token`: full access to the API;
- `join-token`: for one node, for 24 hours.

## Add a node

Install and seal it, then:

```sh
torngatd join --controller <controller> --token-file <file>
systemctl start torngatd
```

A token works for one node. By default nodes must hold their key in a TPM that the controller can
trust, in one of two ways:

- the maker's CA certificates, given to `torngatd init --tpm-ca <file>`;
- a token made for that TPM. Read its pin on the new node with `torngatd tpm-pin` and pass it as
  `ek_sha256`.

Make a token (API on the controller, through an SSH tunnel):

```sh
curl -sS --config <(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN") \
  -H 'Content-Type: application/json' \
  --data '{"node": "n2", "ttl_seconds": 3600, "ek_sha256": "<pin>"}' \
  http://127.0.0.1:8080/v1/platform/joinTokens
```

The answer holds the token: write it to a file only root can read, and delete it after joining.

| Operation | Request |
|---|---|
| List nodes | `GET /v1/platform/nodes` |
| List, revoke tokens | `GET /v1/platform/joinTokens`, `DELETE /v1/platform/joinTokens/{id}` |
| Allow nodes without a TPM | `PUT /v1/platform/settings/tpm` with `{"required": false}` (weaker) |

## Not there yet

- Removing a node through the API.
- Renewing node certificates: they last one year.
- More than one controller. Back its state up, or expect to lose the cluster with it.
