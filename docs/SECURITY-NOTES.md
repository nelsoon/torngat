# Security notes carried between chunks

Items found in reviews that a later chunk must enforce.

- **apiserver:**
  - Strip or ignore server-set metadata (uid, cell, generation, etag, timestamps, status) on create/update.
  - Run every `validate()` (ObjectMeta, Scope, specs) at the API boundary. Deserialization alone does not enforce them.
- **IAM (apiserver):**
  - Operations live under a global id and carry only their `target` path. `GET /v1/operations/{id}` must authorize against the scope parsed from `target`.
  - `serve()` refuses plain HTTP off loopback; anything that mounts `router()` directly must provide TLS itself.
- **scheduler:** evaluate claim `selector` CEL in a sandbox with cost/time limits.
- **controller:**
  - Treat agent-reported data (inventory, allocations, status) as untrusted.
  - Always call `NodeStatus::validate()`.
  - Never accept allocations from agents.
- **node identity / join:**
  - A node is its certificate name **and** the public key recorded at join (`platform/nodeidentities/<node>`). Every control RPC must go through `identity::authenticate`; deleting the record revokes the node.
  - TPM policy (`platform/settings/tpm`, default and missing = required): file-key joins are refused when required. TPM keys are only recorded as `tpm` after attestation (EK trusted via `pki/tpm-roots` or a token `ek_sha256` pin, credential activation for the AK, AK certification of a fixed-TPM node key matching the CSR). Admins can change it with `PUT /v1/platform/settings/tpm` (body `{"required": bool}`; admin only).
  - EK trust is one hop: the EK certificate must be signed directly by an anchor in `pki/tpm-roots` (put vendor intermediates there). No revocation checking of EK certificates yet.
  - The controller's own node is enrolled by `init` without attestation (the operator is the trust root).
  - TPM keys (SRK and node key) use no authorization value and are created `noDA`, so they never count towards dictionary-attack lockout; access to the TPM device is the boundary. Without `noDA`, each power loss after the key was used counted as a failed authorization, and a few power cuts in a row locked the node out of its key (found by `image/test/power-loss.sh`). Keys created before this change need re-enrollment. PCR-bound policies come later.
  - The CA key sits on the controller's disk (0600). Move it to an HSM/TPM-sealed store before multi-controller.
  - Certificates live one year and there is no rotation yet; add renewal (same key) before production.
  - `node.json`, `identity/` and `pki/` are trusted local state: anyone who can write them owns the node.
- **storage:**
  - Pool sizes and capabilities come from agents: only the pool's own node may report them. Reservations are written by the controller only, with compare-and-swap, before a volume is placed.
  - A driver must refuse a volume group or ZFS pool that carries another pool's or cluster's mark.
  - Before volumes are opened on a host: a udev rule so that their content is not probed.
  - Volume status has the pool's name, for operators: hide it from tenants when IAM comes.
  - A volume type or pool name in a stored object may no longer exist, or be another one: compare the uid.
  - Placement order: pool and `granted_bytes` in the volume's status, then the reservation, then `Placed`; without space both are cleared again. Growth order: the reservation, then `granted_bytes`. Deletion order: blocks, reservation (the pool is always written), then the object. Sweep reservations of volumes that are gone. Before reserving, check the pool's uid and that it is not being deleted.
  - Before a pool is finally removed, check again that no volume type lists it.
  - A key for a destroyed volume uid is never made again (tombstone): racing creates with one request id can briefly reuse a uid.
  - A device is formatted only if the volume was never formatted and its header area is blank.
  - Volumes and request id records have no limit per project, and the records never expire: before tenants get access.
  - An older version that changes an object drops fields that it does not know: before rolling upgrades.
- **CI:** third-party actions are pinned to commit SHAs; keep them pinned when updating.
