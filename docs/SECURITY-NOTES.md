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
  - TPM keys use no authorization value (no dictionary-attack lockout risk); access to the TPM device is the boundary. PCR-bound policies come later.
  - The CA key sits on the controller's disk (0600). Move it to an HSM/TPM-sealed store before multi-controller.
  - Certificates live one year and there is no rotation yet; add renewal (same key) before production.
  - `node.json`, `identity/` and `pki/` are trusted local state: anyone who can write them owns the node.
- **CI:** third-party actions are pinned to commit SHAs; keep them pinned when updating.
