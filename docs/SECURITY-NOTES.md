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
  - Node keys are files (`key_storage: file`) until TPM enrollment lands; `tpm` claims are refused until attestation can back them. Enforce the cluster's TPM policy at join once it does.
  - The CA key sits on the controller's disk (0600). Move it to an HSM/TPM-sealed store before multi-controller.
  - Certificates live one year and there is no rotation yet; add renewal (same key) before production.
  - `node.json`, `identity/` and `pki/` are trusted local state: anyone who can write them owns the node.
- **CI:** third-party actions are pinned to commit SHAs; keep them pinned when updating.
