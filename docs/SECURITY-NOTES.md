# Security notes carried between chunks

Items found in reviews that a later chunk must enforce.

- **apiserver:**
  - Strip or ignore server-set metadata (uid, cell, generation, etag, timestamps, status) on create/update.
  - Run every `validate()` (ObjectMeta, Scope, specs) at the API boundary. Deserialization alone does not enforce them.
- **scheduler:** evaluate claim `selector` CEL in a sandbox with cost/time limits.
- **controller:**
  - Treat agent-reported data (inventory, allocations, status) as untrusted.
  - Always call `NodeStatus::validate()`.
  - Never accept allocations from agents.
- **CI:** third-party actions are pinned to commit SHAs; keep them pinned when updating.
