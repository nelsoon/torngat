# Torngat

A multi-tenant cloud platform that runs on anything from a single edge box to 500-node regions: VMs, microVM containers, functions and WASM, with tenancy, workload identity and a declarative resource API built in.

Status: pre-alpha, design and M0 skeleton. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and the [administrator and user guides](docs/README.md).

## Licensing
- Core (this repository): **AGPL-3.0**, see [LICENSE](LICENSE). Contributions require a CLA (to be published).
- API definitions in [`api/`](api/): **Apache-2.0**, see [api/LICENSE](api/LICENSE), so SDKs, the Terraform provider and integrations can use them freely.
