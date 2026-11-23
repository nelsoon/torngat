# Torngat architecture

Status: pre-alpha. This document describes the target architecture; most of it is not built yet.

## Goals

- **One product from 1 to 500 nodes per region.** A single node is a valid cluster; adding nodes
  grows it without reinstalling.
- **Multi-tenant from the start.** Tenancy, identity and isolation are part of the core, not add-ons.
- **Few moving parts.** A small set of Rust daemons, one declarative API, and proven open-source
  data-plane components reused as they are.
- **Built to evolve.** Versioned APIs and driver contracts so components can be replaced without
  rewriting the platform.

## Resource model

```
Organization ─┬─ Folder (nestable) ─ Project
              └─ Project
Project ─ VPC ─ Subnet ─ SecurityGroup ─ FloatingIP ─ LoadBalancer
        ─ Instance ─ Service (containers / functions) ─ Volume ─ Snapshot ─ Image
        ─ Bucket ─ Secret ─ ServiceAccount ─ ResourceClaim ─ NetworkInterface
Infrastructure: Region ─ Zone ─ Cell ─ Node
```

Every object has metadata (validated name, scope, uid, cell, generation, etag, timestamps), a
`spec` (desired state) and a `status` (observed state). API conventions follow Google's API
Improvement Proposals ([AIP](https://google.aip.dev)). Mutations that take time return an
`Operation`. Creates accept a `request_id` for idempotency; updates carry an `etag`.

## Components

| Daemon | Role |
|---|---|
| `torngat-controller` | Holds desired state in an embedded Raft store and runs reconcile loops |
| `torngat-apiserver` | Public and operator APIs: TLS, authentication, authorization, quotas, audit |
| `torngat-agent` | Runs on every node: reports inventory, drives workloads, network and storage |
| `torngat-gateway` | North-south traffic: NAT, floating IPs, BGP |
| `torngat` | Command-line client |

- Desired state and durable status go through Raft (3 or 5 voters; 1 on a single node). Liveness
  and metrics are soft state kept in memory.
- Controllers use the same resource API as external clients, never the store directly.
- Storage, network and device drivers talk to the agent over versioned gRPC contracts, so drivers
  can live outside this repository.

## Compute

Users request **capabilities** (live-migratable, GPU, SR-IOV, confidential, real-time…); the
platform chooses the runtime.

| Workload | Runtime |
|---|---|
| Virtual machines | QEMU/KVM or Cloud Hypervisor, chosen by capability |
| Containers (OCI images) and functions | Cloud Hypervisor microVMs with a minimal Rust guest init |
| WASM | Wasmtime, one sandboxed host process per project |

Node hardware is described by a typed, nested inventory (NUMA nodes, GPUs and partitions, NICs and
virtual functions), and devices are allocated through claims, so topology-aware placement is part
of the model from day one.

## Networking

- Tenant networks on OVS/OVN with Geneve overlays; dual stack, IPv6 first.
- Network interfaces are resources with a binding type (virtio, vhost-user, SR-IOV VF, vDPA,
  passthrough, InfiniBand VF). Features such as security groups and live migration depend on it.
- Scale-out by zone, with BGP/EVPN integration to the physical network.

## Storage

- Ceph (block, object, file) for clusters of three or more nodes.
- ZFS and an S3-compatible object store for single nodes and edge sites.
- Local NVMe volumes for fast, non-replicated disks.

## Identity and security

- Organization → folder → project hierarchy with inherited role bindings, deny policies and
  resource tags. Policy decisions use Cedar; organization constraints use CEL.
- Workload identity: every workload gets short-lived OIDC tokens; external identities are
  federated through token exchange (RFC 8693).
- Secrets in OpenBao. Volumes encrypted by default with per-project keys.
- Node identity backed by the TPM, mTLS between all components.
- Operator access to tenant data requires a time-limited, tenant-visible approval.

## Host OS and lifecycle

- Immutable Debian-based image built with mkosi: read-only `/usr` verified by dm-verity, with the
  platform shipped as signed systemd-sysext layers that update without a reboot.
- Calendar versioning (`YYYY.R.P`), two major releases a year, skip-level upgrades.
- Rolling upgrades in waves; workloads are live-migrated or restarted within tenant maintenance
  windows.

## Edge

An edge site is a small region (one Raft voter or more) that keeps working while disconnected,
attached to a parent region for management. Sites can be installed from an ISO or pre-provisioned
and onboarded with TPM attestation.

## Milestones

| Milestone | Delivers |
|---|---|
| M0 | Raft controller, apiserver, CLI, node join with mTLS, immutable image, one node |
| M1 | VMs on one node, local storage, cloud-init metadata, console |
| M2 | Three nodes, organizations/folders/projects, IAM |
| M3 | Tenant networking, security groups, NAT, floating IPs, IPv6 |
| M4 | Shared storage, snapshots, live migration |
| M5 | Rolling upgrades, observability, platform backup and restore |
| M6 | Tenant backups, quotas, metering, audit: production 1.0 |
