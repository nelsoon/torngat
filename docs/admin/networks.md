# Networks

Pre-alpha: the API and the addresses are there; nodes do not set up networks yet.

## Host networks

What each node's uplinks carry. One per uplink and VLAN:

```
POST /v1/platform/hostNetworks?host_network_id=n1-provider
{"spec": {"node": "n1", "uplink": "eno2", "vlan": 100, "mtu": 1500,
          "roles": ["provider"], "physnet": "physnet1"}}
```

- `uplink`: the NIC or bond on the node. Without `vlan`, untagged.
- `roles`: `platform` (nodes and controllers), `storage`, `provider` (provider networks of instances), `tenant`
  (overlays, later). One uplink may carry several; do not put `provider` on the untagged network of `platform`.
- `physnet`: for the provider role only: the physical network that this uplink reaches. Provider networks name it. A node has one host network per physnet. Node, uplink, VLAN and physnet cannot change.
- Node, uplink and VLAN cannot change.

## Provider networks

A network outside the platform that instances can be on directly:

```
POST /v1/platform/providerNetworks?provider_network_id=public
{"spec": {"physnet": "physnet1", "vlan": 200,
          "pool": {"scope": "external", "cidr": "203.0.113.0/24", "gateway": "203.0.113.1",
                   "first": "203.0.113.10", "last": "203.0.113.200"},
          "tenants": true, "egress": true, "dns": ["203.0.113.53"]}}
```

- `pool.scope`: `external` (reaches outside your networks) or `internal`; not guessed from the addresses. Instances get
  addresses from `first` to `last`; the gateway is outside that range.
- `tenants`: projects may put instances on it (with a network of theirs naming it). **There is no inbound firewall yet**:
  instances on it are reachable, and filter themselves.
- `egress`: the nodes' NAT for private networks goes out by it.
- `dns`: up to 3 name servers, given by DHCP to instances on it, and to instances on private networks that go out by it
  (the first egress provider network by name). Can change.
- Two provider networks on the same physnet and VLAN cannot have overlapping addresses. Networks cannot be in 0/8, loopback, link-local, multicast or 240/4.
- Physnet, VLAN and pool cannot change; `tenants` and `egress` can. A provider network with addresses in use, or named by
  a project's network, cannot be deleted.
- `status.allocations`: the addresses given out, by instance uid.

## Datapath

Each node runs Open vSwitch with one bridge, `br-int`, that only the agent's flows forward on (secure fail mode):

- Each network on the node has a VLAN tag on the bridge, chosen by the node; an instance interface is a port of its
  network's tag. Networks with the same addresses (two projects can have them) stay apart.
- Every instance port lets out only the instance's own MAC, its own address and ARP for it. IPv6, DHCP server replies
  and anything else from the guest are dropped.
- DHCP: one process per node, `torngat-dhcp.service`, user `torngat-dhcp`, sandboxed, on a tap port of the bridge. It
  gets only the instances' DHCP requests, and answers each with the address the controller gave it (no pool, no
  leases). Its leases are in `/run/torngat-dhcp/leases.json`.
- `ovs-vsctl show` and `ovs-ofctl dump-flows br-int` show it all. The agent sets it again on each pass; changes made by
  hand are undone.

Not yet: the router and NAT of private networks, and provider networks' uplinks (next version). Private networks stay on
their node until the tenant overlay: instances on one private network but on different nodes do not reach each other.
