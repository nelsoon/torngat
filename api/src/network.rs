//! Network interfaces (schema reserved in M0).
//!
//! An interface is its own resource with a `binding` that selects the datapath. Several network
//! backends coexist in a region. Security groups and live migration are only available for some
//! bindings, and the API says so instead of failing silently.

use serde::{Deserialize, Serialize};

use crate::meta::Object;

pub type NetworkInterface = Object<NetworkInterfaceSpec, NetworkInterfaceStatus>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Binding {
    /// Overlay (OVN), full features.
    #[default]
    Virtio,
    /// OVS-DPDK user-space datapath.
    VhostUser,
    /// SR-IOV virtual function passed to the guest.
    SriovVf,
    /// vDPA (hardware datapath, virtio control plane).
    Vdpa,
    /// Whole physical function passed to the guest.
    PfPassthrough,
    /// InfiniBand virtual function.
    IbVf,
}

impl Binding {
    /// Whether OVN security groups are enforced on this binding.
    pub fn supports_security_groups(self) -> bool {
        matches!(self, Binding::Virtio | Binding::VhostUser)
    }

    /// Whether an instance using this binding can be live-migrated.
    pub fn supports_live_migration(self) -> bool {
        matches!(self, Binding::Virtio | Binding::VhostUser | Binding::Vdpa)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkInterfaceSpec {
    pub network: crate::Name,
    #[serde(default)]
    pub binding: Binding,
    #[serde(default)]
    pub security_groups: Vec<crate::Name>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkInterfaceStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    #[serde(default)]
    pub ip_addresses: Vec<String>,
}

// ---------- M1 networks ----------

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

/// Largest network: its allocations are kept in its status.
pub const MAX_PREFIX_ADDRESSES: u32 = 4096;
/// Interfaces of one instance.
pub const MAX_INTERFACES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetworkError {
    #[error("uplink must be 1 to 15 letters, digits, '-', '_' or '.'")]
    Uplink,
    #[error("vlan must be between 1 and 4094")]
    Vlan,
    #[error("mtu must be between 1280 and 9216")]
    Mtu,
    #[error("a host network needs at least one role")]
    Roles,
    #[error("a host network with the provider role needs a physnet, and only it")]
    Physnet,
    #[error("{0} is not an IPv4 network in CIDR form, a.b.c.d/n with no host bits")]
    Cidr(String),
    #[error("a network has at most {MAX_PREFIX_ADDRESSES} addresses (/20) and at least 8 (/29)")]
    Size,
    #[error("{0} is in a reserved range (this host, loopback, link-local, multicast or reserved)")]
    Reserved(String),
    #[error("gateway and range must be inside the network, and the gateway outside the range")]
    Range,
    #[error("at most {MAX_INTERFACES} interfaces, each on a different network")]
    Interfaces,
    #[error("at most {MAX_DNS} name servers")]
    Dns,
    #[error("the network's kind and addresses cannot change")]
    Immutable,
}

/// What a host network carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficRole {
    /// Nodes and controllers among themselves.
    Platform,
    Storage,
    /// Provider networks of instances.
    Provider,
    /// Overlays of tenants (later).
    Tenant,
}

pub type HostNetwork = Object<HostNetworkSpec, HostNetworkStatus>;

/// A node's uplink and what goes over it. Made by the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostNetworkSpec {
    pub node: crate::Name,
    /// The interface (NIC or bond) on the node.
    pub uplink: String,
    /// VLAN of this network on the uplink; none: untagged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    pub roles: BTreeSet<TrafficRole>,
    /// The physical network that this uplink reaches, for the provider role: provider networks
    /// name it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physnet: Option<crate::Name>,
}

fn default_mtu() -> u32 {
    1500
}

fn vlan_ok(v: Option<u16>) -> Result<(), NetworkError> {
    match v {
        Some(id) if !(1..=4094).contains(&id) => Err(NetworkError::Vlan),
        _ => Ok(()),
    }
}

impl HostNetworkSpec {
    pub fn validate(&self) -> Result<(), NetworkError> {
        // An interface name: IFNAMSIZ, and nothing a command line or path would take apart.
        let ok = (1..=15).contains(&self.uplink.len())
            && self
                .uplink
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            && !self.uplink.starts_with(['-', '.']);
        if !ok {
            return Err(NetworkError::Uplink);
        }
        vlan_ok(self.vlan)?;
        if !(1280..=9216).contains(&self.mtu) {
            return Err(NetworkError::Mtu);
        }
        if self.roles.is_empty() {
            return Err(NetworkError::Roles);
        }
        if self.roles.contains(&TrafficRole::Provider) != self.physnet.is_some() {
            return Err(NetworkError::Physnet);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostNetworkStatus {
    /// The node set it up.
    #[serde(default)]
    pub ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// An IPv4 network: `a.b.c.d/n`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cidr {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, NetworkError> {
        let bad = || NetworkError::Cidr(s.chars().take(64).collect());
        let (a, p) = s.split_once('/').ok_or_else(bad)?;
        let addr: Ipv4Addr = a.parse().map_err(|_| bad())?;
        if p.is_empty() || p.len() > 2 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        let prefix: u8 = p.parse().map_err(|_| bad())?;
        if prefix > 32 || u32::from(addr) & !Self::mask(prefix) != 0 {
            return Err(bad());
        }
        Ok(Self { addr, prefix })
    }

    fn mask(prefix: u8) -> u32 {
        u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & Self::mask(self.prefix) == u32::from(self.addr)
    }

    /// Number of addresses, network and broadcast included.
    pub fn size(&self) -> u64 {
        1u64 << (32 - u32::from(self.prefix))
    }

    /// The first and last addresses that hosts may have.
    pub fn hosts(&self) -> (Ipv4Addr, Ipv4Addr) {
        let base = u32::from(self.addr);
        let last = base + (self.size() as u32 - 1);
        (Ipv4Addr::from(base + 1), Ipv4Addr::from(last - 1))
    }

    /// Whether the two share an address.
    pub fn overlaps(&self, other: &Cidr) -> bool {
        let p = self.prefix.min(other.prefix);
        u32::from(self.addr) & Self::mask(p) == u32::from(other.addr) & Self::mask(p)
    }

    /// A network that instances may have: its size, and none of the ranges that are never a
    /// network's (0/8, loopback, link-local, multicast and 240/4).
    fn check_size(&self) -> Result<(), NetworkError> {
        if !(8..=u64::from(MAX_PREFIX_ADDRESSES)).contains(&self.size()) {
            return Err(NetworkError::Size);
        }
        const RESERVED: [(u32, u8); 5] = [
            (0x0000_0000, 8),
            (0x7f00_0000, 8),
            (0xa9fe_0000, 16),
            (0xe000_0000, 4),
            (0xf000_0000, 4),
        ];
        let hit = RESERVED.iter().any(|&(a, prefix)| {
            self.overlaps(&Cidr {
                addr: Ipv4Addr::from(a),
                prefix,
            })
        });
        if hit {
            return Err(NetworkError::Reserved(self.to_string()));
        }
        Ok(())
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl Serialize for Cidr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Cidr::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Whether an address pool reaches outside the operator's networks. Not inferred from the range:
/// an edge site's external pool may be private addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolScope {
    External,
    Internal,
}

/// Addresses that instances (and the node's NAT) get on a provider network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpPool {
    pub scope: PoolScope,
    pub cidr: Cidr,
    pub gateway: Ipv4Addr,
    /// First and last address given out.
    pub first: Ipv4Addr,
    pub last: Ipv4Addr,
}

impl IpPool {
    fn validate(&self) -> Result<(), NetworkError> {
        self.cidr.check_size()?;
        let (lo, hi) = self.cidr.hosts();
        let inside = |ip: Ipv4Addr| ip >= lo && ip <= hi;
        let in_range = |ip: Ipv4Addr| ip >= self.first && ip <= self.last;
        if !inside(self.gateway)
            || !inside(self.first)
            || !inside(self.last)
            || self.first > self.last
            || in_range(self.gateway)
        {
            return Err(NetworkError::Range);
        }
        Ok(())
    }
}

pub type ProviderNetwork = Object<ProviderNetworkSpec, NetworkStatus>;

/// A network outside the platform, reached on a physnet: instances get an address of it directly.
/// Made by the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderNetworkSpec {
    pub physnet: crate::Name,
    /// On the host networks of the physnet; none: untagged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    pub pool: IpPool,
    /// Projects may attach instances to it (through a network of theirs that names it). There is
    /// no inbound firewall yet: the guest filters.
    #[serde(default)]
    pub tenants: bool,
    /// The nodes' NAT for private networks goes out by it (an address of its pool per node).
    #[serde(default)]
    pub egress: bool,
    /// Name servers given to instances by DHCP: on it, and on private networks that go out by it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<Ipv4Addr>,
}

/// Name servers a provider network gives at most.
pub const MAX_DNS: usize = 3;

impl ProviderNetworkSpec {
    pub fn validate(&self) -> Result<(), NetworkError> {
        vlan_ok(self.vlan)?;
        if self.dns.len() > MAX_DNS {
            return Err(NetworkError::Dns);
        }
        self.pool.validate()
    }
}

/// What a node is told of networks: its host networks, and the networks and provider networks
/// its instances are on, with the egress provider networks.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeNetworks {
    #[serde(default)]
    pub host_networks: Vec<HostNetwork>,
    #[serde(default)]
    pub provider_networks: Vec<ProviderNetwork>,
    #[serde(default)]
    pub networks: Vec<Network>,
}

pub type Network = Object<NetworkSpec, NetworkStatus>;

/// A project's network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkSpec {
    /// Its own addresses, on the node only; out through the node's NAT, nothing comes in.
    Private { cidr: Cidr },
    /// A provider network that the operator opened to projects.
    Provider { network: crate::Name },
}

impl NetworkSpec {
    pub fn validate(&self) -> Result<(), NetworkError> {
        match self {
            NetworkSpec::Private { cidr } => cidr.check_size(),
            NetworkSpec::Provider { .. } => Ok(()),
        }
    }

    pub fn validate_update(&self, new: &Self) -> Result<(), NetworkError> {
        if self == new {
            Ok(())
        } else {
            Err(NetworkError::Immutable)
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkStatus {
    /// Addresses given out, to an instance's uid (a provider network's also to a node, for its NAT).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub allocations: BTreeMap<Ipv4Addr, uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// An instance's interface: on a network of its project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceRef {
    pub network: crate::Name,
}

/// What an interface got.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceStatus {
    pub network: crate::Name,
    /// The network's uid: a network made again with the same name is another one.
    pub network_uid: uuid::Uuid,
    pub mac: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<Ipv4Addr>,
}

/// The MAC of an instance's `i`th interface: locally administered, from its uid.
pub fn mac_of(instance: uuid::Uuid, i: usize) -> String {
    let b = instance.as_bytes();
    // 0x02: locally administered, unicast. The uid's random end, and the interface's index.
    format!(
        "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[11],
        b[12],
        b[13],
        b[14],
        (b[15] & 0xf8) | (i as u8 & 0x07)
    )
}

#[cfg(test)]
mod m1_tests {
    use super::*;

    fn n(s: &str) -> crate::Name {
        crate::Name::new(s).unwrap_or_else(|e| unreachable!("{e}"))
    }

    #[test]
    fn cidrs() {
        let c = Cidr::parse("10.1.0.0/24").unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(c.size(), 256);
        assert_eq!(
            c.hosts(),
            (Ipv4Addr::new(10, 1, 0, 1), Ipv4Addr::new(10, 1, 0, 254))
        );
        assert!(c.contains(Ipv4Addr::new(10, 1, 0, 9)) && !c.contains(Ipv4Addr::new(10, 1, 1, 0)));
        for bad in [
            "10.1.0.1/24",
            "10.1.0.0",
            "10.1.0.0/33",
            "10.1.0.0/-1",
            "10.1.0.0/024",
            "x/8",
            "10.1.0.0/ 8",
        ] {
            assert!(Cidr::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(
            serde_json::to_string(&c).unwrap_or_default(),
            "\"10.1.0.0/24\""
        );
        let big = NetworkSpec::Private {
            cidr: Cidr::parse("10.0.0.0/16").unwrap_or_else(|e| unreachable!("{e}")),
        };
        assert_eq!(big.validate(), Err(NetworkError::Size));
        let cidr = |s: &str| Cidr::parse(s).unwrap_or_else(|e| unreachable!("{e}"));
        for reserved in [
            "127.0.0.0/24",
            "169.254.1.0/24",
            "0.0.0.0/24",
            "224.0.0.0/24",
            "255.255.255.0/24",
        ] {
            let spec = NetworkSpec::Private {
                cidr: cidr(reserved),
            };
            assert!(
                matches!(spec.validate(), Err(NetworkError::Reserved(_))),
                "{reserved}"
            );
        }
        assert!(cidr("10.1.0.0/24").overlaps(&cidr("10.1.0.128/25")));
        assert!(cidr("10.1.0.128/25").overlaps(&cidr("10.1.0.0/24")));
        assert!(!cidr("10.1.0.0/25").overlaps(&cidr("10.1.0.128/25")));
    }

    #[test]
    fn host_networks() {
        let h = HostNetworkSpec {
            node: n("n1"),
            uplink: "eno1".into(),
            vlan: Some(100),
            mtu: 1500,
            roles: [TrafficRole::Provider].into(),
            physnet: Some(n("physnet1")),
        };
        assert_eq!(h.validate(), Ok(()));
        for (bad, err) in [
            (
                HostNetworkSpec {
                    uplink: "eth0; rm".into(),
                    ..h.clone()
                },
                NetworkError::Uplink,
            ),
            (
                HostNetworkSpec {
                    uplink: "-x".into(),
                    ..h.clone()
                },
                NetworkError::Uplink,
            ),
            (
                HostNetworkSpec {
                    vlan: Some(4095),
                    ..h.clone()
                },
                NetworkError::Vlan,
            ),
            (
                HostNetworkSpec {
                    mtu: 100,
                    ..h.clone()
                },
                NetworkError::Mtu,
            ),
            (
                HostNetworkSpec {
                    roles: BTreeSet::new(),
                    ..h.clone()
                },
                NetworkError::Roles,
            ),
            (
                HostNetworkSpec {
                    physnet: None,
                    ..h.clone()
                },
                NetworkError::Physnet,
            ),
            (
                HostNetworkSpec {
                    roles: [TrafficRole::Storage].into(),
                    ..h.clone()
                },
                NetworkError::Physnet,
            ),
        ] {
            assert_eq!(bad.validate(), Err(err));
        }
    }

    #[test]
    fn pools() {
        let ip = |s: &str| {
            s.parse::<Ipv4Addr>()
                .unwrap_or_else(|e| unreachable!("{e}"))
        };
        let p = ProviderNetworkSpec {
            physnet: n("physnet1"),
            vlan: None,
            pool: IpPool {
                scope: PoolScope::External,
                cidr: Cidr::parse("203.0.113.0/24").unwrap_or_else(|e| unreachable!("{e}")),
                gateway: ip("203.0.113.1"),
                first: ip("203.0.113.10"),
                last: ip("203.0.113.200"),
            },
            tenants: true,
            egress: true,
            dns: vec![ip("203.0.113.53")],
        };
        assert_eq!(p.validate(), Ok(()));
        let with = |g: &str, f: &str, l: &str| ProviderNetworkSpec {
            pool: IpPool {
                gateway: ip(g),
                first: ip(f),
                last: ip(l),
                ..p.pool.clone()
            },
            ..p.clone()
        };
        for (g, f, l) in [
            ("203.0.113.50", "203.0.113.10", "203.0.113.200"),
            ("203.0.113.1", "203.0.113.0", "203.0.113.200"),
            ("203.0.113.1", "203.0.113.10", "203.0.113.255"),
            ("203.0.113.1", "203.0.113.20", "203.0.113.10"),
            ("198.51.100.1", "203.0.113.10", "203.0.113.20"),
        ] {
            assert_eq!(
                with(g, f, l).validate(),
                Err(NetworkError::Range),
                "{g} {f} {l}"
            );
        }
    }

    #[test]
    fn macs() {
        let u = uuid::Uuid::now_v7();
        let (a, b) = (mac_of(u, 0), mac_of(u, 1));
        assert!(a.starts_with("02:") && a.len() == 17 && a != b);
    }
}
