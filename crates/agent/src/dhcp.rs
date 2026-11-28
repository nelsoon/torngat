//! DHCP answers for the node's instances.
//!
//! The controller gives each interface its address; this only tells it to the guest. There is no
//! pool and no lease state: a MAC that is not in the table on that network gets no answer, and a
//! request for another address is refused. Packets come from guests, so nothing here trusts them
//! beyond looking up their MAC.
//!
//! This is the logic only: frames, sockets and the process it runs in are the datapath's.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use dhcproto::v4::{DhcpOption, HType, Message, MessageType, Opcode, OptionCode};
use dhcproto::{Decodable, Encodable};
use torngat_api::compute::Instance;
use torngat_api::network::{NetworkSpec, NodeNetworks, ProviderNetwork, TrafficRole, parse_mac};
use uuid::Uuid;

/// How long a guest keeps its address before it asks again.
pub const LEASE_SECS: u32 = 12 * 3600;
/// The MTU of private networks (they stay on the node in M1).
pub const PRIVATE_MTU: u16 = 1500;

/// What a guest is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
    /// The gateway, and the server identifier.
    pub router: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub mtu: u16,
}

/// Leases by network uid and MAC.
pub type Table = BTreeMap<(Uuid, [u8; 6]), Lease>;

/// The table for the node's instances: each interface with an address, on a network the node was
/// told of. An address outside its network is left out.
pub fn table(instances: &[Instance], nets: &NodeNetworks) -> Table {
    let live = |p: &&ProviderNetwork| p.metadata.delete_time.is_none();
    // Private networks go out by an egress provider network: the name servers of the first by
    // name that has some, so every node says the same.
    let mut egress: Vec<&ProviderNetwork> = nets
        .provider_networks
        .iter()
        .filter(live)
        .filter(|p| p.spec.egress && !p.spec.dns.is_empty())
        .collect();
    egress.sort_by(|a, b| a.metadata.name.cmp(&b.metadata.name));
    let private_dns = egress
        .first()
        .map(|p| p.spec.dns.clone())
        .unwrap_or_default();
    let mut out = Table::new();
    for inst in instances
        .iter()
        .filter(|i| i.metadata.delete_time.is_none())
    {
        for f in &inst.status.interfaces {
            let (Some(ip), Some(mac)) = (f.ip, parse_mac(&f.mac)) else {
                continue;
            };
            let Some(net) = nets
                .networks
                .iter()
                .find(|n| n.metadata.uid == f.network_uid && n.metadata.delete_time.is_none())
            else {
                continue;
            };
            let lease = match &net.spec {
                NetworkSpec::Private { cidr } => {
                    let (first, _) = cidr.hosts();
                    cidr.contains(ip).then(|| Lease {
                        ip,
                        mask: cidr.netmask(),
                        router: first,
                        dns: private_dns.clone(),
                        mtu: PRIVATE_MTU,
                    })
                }
                NetworkSpec::Provider { network } => nets
                    .provider_networks
                    .iter()
                    .filter(live)
                    .find(|p| &p.metadata.name == network)
                    .filter(|p| p.spec.pool.cidr.contains(ip))
                    .map(|p| Lease {
                        ip,
                        mask: p.spec.pool.cidr.netmask(),
                        router: p.spec.pool.gateway,
                        dns: p.spec.dns.clone(),
                        mtu: nets
                            .host_networks
                            .iter()
                            .find(|h| {
                                h.metadata.delete_time.is_none()
                                    && h.spec.roles.contains(&TrafficRole::Provider)
                                    && h.spec.physnet.as_ref() == Some(&p.spec.physnet)
                            })
                            .and_then(|h| u16::try_from(h.spec.mtu).ok())
                            .unwrap_or(PRIVATE_MTU),
                    }),
            };
            if let Some(l) = lease {
                out.insert((net.metadata.uid, mac), l);
            }
        }
    }
    out
}

/// The answer to `request`, a DHCP message from `src` (the frame's source MAC, which the port
/// allows) on `network` (from the port it came in on, never from the packet); `None` to stay
/// silent.
///
/// The server identifier is the network's gateway: on a provider network that is a router
/// outside, so the datapath takes every DHCP request from an instance port, whatever its
/// destination.
pub fn answer(table: &Table, network: Uuid, src: [u8; 6], request: &[u8]) -> Option<Vec<u8>> {
    let req = Message::from_bytes(request).ok()?;
    // Guests talk to us directly: never through a relay.
    if req.opcode() != Opcode::BootRequest
        || req.htype() != HType::Eth
        || req.hlen() != 6
        || req.giaddr() != Ipv4Addr::UNSPECIFIED
    {
        return None;
    }
    let mac: [u8; 6] = req.chaddr().get(..6)?.try_into().ok()?;
    // Only for itself: never another instance's address.
    if mac != src {
        return None;
    }
    let lease = table.get(&(network, mac))?;
    let opts = req.opts();
    let server = match opts.get(OptionCode::ServerIdentifier) {
        Some(DhcpOption::ServerIdentifier(s)) => Some(*s),
        _ => None,
    };
    let (kind, yiaddr) = match opts.msg_type()? {
        MessageType::Discover => (MessageType::Offer, lease.ip),
        MessageType::Request => {
            // Selecting another server's offer: not ours to answer.
            if server.is_some_and(|s| s != lease.router) {
                return None;
            }
            // Selecting or rebooting: the requested address. Renewing or rebinding: ciaddr.
            let wanted = match opts.get(OptionCode::RequestedIpAddress) {
                Some(DhcpOption::RequestedIpAddress(ip)) => *ip,
                _ => req.ciaddr(),
            };
            if wanted.is_unspecified() {
                return None;
            }
            if wanted == lease.ip {
                (MessageType::Ack, lease.ip)
            } else {
                (MessageType::Nak, Ipv4Addr::UNSPECIFIED)
            }
        }
        // It has its address already (configured by hand): only the options.
        MessageType::Inform => (MessageType::Ack, Ipv4Addr::UNSPECIFIED),
        _ => return None,
    };
    let mut rep = Message::new_with_id(
        req.xid(),
        Ipv4Addr::UNSPECIFIED,
        yiaddr,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        &mac,
    );
    rep.set_opcode(Opcode::BootReply).set_flags(req.flags());
    if kind == MessageType::Inform {
        rep.set_ciaddr(req.ciaddr());
    }
    let o = rep.opts_mut();
    o.insert(DhcpOption::MessageType(kind));
    o.insert(DhcpOption::ServerIdentifier(lease.router));
    if kind != MessageType::Nak {
        if opts.msg_type() != Some(MessageType::Inform) {
            o.insert(DhcpOption::AddressLeaseTime(LEASE_SECS));
        }
        o.insert(DhcpOption::SubnetMask(lease.mask));
        o.insert(DhcpOption::Router(vec![lease.router]));
        if !lease.dns.is_empty() {
            o.insert(DhcpOption::DomainNameServer(lease.dns.clone()));
        }
        o.insert(DhcpOption::InterfaceMtu(lease.mtu));
    }
    rep.to_vec().ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const MAC: [u8; 6] = [2, 1, 2, 3, 4, 5];

    fn lease() -> Lease {
        Lease {
            ip: Ipv4Addr::new(10, 9, 0, 2),
            mask: Ipv4Addr::new(255, 255, 255, 248),
            router: Ipv4Addr::new(10, 9, 0, 1),
            dns: vec![Ipv4Addr::new(203, 0, 113, 53)],
            mtu: 1500,
        }
    }

    fn request(kind: MessageType, mac: &[u8], extra: &[DhcpOption]) -> Vec<u8> {
        let z = Ipv4Addr::UNSPECIFIED;
        let mut m = Message::new_with_id(42, z, z, z, z, mac);
        m.opts_mut().insert(DhcpOption::MessageType(kind));
        for o in extra {
            m.opts_mut().insert(o.clone());
        }
        m.to_vec().unwrap()
    }

    fn reply(b: &[u8]) -> Message {
        Message::from_bytes(b).unwrap()
    }

    #[test]
    fn answers_known_macs_only() {
        let net = Uuid::now_v7();
        let t: Table = [((net, MAC), lease())].into();

        let offer =
            reply(&answer(&t, net, MAC, &request(MessageType::Discover, &MAC, &[])).unwrap());
        assert_eq!(offer.opcode(), Opcode::BootReply);
        assert_eq!(offer.xid(), 42);
        assert_eq!(offer.opts().msg_type(), Some(MessageType::Offer));
        assert_eq!(offer.yiaddr(), lease().ip);
        assert_eq!(
            offer.opts().get(OptionCode::Router),
            Some(&DhcpOption::Router(vec![lease().router]))
        );
        assert_eq!(
            offer.opts().get(OptionCode::DomainNameServer),
            Some(&DhcpOption::DomainNameServer(lease().dns))
        );

        // Another MAC, the same MAC on another network, a relay: silence.
        assert!(
            answer(
                &t,
                net,
                [2, 9, 9, 9, 9, 9],
                &request(MessageType::Discover, &[2, 9, 9, 9, 9, 9], &[])
            )
            .is_none()
        );
        assert!(
            answer(
                &t,
                Uuid::now_v7(),
                MAC,
                &request(MessageType::Discover, &MAC, &[])
            )
            .is_none()
        );
        let z = Ipv4Addr::UNSPECIFIED;
        let mut relayed = Message::new_with_id(1, z, z, z, Ipv4Addr::new(10, 0, 0, 1), &MAC);
        relayed
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Discover));
        assert!(answer(&t, net, MAC, &relayed.to_vec().unwrap()).is_none());
        // Another MAC than the frame's: never another instance's lease.
        assert!(
            answer(
                &t,
                net,
                [2, 9, 9, 9, 9, 9],
                &request(MessageType::Discover, &MAC, &[])
            )
            .is_none()
        );
        // Not DHCP at all.
        assert!(answer(&t, net, MAC, b"\x01\x02garbage").is_none());
        assert!(answer(&t, net, MAC, &[]).is_none());
    }

    #[test]
    fn requests() {
        let net = Uuid::now_v7();
        let t: Table = [((net, MAC), lease())].into();
        let ask = |extra: &[DhcpOption]| {
            answer(&t, net, MAC, &request(MessageType::Request, &MAC, extra)).map(|b| reply(&b))
        };
        let ack = ask(&[DhcpOption::RequestedIpAddress(lease().ip)]).unwrap();
        assert_eq!(ack.opts().msg_type(), Some(MessageType::Ack));
        assert_eq!(ack.yiaddr(), lease().ip);
        assert_eq!(
            ack.opts().get(OptionCode::AddressLeaseTime),
            Some(&DhcpOption::AddressLeaseTime(LEASE_SECS))
        );
        // Another address: refused, with nothing else said.
        let nak = ask(&[DhcpOption::RequestedIpAddress(Ipv4Addr::new(10, 9, 0, 3))]).unwrap();
        assert_eq!(nak.opts().msg_type(), Some(MessageType::Nak));
        assert_eq!(nak.yiaddr(), Ipv4Addr::UNSPECIFIED);
        assert!(nak.opts().get(OptionCode::Router).is_none());
        // Another server's offer: not answered.
        assert!(
            ask(&[
                DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 9, 0, 6)),
                DhcpOption::RequestedIpAddress(lease().ip),
            ])
            .is_none()
        );
        // No address at all: not a request we can answer.
        assert!(ask(&[]).is_none());
        // Release and decline: nothing to do.
        assert!(answer(&t, net, MAC, &request(MessageType::Release, &MAC, &[])).is_none());
    }

    fn object<T: serde::de::DeserializeOwned>(
        name: &str,
        scope: &torngat_api::Scope,
        spec: serde_json::Value,
        status: serde_json::Value,
    ) -> T {
        serde_json::from_value(serde_json::json!({
            "metadata": {"name": name, "scope": scope, "uid": Uuid::now_v7(), "generation": 1},
            "spec": spec, "status": status}))
        .unwrap()
    }

    #[test]
    fn tables() {
        use serde_json::json;
        use torngat_api::{Name, Scope};
        let p = Scope::Project {
            org: Name::new("acme").unwrap(),
            project: Name::new("web").unwrap(),
        };
        let pool = json!({"scope": "external", "cidr": "203.0.113.0/24", "gateway": "203.0.113.1",
                          "first": "203.0.113.10", "last": "203.0.113.20"});
        let nets = NodeNetworks {
            host_networks: vec![object(
                "n1-eno2",
                &Scope::Platform,
                json!({"node": "n1", "uplink": "eno2", "mtu": 9000, "roles": ["provider"],
                       "physnet": "physnet1"}),
                json!({}),
            )],
            provider_networks: vec![object(
                "public",
                &Scope::Platform,
                json!({"physnet": "physnet1", "pool": pool, "tenants": true, "egress": true,
                           "dns": ["203.0.113.53"]}),
                json!({}),
            )],
            networks: vec![
                object(
                    "lan",
                    &p,
                    json!({"private": {"cidr": "10.9.0.0/29"}}),
                    json!({}),
                ),
                object(
                    "wan",
                    &p,
                    json!({"provider": {"network": "public"}}),
                    json!({}),
                ),
            ],
        };
        let (lan, wan) = (nets.networks[0].metadata.uid, nets.networks[1].metadata.uid);
        let inst: Instance = object(
            "a",
            &p,
            json!({"vcpus": 1, "memory_mib": 64}),
            json!({"interfaces": [
                {"network": "lan", "network_uid": lan, "mac": "02:00:00:00:00:01", "ip": "10.9.0.2"},
                {"network": "wan", "network_uid": wan, "mac": "02:00:00:00:00:02", "ip": "203.0.113.10"},
                // Outside its network, no address yet, a network the node was not told of.
                {"network": "lan", "network_uid": lan, "mac": "02:00:00:00:00:03", "ip": "10.9.1.2"},
                {"network": "lan", "network_uid": lan, "mac": "02:00:00:00:00:04"},
                {"network": "x", "network_uid": Uuid::now_v7(), "mac": "02:00:00:00:00:05", "ip": "10.9.0.3"},
            ]}),
        );
        let t = table(&[inst], &nets);
        assert_eq!(t.len(), 2, "{t:?}");
        let dns = vec![Ipv4Addr::new(203, 0, 113, 53)];
        assert_eq!(
            t[&(lan, [2, 0, 0, 0, 0, 1])],
            Lease {
                ip: Ipv4Addr::new(10, 9, 0, 2),
                mask: Ipv4Addr::new(255, 255, 255, 248),
                router: Ipv4Addr::new(10, 9, 0, 1),
                dns: dns.clone(),
                mtu: PRIVATE_MTU,
            }
        );
        assert_eq!(
            t[&(wan, [2, 0, 0, 0, 0, 2])],
            Lease {
                ip: Ipv4Addr::new(203, 0, 113, 10),
                mask: Ipv4Addr::new(255, 255, 255, 0),
                router: Ipv4Addr::new(203, 0, 113, 1),
                dns,
                mtu: 9000,
            }
        );
    }

    #[test]
    fn macs() {
        assert_eq!(parse_mac("02:01:02:03:04:0f"), Some([2, 1, 2, 3, 4, 15]));
        let uid = Uuid::now_v7();
        assert!(parse_mac(&torngat_api::network::mac_of(uid, 3)).is_some());
        for bad in [
            "02:01:02:03:04",
            "02:01:02:03:04:05:06",
            "2:01:02:03:04:05",
            "zz:01:02:03:04:05",
            "+f:01:02:03:04:05",
        ] {
            assert_eq!(parse_mac(bad), None, "{bad}");
        }
    }
}
