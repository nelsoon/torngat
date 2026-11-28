//! DHCP answers for the node's instances.
//!
//! The controller gives each interface its address; this only tells it to the guest. There is no
//! pool and no lease state: a MAC that is not in the table on that network gets no answer, and a
//! request for another address is refused. Packets come from guests, so nothing here trusts them
//! beyond looking up their MAC.
//!
//! [`answer`] is the logic; [`serve`] runs it on the datapath's DHCP port, a tap on the node's
//! bridge that gets each network's DHCP requests with the network's VLAN tag.

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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Lease {
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
    /// The gateway, and the server identifier.
    pub router: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub mtu: u16,
}

/// A network's leases, by MAC.
pub type Leases = BTreeMap<[u8; 6], Lease>;
/// Leases by network uid.
pub type Table = BTreeMap<Uuid, Leases>;

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
                out.entry(net.metadata.uid).or_default().insert(mac, l);
            }
        }
    }
    out
}

/// The answer to `request`, a DHCP message from `src` (the frame's source MAC, which the port
/// allows) on the network whose `leases` these are (from the port it came in on, never from the
/// packet); `None` to stay silent.
///
/// The server identifier is the network's gateway: on a provider network that is a router
/// outside, so the datapath takes every DHCP request from an instance port, whatever its
/// destination.
pub fn answer(leases: &Leases, src: [u8; 6], request: &[u8]) -> Option<Vec<u8>> {
    reply(leases, src, request)?.0.to_vec().ok()
}

/// The reply, and where it goes: the client's address, or broadcast.
fn reply(leases: &Leases, src: [u8; 6], request: &[u8]) -> Option<(Message, Ipv4Addr)> {
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
    let lease = leases.get(&mac)?;
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
    let inform = opts.msg_type() == Some(MessageType::Inform);
    rep.set_opcode(Opcode::BootReply).set_flags(req.flags());
    if inform {
        rep.set_ciaddr(req.ciaddr());
    }
    let o = rep.opts_mut();
    o.insert(DhcpOption::MessageType(kind));
    o.insert(DhcpOption::ServerIdentifier(lease.router));
    if kind != MessageType::Nak {
        if !inform {
            o.insert(DhcpOption::AddressLeaseTime(LEASE_SECS));
        }
        o.insert(DhcpOption::SubnetMask(lease.mask));
        o.insert(DhcpOption::Router(vec![lease.router]));
        if !lease.dns.is_empty() {
            o.insert(DhcpOption::DomainNameServer(lease.dns.clone()));
        }
        o.insert(DhcpOption::InterfaceMtu(lease.mtu));
    }
    // RFC 2131 4.1: to the address it has, else broadcast if it asks or is refused, else to the
    // address given. Always to its MAC at layer 2.
    let to = if kind == MessageType::Nak {
        Ipv4Addr::BROADCAST
    } else if !req.ciaddr().is_unspecified() {
        req.ciaddr()
    } else if req.flags().broadcast() {
        Ipv4Addr::BROADCAST
    } else {
        yiaddr
    };
    Some((rep, to))
}

/// What the DHCP process is told: each lease, with its network's VLAN tag on the DHCP port.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PortLease {
    pub tag: u16,
    pub mac: String,
    pub lease: Lease,
}

/// Leases by VLAN tag on the DHCP port.
pub type PortTable = BTreeMap<u16, Leases>;

/// [`PortTable`] from what the DHCP process is told; entries with a bad MAC are left out.
pub fn port_table(entries: &[PortLease]) -> PortTable {
    let mut out = PortTable::new();
    for e in entries {
        if let Some(mac) = parse_mac(&e.mac) {
            out.entry(e.tag).or_default().insert(mac, e.lease.clone());
        }
    }
    out
}

const VLAN: u16 = 0x8100;
const IPV4: u16 = 0x0800;
const UDP: u8 = 17;
/// The largest frame read: a tagged Ethernet frame of 1500 bytes of payload.
pub const MAX_FRAME: usize = 1522;

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

/// The Internet checksum of `data`, with `sum` already added.
fn checksum(sum: u32, data: &[u8]) -> u16 {
    let mut sum = sum;
    for c in data.chunks(2) {
        sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The reply to `frame`, read on the DHCP port: an 802.1Q-tagged Ethernet frame carrying IPv4 and
/// UDP from port 68 to 67. The reply carries the same tag, comes from `server_mac`, and goes to the
/// client's MAC. Anything else gets nothing.
pub fn on_frame(table: &PortTable, server_mac: [u8; 6], frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() > MAX_FRAME || be16(frame, 12)? != VLAN || be16(frame, 16)? != IPV4 {
        return None;
    }
    let tag = be16(frame, 14)? & 0x0fff;
    let src: [u8; 6] = frame.get(6..12)?.try_into().ok()?;
    let ip = frame.get(18..)?;
    let ihl = usize::from(ip.first()? & 0x0f) * 4;
    let total = usize::from(be16(ip, 2)?);
    // IPv4, no options we do not skip, not a fragment.
    if ip[0] >> 4 != 4 || ihl < 20 || total < ihl + 8 || total > ip.len() || *ip.get(9)? != UDP {
        return None;
    }
    if be16(ip, 6)? & 0x3fff != 0 {
        return None;
    }
    let udp = &ip[ihl..total];
    let len = usize::from(be16(udp, 4)?);
    if be16(udp, 0)? != 68 || be16(udp, 2)? != 67 || len < 8 || len > udp.len() {
        return None;
    }
    let (msg, to) = reply(table.get(&tag)?, src, &udp[8..len])?;
    let from = match msg.opts().get(OptionCode::ServerIdentifier) {
        Some(DhcpOption::ServerIdentifier(s)) => *s,
        _ => return None,
    };
    let payload = msg.to_vec().ok()?;
    Some(frame_of(tag, server_mac, src, from, to, &payload))
}

/// [`on_frame`], with a panic in the DHCP decoder (on bytes a guest chose) counted as no answer.
/// dhcproto has `debug_assert!`s on option lengths, and a subtraction that can go below zero.
pub fn on_frame_guarded(table: &PortTable, server_mac: [u8; 6], frame: &[u8]) -> Option<Vec<u8>> {
    std::panic::catch_unwind(|| on_frame(table, server_mac, frame)).unwrap_or_else(|_| {
        tracing::debug!("a frame the decoder could not take: dropped");
        None
    })
}

/// A tagged Ethernet frame with IPv4 and UDP from port 67 to 68.
fn frame_of(
    tag: u16,
    from_mac: [u8; 6],
    to_mac: [u8; 6],
    from: Ipv4Addr,
    to: Ipv4Addr,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let ip_len = 20 + udp_len;
    let mut f = Vec::with_capacity(18 + ip_len);
    f.extend_from_slice(&to_mac);
    f.extend_from_slice(&from_mac);
    f.extend_from_slice(&VLAN.to_be_bytes());
    f.extend_from_slice(&(tag & 0x0fff).to_be_bytes());
    f.extend_from_slice(&IPV4.to_be_bytes());
    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = UDP;
    ip[12..16].copy_from_slice(&from.octets());
    ip[16..20].copy_from_slice(&to.octets());
    let sum = checksum(0, &ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    f.extend_from_slice(&ip);
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&67u16.to_be_bytes());
    udp.extend_from_slice(&68u16.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    // Pseudo-header: addresses, protocol, length.
    let mut pseudo = 0u32;
    for o in [from.octets(), to.octets()] {
        pseudo += u32::from(u16::from_be_bytes([o[0], o[1]]))
            + u32::from(u16::from_be_bytes([o[2], o[3]]));
    }
    pseudo += u32::from(UDP) + udp_len as u32;
    let sum = match checksum(pseudo, &udp) {
        0 => 0xffff,
        s => s,
    };
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    f.extend_from_slice(&udp);
    f
}

/// Answers DHCP on the tap `tap` (made by the agent, owned by this process's user) from the
/// leases in `table` (JSON of [`PortLease`]s, written by the agent), read again when it changes.
/// Runs until the tap fails.
pub async fn serve(tap: &str, table: &std::path::Path) -> std::io::Result<()> {
    // This process only serves DHCP: a panic is a frame dropped (see on_frame_guarded), not a
    // message per frame a guest sends.
    std::panic::set_hook(Box::new(|_| {}));
    let tun = tokio_tun::Tun::builder().name(tap).tap().build_one()?;
    let mac = tun.mac_address()?;
    let mut leases = PortTable::new();
    let mut seen = None;
    let mut buf = vec![0u8; MAX_FRAME + 1];
    loop {
        let n = tun.recv(&mut buf).await?.payload().len();
        // The agent writes a new file and renames it: a new inode, even within one clock tick.
        let modified = std::fs::metadata(table).ok().map(|m| {
            use std::os::unix::fs::MetadataExt;
            (m.modified().ok(), m.ino(), m.len())
        });
        if modified != seen {
            seen = modified;
            leases =
                match std::fs::read(table).map(|b| serde_json::from_slice::<Vec<PortLease>>(&b)) {
                    Ok(Ok(e)) => port_table(&e),
                    Ok(Err(e)) => {
                        tracing::error!(error = %e, "undecodable lease table: answering no one");
                        PortTable::new()
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "no lease table yet");
                        PortTable::new()
                    }
                };
        }
        if let Some(reply) = on_frame_guarded(&leases, mac, &buf[..n])
            && let Err(e) = tun.send(reply.as_slice()).await
        {
            tracing::warn!(error = %e, "cannot send a DHCP reply");
        }
    }
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

    fn reply_msg(b: &[u8]) -> Message {
        Message::from_bytes(b).unwrap()
    }

    #[test]
    fn answers_known_macs_only() {
        let t: Leases = [(MAC, lease())].into();

        let offer =
            reply_msg(&answer(&t, MAC, &request(MessageType::Discover, &MAC, &[])).unwrap());
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
                [2, 9, 9, 9, 9, 9],
                &request(MessageType::Discover, &[2, 9, 9, 9, 9, 9], &[])
            )
            .is_none()
        );
        assert!(
            answer(
                &Leases::new(),
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
        assert!(answer(&t, MAC, &relayed.to_vec().unwrap()).is_none());
        // Another MAC than the frame's: never another instance's lease.
        assert!(
            answer(
                &t,
                [2, 9, 9, 9, 9, 9],
                &request(MessageType::Discover, &MAC, &[])
            )
            .is_none()
        );
        // Not DHCP at all.
        assert!(answer(&t, MAC, b"\x01\x02garbage").is_none());
        assert!(answer(&t, MAC, &[]).is_none());
    }

    #[test]
    fn requests() {
        let t: Leases = [(MAC, lease())].into();
        let ask = |extra: &[DhcpOption]| {
            answer(&t, MAC, &request(MessageType::Request, &MAC, extra)).map(|b| reply_msg(&b))
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
        assert!(answer(&t, MAC, &request(MessageType::Release, &MAC, &[])).is_none());
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
        assert_eq!(t.values().map(Leases::len).sum::<usize>(), 2, "{t:?}");
        let dns = vec![Ipv4Addr::new(203, 0, 113, 53)];
        assert_eq!(
            t[&lan][&[2, 0, 0, 0, 0, 1]],
            Lease {
                ip: Ipv4Addr::new(10, 9, 0, 2),
                mask: Ipv4Addr::new(255, 255, 255, 248),
                router: Ipv4Addr::new(10, 9, 0, 1),
                dns: dns.clone(),
                mtu: PRIVATE_MTU,
            }
        );
        assert_eq!(
            t[&wan][&[2, 0, 0, 0, 0, 2]],
            Lease {
                ip: Ipv4Addr::new(203, 0, 113, 10),
                mask: Ipv4Addr::new(255, 255, 255, 0),
                router: Ipv4Addr::new(203, 0, 113, 1),
                dns,
                mtu: 9000,
            }
        );
    }

    /// A tagged DHCP request frame from `mac`.
    fn request_frame(tag: u16, mac: [u8; 6], dhcp: &[u8]) -> Vec<u8> {
        let mut f = frame_of(
            tag,
            mac,
            [0xff; 6],
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            dhcp,
        );
        // frame_of makes server replies: turn the ports around.
        let udp = 18 + 20;
        f[udp..udp + 2].copy_from_slice(&68u16.to_be_bytes());
        f[udp + 2..udp + 4].copy_from_slice(&67u16.to_be_bytes());
        f
    }

    #[test]
    fn frames() {
        let server = [2, 0, 0, 0, 0, 0xfe];
        let t: PortTable = [(7, [(MAC, lease())].into())].into();
        let disc = request(MessageType::Discover, &MAC, &[]);
        let out = on_frame(&t, server, &request_frame(7, MAC, &disc)).unwrap();
        // To the client's MAC, from ours, with the same tag.
        assert_eq!(&out[0..6], &MAC);
        assert_eq!(&out[6..12], &server);
        assert_eq!(be16(&out, 12), Some(VLAN));
        assert_eq!(be16(&out, 14), Some(7));
        let ip = &out[18..];
        assert_eq!(checksum(0, &ip[..20]), 0, "IPv4 header checksum");
        assert_eq!(&ip[12..16], &lease().router.octets());
        // Not broadcast and no address yet: to the address offered.
        assert_eq!(&ip[16..20], &lease().ip.octets());
        let udp = &ip[20..];
        assert_eq!((be16(udp, 0), be16(udp, 2)), (Some(67), Some(68)));
        let offer = reply_msg(&udp[8..]);
        assert_eq!(offer.yiaddr(), lease().ip);

        // Another tag, another MAC in the frame than in the message, not 68 to 67, too long,
        // untagged, cut short: nothing.
        assert!(on_frame(&t, server, &request_frame(8, MAC, &disc)).is_none());
        assert!(on_frame(&t, server, &request_frame(7, [2, 9, 9, 9, 9, 9], &disc)).is_none());
        let mut wrong_port = request_frame(7, MAC, &disc);
        wrong_port[18 + 20 + 3] = 68;
        assert!(on_frame(&t, server, &wrong_port).is_none());
        let mut long = request_frame(7, MAC, &disc);
        long.resize(MAX_FRAME + 1, 0);
        assert!(on_frame(&t, server, &long).is_none());
        let mut untagged = request_frame(7, MAC, &disc);
        untagged.drain(12..16);
        assert!(on_frame(&t, server, &untagged).is_none());
        let f = request_frame(7, MAC, &disc);
        for cut in [0, 13, 17, 30, 45, f.len() - 1] {
            assert!(on_frame(&t, server, &f[..cut]).is_none(), "{cut}");
        }
        // A refusal is broadcast.
        let other = request(
            MessageType::Request,
            &MAC,
            &[DhcpOption::RequestedIpAddress(Ipv4Addr::new(10, 9, 0, 5))],
        );
        let nak = on_frame(&t, server, &request_frame(7, MAC, &other)).unwrap();
        assert_eq!(&nak[18 + 16..18 + 20], &[255; 4]);
    }

    /// Hostile frames: nothing panics, whatever the bytes.
    #[test]
    fn random_frames() {
        let t: PortTable = [(7, [(MAC, lease())].into())].into();
        let good = request_frame(7, MAC, &request(MessageType::Discover, &MAC, &[]));
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20_000 {
            let mut f = good.clone();
            // A few bytes changed, or cut short, or all random.
            match next() % 3 {
                0 => {
                    for _ in 0..(next() % 8) {
                        let i = (next() as usize) % f.len();
                        f[i] = next() as u8;
                    }
                }
                1 => f.truncate((next() as usize) % f.len()),
                _ => f = (0..(next() % 600)).map(|_| next() as u8).collect(),
            }
            let _ = on_frame_guarded(&t, [2, 0, 0, 0, 0, 0xfe], &f);
        }
    }

    #[test]
    fn port_tables() {
        let e = vec![
            PortLease {
                tag: 3,
                mac: "02:01:02:03:04:05".into(),
                lease: lease(),
            },
            PortLease {
                tag: 3,
                mac: "bad".into(),
                lease: lease(),
            },
        ];
        let t = port_table(&e);
        assert_eq!(t[&3].len(), 1);
        let json = serde_json::to_vec(&e).unwrap();
        assert_eq!(serde_json::from_slice::<Vec<PortLease>>(&json).unwrap(), e);
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
