//! The node's datapath for instance networks: Open vSwitch, driven by `ovs-vsctl` and `ovs-ofctl`.
//!
//! - One bridge, `br-int`, in secure fail mode: only our flows forward.
//! - Each network on the node gets a VLAN tag on it, chosen here and kept on its ports
//!   (`external_ids:torngat-network`), so a restarted agent finds the same tags.
//! - An instance interface is an access port of its network's tag. Its flows let out only its
//!   own MAC, its own address and ARP for it; DHCP requests go to the DHCP port, whatever their
//!   destination; DHCP replies, IPv6 and everything else from it are dropped. Normal switching,
//!   which keeps tags apart, does the rest.
//! - The DHCP port is a tap that a sandboxed process answers on ([`crate::dhcp::serve`]), with
//!   the leases this writes for it. It is a trunk, out of flooding: it gets only what the flows
//!   send it, and only its replies to an instance's MAC on that instance's tag go back.
//!
//! Instance interfaces are made elsewhere (QEMU's taps); this puts those that exist on the bridge.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;

use torngat_api::compute::Instance;
use torngat_api::network::{NodeNetworks, parse_mac};
use uuid::Uuid;

use crate::dhcp::{self, PortLease};

pub const BRIDGE: &str = "br-int";
pub const DHCP_PORT: &str = "tg-dhcp";
/// The user the DHCP process runs as, and owns its tap.
pub const DHCP_USER: &str = "torngat-dhcp";
pub const DHCP_UNIT: &str = "torngat-dhcp.service";
const NETWORK_KEY: &str = "torngat-network";
const VSCTL: &str = "/usr/bin/ovs-vsctl";
const OFCTL: &str = "/usr/bin/ovs-ofctl";
const IP: &str = "/usr/sbin/ip";
const SYSCTL: &str = "/usr/sbin/sysctl";
/// How long a command may take.
const COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The host interface of an instance's `i`th interface: "tgi", 10 hex digits of the instance uid
/// (its random end, as in its MACs), the index. 14 characters, under IFNAMSIZ.
pub fn port_name(instance: Uuid, i: usize) -> String {
    let b = instance.as_bytes();
    format!(
        "tgi{:02x}{:02x}{:02x}{:02x}{:02x}{:x}",
        b[11],
        b[12],
        b[13],
        b[14],
        b[15],
        i & 0xf
    )
}

/// An instance interface on the bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    pub name: String,
    pub network: Uuid,
    pub tag: u16,
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
}

fn mac_str(m: [u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// All of the bridge's flows, for `ovs-ofctl replace-flows`.
pub fn flows(ports: &[Port]) -> String {
    let mut f = Vec::new();
    for p in ports {
        let (n, mac, ip, tag) = (&p.name, mac_str(p.mac), p.ip, p.tag);
        // Untagged frames only: a tag from the guest never counts.
        let own = format!("in_port={n},vlan_tci=0x0000/0x1fff,dl_src={mac}");
        // Its DHCP requests: to the DHCP port, tagged, wherever they were sent.
        f.push(format!(
            "priority=300,{own},udp,tp_src=68,tp_dst=67,actions=mod_vlan_vid:{tag},output:{DHCP_PORT}"
        ));
        // A DHCP server in the guest, or replies to other guests' clients: never.
        f.push(format!(
            "priority=290,in_port={n},udp,tp_src=67,actions=drop"
        ));
        f.push(format!(
            "priority=290,in_port={n},udp,tp_dst=68,actions=drop"
        ));
        // Its own address and ARP for it.
        f.push(format!(
            "priority=200,{own},arp,arp_spa={ip},arp_sha={mac},actions=NORMAL"
        ));
        f.push(format!("priority=200,{own},ip,nw_src={ip},actions=NORMAL"));
        f.push(format!("priority=100,in_port={n},actions=drop"));
        // DHCP replies for it, from the DHCP port, on its tag.
        f.push(format!(
            "priority=300,in_port={DHCP_PORT},dl_vlan={tag},dl_dst={mac},udp,tp_src=67,tp_dst=68,actions=strip_vlan,output:{n}"
        ));
    }
    f.push(format!("priority=100,in_port={DHCP_PORT},actions=drop"));
    // Anything else, such as a port added before its flows: dropped. Routers and uplinks (later)
    // get their own NORMAL flows.
    f.push("priority=0,actions=drop".into());
    let mut out = f.join("\n");
    out.push('\n');
    out
}

/// Tags for `networks`: the ones they have, the lowest free for the others, never one of
/// `reserved` (tags on ports that are not ours).
pub fn tags(
    networks: &BTreeSet<Uuid>,
    had: &BTreeMap<Uuid, u16>,
    reserved: &BTreeSet<u16>,
) -> BTreeMap<Uuid, u16> {
    let mut out: BTreeMap<Uuid, u16> = had
        .iter()
        .filter(|(n, t)| networks.contains(n) && !reserved.contains(t))
        .map(|(n, t)| (*n, *t))
        .collect();
    let mut used: BTreeSet<u16> = out.values().chain(reserved).copied().collect();
    let mut next = 1u16;
    for n in networks {
        if out.contains_key(n) {
            continue;
        }
        while used.contains(&next) {
            next += 1;
        }
        if next > 4094 {
            tracing::error!(network = %n, "no VLAN tag left on the node's bridge");
            continue;
        }
        out.insert(*n, next);
        used.insert(next);
    }
    out
}

/// A port of the bridge as OVS has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OvsPort {
    pub name: String,
    pub tag: Option<u16>,
    /// The network it was put on by us; `None` for ports that are not ours.
    pub network: Option<Uuid>,
}

/// Parses `ovs-vsctl --format=json --columns=name,tag,external_ids list Port`.
pub fn parse_ports(json: &str) -> Result<Vec<OvsPort>, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let rows = v["data"].as_array().ok_or("no data")?;
    let mut out = Vec::new();
    for r in rows {
        let name = r[0].as_str().ok_or("no name")?.to_owned();
        // An empty optional column is ["set", []].
        let tag = r[1].as_u64().and_then(|t| u16::try_from(t).ok());
        let mut network = None;
        if let Some(pairs) = r[2][1].as_array() {
            for kv in pairs {
                if kv[0].as_str() == Some(NETWORK_KEY) {
                    network = kv[1].as_str().and_then(|s| s.parse().ok());
                }
            }
        }
        out.push(OvsPort { name, tag, network });
    }
    Ok(out)
}

/// What the datapath runs. Faked in tests.
pub trait Host: Send + Sync {
    /// Runs `prog` with `args` (and `stdin`), returning its output.
    fn run(
        &self,
        prog: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> impl Future<Output = Result<String, String>> + Send;
    /// Whether the network interface `name` exists.
    fn has_link(&self, name: &str) -> bool;
    /// Writes the DHCP leases for the DHCP process (atomically).
    fn write_leases(&self, leases: &[u8]) -> std::io::Result<()>;
    /// Where the DHCP process reads them.
    fn leases_path(&self) -> &std::path::Path;
}

/// The real host.
#[derive(Debug, Clone)]
pub struct System {
    /// Where the DHCP process reads its leases.
    pub leases: PathBuf,
}

impl Default for System {
    fn default() -> Self {
        Self {
            leases: PathBuf::from("/run/torngat/dhcp/leases.json"),
        }
    }
}

impl Host for System {
    async fn run(&self, prog: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<String, String> {
        use tokio::io::AsyncWriteExt;
        let mut cmd = tokio::process::Command::new(prog);
        cmd.args(args)
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| format!("{prog}: {e}"))?;
        // A stuck command (a hung ovsdb) must not hold up the agent's session: killed on drop.
        let done = async {
            if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
                pipe.write_all(input)
                    .await
                    .map_err(|e| format!("{prog}: {e}"))?;
            }
            child
                .wait_with_output()
                .await
                .map_err(|e| format!("{prog}: {e}"))
        };
        let out = tokio::time::timeout(COMMAND_TIMEOUT, done)
            .await
            .map_err(|_| format!("{prog}: no answer in {COMMAND_TIMEOUT:?}"))??;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(format!(
                "{prog} {}: {}",
                args.first().copied().unwrap_or_default(),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    fn has_link(&self, name: &str) -> bool {
        std::path::Path::new("/sys/class/net").join(name).exists()
    }

    fn write_leases(&self, leases: &[u8]) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = self.leases.parent().unwrap_or(std::path::Path::new("/"));
        std::fs::create_dir_all(dir)?;
        // Whatever the agent's umask: the DHCP process's user must get in.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
        let tmp = self.leases.with_extension("tmp");
        std::fs::write(&tmp, leases)?;
        // Read by the DHCP process's user: addresses and MACs, nothing secret to the node.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
        std::fs::rename(tmp, &self.leases)
    }

    fn leases_path(&self) -> &std::path::Path {
        &self.leases
    }
}

/// The networks side of the agent: what it does with the node's networks each pass.
pub trait Network: Send {
    fn apply(
        &mut self,
        instances: &[Instance],
        nets: &NodeNetworks,
    ) -> impl Future<Output = ()> + Send;
}

/// No datapath: for tests, and nodes without networks.
#[derive(Debug, Default)]
pub struct Off;

impl Network for Off {
    async fn apply(&mut self, _: &[Instance], _: &NodeNetworks) {}
}

/// The Open vSwitch datapath.
#[derive(Debug)]
pub struct Ovs<H> {
    host: H,
    /// This program, run as the DHCP process; `None`: the caller runs [`dhcp::serve`] itself.
    exe: Option<PathBuf>,
    /// The bridge and DHCP port were set up (again after any error).
    based: bool,
    /// The last leases written: only changes are. Flows are replaced every pass (a diff for
    /// OVS): a restarted switch gets them back.
    leases: Option<Vec<u8>>,
    /// The DHCP process was started by this agent: one left from before (an older binary, other
    /// arguments) is replaced once.
    dhcp_started: bool,
}

impl<H: Host> Ovs<H> {
    pub fn new(host: H, exe: Option<PathBuf>) -> Self {
        Self {
            host,
            exe,
            based: false,
            leases: None,
            dhcp_started: false,
        }
    }

    async fn vsctl(&self, args: &[&str]) -> Result<String, String> {
        self.host.run(VSCTL, args, None).await
    }

    /// The bridge and the DHCP port, as they should be: once, and again after an error.
    async fn base(&mut self) -> Result<(), String> {
        if self.based {
            return Ok(());
        }
        self.vsctl(&[
            "--may-exist",
            "add-br",
            BRIDGE,
            "--",
            "set",
            "Bridge",
            BRIDGE,
            "fail-mode=secure",
        ])
        .await?;
        if !self.host.has_link(DHCP_PORT) {
            self.host
                .run(
                    IP,
                    &[
                        "tuntap", "add", "dev", DHCP_PORT, "mode", "tap", "user", DHCP_USER,
                    ],
                    None,
                )
                .await?;
        }
        // The host's own IPv6 says nothing on it (router solicitations, MLD).
        self.host
            .run(
                SYSCTL,
                &[
                    "-q",
                    "-w",
                    &format!("net.ipv6.conf.{DHCP_PORT}.disable_ipv6=1"),
                ],
                None,
            )
            .await?;
        self.host
            .run(IP, &["link", "set", DHCP_PORT, "up"], None)
            .await?;
        self.vsctl(&[
            "--may-exist",
            "add-port",
            BRIDGE,
            DHCP_PORT,
            "--",
            "set",
            "Port",
            DHCP_PORT,
            "vlan_mode=trunk",
        ])
        .await?;
        // Out of flooding: it gets only what the flows send it.
        self.host
            .run(OFCTL, &["mod-port", BRIDGE, DHCP_PORT, "no-flood"], None)
            .await?;
        self.based = true;
        Ok(())
    }

    /// The DHCP process, started if it is not running.
    async fn dhcp_process(&mut self) -> Result<(), String> {
        let Some(exe) = &self.exe else {
            return Ok(());
        };
        // Restarting after a crash counts as running: starting another would clash.
        let state = self
            .host
            .run(
                crate::qemu::SYSTEMCTL,
                &["show", "-p", "ActiveState", "--value", DHCP_UNIT],
                None,
            )
            .await
            .unwrap_or_default();
        let active = matches!(state.trim(), "active" | "activating" | "reloading");
        if active && self.dhcp_started {
            return Ok(());
        }
        if active {
            self.host
                .run(crate::qemu::SYSTEMCTL, &["stop", DHCP_UNIT], None)
                .await?;
        }
        // A failed unit of the same name would block the new one.
        let _ = self
            .host
            .run(crate::qemu::SYSTEMCTL, &["reset-failed", DHCP_UNIT], None)
            .await;
        // After an upgrade the running binary's path ends in " (deleted)": the new one is there.
        let exe = exe.to_string_lossy();
        let exe = exe.strip_suffix(" (deleted)").unwrap_or(&exe).to_owned();
        let leases = self.host.leases_path().to_owned();
        let mut args: Vec<String> = vec![
            format!("--unit={DHCP_UNIT}"),
            "--collect".into(),
            "--quiet".into(),
            format!("--property=User={DHCP_USER}"),
            "--property=Restart=always".into(),
            "--property=RestartSec=1".into(),
        ];
        for p in dhcp_confinement() {
            args.push(format!("--property={p}"));
        }
        args.extend([
            "--".into(),
            exe,
            "dhcp-server".into(),
            "--tap".into(),
            DHCP_PORT.into(),
            "--leases".into(),
            leases.to_string_lossy().into_owned(),
        ]);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        self.host.run(crate::qemu::SYSTEMD_RUN, &args, None).await?;
        self.dhcp_started = true;
        Ok(())
    }

    /// One pass. Errors are the caller's to log; the next pass tries again.
    pub async fn reconcile(
        &mut self,
        instances: &[Instance],
        nets: &NodeNetworks,
    ) -> Result<(), String> {
        let any = instances.iter().any(|i| !i.status.interfaces.is_empty());
        // A node that never had an instance network sets nothing up.
        if !any && !self.based {
            return Ok(());
        }
        self.base().await?;
        let table = dhcp::table(instances, nets);
        let had = parse_ports(
            &self
                .vsctl(&[
                    "--format=json",
                    "--columns=name,tag,external_ids",
                    "list",
                    "Port",
                ])
                .await?,
        )?;
        let had_tags: BTreeMap<Uuid, u16> = had
            .iter()
            .filter_map(|p| Some((p.network?, p.tag?)))
            .collect();
        let reserved: BTreeSet<u16> = had
            .iter()
            .filter(|p| p.network.is_none())
            .filter_map(|p| p.tag)
            .collect();

        // Interfaces whose host interface exists, with an address on a network the node has.
        let mut ports = Vec::new();
        for inst in instances
            .iter()
            .filter(|i| i.metadata.delete_time.is_none())
        {
            for (i, f) in inst.status.interfaces.iter().enumerate() {
                let (Some(ip), Some(mac)) = (f.ip, parse_mac(&f.mac)) else {
                    continue;
                };
                if !table
                    .get(&f.network_uid)
                    .is_some_and(|l| l.contains_key(&mac))
                {
                    continue;
                }
                let name = port_name(inst.metadata.uid, i);
                if self.host.has_link(&name) {
                    ports.push((name, f.network_uid, mac, ip));
                }
            }
        }
        let networks: BTreeSet<Uuid> = ports.iter().map(|p| p.1).collect();
        let tags = tags(&networks, &had_tags, &reserved);
        let ports: Vec<Port> = ports
            .into_iter()
            .filter_map(|(name, network, mac, ip)| {
                Some(Port {
                    tag: *tags.get(&network)?,
                    name,
                    network,
                    mac,
                    ip,
                })
            })
            .collect();

        // First the flows of the ports that stay as they are, so that nothing of a port that goes
        // or changes is left for a port that gets its number. Then ports go and come (dropped by
        // default until their flows), then all flows.
        let unchanged: Vec<Port> = ports
            .iter()
            .filter(|p| {
                had.iter().any(|h| {
                    h.name == p.name && h.tag == Some(p.tag) && h.network == Some(p.network)
                })
            })
            .cloned()
            .collect();
        self.replace_flows(&unchanged).await?;
        let wanted: BTreeMap<&str, &Port> = ports.iter().map(|p| (p.name.as_str(), p)).collect();
        for p in had.iter().filter(|p| p.network.is_some()) {
            if !wanted.contains_key(p.name.as_str()) {
                self.vsctl(&["--if-exists", "del-port", BRIDGE, &p.name])
                    .await?;
            }
        }
        for p in &ports {
            let current = had.iter().find(|h| h.name == p.name);
            if current.is_some_and(|c| c.tag == Some(p.tag) && c.network == Some(p.network)) {
                continue;
            }
            let tag = format!("tag={}", p.tag);
            let ext = format!("external_ids:{NETWORK_KEY}={}", p.network);
            self.vsctl(&[
                "--may-exist",
                "add-port",
                BRIDGE,
                &p.name,
                "--",
                "set",
                "Port",
                &p.name,
                &tag,
                &ext,
            ])
            .await?;
        }

        // Leases first, then flows: an instance gets DHCP once it can be answered.
        let mut entries = Vec::new();
        for p in &ports {
            if let Some(l) = table.get(&p.network).and_then(|l| l.get(&p.mac)) {
                entries.push(PortLease {
                    tag: p.tag,
                    mac: mac_str(p.mac),
                    lease: l.clone(),
                });
            }
        }
        let leases = serde_json::to_vec(&entries).map_err(|e| e.to_string())?;
        if self.leases.as_ref() != Some(&leases) {
            self.host
                .write_leases(&leases)
                .map_err(|e| format!("DHCP leases: {e}"))?;
            self.leases = Some(leases);
        }
        self.replace_flows(&ports).await?;
        self.dhcp_process().await
    }

    async fn replace_flows(&self, ports: &[Port]) -> Result<(), String> {
        self.host
            .run(
                OFCTL,
                &["--bundle", "replace-flows", BRIDGE, "-"],
                Some(flows(ports).as_bytes()),
            )
            .await
            .map(|_| ())
    }
}

/// The DHCP process's sandbox: the VM units' one, but in the host's network namespace (it
/// attaches to its tap by name) and with an IPv4 socket for the tap's ioctls; no addresses.
pub fn dhcp_confinement() -> Vec<String> {
    let mut p = crate::qemu::sandbox();
    p.extend([
        "IPAddressDeny=any".into(),
        // No unix sockets either: in the host's namespace they would reach abstract ones.
        "RestrictAddressFamilies=AF_INET".into(),
        "RestrictSUIDSGID=yes".into(),
        "LimitCORE=0".into(),
        "UMask=0077".into(),
        "CPUQuota=50%".into(),
        "DevicePolicy=closed".into(),
        "DeviceAllow=/dev/net/tun rw".into(),
        "MemoryMax=64M".into(),
        "TasksMax=16".into(),
        "SystemCallFilter=@system-service".into(),
        "SystemCallErrorNumber=EPERM".into(),
    ]);
    p
}

impl<H: Host> Network for Ovs<H> {
    async fn apply(&mut self, instances: &[Instance], nets: &NodeNetworks) {
        if let Err(e) = self.reconcile(instances, nets).await {
            tracing::warn!(error = %e, "networks not set up");
            // Set again on the next pass.
            self.based = false;
            self.leases = None;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn names() {
        let u: Uuid = "0190a1b2-c3d4-7e5f-8a6b-1c2d3e4f5a6b".parse().unwrap();
        assert_eq!(port_name(u, 3), "tgi2d3e4f5a6b3");
        assert!(port_name(u, 7).len() <= 15);
    }

    #[test]
    fn tag_choice() {
        let (a, b, c) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let had: BTreeMap<Uuid, u16> = [(a, 2), (Uuid::now_v7(), 1)].into();
        let t = tags(&[a, b, c].into(), &had, &[3].into());
        assert_eq!(t[&a], 2);
        // 1 is free again: its network is gone.
        let mut rest = vec![t[&b], t[&c]];
        rest.sort();
        // 3 is a tag of a port that is not ours.
        assert_eq!(rest, [1, 4]);
    }

    #[test]
    fn flow_rules() {
        let p = Port {
            name: "tgi0102030405".into(),
            network: Uuid::now_v7(),
            tag: 5,
            mac: [2, 1, 2, 3, 4, 5],
            ip: Ipv4Addr::new(10, 9, 0, 2),
        };
        let f = flows(&[p]);
        for want in [
            "in_port=tgi0102030405,vlan_tci=0x0000/0x1fff,dl_src=02:01:02:03:04:05,udp,tp_src=68,tp_dst=67,actions=mod_vlan_vid:5,output:tg-dhcp",
            "in_port=tgi0102030405,udp,tp_src=67,actions=drop",
            "in_port=tgi0102030405,udp,tp_dst=68,actions=drop",
            "arp,arp_spa=10.9.0.2,arp_sha=02:01:02:03:04:05,actions=NORMAL",
            "ip,nw_src=10.9.0.2,actions=NORMAL",
            "priority=100,in_port=tgi0102030405,actions=drop",
            "in_port=tg-dhcp,dl_vlan=5,dl_dst=02:01:02:03:04:05,udp,tp_src=67,tp_dst=68,actions=strip_vlan,output:tgi0102030405",
            "priority=100,in_port=tg-dhcp,actions=drop",
            "priority=0,actions=drop",
        ] {
            assert!(f.contains(want), "{want}\n{f}");
        }
    }

    #[test]
    fn ports_from_ovs() {
        let u = Uuid::now_v7();
        let json = format!(
            r#"{{"data":[["br-int",["set",[]],["map",[]]],["tgi0102030405",5,["map",[["{NETWORK_KEY}","{u}"]]]],["eth1",["set",[]],["map",[["other","x"]]]]],"headings":["name","tag","external_ids"]}}"#
        );
        let p = parse_ports(&json).unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].tag, None);
        assert_eq!(
            p[1],
            OvsPort {
                name: "tgi0102030405".into(),
                tag: Some(5),
                network: Some(u)
            }
        );
        assert_eq!(p[2].network, None);
    }
}
