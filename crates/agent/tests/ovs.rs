//! The Open vSwitch datapath on a real bridge, with network namespaces as guests. Needs root,
//! Open vSwitch, iproute2 and dhcpcd:
//!
//! ```sh
//! sudo env PATH=/usr/sbin:/usr/bin:/sbin:/bin [TORNGATD=/path/to/torngatd] <test binary> --ignored --test-threads=1
//! ```
//!
//! With `TORNGATD`, the DHCP process runs as the agent runs it (a sandboxed unit, as the
//! `torngat-dhcp` user); without, in this test.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use serde_json::json;
use torngat_agent::net::{self, Ovs, System};
use torngat_api::compute::Instance;
use torngat_api::network::{NodeNetworks, mac_of};
use torngat_api::{Name, Scope};
use uuid::Uuid;

fn sh(cmd: &str) -> Result<String, String> {
    let out = Command::new("sh").args(["-c", cmd]).output().unwrap();
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!("{cmd}: {}", String::from_utf8_lossy(&out.stderr)))
    }
}

fn ok(cmd: &str) -> String {
    sh(cmd).unwrap()
}

fn object<T: serde::de::DeserializeOwned>(
    name: &str,
    scope: &Scope,
    uid: Uuid,
    spec: serde_json::Value,
    status: serde_json::Value,
) -> T {
    serde_json::from_value(json!({
        "metadata": {"name": name, "scope": scope, "uid": uid, "generation": 1},
        "spec": spec, "status": status}))
    .unwrap()
}

/// A guest: a namespace with `eth0`, whose peer on the host is the instance's port.
struct Guest {
    ns: String,
    uid: Uuid,
}

impl Guest {
    fn new(ns: &str) -> Self {
        let uid = Uuid::now_v7();
        let port = net::port_name(uid, 0);
        let _ = sh(&format!("ip netns del {ns}"));
        ok(&format!("ip netns add {ns}"));
        ok(&format!(
            "ip link add {port} type veth peer name eth0 netns {ns}"
        ));
        ok(&format!(
            "ip -n {ns} link set eth0 address {} up && ip -n {ns} link set lo up && ip link set {port} up",
            mac_of(uid, 0)
        ));
        Guest { ns: ns.into(), uid }
    }

    fn run(&self, cmd: &str) -> Result<String, String> {
        sh(&format!("ip netns exec {} {cmd}", self.ns))
    }

    /// The address DHCP offers, without configuring it.
    fn dhcp(&self) -> Option<Ipv4Addr> {
        let out = self.run("dhcpcd -4 -1 -t 15 -T eth0").ok()?;
        out.lines()
            .find_map(|l| l.strip_prefix("new_ip_address="))
            .and_then(|v| v.trim_matches('\'').parse().ok())
    }

    fn set(&self, addr: &str) {
        self.run(&format!("ip addr add {addr} dev eth0")).unwrap();
    }

    fn pings(&self, to: &str, from: Option<&str>) -> bool {
        let src = from.map(|f| format!("-I {f}")).unwrap_or_default();
        self.run(&format!("ping -c 1 -W 2 {src} {to}")).is_ok()
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        let _ = sh(&format!("ip netns del {}", self.ns));
        let _ = sh(&format!(
            "ovs-vsctl --if-exists del-port br-int {}",
            net::port_name(self.uid, 0)
        ));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root, Open vSwitch, iproute2 and dhcpcd"]
async fn guests_get_their_address_and_only_it() {
    if sh(&format!("id -u {}", net::DHCP_USER)).is_err() {
        ok(&format!(
            "useradd --system --no-create-home --shell /usr/sbin/nologin {}",
            net::DHCP_USER
        ));
    }
    // One left by an earlier run would serve other leases.
    let _ = sh(&format!("systemctl stop {}", net::DHCP_UNIT));
    // Not under /tmp: the DHCP unit has its own.
    let dir = tempfile::TempDir::new_in("/run").unwrap();
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let leases = dir.path().join("leases.json");
    let exe = std::env::var_os("TORNGATD").map(PathBuf::from);
    let in_test = exe.is_none();
    let mut ovs = Ovs::new(
        System {
            leases: leases.clone(),
        },
        exe,
    );

    let p = Scope::Project {
        org: Name::new("acme").unwrap(),
        project: Name::new("web").unwrap(),
    };
    let (lan, other) = (Uuid::now_v7(), Uuid::now_v7());
    let nets = NodeNetworks {
        host_networks: vec![],
        provider_networks: vec![],
        networks: vec![
            object(
                "lan",
                &p,
                lan,
                json!({"private": {"cidr": "10.9.0.0/24"}}),
                json!({}),
            ),
            // Same range: two projects can have it; only the tags keep them apart.
            object(
                "other",
                &p,
                other,
                json!({"private": {"cidr": "10.9.0.0/24"}}),
                json!({}),
            ),
        ],
    };
    let (a, b, c) = (Guest::new("tg-a"), Guest::new("tg-b"), Guest::new("tg-c"));
    let inst = |g: &Guest, name: &str, net: Uuid, ip: &str| -> Instance {
        object(
            name,
            &p,
            g.uid,
            json!({"vcpus": 1, "memory_mib": 64}),
            json!({"interfaces": [{"network": name, "network_uid": net, "mac": mac_of(g.uid, 0), "ip": ip}]}),
        )
    };
    let instances = vec![
        inst(&a, "a", lan, "10.9.0.2"),
        inst(&b, "b", lan, "10.9.0.3"),
        inst(&c, "c", other, "10.9.0.4"),
    ];
    ovs.reconcile(&instances, &nets).await.unwrap();
    let server = in_test.then(|| {
        let leases = leases.clone();
        tokio::spawn(async move { torngat_agent::dhcp::serve(net::DHCP_PORT, &leases).await })
    });
    if !in_test {
        // Its user, and its sandbox.
        let user = ok(&format!(
            "systemctl show -p User --value {}",
            net::DHCP_UNIT
        ));
        assert_eq!(user.trim(), net::DHCP_USER);
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Each gets its own address.
    assert_eq!(a.dhcp(), Some(Ipv4Addr::new(10, 9, 0, 2)));
    assert_eq!(b.dhcp(), Some(Ipv4Addr::new(10, 9, 0, 3)));
    assert_eq!(c.dhcp(), Some(Ipv4Addr::new(10, 9, 0, 4)));
    println!("ok: each guest gets its address by DHCP");

    a.set("10.9.0.2/24");
    b.set("10.9.0.3/24");
    c.set("10.9.0.4/24");
    assert!(a.pings("10.9.0.3", None), "a reaches b");
    assert!(
        !a.pings("10.9.0.4", None),
        "a must not reach c, on another network"
    );
    println!("ok: same network reached, another network not");

    // Another address, another MAC: dropped.
    a.set("10.9.0.9/24");
    assert!(!a.pings("10.9.0.3", Some("10.9.0.9")), "spoofed address");
    a.run("ip link set eth0 address 02:99:99:99:99:99").unwrap();
    assert!(!a.pings("10.9.0.3", None), "spoofed MAC");
    a.run(&format!("ip link set eth0 address {}", mac_of(a.uid, 0)))
        .unwrap();
    assert!(a.pings("10.9.0.3", None), "a back to its own");
    println!("ok: spoofed address and MAC dropped");

    // A DHCP server in a guest: its replies never reach the others.
    let flows = ok("ovs-ofctl dump-flows br-int");
    assert!(flows.contains("tp_src=67 actions=drop"), "{flows}");

    // b goes: its port leaves the bridge, a no longer gets answers meant for it.
    drop(b);
    ovs.reconcile(&instances[..1], &nets).await.unwrap();
    let ports = ok("ovs-vsctl list-ports br-int");
    assert!(
        !ports.contains(&net::port_name(instances[1].metadata.uid, 0)),
        "{ports}"
    );
    println!("ok: a removed instance's port is gone");

    if let Some(s) = server {
        s.abort();
    } else {
        let _ = sh(&format!("systemctl stop {}", net::DHCP_UNIT));
    }
    println!("PASS");
}
