//! Interfaces get their MAC and address from the controller, and give the address back.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use common::{Env, env, n, node_cfg};
use serde::Serialize;
use serde_json::json;
use torngat_api::Scope;
use torngat_api::compute::Instance;
use torngat_api::network::{Network, NodeNetworks, ProviderNetwork};
use torngat_controller::keys;
use torngat_store::{Key, Precondition};
use uuid::Uuid;

async fn put(e: &Env, key: Key, v: &impl Serialize) {
    e.store
        .put(key, serde_json::to_vec(v).unwrap(), Precondition::None)
        .await
        .unwrap();
}

async fn read<T: serde::de::DeserializeOwned>(e: &Env, key: Key) -> Option<T> {
    let v = e.store.get(&key).await.unwrap()?;
    Some(serde_json::from_slice(&v.value).unwrap())
}

async fn until<F: Future<Output = bool>>(what: &str, mut f: impl FnMut() -> F) {
    let end = Instant::now() + Duration::from_secs(20);
    while !f().await {
        assert!(Instant::now() < end, "never: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn object(name: &str, scope: &Scope, spec: serde_json::Value) -> serde_json::Value {
    json!({"metadata": {"name": name, "scope": scope, "uid": Uuid::now_v7(), "generation": 1},
           "spec": spec, "status": {}})
}

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interfaces_get_addresses() {
    let e = env(Vec::new(), false).await;
    let p = Scope::Project {
        org: n("acme"),
        project: n("web"),
    };
    let private = object("lan", &p, json!({"private": {"cidr": "10.9.0.0/29"}}));
    put(&e, keys::network(&p, &n("lan")).unwrap(), &private).await;
    let public = object(
        "public",
        &Scope::Platform,
        json!({"physnet": "physnet1", "tenants": true,
               "pool": {"scope": "external", "cidr": "203.0.113.0/24", "gateway": "203.0.113.1",
                        "first": "203.0.113.10", "last": "203.0.113.11"}}),
    );
    put(&e, keys::provider_network(&n("public")).unwrap(), &public).await;
    let wan = object("wan", &p, json!({"provider": {"network": "public"}}));
    put(&e, keys::network(&p, &n("wan")).unwrap(), &wan).await;

    let vm = |name: &str, nets: &[&str]| {
        let nets: Vec<_> = nets.iter().map(|n| json!({"network": n})).collect();
        object(
            name,
            &p,
            json!({"vcpus": 1, "memory_mib": 64, "power_state": "stopped", "interfaces": nets}),
        )
    };
    let inst = |name: &'static str| {
        let key = keys::instance(&p, &n(name)).unwrap();
        let e = &e;
        async move { read::<Instance>(e, key).await.unwrap() }
    };
    put(
        &e,
        keys::instance(&p, &n("a")).unwrap(),
        &vm("a", &["lan", "wan"]),
    )
    .await;
    until("a's addresses", || async {
        inst("a").await.status.interfaces.len() == 2
    })
    .await;
    let a = inst("a").await;
    let got: Vec<_> = a.status.interfaces.iter().map(|i| i.ip).collect();
    // The private network's first address is its router's.
    assert_eq!(got, vec![Some(ip("10.9.0.2")), Some(ip("203.0.113.10"))]);
    assert_ne!(a.status.interfaces[0].mac, a.status.interfaces[1].mac);
    let lan: Network = read(&e, keys::network(&p, &n("lan")).unwrap())
        .await
        .unwrap();
    assert_eq!(
        lan.status.allocations.get(&ip("10.9.0.2")),
        Some(&a.metadata.uid)
    );

    put(&e, keys::instance(&p, &n("b")).unwrap(), &vm("b", &["wan"])).await;
    until("b's address", || async {
        !inst("b").await.status.interfaces.is_empty()
    })
    .await;
    assert_eq!(
        inst("b").await.status.interfaces[0].ip,
        Some(ip("203.0.113.11"))
    );
    // The pool is used up.
    put(&e, keys::instance(&p, &n("c")).unwrap(), &vm("c", &["wan"])).await;
    until("c told", || async {
        inst("c").await.status.message.as_deref() == Some("network wan has no free address")
    })
    .await;
    put(
        &e,
        keys::instance(&p, &n("d")).unwrap(),
        &vm("d", &["nope"]),
    )
    .await;
    until("d told", || async {
        inst("d").await.status.message.as_deref() == Some("there is no network nope")
    })
    .await;

    // a leaves wan: its address goes to c.
    let mut a2 = inst("a").await;
    a2.spec.interfaces.truncate(1);
    put(&e, keys::instance(&p, &n("a")).unwrap(), &a2).await;
    until("c's address", || async {
        inst("c").await.status.interfaces.first().and_then(|i| i.ip) == Some(ip("203.0.113.10"))
    })
    .await;
    // b is deleted: its address is free.
    e.store
        .delete(keys::instance(&p, &n("b")).unwrap(), Precondition::None)
        .await
        .unwrap();
    until("b's address freed", || async {
        let pn: ProviderNetwork = read(&e, keys::provider_network(&n("public")).unwrap())
            .await
            .unwrap();
        !pn.status.allocations.contains_key(&ip("203.0.113.11"))
    })
    .await;
    assert_eq!(inst("a").await.status.interfaces.len(), 1);

    // Two networks of the project on one provider network: refused, not one address twice.
    let wan2 = object("wan2", &p, json!({"provider": {"network": "public"}}));
    put(&e, keys::network(&p, &n("wan2")).unwrap(), &wan2).await;
    put(
        &e,
        keys::instance(&p, &n("f")).unwrap(),
        &vm("f", &["wan", "wan2"]),
    )
    .await;
    until("f told", || async {
        inst("f").await.status.message.as_deref()
            == Some("network wan2 is on the same provider network as another interface's")
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nodes_get_their_networks() {
    let e = env(Vec::new(), false).await;
    let p = Scope::Project {
        org: n("acme"),
        project: n("web"),
    };
    let pool = |net: &str| {
        json!({"scope": "external", "cidr": format!("{net}.0/24"), "gateway": format!("{net}.1"),
               "first": format!("{net}.10"), "last": format!("{net}.20")})
    };
    for (name, spec) in [
        (
            "public",
            json!({"physnet": "physnet1", "tenants": true, "pool": pool("203.0.113")}),
        ),
        (
            "out",
            json!({"physnet": "physnet1", "vlan": 7, "egress": true, "pool": pool("198.51.100")}),
        ),
        (
            "other",
            json!({"physnet": "physnet1", "vlan": 8, "pool": pool("192.0.2")}),
        ),
    ] {
        let o = object(name, &Scope::Platform, spec);
        put(&e, keys::provider_network(&n(name)).unwrap(), &o).await;
    }
    for (name, node) in [("n1-eno2", "n1"), ("n2-eno2", "n2")] {
        let o = object(
            name,
            &Scope::Platform,
            json!({"node": node, "uplink": "eno2", "roles": ["provider"], "physnet": "physnet1"}),
        );
        put(&e, keys::host_network(&n(name)).unwrap(), &o).await;
    }
    for (name, spec) in [
        ("lan", json!({"private": {"cidr": "10.9.0.0/29"}})),
        ("wan", json!({"provider": {"network": "public"}})),
        ("unused", json!({"private": {"cidr": "10.8.0.0/29"}})),
    ] {
        put(
            &e,
            keys::network(&p, &n(name)).unwrap(),
            &object(name, &p, spec),
        )
        .await;
    }
    let mut vm = object(
        "a",
        &p,
        json!({"vcpus": 1, "memory_mib": 64, "power_state": "stopped",
               "interfaces": [{"network": "lan"}, {"network": "wan"}]}),
    );
    vm["status"] = json!({"node": "n1"});
    put(&e, keys::instance(&p, &n("a")).unwrap(), &vm).await;

    let mut c = torngat_agent::connect(&node_cfg(&e, "n1", "active").await)
        .await
        .unwrap();
    let mut stream = c
        .assignments(torngat_proto::v1::AssignmentsRequest {})
        .await
        .unwrap()
        .into_inner();
    let set = stream.message().await.unwrap().unwrap();
    assert!(!set.networks_unavailable);
    let got: NodeNetworks = serde_json::from_slice(&set.networks_json).unwrap();
    let names = |v: Vec<String>| {
        let mut v = v;
        v.sort();
        v
    };
    assert_eq!(
        names(
            got.networks
                .iter()
                .map(|x| x.metadata.name.to_string())
                .collect()
        ),
        ["lan", "wan"]
    );
    assert_eq!(
        names(
            got.provider_networks
                .iter()
                .map(|x| x.metadata.name.to_string())
                .collect()
        ),
        ["out", "public"]
    );
    assert_eq!(
        names(
            got.host_networks
                .iter()
                .map(|x| x.metadata.name.to_string())
                .collect()
        ),
        ["n1-eno2"]
    );
}
