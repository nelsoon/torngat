//! Helpers shared by the store's integration tests.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use openraft::Config;
use torngat_store::testnet::TestNet;
use torngat_store::{Node, NodeId, Store};

/// Opens replica `id` in `dir` without making it reachable on `net` yet.
pub async fn open_unregistered(net: &TestNet, dir: &Path, id: NodeId, config: Config) -> Store {
    Store::open(dir, id, config, net.factory(id)).await.unwrap()
}

/// Opens replica `id` in `dir` with the default configuration and registers it on `net`.
pub async fn open(net: &TestNet, dir: &Path, id: NodeId) -> Store {
    let s = open_unregistered(net, dir, id, torngat_store::default_config()).await;
    net.register(id, s.raft().clone());
    s
}

pub fn members(ids: &[NodeId]) -> BTreeMap<NodeId, Node> {
    ids.iter().map(|i| (*i, Node::default())).collect()
}

/// The leader that some store in `stores` (other than `exclude`) agrees on, if any.
pub async fn current_leader(stores: &[&Store], exclude: Option<NodeId>) -> Option<NodeId> {
    for s in stores {
        if Some(s.id()) == exclude {
            continue;
        }
        if let Some(l) = s.raft().current_leader().await
            && Some(l) != exclude
            && s.raft().is_leader() == (l == s.id())
        {
            return Some(l);
        }
    }
    None
}

/// Waits (up to 15 s of real time) for a leader other than `exclude`.
pub async fn wait_leader(stores: &[&Store], exclude: Option<NodeId>) -> NodeId {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(l) = current_leader(stores, exclude).await {
            return l;
        }
        assert!(Instant::now() < deadline, "no leader elected");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
