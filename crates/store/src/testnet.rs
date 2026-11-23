//! In-process network for multi-node tests, with link partitions.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};

use openraft::alias::{SnapshotOf, VoteOf};
use openraft::errors::{ReplicationClosed, StreamingError, Unreachable};
use openraft::network::RPCOption;
use openraft::network::v2::RaftNetworkV2;
use openraft::raft::{
    AppendEntriesRequest, AppendResult, SnapshotResponse, VoteRequest, VoteResponse,
};
use openraft::{OptionalSend, RaftNetworkFactory};

use crate::types::{Node, NodeId, Raft, SnapshotData, TypeConfig};

type RpcError = openraft::errors::RPCError<TypeConfig>;

#[derive(Default)]
struct Inner {
    nodes: BTreeMap<NodeId, Raft>,
    /// Directed links that drop every message.
    cut: BTreeSet<(NodeId, NodeId)>,
}

/// Shared routing table. Clone it into every node's network factory.
#[derive(Clone, Default)]
pub struct TestNet(Arc<Mutex<Inner>>);

impl std::fmt::Debug for TestNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestNet")
    }
}

impl TestNet {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn register(&self, id: NodeId, raft: Raft) {
        self.lock().nodes.insert(id, raft);
    }

    pub fn unregister(&self, id: NodeId) {
        self.lock().nodes.remove(&id);
    }

    /// Cuts both directions between `node` and every other node.
    pub fn isolate(&self, node: NodeId) {
        let mut g = self.lock();
        let others: Vec<NodeId> = g.nodes.keys().copied().filter(|n| *n != node).collect();
        for o in others {
            g.cut.insert((node, o));
            g.cut.insert((o, node));
        }
    }

    pub fn heal(&self) {
        self.lock().cut.clear();
    }

    /// A factory for node `from`.
    pub fn factory(&self, from: NodeId) -> NetFactory {
        NetFactory {
            net: self.clone(),
            from,
        }
    }

    fn target(&self, from: NodeId, to: NodeId) -> Result<Raft, Unreachable<TypeConfig>> {
        let g = self.lock();
        if g.cut.contains(&(from, to)) {
            return Err(Unreachable::new(&std::io::Error::other("partitioned")));
        }
        g.nodes
            .get(&to)
            .cloned()
            .ok_or_else(|| Unreachable::new(&std::io::Error::other("node down")))
    }
}

#[derive(Debug, Clone)]
pub struct NetFactory {
    net: TestNet,
    from: NodeId,
}

impl RaftNetworkFactory<TypeConfig> for NetFactory {
    type Network = Conn;

    async fn new_client(&mut self, target: NodeId, _node: &Node) -> Conn {
        Conn {
            net: self.net.clone(),
            from: self.from,
            to: target,
        }
    }
}

#[derive(Debug)]
pub struct Conn {
    net: TestNet,
    from: NodeId,
    to: NodeId,
}

fn unreachable(e: impl std::error::Error + 'static) -> RpcError {
    RpcError::Unreachable(Unreachable::new(&e))
}

impl RaftNetworkV2<TypeConfig> for Conn {
    type SnapshotData = SnapshotData;

    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _o: RPCOption,
    ) -> Result<AppendResult<TypeConfig>, RpcError> {
        let raft = self.net.target(self.from, self.to)?;
        raft.append_entries(rpc).await.map_err(unreachable)
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<TypeConfig>,
        _o: RPCOption,
    ) -> Result<VoteResponse<TypeConfig>, RpcError> {
        let raft = self.net.target(self.from, self.to)?;
        raft.vote(rpc).await.map_err(unreachable)
    }

    async fn pre_vote(
        &mut self,
        rpc: VoteRequest<TypeConfig>,
        _o: RPCOption,
    ) -> Result<VoteResponse<TypeConfig>, RpcError> {
        let raft = self.net.target(self.from, self.to)?;
        raft.pre_vote(rpc).await.map_err(unreachable)
    }

    async fn full_snapshot(
        &mut self,
        vote: VoteOf<TypeConfig>,
        snapshot: SnapshotOf<TypeConfig, SnapshotData>,
        _cancel: impl Future<Output = ReplicationClosed> + OptionalSend + 'static,
        _o: RPCOption,
    ) -> Result<SnapshotResponse<TypeConfig>, StreamingError<TypeConfig>> {
        let raft = self.net.target(self.from, self.to)?;
        raft.install_full_snapshot(vote, snapshot)
            .await
            .map_err(|e| StreamingError::from(Unreachable::new(&e)))
    }
}
