//! In-process network for multi-node tests, with link partitions and seeded message faults.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

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

/// SplitMix64: a tiny seedable generator, so fault schedules replay from a seed without a
/// dependency.
#[derive(Debug, Clone)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n` (`n` must be non-zero; the modulo bias is irrelevant here).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

/// Message faults applied to every RPC.
#[derive(Debug)]
struct Faults {
    drop_per_mille: u32,
    max_delay: Duration,
    rng: SplitMix64,
}

/// What the network did to messages so far.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FaultStats {
    /// RPCs dropped by the seeded fault model (not counting cut links).
    pub dropped: u64,
    /// RPCs delayed by a non-zero duration.
    pub delayed: u64,
    /// RPCs refused because the link was cut or the node was down.
    pub refused: u64,
}

#[derive(Default)]
struct Inner {
    nodes: BTreeMap<NodeId, Raft>,
    /// Directed links that drop every message.
    cut: BTreeSet<(NodeId, NodeId)>,
    faults: Option<Faults>,
    stats: FaultStats,
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

    /// Cuts every link between nodes in different `groups` (both directions). Nodes in the same
    /// group, and nodes in no group, keep their links. Adds to existing cuts; see [`Self::heal`].
    pub fn partition(&self, groups: &[&[NodeId]]) {
        let mut g = self.lock();
        for (i, a) in groups.iter().enumerate() {
            for b in &groups[i + 1..] {
                for &x in *a {
                    for &y in *b {
                        g.cut.insert((x, y));
                        g.cut.insert((y, x));
                    }
                }
            }
        }
    }

    pub fn heal(&self) {
        self.lock().cut.clear();
    }

    /// Makes every RPC fail as unreachable with probability `drop_per_mille` / 1000 and
    /// otherwise delays it by a random duration in `[0, max_delay]`. The choices come from a
    /// generator seeded with `seed`, so a seed replays the same sequence of decisions (which RPC
    /// meets each decision still depends on task scheduling). `set_faults(0, Duration::ZERO, _)`
    /// turns the faults off.
    pub fn set_faults(&self, drop_per_mille: u32, max_delay: Duration, seed: u64) {
        let mut g = self.lock();
        g.faults = (drop_per_mille > 0 || !max_delay.is_zero()).then(|| Faults {
            drop_per_mille,
            max_delay,
            rng: SplitMix64::new(seed),
        });
    }

    /// Counters of injected faults since creation.
    pub fn fault_stats(&self) -> FaultStats {
        self.lock().stats
    }

    /// A factory for node `from`.
    pub fn factory(&self, from: NodeId) -> NetFactory {
        NetFactory {
            net: self.clone(),
            from,
        }
    }

    /// Routes one RPC: applies faults (possibly sleeping), then returns the target node.
    async fn target(&self, from: NodeId, to: NodeId) -> Result<Raft, Unreachable<TypeConfig>> {
        let (delay, result) = {
            let mut g = self.lock();
            let mut delay = Duration::ZERO;
            let mut dropped = false;
            if let Some(f) = g.faults.as_mut() {
                dropped = f.rng.below(1000) < u64::from(f.drop_per_mille);
                let max = u64::try_from(f.max_delay.as_micros()).unwrap_or(u64::MAX);
                if !dropped && max > 0 {
                    delay = Duration::from_micros(f.rng.below(max.saturating_add(1)));
                }
            }
            let result = if dropped {
                g.stats.dropped += 1;
                Err("dropped")
            } else if g.cut.contains(&(from, to)) {
                g.stats.refused += 1;
                Err("partitioned")
            } else if let Some(r) = g.nodes.get(&to).cloned() {
                if !delay.is_zero() {
                    g.stats.delayed += 1;
                }
                Ok(r)
            } else {
                g.stats.refused += 1;
                Err("node down")
            };
            (delay, result)
        };
        let raft = result.map_err(|e| Unreachable::new(&std::io::Error::other(e)))?;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        // Links may have been cut, or the node replaced, while the message was in flight; a
        // message already on the wire is still delivered to the node it was addressed to.
        Ok(raft)
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
        let raft = self.net.target(self.from, self.to).await?;
        raft.append_entries(rpc).await.map_err(unreachable)
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<TypeConfig>,
        _o: RPCOption,
    ) -> Result<VoteResponse<TypeConfig>, RpcError> {
        let raft = self.net.target(self.from, self.to).await?;
        raft.vote(rpc).await.map_err(unreachable)
    }

    async fn pre_vote(
        &mut self,
        rpc: VoteRequest<TypeConfig>,
        _o: RPCOption,
    ) -> Result<VoteResponse<TypeConfig>, RpcError> {
        let raft = self.net.target(self.from, self.to).await?;
        raft.pre_vote(rpc).await.map_err(unreachable)
    }

    async fn full_snapshot(
        &mut self,
        vote: VoteOf<TypeConfig>,
        snapshot: SnapshotOf<TypeConfig, SnapshotData>,
        _cancel: impl Future<Output = ReplicationClosed> + OptionalSend + 'static,
        _o: RPCOption,
    ) -> Result<SnapshotResponse<TypeConfig>, StreamingError<TypeConfig>> {
        let raft = self.net.target(self.from, self.to).await?;
        raft.install_full_snapshot(vote, snapshot)
            .await
            .map_err(|e| StreamingError::from(Unreachable::new(&e)))
    }
}
