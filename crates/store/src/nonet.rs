//! Network for a single-voter cluster: there is no peer to talk to, so every RPC fails.

use std::future::Future;

use openraft::alias::{SnapshotOf, VoteOf};
use openraft::errors::{ReplicationClosed, StreamingError, Unreachable};
use openraft::network::RPCOption;
use openraft::network::v2::RaftNetworkV2;
use openraft::raft::{
    AppendEntriesRequest, AppendResult, SnapshotResponse, VoteRequest, VoteResponse,
};
use openraft::{OptionalSend, RaftNetworkFactory};

use crate::types::{Node, NodeId, SnapshotData, TypeConfig};

type RpcError = openraft::errors::RPCError<TypeConfig>;

fn none() -> Unreachable<TypeConfig> {
    Unreachable::new(&std::io::Error::other("single-node cluster has no peers"))
}

/// Network factory for a single-node cluster.
#[derive(Debug, Clone, Default)]
pub struct NoNetwork;

impl RaftNetworkFactory<TypeConfig> for NoNetwork {
    type Network = NoNetwork;
    async fn new_client(&mut self, _target: NodeId, _node: &Node) -> NoNetwork {
        NoNetwork
    }
}

impl RaftNetworkV2<TypeConfig> for NoNetwork {
    type SnapshotData = SnapshotData;

    async fn append_entries(
        &mut self,
        _r: AppendEntriesRequest<TypeConfig>,
        _o: RPCOption,
    ) -> Result<AppendResult<TypeConfig>, RpcError> {
        Err(none().into())
    }
    async fn vote(
        &mut self,
        _r: VoteRequest<TypeConfig>,
        _o: RPCOption,
    ) -> Result<VoteResponse<TypeConfig>, RpcError> {
        Err(none().into())
    }
    async fn full_snapshot(
        &mut self,
        _v: VoteOf<TypeConfig>,
        _s: SnapshotOf<TypeConfig, SnapshotData>,
        _c: impl Future<Output = ReplicationClosed> + OptionalSend + 'static,
        _o: RPCOption,
    ) -> Result<SnapshotResponse<TypeConfig>, StreamingError<TypeConfig>> {
        Err(none().into())
    }
}
