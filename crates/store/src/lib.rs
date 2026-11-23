//! Replicated key-value store for the Torngat control plane.
//!
//! Desired state and durable status live here, replicated by Raft ([openraft]) across 1, 3 or 5
//! voters. The log is a write-ahead log, the state machine a fjall database; both fsync before a
//! write is acknowledged. Every write carries a [`Precondition`] so callers get optimistic
//! concurrency (etags are derived from revisions). Liveness, metrics and other soft state must not
//! be written here.

#![forbid(unsafe_code)]

pub mod key;
pub mod sm;
#[cfg(feature = "test-util")]
pub mod testnet;
pub mod types;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use openraft::error::{ClientWriteError, RaftError};
use openraft::{Config, RaftNetworkFactory, ReadPolicy};
use openraft_log_wal::WalLogStore;
use tokio::sync::broadcast;

pub use key::{Key, KeyError, Prefix};
pub use sm::Event;
pub use types::{
    Command, MAX_VALUE_LEN, Node, NodeId, Precondition, Raft, Response, TypeConfig, Versioned,
};

/// Maximum number of keys returned by one [`Store::list`] call.
pub const MAX_LIST: usize = 1000;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("value larger than {MAX_VALUE_LEN} bytes")]
    ValueTooLarge,
    #[error("precondition failed (current revision: {current:?})")]
    PreconditionFailed { current: Option<u64> },
    #[error("not the leader (leader: {leader:?})")]
    NotLeader { leader: Option<NodeId> },
    #[error("watch fell behind; re-list and watch again")]
    WatchLagged,
    #[error("raft: {0}")]
    Raft(String),
    #[error("storage: {0}")]
    Io(#[from] std::io::Error),
}

impl<E: std::fmt::Display> From<RaftError<TypeConfig, E>> for StoreError {
    fn from(e: RaftError<TypeConfig, E>) -> Self {
        StoreError::Raft(e.to_string())
    }
}

/// Raft timing defaults. Election timeouts are conservative because the state machine fsyncs.
pub fn default_config() -> Config {
    Config {
        cluster_name: "torngat".into(),
        heartbeat_interval: 150,
        election_timeout_min: 600,
        election_timeout_max: 1200,
        ..Default::default()
    }
}

/// A store replica.
#[derive(Clone, Debug)]
pub struct Store {
    raft: Raft,
    sm: sm::StateMachine,
    id: NodeId,
}

impl Store {
    /// Opens (or creates) the replica stored in `dir` and starts its Raft node. The node does
    /// nothing until it is [initialized](Store::initialize) or added to an existing cluster.
    pub async fn open<N>(
        dir: impl AsRef<Path>,
        id: NodeId,
        config: Config,
        network: N,
    ) -> Result<Self, StoreError>
    where
        N: RaftNetworkFactory<TypeConfig>,
        N::Network: openraft::network::NetSnapshot<TypeConfig, SnapshotData = types::SnapshotData>,
    {
        let dir = dir.as_ref();
        let config = Arc::new(
            config
                .validate()
                .map_err(|e| StoreError::Raft(e.to_string()))?,
        );
        let log = WalLogStore::<TypeConfig>::open(dir.join("log").display())?;
        let sm = sm::StateMachine::open(dir.join("sm"))?;
        let raft = openraft::Raft::new(id, config, network, log, sm.clone())
            .await
            .map_err(|e| StoreError::Raft(e.to_string()))?;
        Ok(Self { raft, sm, id })
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    /// Access to Raft for membership changes, metrics and RPC handling.
    pub fn raft(&self) -> &Raft {
        &self.raft
    }

    /// Creates a new cluster whose voters are `members`. Call once, on one node.
    pub async fn initialize(&self, members: BTreeMap<NodeId, Node>) -> Result<(), StoreError> {
        Ok(self.raft.initialize(members).await?)
    }

    async fn write(&self, cmd: Command) -> Result<u64, StoreError> {
        let res = self
            .raft
            .client_write(cmd)
            .await
            .map_err(|e| match e.api_error() {
                Some(ClientWriteError::ForwardToLeader(f)) => StoreError::NotLeader {
                    leader: f.leader_id,
                },
                _ => StoreError::from(e),
            })?;
        match res.data {
            Response::Applied { revision } => Ok(revision),
            Response::PreconditionFailed { current } => {
                Err(StoreError::PreconditionFailed { current })
            }
            Response::None => Err(StoreError::Raft("unexpected empty response".into())),
        }
    }

    /// Writes `value` under `key` if `precondition` holds. Returns the new revision.
    pub async fn put(
        &self,
        key: Key,
        value: Vec<u8>,
        precondition: Precondition,
    ) -> Result<u64, StoreError> {
        if value.len() > MAX_VALUE_LEN {
            return Err(StoreError::ValueTooLarge);
        }
        self.write(Command::Put {
            key,
            value,
            precondition,
        })
        .await
    }

    /// Deletes `key` if `precondition` holds. Deleting a missing key with
    /// [`Precondition::None`] succeeds.
    pub async fn delete(&self, key: Key, precondition: Precondition) -> Result<u64, StoreError> {
        self.write(Command::Delete { key, precondition }).await
    }

    /// Waits until this node may serve a linearizable read (it is the leader and has applied
    /// everything committed before the read began).
    async fn linearize(&self) -> Result<(), StoreError> {
        let read = self
            .raft
            .ensure_linearizable(ReadPolicy::ReadIndex)
            .await
            .map_err(|e| match e.api_error() {
                Some(openraft::error::LinearizableReadError::ForwardToLeader(f)) => {
                    StoreError::NotLeader {
                        leader: f.leader_id,
                    }
                }
                _ => StoreError::from(e),
            })?;
        let _ = read;
        Ok(())
    }

    /// Linearizable read of one key.
    pub async fn get(&self, key: &Key) -> Result<Option<Versioned>, StoreError> {
        self.linearize().await?;
        Ok(self.sm.get(key)?)
    }

    /// Linearizable list of up to `limit` (≤ [`MAX_LIST`]) keys under `prefix`, after
    /// `start_after`.
    pub async fn list(
        &self,
        prefix: &Prefix,
        start_after: Option<&Key>,
        limit: usize,
    ) -> Result<Vec<(Key, Versioned)>, StoreError> {
        self.linearize().await?;
        Ok(self
            .sm
            .list(prefix, start_after, limit.clamp(1, MAX_LIST))?)
    }

    /// Subscribes to changes under `prefix`, as they are applied on *this* replica. To watch
    /// without missing events: subscribe, then list, then ignore events at or below the listed
    /// revisions.
    pub fn watch(&self, prefix: Prefix) -> Watch {
        Watch {
            rx: self.sm.subscribe(),
            prefix,
        }
    }

    pub async fn shutdown(&self) -> Result<(), StoreError> {
        self.raft
            .shutdown()
            .await
            .map_err(|e| StoreError::Raft(e.to_string()))
    }
}

/// A stream of changes under a prefix.
#[derive(Debug)]
pub struct Watch {
    rx: broadcast::Receiver<Event>,
    prefix: Prefix,
}

impl Watch {
    /// Next change under the prefix. Returns [`StoreError::WatchLagged`] if events were dropped
    /// because this watcher was too slow; the caller must re-list.
    pub async fn next(&mut self) -> Result<Event, StoreError> {
        loop {
            match self.rx.recv().await {
                Ok(e) if e.key.has_prefix(&self.prefix) => return Ok(e),
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => return Err(StoreError::WatchLagged),
                Err(broadcast::error::RecvError::Closed) => {
                    return Err(StoreError::Raft("store closed".into()));
                }
            }
        }
    }
}
