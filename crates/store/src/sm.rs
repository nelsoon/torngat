//! Durable state machine on fjall.
//!
//! Adapted from openraft's `examples/sm-fjall` (v0.10.1, MIT OR Apache-2.0). Changes: commands
//! are Torngat's [`Command`]s with preconditions, values are binary, encoding is MessagePack, and
//! applied changes are published on a broadcast channel for watchers.
//!
//! Every `apply()` writes its entries and the applied log id in one atomic batch and syncs it
//! before responding, so an acknowledged write survives a crash.

use std::collections::BTreeMap;
use std::io::{self, Cursor};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode, Readable};
use futures::{Stream, TryStreamExt};
use openraft::alias::{LogIdOf, SnapshotMetaOf, SnapshotOf, StoredMembershipOf};
use openraft::entry::RaftEntry;
use openraft::storage::{EntryResponder, RaftStateMachine};
use openraft::type_config::TypeConfigExt;
use openraft::{EntryPayload, RaftSnapshotBuilder};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::broadcast;

use crate::key::{Key, Prefix};
use crate::types::{Command, Precondition, Response, TypeConfig, Versioned};

const LAST_APPLIED_LOG: &str = "last_applied_log";
const LAST_MEMBERSHIP: &str = "last_membership";
const SNAPSHOT_META: &str = "meta";
const SNAPSHOT_DATA: &str = "data";

/// Capacity of the change channel. A watcher that falls further behind is told it lagged and
/// must re-list.
pub const WATCH_BUFFER: usize = 4096;

/// A change applied to the store, published after it is durable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub key: Key,
    pub revision: u64,
    /// `None` for a delete.
    pub value: Option<Arc<Vec<u8>>>,
}

/// What travels on the change channel.
#[derive(Debug, Clone)]
pub(crate) enum Signal {
    Change(Event),
    /// State was replaced wholesale (snapshot install): watchers must re-list.
    Reset,
    /// The store is shutting down.
    Closed,
}

#[derive(Clone)]
pub struct StateMachine {
    db: Database,
    data: Keyspace,
    meta: Keyspace,
    snapshot: Keyspace,
    snapshot_lock: Arc<Mutex<()>>,
    events: broadcast::Sender<Signal>,
}

impl std::fmt::Debug for StateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateMachine").finish_non_exhaustive()
    }
}

impl StateMachine {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let db = Database::builder(path).open().map_err(io::Error::other)?;
        let ks = |name| {
            db.keyspace(name, KeyspaceCreateOptions::default)
                .map_err(io::Error::other)
        };
        let (data, meta, snapshot) = (ks("sm_data")?, ks("sm_meta")?, ks("sm_snapshot")?);
        let (events, _) = broadcast::channel(WATCH_BUFFER);
        Ok(Self {
            db,
            data,
            meta,
            snapshot,
            snapshot_lock: Arc::default(),
            events,
        })
    }

    /// Reads a key from local state. Callers needing linearizability must first confirm
    /// leadership through Raft (see [`crate::Store::get`]).
    pub fn get(&self, key: &Key) -> io::Result<Option<Versioned>> {
        read(&self.db.snapshot(), &self.data, key.as_str())
    }

    /// Lists keys under `prefix` in key order, starting after `start_after`, at most `limit`.
    pub fn list(
        &self,
        prefix: &Prefix,
        start_after: Option<&Key>,
        limit: usize,
    ) -> io::Result<Vec<(Key, Versioned)>> {
        let mut out = Vec::new();
        if limit == 0 {
            return Ok(out);
        }
        let p = prefix.as_str().as_bytes();
        // Keys under `p` are `p` itself or `p/...`. They all sort below `p0` ('0' follows '/'),
        // so the scan is bounded; seek past `start_after` instead of skipping one by one.
        let mut end = p.to_vec();
        end.push(b'0');
        let start: Vec<u8> = match start_after {
            Some(s) if s.as_str().as_bytes() >= p => {
                let mut v = s.as_str().as_bytes().to_vec();
                v.push(0); // smallest key strictly greater than `start_after`
                v
            }
            _ => p.to_vec(),
        };
        if start >= end {
            return Ok(out);
        }
        let view = self.db.snapshot();
        for item in view.range(&self.data, start..end) {
            let (k, v) = item.into_inner().map_err(io::Error::other)?;
            // Cheap byte check first: `p-x` sorts inside the range but is a different segment.
            let under = k.len() == p.len() || k.get(p.len()) == Some(&b'/');
            if !under {
                continue;
            }
            let key = std::str::from_utf8(&k)
                .ok()
                .and_then(|s| Key::try_from(s.to_owned()).ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid stored key"))?;
            out.push((key, deserialize(&v)?));
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Signal> {
        self.events.subscribe()
    }

    /// Tells every watcher the store is closing.
    pub(crate) fn close(&self) {
        let _ = self.events.send(Signal::Closed);
    }

    fn read_applied<R: Readable>(&self, view: &R) -> io::Result<SnapshotMetaOf<TypeConfig>> {
        Ok(SnapshotMetaOf::<TypeConfig> {
            last_log_id: read(view, &self.meta, LAST_APPLIED_LOG)?,
            last_membership: read(view, &self.meta, LAST_MEMBERSHIP)?.unwrap_or_default(),
        })
    }

    fn encode_data<R: Readable>(&self, view: &R) -> io::Result<Vec<u8>> {
        let mut kvs = BTreeMap::<String, Versioned>::new();
        for item in view.iter(&self.data) {
            let (k, v) = item.into_inner().map_err(io::Error::other)?;
            let k = String::from_utf8(k.to_vec())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            kvs.insert(k, deserialize(&v)?);
        }
        serialize(&kvs)
    }

    fn save_built_snapshot(
        &self,
        meta: &SnapshotMetaOf<TypeConfig>,
        data: &[u8],
    ) -> io::Result<()> {
        let _g = self
            .snapshot_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let current: Option<SnapshotMetaOf<TypeConfig>> =
            read(&self.db.snapshot(), &self.snapshot, SNAPSHOT_META)?;
        if current.is_some_and(|c| c.last_log_id > meta.last_log_id) {
            return Ok(());
        }
        let mut batch = self.db.batch().durability(Some(PersistMode::SyncAll));
        batch.insert(&self.snapshot, SNAPSHOT_META, serialize(meta)?);
        batch.insert(&self.snapshot, SNAPSHOT_DATA, data);
        batch.commit().map_err(io::Error::other)
    }

    fn install(&self, meta: &SnapshotMetaOf<TypeConfig>, data: Vec<u8>) -> io::Result<()> {
        let kvs: BTreeMap<String, Versioned> = deserialize(&data)?;
        // Snapshot data comes from another voter; still refuse keys that would not validate.
        for k in kvs.keys() {
            Key::try_from(k.clone()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }
        let _g = self
            .snapshot_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut batch = self.db.batch().durability(Some(PersistMode::SyncAll));
        for item in self.data.iter() {
            let key = item.key().map_err(io::Error::other)?;
            if !std::str::from_utf8(&key).is_ok_and(|k| kvs.contains_key(k)) {
                batch.remove(&self.data, key);
            }
        }
        for (k, v) in &kvs {
            batch.insert(&self.data, k.as_str(), serialize(v)?);
        }
        match &meta.last_log_id {
            Some(id) => batch.insert(&self.meta, LAST_APPLIED_LOG, serialize(id)?),
            None => batch.remove(&self.meta, LAST_APPLIED_LOG),
        }
        batch.insert(
            &self.meta,
            LAST_MEMBERSHIP,
            serialize(&meta.last_membership)?,
        );
        batch.insert(&self.snapshot, SNAPSHOT_META, serialize(meta)?);
        batch.insert(&self.snapshot, SNAPSHOT_DATA, data);
        batch.commit().map_err(io::Error::other)?;
        // Watchers cannot be told what changed key by key; make them re-list.
        let _ = self.events.send(Signal::Reset);
        Ok(())
    }
}

/// Decides a command against the current revision of its key.
fn decide(precondition: Precondition, current: Option<u64>) -> bool {
    match precondition {
        Precondition::None => true,
        Precondition::Absent => current.is_none(),
        Precondition::Revision(r) => current == Some(r),
    }
}

impl RaftStateMachine<TypeConfig> for StateMachine {
    type SnapshotData = Cursor<Vec<u8>>;
    type SnapshotBuilder = SnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> io::Result<(Option<LogIdOf<TypeConfig>>, StoredMembershipOf<TypeConfig>)> {
        let a = self.read_applied(&self.db.snapshot())?;
        Ok((a.last_log_id, a.last_membership))
    }

    async fn apply<S>(&mut self, mut entries: S) -> io::Result<()>
    where
        S: Stream<Item = io::Result<EntryResponder<TypeConfig>>> + Unpin + openraft::OptionalSend,
    {
        let mut last_applied = None;
        let mut last_membership = None;
        // Writes made earlier in this batch: `None` = deleted. Preconditions must see them.
        let mut updates = BTreeMap::<Key, Option<Versioned>>::new();
        let mut events = Vec::new();
        let mut responses = Vec::new();

        while let Some((entry, responder)) = entries.try_next().await? {
            let log_id = entry.log_id();
            let revision = log_id.index();
            let response = match entry.payload {
                EntryPayload::Blank => Response::None,
                EntryPayload::Membership(m) => {
                    last_membership = Some(StoredMembershipOf::<TypeConfig>::new(Some(log_id), m));
                    Response::None
                }
                EntryPayload::Normal(cmd) => {
                    let key = cmd.key().clone();
                    let current = match updates.get(&key) {
                        Some(v) => v.as_ref().map(|v| v.revision),
                        None => self.get(&key)?.map(|v| v.revision),
                    };
                    let precondition = match &cmd {
                        Command::Put { precondition, .. }
                        | Command::Delete { precondition, .. } => *precondition,
                    };
                    // A delete of a missing key with no precondition succeeds as a no-op.
                    if !decide(precondition, current) {
                        Response::PreconditionFailed { current }
                    } else {
                        match cmd {
                            Command::Put { value, .. } => {
                                let value = Arc::new(value);
                                events.push(Event {
                                    key: key.clone(),
                                    revision,
                                    value: Some(value.clone()),
                                });
                                updates.insert(
                                    key,
                                    Some(Versioned {
                                        revision,
                                        value: value.as_ref().clone(),
                                    }),
                                );
                            }
                            Command::Delete { .. } => {
                                if current.is_some() {
                                    events.push(Event {
                                        key: key.clone(),
                                        revision,
                                        value: None,
                                    });
                                }
                                updates.insert(key, None);
                            }
                        }
                        Response::Applied { revision }
                    }
                }
            };
            last_applied = Some(log_id);
            if let Some(r) = responder {
                responses.push((r, response));
            }
        }

        let Some(last_applied) = last_applied else {
            return Ok(());
        };
        let mut batch = self.db.batch().durability(Some(PersistMode::SyncAll));
        for (k, v) in &updates {
            match v {
                Some(v) => batch.insert(&self.data, k.as_str(), serialize(v)?),
                None => batch.remove(&self.data, k.as_str()),
            }
        }
        batch.insert(&self.meta, LAST_APPLIED_LOG, serialize(&last_applied)?);
        if let Some(m) = &last_membership {
            batch.insert(&self.meta, LAST_MEMBERSHIP, serialize(m)?);
        }
        TypeConfig::spawn_blocking(move || batch.commit())
            .await?
            .map_err(io::Error::other)?;

        // Only after the batch is durable: answer clients and notify watchers.
        for (r, resp) in responses {
            r.send(resp);
        }
        for e in events {
            // No receivers is fine.
            let _ = self.events.send(Signal::Change(e));
        }
        Ok(())
    }

    async fn get_snapshot_builder(&mut self) -> SnapshotBuilder {
        SnapshotBuilder {
            sm: self.clone(),
            view: self.db.snapshot(),
        }
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMetaOf<TypeConfig>,
        snapshot: Self::SnapshotData,
    ) -> io::Result<()> {
        let sm = self.clone();
        let meta = meta.clone();
        TypeConfig::spawn_blocking(move || sm.install(&meta, snapshot.into_inner())).await?
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> io::Result<Option<SnapshotOf<TypeConfig, Self::SnapshotData>>> {
        let view = self.db.snapshot();
        let Some(meta) =
            read::<SnapshotMetaOf<TypeConfig>, _>(&view, &self.snapshot, SNAPSHOT_META)?
        else {
            return Ok(None);
        };
        let data = view
            .get(&self.snapshot, SNAPSHOT_DATA)
            .map_err(io::Error::other)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "snapshot data missing"))?;
        Ok(Some(SnapshotOf::<TypeConfig, Self::SnapshotData> {
            meta,
            snapshot: Cursor::new(data.to_vec()),
        }))
    }
}

pub struct SnapshotBuilder {
    sm: StateMachine,
    view: fjall::Snapshot,
}

impl std::fmt::Debug for SnapshotBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotBuilder").finish_non_exhaustive()
    }
}

impl RaftSnapshotBuilder<TypeConfig> for SnapshotBuilder {
    type SnapshotData = Cursor<Vec<u8>>;

    async fn build_snapshot(&mut self) -> io::Result<SnapshotOf<TypeConfig, Self::SnapshotData>> {
        let sm = self.sm.clone();
        let view = self.view.clone();
        TypeConfig::spawn_blocking(move || {
            let meta = sm.read_applied(&view)?;
            let data = sm.encode_data(&view)?;
            sm.save_built_snapshot(&meta, &data)?;
            Ok(SnapshotOf::<TypeConfig, Self::SnapshotData> {
                meta,
                snapshot: Cursor::new(data),
            })
        })
        .await?
    }
}

fn read<T: DeserializeOwned, R: Readable>(
    view: &R,
    ks: &Keyspace,
    key: &str,
) -> io::Result<Option<T>> {
    view.get(ks, key)
        .map_err(io::Error::other)?
        .map(|b| deserialize(&b))
        .transpose()
}

fn serialize<T: Serialize>(v: &T) -> io::Result<Vec<u8>> {
    rmp_serde::to_vec_named(v).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn deserialize<T: DeserializeOwned>(b: &[u8]) -> io::Result<T> {
    rmp_serde::from_slice(b).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
