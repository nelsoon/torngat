//! Volume keys: made at first use, given to the node that has the volume, destroyed with it.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tonic::Status;
use torngat_api::node::{Node, NodePhase};
use torngat_api::storage::{StoragePool, Volume, VolumePhase};
use torngat_api::{Name, Scope};
use torngat_keys::{PlatformKey, Purpose, Secret, Wrapped};
use torngat_store::{Key, Precondition, Store, StoreError, Versioned};
use uuid::Uuid;

use crate::scheduler::{ScheduleError, list_all};
use crate::service::{internal, store_err};
use crate::{Controller, keys};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformKeyRecord {
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectKeyRecord {
    pub id: Uuid,
    /// Platform key that wraps it.
    pub platform_key: String,
    pub wrapped: Wrapped,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeKeyRecord {
    pub scope: Scope,
    pub name: Name,
    /// Project key that wraps it.
    pub project_key: Uuid,
    /// `None` once the volume is gone: no key is made for its uid again.
    pub wrapped: Option<Wrapped>,
}

#[derive(Debug, thiserror::Error)]
pub enum PlatformKeyError {
    #[error("{0}: {1}")]
    File(String, torngat_keys::KeyError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    StoreKey(#[from] torngat_store::KeyError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("{0} is missing: without it no volume can be opened. Restore it from a backup")]
    Missing(String),
    #[error("the store has keys, but no record of their platform key")]
    NoRecord,
    #[error("{0} is not this cluster's platform key")]
    Wrong(String),
}

/// The cluster's platform key. Made only if the cluster never had one: a lost key is an error, not
/// replaced by another.
pub async fn load_platform_key(
    store: &Store,
    path: &Path,
) -> Result<PlatformKey, PlatformKeyError> {
    let at = keys::platform_key()?;
    let shown = || path.display().to_string();
    let failed = |e| PlatformKeyError::File(shown(), e);
    let file = PlatformKey::load(path).map_err(failed)?;
    if let Some(v) = store.get(&at).await? {
        let rec: PlatformKeyRecord = serde_json::from_slice(&v.value)?;
        let key = file.ok_or_else(|| PlatformKeyError::Missing(shown()))?;
        if key.id() != rec.id {
            return Err(PlatformKeyError::Wrong(shown()));
        }
        return Ok(key);
    }
    // Without its record there is no telling which key the others need.
    if !store.list(&keys::all_keys()?, None, 1).await?.is_empty() {
        return Err(PlatformKeyError::NoRecord);
    }
    let key = match file {
        // A crash between the file and the record.
        Some(k) => k,
        None => {
            let k = PlatformKey::generate().map_err(failed)?;
            k.save(path).map_err(failed)?;
            k
        }
    };
    // Before anything depends on it.
    PlatformKey::sync(path).map_err(failed)?;
    let rec = PlatformKeyRecord {
        id: key.id().to_owned(),
    };
    store
        .put(at, serde_json::to_vec(&rec)?, Precondition::Absent)
        .await?;
    Ok(key)
}

fn decode<T: serde::de::DeserializeOwned>(v: &Versioned) -> Result<T, Status> {
    serde_json::from_slice(&v.value).map_err(internal)
}

async fn get<T: serde::de::DeserializeOwned>(
    store: &Store,
    key: &Key,
) -> Result<Option<T>, Status> {
    let v = store.get(key).await.map_err(store_err)?;
    v.as_ref().map(decode).transpose()
}

/// Creates a record, or reads the one that is there.
async fn create_or_get<T: Serialize + serde::de::DeserializeOwned>(
    store: &Store,
    key: Key,
    rec: T,
) -> Result<T, Status> {
    let value = serde_json::to_vec(&rec).map_err(internal)?;
    match store.put(key.clone(), value, Precondition::Absent).await {
        Ok(_) => Ok(rec),
        Err(StoreError::PreconditionFailed { .. }) => get(store, &key)
            .await?
            .ok_or_else(|| Status::aborted("concurrent change, retry")),
        Err(e) => Err(store_err(e)),
    }
}

/// The volume's key, if `node` may have it now.
pub(crate) async fn volume_key(
    ctl: &Controller,
    node: &Name,
    scope: &Scope,
    name: &Name,
    uid: Uuid,
) -> Result<Secret, Status> {
    let res = check_and_get(ctl, node, scope, name, uid).await;
    match &res {
        Ok(_) => tracing::info!(node = %node, volume = %uid, "volume key given"),
        Err(e) => {
            tracing::warn!(node = %node, volume = %uid, reason = e.message(), "volume key refused");
        }
    }
    res
}

/// The same refusal whether the volume is missing or another node's.
async fn check_and_get(
    ctl: &Controller,
    node: &Name,
    scope: &Scope,
    name: &Name,
    uid: Uuid,
) -> Result<Secret, Status> {
    let denied = || Status::permission_denied("volume is not on this node");
    let store = &ctl.store;
    let Some(volume) = get::<Volume>(store, &keys::volume(scope, name).map_err(internal)?).await?
    else {
        return Err(denied());
    };
    let Some(pool_ref) = &volume.status.pool else {
        return Err(denied());
    };
    let pool_key = keys::storage_pool(&pool_ref.name).map_err(internal)?;
    let pool: Option<StoragePool> = get(store, &pool_key).await?;
    let on_node = pool.is_some_and(|p| p.metadata.uid == pool_ref.uid && p.spec.node == *node);
    if volume.metadata.uid != uid || !on_node {
        return Err(denied());
    }
    let usable = match get::<Node>(store, &keys::node(node).map_err(internal)?).await? {
        // Every phase is listed, so that a new one gets a decision.
        Some(n) => match n.status.phase {
            NodePhase::Active | NodePhase::Maintenance | NodePhase::Draining => true,
            NodePhase::Provisioning
            | NodePhase::Joining
            | NodePhase::Decommissioned
            | NodePhase::Failed => false,
        },
        None => false,
    };
    if !usable {
        return Err(Status::failed_precondition("node is not active"));
    }
    if volume.metadata.delete_time.is_some()
        || !matches!(
            volume.status.phase,
            VolumePhase::Placed | VolumePhase::Ready
        )
    {
        return Err(Status::failed_precondition("volume is not in use"));
    }
    // Once there is data, only while an instance uses it.
    if volume.status.formatted && volume.status.attached_to.is_none() {
        return Err(Status::failed_precondition("no instance uses the volume"));
    }

    let at = keys::volume_key(uid).map_err(internal)?;
    let old: Option<VolumeKeyRecord> = get(store, &at).await?;
    if old.is_none() && volume.status.formatted {
        return Err(internal(format!("the key of volume {uid} is gone")));
    }
    let destroyed = || Status::failed_precondition("the volume's key is destroyed");
    if old.as_ref().is_some_and(|r| r.wrapped.is_none()) {
        return Err(destroyed());
    }
    let purpose = Purpose::Volume { volume: uid };
    let (id, project_key) = project_key(ctl, scope, old.is_none()).await?;
    let rec = match old {
        Some(r) => r,
        None => {
            let key = Secret::generate().map_err(internal)?;
            let rec = VolumeKeyRecord {
                scope: scope.clone(),
                name: name.clone(),
                project_key: id,
                wrapped: Some(project_key.wrap(&key, purpose).map_err(internal)?),
            };
            create_or_get(store, at, rec).await?
        }
    };
    let Some(wrapped) = &rec.wrapped else {
        // Meanwhile.
        return Err(destroyed());
    };
    if id != rec.project_key {
        return Err(internal(format!(
            "volume {uid} needs project key {}, not {id}",
            rec.project_key
        )));
    }
    project_key.unwrap(wrapped, purpose).map_err(internal)
}

/// The project's key and its id.
async fn project_key(
    ctl: &Controller,
    scope: &Scope,
    create: bool,
) -> Result<(Uuid, Secret), Status> {
    let at = keys::project_key(scope).map_err(internal)?;
    let project = scope.segments().join("/");
    let purpose = |id| Purpose::Project {
        id,
        project: &project,
    };
    let platform = ctl.platform_key.key();
    let rec = match get::<ProjectKeyRecord>(&ctl.store, &at).await? {
        Some(r) => r,
        None if !create => return Err(internal(format!("the key of {project} is gone"))),
        None => {
            let id = Uuid::now_v7();
            let key = Secret::generate().map_err(internal)?;
            let rec = ProjectKeyRecord {
                id,
                platform_key: ctl.platform_key.id().to_owned(),
                wrapped: platform.wrap(&key, purpose(id)).map_err(internal)?,
            };
            create_or_get(&ctl.store, at, rec).await?
        }
    };
    if rec.platform_key != ctl.platform_key.id() {
        return Err(internal(format!("{project} needs another platform key")));
    }
    let key = platform
        .unwrap(&rec.wrapped, purpose(rec.id))
        .map_err(internal)?;
    Ok((rec.id, key))
}

/// Destroys the keys of volumes that are gone. Returns how many.
pub async fn destroy_volume_keys_once(store: &Store) -> Result<usize, ScheduleError> {
    let mut destroyed = 0;
    for (at, v) in list_all(store, &keys::volume_keys()?).await? {
        // One bad record must not keep all the others.
        match destroy_if_gone(store, &at, v).await {
            Ok(true) => {
                tracing::info!(key = at.as_str(), "volume key destroyed");
                destroyed += 1;
            }
            Ok(false) | Err(ScheduleError::Store(StoreError::PreconditionFailed { .. })) => {}
            Err(ScheduleError::Store(e)) => return Err(e.into()),
            Err(e) => tracing::error!(key = at.as_str(), error = %e, "cannot check a volume key"),
        }
    }
    Ok(destroyed)
}

async fn destroy_if_gone(store: &Store, at: &Key, v: Versioned) -> Result<bool, ScheduleError> {
    let mut rec: VolumeKeyRecord = serde_json::from_slice(&v.value)?;
    if rec.wrapped.is_none() {
        return Ok(false);
    }
    if let Some(cur) = store.get(&keys::volume(&rec.scope, &rec.name)?).await? {
        let volume: Volume = serde_json::from_slice(&cur.value)?;
        if keys::volume_key(volume.metadata.uid)? == *at {
            return Ok(false);
        }
    }
    rec.wrapped = None;
    store
        .put(
            at.clone(),
            serde_json::to_vec(&rec)?,
            Precondition::Revision(v.revision),
        )
        .await?;
    Ok(true)
}
