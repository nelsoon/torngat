//! Storage on the controller: pools are claimed and released, volumes placed, grown and deleted.
//!
//! The order of writes is what keeps space from being promised twice (docs/SECURITY-NOTES.md):
//! - placement: pool and `granted_bytes` in the volume's status, then the reservation, then
//!   `Placed`; without space both are cleared again;
//! - growth: the reservation, then `granted_bytes`;
//! - deletion: blocks (the node), the reservation (the pool is always written), the key's tombstone,
//!   then the object.
//!
//! Every step is a compare-and-swap that the next pass repeats if it was interrupted. A reservation
//! left by a step that came too late is released by the sweep.

use std::collections::{BTreeSet, HashMap};

use serde::Serialize;
use serde::de::DeserializeOwned;
use torngat_api::storage::{
    MAX_VOLUMES_PER_POOL, PoolRef, StorageCapabilities, StoragePool, Volume, VolumePhase,
    VolumeType,
};
use torngat_api::{Name, Scope};
use torngat_store::{Key, Precondition, Store, StoreError, Versioned};
use uuid::Uuid;

use crate::scheduler::{ScheduleError, list_all};
use crate::{Controller, keys, volume_keys};

/// Retries for compare-and-swap loops.
const CAS_RETRIES: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum PlaceError {
    #[error("no such volume")]
    NotFound,
    #[error("the volume is not waiting to be placed")]
    NotPending,
    #[error("no pool of the volume's type has room{}", on_node(.0))]
    NoRoom(Option<Name>),
    #[error("the volume's key was destroyed: it cannot be used")]
    Destroyed,
    /// Changed meanwhile, or the chosen pool filled up: try again.
    #[error("concurrent change, retry")]
    Conflict,
    #[error(transparent)]
    Controller(#[from] ScheduleError),
}

fn on_node(n: &Option<Name>) -> String {
    n.as_ref().map(|n| format!(" on {n}")).unwrap_or_default()
}

macro_rules! via_controller {
    ($($t:ty),*) => {$(
        impl From<$t> for PlaceError {
            fn from(e: $t) -> Self {
                Self::Controller(e.into())
            }
        }
    )*};
}
via_controller!(StoreError, torngat_store::KeyError, serde_json::Error);

/// Reads, changes and writes back an object with compare-and-swap, retrying on conflicts. `change`
/// returns false to leave it as it is. `None` if there is no object.
pub(crate) async fn modify<T: Serialize + DeserializeOwned>(
    store: &Store,
    key: &Key,
    mut change: impl FnMut(&mut T) -> bool,
) -> Result<Option<T>, PlaceError> {
    for _ in 0..CAS_RETRIES {
        let Some(v) = store.get(key).await? else {
            return Ok(None);
        };
        let mut obj: T = serde_json::from_slice(&v.value)?;
        if !change(&mut obj) {
            return Ok(Some(obj));
        }
        match store
            .put(
                key.clone(),
                serde_json::to_vec(&obj)?,
                Precondition::Revision(v.revision),
            )
            .await
        {
            Ok(_) => return Ok(Some(obj)),
            Err(StoreError::PreconditionFailed { .. }) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(PlaceError::Conflict)
}

/// An object and its revision. An object that does not decode is an error, never "missing".
pub(crate) async fn get<T: DeserializeOwned>(
    store: &Store,
    key: &Key,
) -> Result<Option<(T, u64)>, PlaceError> {
    match store.get(key).await? {
        Some(v) => Ok(Some((serde_json::from_slice(&v.value)?, v.revision))),
        None => Ok(None),
    }
}

/// Every object under a prefix, with what was stored. `None` if one does not decode.
pub(crate) async fn all<T: DeserializeOwned>(
    store: &Store,
    prefix: &torngat_store::Prefix,
) -> Result<Option<Vec<(T, Versioned)>>, ScheduleError> {
    let mut out = Vec::new();
    for (k, v) in list_all(store, prefix).await? {
        match serde_json::from_slice(&v.value) {
            Ok(o) => out.push((o, v)),
            Err(e) => {
                tracing::error!(key = k.as_str(), error = %e, "unreadable object");
                return Ok(None);
            }
        }
    }
    Ok(Some(out))
}

pub(crate) fn unreadable() -> ScheduleError {
    ScheduleError::Store(StoreError::Raft("unreadable storage object".into()))
}

/// The size to reserve for `bytes`: whole allocation units.
pub(crate) fn rounded(pool: &StoragePool, bytes: u64) -> u64 {
    match pool.status.allocation_unit_bytes {
        0 | 1 => bytes,
        u => bytes.div_ceil(u).saturating_mul(u),
    }
}

/// Whether new volumes may go to this pool.
pub(crate) fn usable(p: &StoragePool) -> bool {
    p.metadata.delete_time.is_none()
        && p.status.claimed
        && p.status.ready
        && !p.spec.unschedulable
        && p.status.reservations.len() < MAX_VOLUMES_PER_POOL
}

fn volume_key(v: &Volume) -> Result<Key, torngat_store::KeyError> {
    keys::volume(&v.metadata.scope, &v.metadata.name)
}

/// Gives a pending volume a pool, on `node` if set: for a volume's first use by an instance there.
pub async fn place_volume(
    ctl: &Controller,
    scope: &Scope,
    name: &Name,
    uid: Uuid,
    node: Option<&Name>,
) -> Result<Volume, PlaceError> {
    let store = &ctl.store;
    let key = keys::volume(scope, name)?;
    let (volume, rev) = get::<Volume>(store, &key)
        .await?
        .ok_or(PlaceError::NotFound)?;
    if volume.metadata.uid != uid {
        return Err(PlaceError::NotFound);
    }
    if volume.metadata.delete_time.is_some() || volume.status.phase != VolumePhase::Pending {
        return Err(PlaceError::NotPending);
    }
    // A uid brought back by racing creates: its key is gone.
    if volume_keys::is_destroyed(store, uid).await? {
        return Err(PlaceError::Destroyed);
    }
    let no_room = || PlaceError::NoRoom(node.cloned());
    let (t, _) = get::<VolumeType>(store, &keys::volume_type(&volume.spec.volume_type)?)
        .await?
        .ok_or_else(no_room)?;
    let mut best: Option<(u64, StoragePool)> = None;
    for p in &t.spec.pools {
        let Some((pool, _)) = get::<StoragePool>(store, &keys::storage_pool(p)?).await? else {
            continue;
        };
        if !usable(&pool) || node.is_some_and(|n| *n != pool.spec.node) {
            continue;
        }
        let free = pool
            .status
            .capacity_bytes
            .saturating_sub(pool.status.reserved_bytes());
        if free >= rounded(&pool, volume.spec.device_bytes())
            && best.as_ref().is_none_or(|(f, _)| free > *f)
        {
            best = Some((free, pool));
        }
    }
    let (_, pool) = best.ok_or_else(no_room)?;

    let mut placing = volume;
    placing.status.phase = VolumePhase::Placing;
    placing.status.pool = Some(PoolRef {
        name: pool.metadata.name.clone(),
        uid: pool.metadata.uid,
    });
    placing.status.granted_bytes = placing.spec.size_bytes();
    placing.metadata.etag = None;
    match store
        .put(
            key,
            serde_json::to_vec(&placing)?,
            Precondition::Revision(rev),
        )
        .await
    {
        Ok(_) => {}
        Err(StoreError::PreconditionFailed { .. }) => return Err(PlaceError::Conflict),
        Err(e) => return Err(e.into()),
    }
    match finish_placing(store, &placing).await? {
        Some(v) if v.status.phase == VolumePhase::Placed => Ok(v),
        Some(_) => Err(PlaceError::Conflict),
        None => Err(PlaceError::NotFound),
    }
}

/// Whether `v` is still being placed on `pool`.
fn placing_on(v: &Volume, uid: Uuid, pool: &PoolRef) -> bool {
    v.metadata.uid == uid
        && v.status.phase == VolumePhase::Placing
        && v.status.pool.as_ref() == Some(pool)
}

/// Reserves the space of a volume that names its pool, or takes the pool back if there is none.
async fn finish_placing(store: &Store, volume: &Volume) -> Result<Option<Volume>, PlaceError> {
    let Some(pool_ref) = volume.status.pool.clone() else {
        return Ok(Some(volume.clone()));
    };
    let uid = volume.metadata.uid;
    let vkey = volume_key(volume)?;
    // `volume` may be an old read.
    let volume = match get::<Volume>(store, &vkey).await? {
        Some((v, _)) if placing_on(&v, uid, &pool_ref) => v,
        other => return Ok(other.map(|(v, _)| v)),
    };
    let pool_key = keys::storage_pool(&pool_ref.name)?;
    let mut refused = false;
    let reserved = modify(store, &pool_key, |p: &mut StoragePool| {
        refused = p.metadata.uid != pool_ref.uid || p.metadata.delete_time.is_some();
        if refused {
            return false;
        }
        let size = rounded(p, volume.spec.device_bytes());
        if p.status.reservations.get(&uid).is_some_and(|r| *r >= size) {
            return false;
        }
        refused = p.status.reserve(uid, size).is_err();
        !refused
    })
    .await?;
    let refused = refused || reserved.is_none();
    modify(store, &vkey, |v: &mut Volume| {
        if !placing_on(v, uid, &pool_ref) {
            return false;
        }
        if refused {
            v.status.pool = None;
            v.status.granted_bytes = 0;
            v.status.phase = VolumePhase::Pending;
        } else {
            v.status.phase = VolumePhase::Placed;
        }
        v.metadata.etag = None;
        true
    })
    .await
}

/// One pass over pools and volumes. Returns how many objects it changed.
pub async fn storage_once(ctl: &Controller) -> Result<usize, ScheduleError> {
    let store = &ctl.store;
    let mut changed = 0;
    // One that does not decode might hold space or a pool: then nothing is decided from the list.
    let Some(volumes) = all::<Volume>(store, &keys::all_volumes()?).await? else {
        return Ok(0);
    };
    let Some(types) = all::<VolumeType>(store, &keys::volume_types()?).await? else {
        return Ok(0);
    };
    // Before the volumes are read again: see `sweep`.
    let Some(pools) = all::<StoragePool>(store, &keys::storage_pools()?).await? else {
        return Ok(0);
    };
    for (p, v) in &pools {
        let in_use = types
            .iter()
            .any(|(t, _)| t.spec.pools.contains(&p.metadata.name))
            || volumes.iter().any(|(vol, _)| names(vol, p));
        changed += usize::from(pool_step(store, p, v.revision, in_use).await?);
    }

    for (v, _) in &volumes {
        let step = match v.status.phase {
            VolumePhase::Placing => finish_placing(store, v).await.map(|_| false),
            VolumePhase::Placed | VolumePhase::Ready => grow(store, v).await,
            _ => Ok(false),
        };
        match step {
            Ok(c) => changed += usize::from(c),
            Err(PlaceError::Controller(e)) => return Err(e),
            Err(e) => tracing::warn!(volume = %v.metadata.uid, error = %e, "volume step failed"),
        }
    }
    changed += sweep(store, &pools).await?;
    Ok(changed)
}

/// Whether the volume names this pool.
fn names(v: &Volume, p: &StoragePool) -> bool {
    v.status
        .pool
        .as_ref()
        .is_some_and(|r| r.uid == p.metadata.uid)
}

/// Claims a new pool for its node, or removes a deleted one that its node released and that
/// nothing uses.
async fn pool_step(
    store: &Store,
    p: &StoragePool,
    rev: u64,
    in_use: bool,
) -> Result<bool, ScheduleError> {
    let key = keys::storage_pool(&p.metadata.name)?;
    let pre = Precondition::Revision(rev);
    let res = if p.metadata.delete_time.is_none() {
        if p.status.claimed {
            return Ok(false);
        }
        // Before the node is asked to mark the storage, so that deleting the pool waits for it.
        let mut claimed = p.clone();
        claimed.status.claimed = true;
        claimed.metadata.etag = None;
        store.put(key, serde_json::to_vec(&claimed)?, pre).await
    } else if p.status.claimed || !p.status.reservations.is_empty() || in_use {
        return Ok(false);
    } else {
        store.delete(key, pre).await
    };
    match res {
        Ok(_) => Ok(true),
        Err(StoreError::PreconditionFailed { .. }) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Grows the reservation, then grants the size.
async fn grow(store: &Store, v: &Volume) -> Result<bool, PlaceError> {
    let want = v.spec.size_bytes();
    let Some(pool_ref) = &v.status.pool else {
        return Ok(false);
    };
    if v.metadata.delete_time.is_some() || v.status.granted_bytes >= want {
        return Ok(false);
    }
    let uid = v.metadata.uid;
    let mut ok = false;
    modify(
        store,
        &keys::storage_pool(&pool_ref.name)?,
        |p: &mut StoragePool| {
            if p.metadata.uid != pool_ref.uid {
                ok = false;
                return false;
            }
            let size = rounded(p, v.spec.device_bytes());
            let before = p.status.reservations.get(&uid).copied();
            // Otherwise it waits for room, or for the size to be taken back.
            ok = p.status.grow(uid, size).is_ok();
            ok && before != p.status.reservations.get(&uid).copied()
        },
    )
    .await?;
    if !ok {
        return Ok(false);
    }
    let granted = modify(store, &volume_key(v)?, |cur: &mut Volume| {
        // Only for the size that was reserved. Taken back meanwhile, the reservation stays larger
        // until the volume is deleted.
        if cur.metadata.uid != uid
            || cur.spec.size_bytes() < want
            || cur.status.granted_bytes >= want
        {
            return false;
        }
        cur.status.granted_bytes = want;
        cur.metadata.etag = None;
        true
    })
    .await?;
    Ok(granted.is_some())
}

/// The last step of a deletion: no key for the uid again, then the object goes.
async fn remove_volume(store: &Store, v: &Volume) -> Result<(), PlaceError> {
    volume_keys::destroy(store, &v.metadata.scope, &v.metadata.name, v.metadata.uid).await?;
    let key = volume_key(v)?;
    for _ in 0..CAS_RETRIES {
        let Some((cur, rev)) = get::<Volume>(store, &key).await? else {
            return Ok(());
        };
        if cur.metadata.uid != v.metadata.uid {
            return Ok(());
        }
        match store.delete(key.clone(), Precondition::Revision(rev)).await {
            Ok(_) => return Ok(()),
            Err(StoreError::PreconditionFailed { .. }) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(PlaceError::Conflict)
}

/// Releases reservations of volumes that no longer name the pool. The pools were read before the
/// volumes are read here: a reservation is only made after its volume names the pool, so any
/// reservation in that read belongs to a volume that this read shows, unless it is gone.
async fn sweep(store: &Store, pools: &[(StoragePool, Versioned)]) -> Result<usize, ScheduleError> {
    let Some(volumes) = all::<Volume>(store, &keys::all_volumes()?).await? else {
        return Ok(0);
    };
    let mut holders: HashMap<Uuid, BTreeSet<Uuid>> = HashMap::new();
    for (v, _) in &volumes {
        if let Some(p) = &v.status.pool {
            holders.entry(p.uid).or_default().insert(v.metadata.uid);
        }
    }
    let mut released = 0;
    for (p, stored) in pools {
        let keep = holders.get(&p.metadata.uid);
        let gone: Vec<Uuid> = p
            .status
            .reservations
            .keys()
            .filter(|u| !keep.is_some_and(|k| k.contains(u)))
            .copied()
            .collect();
        if gone.is_empty() {
            continue;
        }
        let mut swept = p.clone();
        for u in &gone {
            swept.status.release(u);
        }
        swept.metadata.etag = None;
        let key = keys::storage_pool(&p.metadata.name)?;
        let pre = Precondition::Revision(stored.revision);
        match store.put(key, serde_json::to_vec(&swept)?, pre).await {
            Ok(_) => {
                tracing::info!(pool = %p.metadata.name, count = gone.len(), "reservations released");
                released += gone.len();
            }
            Err(StoreError::PreconditionFailed { .. }) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(released)
}

fn denied() -> tonic::Status {
    tonic::Status::permission_denied("not on this node")
}

fn status(e: PlaceError) -> tonic::Status {
    match e {
        PlaceError::Conflict
        | PlaceError::Controller(ScheduleError::Store(StoreError::PreconditionFailed { .. })) => {
            tonic::Status::aborted("concurrent change, retry")
        }
        PlaceError::Controller(ScheduleError::Store(e)) => crate::service::store_err(e),
        e => crate::service::internal(e),
    }
}

/// Largest allocation unit accepted from a node.
const MAX_ALLOCATION_UNIT: u64 = 1 << 30;

/// What a node found in one of its pools.
#[derive(Debug)]
pub(crate) struct PoolState {
    pub uid: Uuid,
    pub ready: bool,
    pub capacity_bytes: u64,
    /// Only for a ready pool.
    pub allocation_unit_bytes: u64,
    pub capabilities: StorageCapabilities,
    pub message: Option<String>,
    /// The node removed its mark (only for a pool being deleted).
    pub released: bool,
}

/// A node reports on a pool of its own. Never touches the reservations.
pub(crate) async fn report_pool(
    store: &Store,
    node: &Name,
    name: &Name,
    r: PoolState,
) -> Result<(), tonic::Status> {
    let unit = r.allocation_unit_bytes;
    if r.ready && (!unit.is_power_of_two() || unit > MAX_ALLOCATION_UNIT) {
        return Err(tonic::Status::invalid_argument("invalid allocation unit"));
    }
    let key = keys::storage_pool(name).map_err(crate::service::internal)?;
    let (pool, _) = get::<StoragePool>(store, &key)
        .await
        .map_err(status)?
        .ok_or_else(denied)?;
    if pool.metadata.uid != r.uid || pool.spec.node != *node {
        return Err(denied());
    }
    // Volumes still on it keep their space and their deletion: it cannot be released yet.
    let on_it = if r.released {
        let volumes = all::<Volume>(
            store,
            &keys::all_volumes().map_err(crate::service::internal)?,
        )
        .await
        .map_err(|e| status(e.into()))?;
        volumes.is_none_or(|vs| vs.iter().any(|(v, _)| names(v, &pool)))
    } else {
        false
    };
    let mut refusal = None;
    modify(store, &key, |p: &mut StoragePool| {
        refusal = None;
        if p.metadata.uid != r.uid {
            refusal = Some(denied());
            return false;
        }
        let deleting = p.metadata.delete_time.is_some();
        let not_now = || {
            Some(tonic::Status::failed_precondition(
                "the pool is not in that state",
            ))
        };
        let mut new = p.status.clone();
        if r.released {
            if !deleting || on_it || !p.status.reservations.is_empty() {
                refusal = not_now();
                return false;
            }
            new.claimed = false;
            new.ready = false;
        } else {
            // A node may only use what the controller claimed for it.
            if !p.status.claimed {
                refusal = not_now();
                return false;
            }
            // Devices already made are rounded to the old unit.
            let unit_changes = r.ready && p.status.allocation_unit_bytes != unit;
            if unit_changes
                && !p.status.reservations.is_empty()
                && p.status.allocation_unit_bytes != 0
            {
                refusal = Some(tonic::Status::failed_precondition(
                    "the allocation unit cannot change while the pool holds volumes",
                ));
                return false;
            }
            new.ready = r.ready && !deleting;
            new.capacity_bytes = r.capacity_bytes;
            if r.ready {
                new.allocation_unit_bytes = unit;
            }
            new.capabilities = r.capabilities.clone();
            new.message = r.message.clone();
        }
        if new == p.status {
            return false;
        }
        p.status = new;
        p.metadata.etag = None;
        true
    })
    .await
    .map_err(status)?
    .ok_or_else(denied)?;
    refusal.map_or(Ok(()), Err)
}

/// What a node did with one of its volumes.
#[derive(Debug)]
pub(crate) struct VolumeState {
    pub uid: Uuid,
    /// Exists on the node, encrypted and usable.
    pub created: bool,
    /// What the instance can see.
    pub size_bytes: u64,
    /// Its blocks are gone (only for a volume being deleted).
    pub deleted: bool,
    /// Formatted on the node: never cleared.
    pub formatted: bool,
    /// Open on the node for an instance.
    pub open: bool,
    pub message: Option<String>,
}

/// The volume, if it is on one of `node`'s pools.
async fn node_volume(
    store: &Store,
    node: &Name,
    scope: &Scope,
    name: &Name,
    uid: Uuid,
) -> Result<(Volume, PoolRef), tonic::Status> {
    let internal = crate::service::internal;
    let key = keys::volume(scope, name).map_err(internal)?;
    let (v, _) = get::<Volume>(store, &key)
        .await
        .map_err(status)?
        .ok_or_else(denied)?;
    let Some(pool_ref) = v.status.pool.clone() else {
        return Err(denied());
    };
    let pool_key = keys::storage_pool(&pool_ref.name).map_err(internal)?;
    let pool = get::<StoragePool>(store, &pool_key).await.map_err(status)?;
    let on_node = pool.is_some_and(|(p, _)| p.metadata.uid == pool_ref.uid && p.spec.node == *node);
    if v.metadata.uid != uid || !on_node {
        return Err(denied());
    }
    Ok((v, pool_ref))
}

pub(crate) async fn report_volume(
    store: &Store,
    node: &Name,
    scope: &Scope,
    name: &Name,
    r: VolumeState,
) -> Result<(), tonic::Status> {
    let (v, pool_ref) = node_volume(store, node, scope, name, r.uid).await?;
    if r.deleted {
        if v.status.phase != VolumePhase::Deleting {
            return Err(tonic::Status::failed_precondition(
                "the volume is not being deleted",
            ));
        }
        // Always written: a growth that comes late then fails, and the sweep takes back a placement
        // that does.
        let pool_key = keys::storage_pool(&pool_ref.name).map_err(crate::service::internal)?;
        modify(store, &pool_key, |p: &mut StoragePool| {
            if p.metadata.uid != pool_ref.uid {
                return false;
            }
            p.status.release(&r.uid);
            p.metadata.etag = None;
            true
        })
        .await
        .map_err(status)?;
        return remove_volume(store, &v).await.map_err(status);
    }
    let key = volume_key(&v).map_err(crate::service::internal)?;
    modify(store, &key, |cur: &mut Volume| {
        if cur.metadata.uid != r.uid || cur.status.pool.as_ref() != Some(&pool_ref) {
            return false;
        }
        let mut new = cur.status.clone();
        if r.created && new.phase == VolumePhase::Placed {
            new.phase = VolumePhase::Ready;
        }
        new.formatted |= r.formatted;
        new.open = r.open;
        // Never more than was granted.
        new.size_bytes = r.size_bytes.min(new.granted_bytes);
        new.message = r.message.clone();
        if new == cur.status {
            return false;
        }
        cur.status = new;
        cur.metadata.etag = None;
        true
    })
    .await
    .map_err(status)?;
    Ok(())
}

/// The pools of `node` that it should look after, and the volumes on them.
pub(crate) async fn assigned_storage(
    store: &Store,
    node: &Name,
) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), ScheduleError> {
    let pools = all::<StoragePool>(store, &keys::storage_pools()?)
        .await?
        .ok_or_else(unreadable)?;
    // Deleted ones too, until the node released them.
    let (pools, mine): (Vec<_>, BTreeSet<_>) = pools
        .into_iter()
        .filter(|(p, _)| p.spec.node == *node && p.status.claimed)
        .map(|(p, v)| (v.value, p.metadata.uid))
        .unzip();
    let volumes = all::<Volume>(store, &keys::all_volumes()?)
        .await?
        .ok_or_else(unreadable)?;
    let volumes = volumes
        .into_iter()
        .filter(|(v, _)| {
            v.status
                .pool
                .as_ref()
                .is_some_and(|p| mine.contains(&p.uid))
                && matches!(
                    v.status.phase,
                    VolumePhase::Placed | VolumePhase::Ready | VolumePhase::Deleting
                )
        })
        .map(|(_, v)| v.value)
        .collect();
    Ok((pools, volumes))
}
