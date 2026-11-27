//! Instance disks.
//!
//! - A boot disk is the volume `<instance>-boot`, made by the controller and owned by the instance
//!   (`status.owner`). Only its owner uses it. When the instance is gone it is deleted, or with
//!   `boot_disk.keep` it becomes a volume like any other.
//! - A volume is attached (`status.attached_to`) to the one instance that lists it, once that
//!   instance has a node: placed on that node first if it was not placed yet. Local volumes bind
//!   instances to their node, so the scheduler takes them into account ([`Needs`]).
//! - A volume is released when its instance is gone or no longer lists it, and only once its node
//!   closed it (`status.open`): the instance's VM may still be stopping.
//! - If an instance or volume does not decode, nothing is released or deleted.

use std::collections::{BTreeMap, HashMap};

use time::OffsetDateTime;
use torngat_api::compute::Instance;
use torngat_api::meta::Cell;
use torngat_api::storage::{
    StoragePool, Volume, VolumeOwner, VolumePhase, VolumeSpec, VolumeStatus, VolumeType,
};
use torngat_api::{Name, Object, ObjectMeta, Scope};
use torngat_store::{Precondition, Store, StoreError};
use uuid::Uuid;

use crate::scheduler::ScheduleError;
use crate::storage::{PlaceError, all, get, modify, place_volume, rounded, usable};
use crate::{Controller, keys};

/// Every instance, pool, type and volume, read once per pass.
#[derive(Debug)]
pub struct World {
    pub instances: Vec<Instance>,
    volumes: BTreeMap<Scope, BTreeMap<Name, Volume>>,
    pools: BTreeMap<Name, StoragePool>,
    types: BTreeMap<Name, VolumeType>,
}

impl World {
    /// `None` if an object does not decode.
    pub(crate) async fn read(store: &Store) -> Result<Option<Self>, ScheduleError> {
        let (Some(instances), Some(volumes), Some(pools), Some(types)) = (
            all::<Instance>(store, &keys::all_instances()?).await?,
            all::<Volume>(store, &keys::all_volumes()?).await?,
            all::<StoragePool>(store, &keys::storage_pools()?).await?,
            all::<VolumeType>(store, &keys::volume_types()?).await?,
        ) else {
            return Ok(None);
        };
        let mut by_scope: BTreeMap<Scope, BTreeMap<Name, Volume>> = BTreeMap::new();
        for (v, _) in volumes {
            by_scope
                .entry(v.metadata.scope.clone())
                .or_default()
                .insert(v.metadata.name.clone(), v);
        }
        Ok(Some(Self {
            instances: instances.into_iter().map(|(i, _)| i).collect(),
            volumes: by_scope,
            pools: pools
                .into_iter()
                .map(|(p, _)| (p.metadata.name.clone(), p))
                .collect(),
            types: types
                .into_iter()
                .map(|(t, _)| (t.metadata.name.clone(), t))
                .collect(),
        }))
    }

    fn volume(&self, scope: &Scope, name: &Name) -> Option<&Volume> {
        self.volumes.get(scope)?.get(name)
    }

    /// The node of a placed volume's pool.
    fn node_of(&self, v: &Volume) -> Option<&Name> {
        let r = v.status.pool.as_ref()?;
        self.pools
            .get(&r.name)
            .filter(|p| p.metadata.uid == r.uid)
            .map(|p| &p.spec.node)
    }
}

/// Why `v` cannot be `inst`'s volume `name` now, if it cannot. Messages are for tenants: no node
/// or pool names.
fn refusal(v: &Volume, inst: &Instance, boot: Option<&Name>) -> Option<String> {
    let n = &v.metadata.name;
    let me = inst.metadata.uid;
    let owner = v.status.owner.map(|o| o.instance);
    if boot == Some(n) && owner != Some(me) {
        return Some(format!(
            "volume {n} already exists and is not this instance's boot disk"
        ));
    }
    if owner.is_some_and(|o| o != me) {
        return Some(format!("volume {n} is another instance's boot disk"));
    }
    if v.metadata.delete_time.is_some() || v.status.phase == VolumePhase::Deleting {
        return Some(format!("volume {n} is being deleted"));
    }
    if v.status.phase == VolumePhase::Failed {
        return Some(format!("volume {n} failed"));
    }
    if v.status.attached_to.is_some_and(|u| u != me) {
        return Some(format!("volume {n} is used by another instance"));
    }
    // Released, but its node has not closed it yet.
    if v.status.open && v.status.attached_to.is_none() {
        return Some(format!("volume {n} is still open on its node"));
    }
    None
}

/// What an instance's volumes ask of its node.
#[derive(Debug, Default)]
pub(crate) struct Needs {
    /// The node that its placed volumes are on.
    pub node: Option<Name>,
    /// Volumes still to be placed.
    pub pending: Vec<Volume>,
}

/// What `inst`'s volumes ask of its node, or why it cannot run yet.
pub(crate) fn needs(w: &World, inst: &Instance) -> Result<Needs, String> {
    let scope = &inst.metadata.scope;
    let name = &inst.metadata.name;
    let boot = inst.spec.boot_volume(name).map_err(|e| e.to_string())?;
    let mut out = Needs::default();
    for n in inst.spec.volumes(name).map_err(|e| e.to_string())? {
        let Some(v) = w.volume(scope, &n) else {
            return Err(format!("there is no volume {n}"));
        };
        if let Some(r) = refusal(v, inst, boot.as_ref()) {
            return Err(r);
        }
        if v.status.pool.is_none() {
            out.pending.push(v.clone());
            continue;
        }
        let Some(node) = w.node_of(v) else {
            return Err(format!("volume {n} is being placed"));
        };
        match &out.node {
            Some(other) if other != node => return Err("its volumes are on different nodes".into()),
            _ => out.node = Some(node.clone()),
        }
    }
    Ok(out)
}

/// Whether `pending` volumes can all be placed on `node` (an estimate: placement decides).
pub(crate) fn fits(w: &World, node: &Name, pending: &[Volume]) -> bool {
    let mut taken: HashMap<&Name, u64> = HashMap::new();
    pending.iter().all(|v| {
        let Some(t) = w.types.get(&v.spec.volume_type) else {
            return false;
        };
        let pool = t
            .spec
            .pools
            .iter()
            .filter_map(|p| w.pools.get(p))
            .find(|p| {
                let free = p
                    .status
                    .capacity_bytes
                    .saturating_sub(p.status.reserved_bytes())
                    .saturating_sub(taken.get(&p.metadata.name).copied().unwrap_or(0));
                usable(p) && p.spec.node == *node && free >= rounded(p, v.spec.device_bytes())
            });
        match pool {
            Some(p) => {
                *taken.entry(&p.metadata.name).or_default() += rounded(p, v.spec.device_bytes());
                true
            }
            None => false,
        }
    })
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn now() -> Option<OffsetDateTime> {
    Some(OffsetDateTime::now_utc())
}

/// A pass's count of changes, from a compare-and-swap that may have lost a race (retried next pass).
fn changed<T>(r: Result<T, PlaceError>) -> Result<usize, ScheduleError> {
    match r {
        Ok(_) | Err(PlaceError::Conflict) => Ok(1),
        Err(PlaceError::Controller(e)) => Err(e),
        Err(e) => Err(ScheduleError::Store(StoreError::Raft(e.to_string()))),
    }
}

/// Attaches `inst`'s volume `name` on `node`, placing it there first if needed. Returns whether it
/// changed anything; `w` saves the reads when it is already done.
pub(crate) async fn attach(
    ctl: &Controller,
    w: &World,
    inst: &Instance,
    name: &Name,
    node: &Name,
) -> Result<bool, String> {
    let scope = &inst.metadata.scope;
    let me = inst.metadata.uid;
    let boot = inst.spec.boot_volume(&inst.metadata.name).map_err(err)?;
    if let Some(v) = w.volume(scope, name)
        && v.status.attached_to == Some(me)
        && w.node_of(v) == Some(node)
        && refusal(v, inst, boot.as_ref()).is_none()
    {
        return Ok(false);
    }
    let key = keys::volume(scope, name).map_err(err)?;
    for _ in 0..4 {
        let Some((v, _)) = get::<Volume>(&ctl.store, &key).await.map_err(err)? else {
            return Err(format!("there is no volume {name}"));
        };
        if let Some(r) = refusal(&v, inst, boot.as_ref()) {
            return Err(r);
        }
        match v.status.phase {
            VolumePhase::Pending => {
                match place_volume(ctl, scope, name, v.metadata.uid, Some(node)).await {
                    Ok(_) | Err(PlaceError::Conflict | PlaceError::NotPending) => continue,
                    Err(PlaceError::NoRoom(_)) => {
                        return Err(format!("there is no room for volume {name} there"));
                    }
                    Err(e) => {
                        tracing::warn!(volume = %name, error = %e, "cannot place a volume");
                        return Err(format!("volume {name} cannot be placed yet"));
                    }
                }
            }
            VolumePhase::Placing => return Err(format!("volume {name} is being placed")),
            _ => {}
        }
        let pool = v.status.pool.as_ref().ok_or("no pool")?;
        let on = get::<StoragePool>(&ctl.store, &keys::storage_pool(&pool.name).map_err(err)?)
            .await
            .map_err(err)?
            .filter(|(p, _)| p.metadata.uid == pool.uid)
            .map(|(p, _)| p.spec.node);
        if on.as_ref() != Some(node) {
            return Err(format!("volume {name} is on another node"));
        }
        if v.status.attached_to == Some(me) {
            return Ok(true);
        }
        let uid = v.metadata.uid;
        modify(&ctl.store, &key, |v: &mut Volume| {
            // Checked again on what is written: it may have changed since.
            if v.metadata.uid != uid || refusal(v, inst, boot.as_ref()).is_some() {
                return false;
            }
            if v.status.attached_to.is_some() {
                return false;
            }
            v.status.attached_to = Some(me);
            v.metadata.etag = None;
            true
        })
        .await
        .map_err(err)?;
    }
    Err(format!("volume {name} changed meanwhile"))
}

/// Attaches all of `inst`'s volumes on `node`. If one fails while the instance has no node yet,
/// those this call attached are released again, so that they do not stay bound to it.
pub(crate) async fn attach_all(
    ctl: &Controller,
    w: &World,
    inst: &Instance,
    node: &Name,
) -> Result<usize, String> {
    let mut done = Vec::new();
    let mut changed = 0;
    for n in inst.spec.volumes(&inst.metadata.name).map_err(err)? {
        match attach(ctl, w, inst, &n, node).await {
            Ok(c) => {
                if c {
                    changed += 1;
                    done.push(n);
                }
            }
            Err(e) => {
                if inst.status.node.is_none() {
                    for n in done {
                        let _ =
                            release(&ctl.store, &inst.metadata.scope, &n, inst.metadata.uid).await;
                    }
                }
                return Err(e);
            }
        }
    }
    Ok(changed)
}

/// One pass. Returns the world it read (for the scheduler) and how many objects it changed.
pub async fn disks_once(ctl: &Controller) -> Result<(Option<World>, usize), ScheduleError> {
    let Some(w) = World::read(&ctl.store).await? else {
        tracing::warn!("an object does not decode: instance disks are left as they are");
        return Ok((None, 0));
    };
    let mut count = 0;
    let by_uid: BTreeMap<Uuid, &Instance> =
        w.instances.iter().map(|i| (i.metadata.uid, i)).collect();

    for inst in &w.instances {
        let r = async {
            let mut n = boot_disk(ctl, &w, inst).await?;
            if let Some(node) = &inst.status.node {
                n += attach_all(ctl, &w, inst, node).await?;
            }
            Ok::<_, String>(n)
        }
        .await;
        match r {
            Ok(n) => count += n,
            Err(problem) => count += tell(ctl, inst, &problem).await?,
        }
    }

    for v in w.volumes.values().flat_map(BTreeMap::values) {
        let lists = |i: &&Instance| {
            i.spec
                .volumes(&i.metadata.name)
                .is_ok_and(|names| names.contains(&v.metadata.name))
        };
        // Released once its node closed it.
        if let Some(u) = v.status.attached_to
            && !by_uid.get(&u).is_some_and(lists)
            && !v.status.open
        {
            count += changed(release(&ctl.store, &v.metadata.scope, &v.metadata.name, u).await)?;
        }
        if let Some(o) = v.status.owner
            && !by_uid.contains_key(&o.instance)
        {
            count += if o.delete_with_it && !v.spec.delete_protection {
                delete_volume(&ctl.store, v).await?
            } else {
                // Kept: now a volume like any other.
                changed(disown(&ctl.store, v).await)?
            };
        }
    }
    Ok((Some(w), count))
}

/// Makes the boot volume, or keeps it in line with the instance (size, `keep`).
async fn boot_disk(ctl: &Controller, w: &World, inst: &Instance) -> Result<usize, String> {
    let (Some(boot), Some(name)) = (
        &inst.spec.boot_disk,
        inst.spec.boot_volume(&inst.metadata.name).map_err(err)?,
    ) else {
        return Ok(0);
    };
    let scope = &inst.metadata.scope;
    let owner = VolumeOwner {
        instance: inst.metadata.uid,
        delete_with_it: !boot.keep,
    };
    let key = keys::volume(scope, &name).map_err(err)?;
    match w.volume(scope, &name) {
        None => {
            let v: Volume = Object {
                metadata: ObjectMeta {
                    name: name.clone(),
                    scope: scope.clone(),
                    uid: Uuid::now_v7(),
                    cell: Some(Cell::default_cell()),
                    labels: Default::default(),
                    generation: 1,
                    etag: None,
                    create_time: now(),
                    update_time: now(),
                    delete_time: None,
                },
                spec: VolumeSpec {
                    volume_type: boot.volume_type.clone(),
                    size_gib: boot.size_gib,
                    delete_protection: false,
                },
                status: VolumeStatus {
                    owner: Some(owner),
                    ..Default::default()
                },
            };
            let made = ctl
                .store
                .put(
                    key,
                    serde_json::to_vec(&v).map_err(err)?,
                    Precondition::Absent,
                )
                .await;
            match made {
                Ok(_) => Ok(1),
                Err(StoreError::PreconditionFailed { .. }) => Ok(0),
                Err(e) => Err(e.to_string()),
            }
        }
        Some(v) if v.status.owner.is_some_and(|o| o.instance == owner.instance) => {
            if v.status.owner == Some(owner) && v.spec.size_gib >= boot.size_gib {
                return Ok(0);
            }
            let uid = v.metadata.uid;
            modify(&ctl.store, &key, |v: &mut Volume| {
                if v.metadata.uid != uid {
                    return false;
                }
                v.status.owner = Some(owner);
                if v.spec.size_gib < boot.size_gib {
                    v.spec.size_gib = boot.size_gib;
                    v.metadata.generation += 1;
                }
                v.metadata.etag = None;
                true
            })
            .await
            .map_err(err)?;
            Ok(1)
        }
        Some(_) => Err(format!(
            "volume {name} already exists and is not this instance's boot disk"
        )),
    }
}

/// Shows a problem in the instance's status.
pub(crate) async fn tell(
    ctl: &Controller,
    inst: &Instance,
    problem: &str,
) -> Result<usize, ScheduleError> {
    if inst.status.message.as_deref() == Some(problem) {
        return Ok(0);
    }
    let key = keys::instance(&inst.metadata.scope, &inst.metadata.name)?;
    let uid = inst.metadata.uid;
    changed(
        modify(&ctl.store, &key, |i: &mut Instance| {
            if i.metadata.uid != uid || i.status.message.as_deref() == Some(problem) {
                return false;
            }
            i.status.message = Some(problem.to_owned());
            i.metadata.etag = None;
            true
        })
        .await,
    )
}

/// Clears `attached_to` if it is still `user`.
async fn release(
    store: &Store,
    scope: &Scope,
    name: &Name,
    user: Uuid,
) -> Result<Option<Volume>, PlaceError> {
    modify(store, &keys::volume(scope, name)?, |v: &mut Volume| {
        // Opened meanwhile by a node that still had the instance listing it.
        if v.status.attached_to != Some(user) || v.status.open {
            return false;
        }
        v.status.attached_to = None;
        v.metadata.etag = None;
        true
    })
    .await
}

/// A kept boot disk whose instance is gone: no owner any more.
async fn disown(store: &Store, v: &Volume) -> Result<Option<Volume>, PlaceError> {
    let (uid, owner) = (v.metadata.uid, v.status.owner);
    modify(
        store,
        &keys::volume(&v.metadata.scope, &v.metadata.name)?,
        |cur: &mut Volume| {
            if cur.metadata.uid != uid || cur.status.owner != owner {
                return false;
            }
            cur.status.owner = None;
            cur.metadata.etag = None;
            true
        },
    )
    .await
}

/// Deletes a boot disk whose instance is gone: like the API, its blocks first once it has a pool.
async fn delete_volume(store: &Store, v: &Volume) -> Result<usize, ScheduleError> {
    let key = keys::volume(&v.metadata.scope, &v.metadata.name)?;
    let Some(cur) = store.get(&key).await? else {
        return Ok(0);
    };
    let mut vol: Volume = serde_json::from_slice(&cur.value)?;
    if vol.metadata.uid != v.metadata.uid
        || vol.status.attached_to.is_some()
        || vol.metadata.delete_time.is_some()
    {
        return Ok(0);
    }
    let pre = Precondition::Revision(cur.revision);
    let r = if vol.status.pool.is_some() {
        vol.status.phase = VolumePhase::Deleting;
        vol.metadata.delete_time = now();
        vol.metadata.etag = None;
        store
            .put(key, serde_json::to_vec(&vol)?, pre)
            .await
            .map(|_| ())
    } else {
        store.delete(key, pre).await.map(|_| ())
    };
    match r {
        Ok(()) => Ok(1),
        Err(StoreError::PreconditionFailed { .. }) => Ok(0),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use serde_json::json;

    fn n(s: &str) -> Name {
        Name::new(s).unwrap()
    }

    fn obj<T: serde::de::DeserializeOwned>(
        name: &str,
        scope: serde_json::Value,
        spec: serde_json::Value,
        status: serde_json::Value,
    ) -> T {
        serde_json::from_value(json!({
            "metadata": {"name": name, "scope": scope, "uid": Uuid::now_v7(), "generation": 1},
            "spec": spec, "status": status,
        }))
        .unwrap()
    }

    fn project() -> serde_json::Value {
        json!({"kind": "project", "org": "acme", "project": "web"})
    }

    #[test]
    fn needs_and_fits() {
        const GIB: u64 = 1 << 30;
        let pool = |name: &str, node: &str, cap: u64| -> StoragePool {
            obj(
                name,
                json!({"kind": "platform"}),
                json!({"node": node, "driver": "lvm", "source": "data"}),
                json!({"claimed": true, "ready": true, "capacity_bytes": cap,
                       "allocation_unit_bytes": 4 << 20}),
            )
        };
        let (p1, p2) = (pool("p1", "n1", 3 * GIB), pool("p2", "n2", 10 * GIB));
        let fast: VolumeType = obj(
            "fast",
            json!({"kind": "platform"}),
            json!({"pools": ["p1", "p2"]}),
            json!(null),
        );
        let vol = |name: &str, gib: u64, status: serde_json::Value| -> Volume {
            obj(
                name,
                project(),
                json!({"volume_type": "fast", "size_gib": gib}),
                status,
            )
        };
        let on_p2 = vol(
            "placed",
            1,
            json!({"phase": "ready", "pool": {"name": "p2", "uid": p2.metadata.uid}}),
        );
        let small = vol("small", 1, json!({}));
        let big = vol("big", 2, json!({}));
        let scope: Scope = serde_json::from_value(project()).unwrap();
        let mut w = World {
            instances: vec![],
            volumes: [(
                scope.clone(),
                [&on_p2, &small, &big]
                    .into_iter()
                    .map(|v| (v.metadata.name.clone(), v.clone()))
                    .collect(),
            )]
            .into_iter()
            .collect(),
            pools: [&p1, &p2]
                .into_iter()
                .map(|p| (p.metadata.name.clone(), p.clone()))
                .collect(),
            types: [(n("fast"), fast)].into_iter().collect(),
        };
        let inst = |disks: &[&str]| -> Instance {
            let disks: Vec<_> = disks.iter().map(|d| json!({"volume": d})).collect();
            obj(
                "web",
                project(),
                json!({"vcpus": 1, "memory_mib": 64, "disks": disks}),
                json!({}),
            )
        };

        // A placed volume binds the instance to its node.
        let need = needs(&w, &inst(&["placed", "small"])).unwrap();
        assert_eq!(need.node, Some(n("n2")));
        assert_eq!(need.pending.len(), 1);
        // Pending volumes: only where they all fit (n1 holds 3 GiB, the two take 3 GiB + 32 MiB).
        let need = needs(&w, &inst(&["small", "big"])).unwrap();
        assert!(!fits(&w, &n("n1"), &need.pending));
        assert!(fits(&w, &n("n2"), &need.pending));
        assert!(fits(&w, &n("n1"), &need.pending[..1]));
        assert!(!fits(&w, &n("n3"), &need.pending));

        assert!(
            needs(&w, &inst(&["missing"]))
                .unwrap_err()
                .contains("no volume")
        );
        let mut used = small.clone();
        used.status.attached_to = Some(Uuid::now_v7());
        w.volumes
            .get_mut(&scope)
            .unwrap()
            .insert(used.metadata.name.clone(), used);
        assert!(
            needs(&w, &inst(&["small"]))
                .unwrap_err()
                .contains("another instance")
        );
        let mut gone = big.clone();
        gone.status.phase = VolumePhase::Deleting;
        w.volumes
            .get_mut(&scope)
            .unwrap()
            .insert(gone.metadata.name.clone(), gone);
        assert!(needs(&w, &inst(&["big"])).unwrap_err().contains("deleted"));
        let mut elsewhere = vol(
            "elsewhere",
            1,
            json!({"phase": "ready", "pool": {"name": "p1", "uid": p1.metadata.uid}}),
        );
        elsewhere.metadata.uid = Uuid::now_v7();
        w.volumes
            .get_mut(&scope)
            .unwrap()
            .insert(elsewhere.metadata.name.clone(), elsewhere);
        assert!(
            needs(&w, &inst(&["placed", "elsewhere"]))
                .unwrap_err()
                .contains("different nodes")
        );
    }
}
