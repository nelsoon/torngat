//! Instance disks.
//!
//! - A boot disk is the volume `<instance>-boot`, made by the controller and owned by the instance
//!   (`status.owner`); it is deleted when the instance is gone, unless `boot_disk.keep`.
//! - A volume is attached (`status.attached_to`) to the one instance that lists it, once that
//!   instance has a node: placed on that node first if it was not placed yet. Local volumes bind
//!   instances to their node, so the scheduler takes them into account ([`Needs`]).
//! - A volume is released when its instance is gone or no longer lists it (only while stopped: the
//!   API refuses it otherwise).
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

type Key = (Scope, Name);

fn key_of(v: &Volume) -> Key {
    (v.metadata.scope.clone(), v.metadata.name.clone())
}

/// Every instance, pool, type and volume, or `None` if one does not decode.
pub(crate) struct World {
    pub instances: Vec<Instance>,
    pub volumes: BTreeMap<Key, Volume>,
    pub pools: BTreeMap<Name, StoragePool>,
    pub types: BTreeMap<Name, VolumeType>,
}

impl World {
    pub(crate) async fn read(store: &Store) -> Result<Option<Self>, ScheduleError> {
        let (Some(instances), Some(volumes), Some(pools), Some(types)) = (
            all::<Instance>(store, &keys::all_instances()?).await?,
            all::<Volume>(store, &keys::all_volumes()?).await?,
            all::<StoragePool>(store, &keys::storage_pools()?).await?,
            all::<VolumeType>(store, &keys::volume_types()?).await?,
        ) else {
            return Ok(None);
        };
        Ok(Some(Self {
            instances: instances.into_iter().map(|(i, _)| i).collect(),
            volumes: volumes.into_iter().map(|(v, _)| (key_of(&v), v)).collect(),
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

    /// The node of a placed volume's pool.
    fn node_of(&self, v: &Volume) -> Option<&Name> {
        let r = v.status.pool.as_ref()?;
        self.pools
            .get(&r.name)
            .filter(|p| p.metadata.uid == r.uid)
            .map(|p| &p.spec.node)
    }
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
    let names = inst
        .spec
        .volumes(&inst.metadata.name)
        .map_err(|e| e.to_string())?;
    let mut out = Needs::default();
    for n in names {
        let Some(v) = w.volumes.get(&(scope.clone(), n.clone())) else {
            return Err(format!("there is no volume {n}"));
        };
        if v.metadata.delete_time.is_some() || v.status.phase == VolumePhase::Deleting {
            return Err(format!("volume {n} is being deleted"));
        }
        if v.status.attached_to.is_some_and(|u| u != inst.metadata.uid) {
            return Err(format!("volume {n} is used by another instance"));
        }
        if v.status.pool.is_none() {
            out.pending.push(v.clone());
            continue;
        }
        let Some(node) = w.node_of(v) else {
            return Err(format!("volume {n} is being placed"));
        };
        match &out.node {
            Some(other) if other != node => {
                return Err(format!(
                    "its volumes are on different nodes ({other}, {node})"
                ));
            }
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

/// Attaches `inst`'s volume `name` on `node`, placing it there first if needed.
pub(crate) async fn attach(
    ctl: &Controller,
    inst: &Instance,
    name: &Name,
    node: &Name,
) -> Result<(), String> {
    let scope = &inst.metadata.scope;
    let key = keys::volume(scope, name).map_err(|e| e.to_string())?;
    let me = inst.metadata.uid;
    for _ in 0..4 {
        let Some((v, _)) = get::<Volume>(&ctl.store, &key).await.map_err(err)? else {
            return Err(format!("there is no volume {name}"));
        };
        if v.metadata.delete_time.is_some() || v.status.phase == VolumePhase::Deleting {
            return Err(format!("volume {name} is being deleted"));
        }
        if v.status.attached_to.is_some_and(|u| u != me) {
            return Err(format!("volume {name} is used by another instance"));
        }
        match v.status.phase {
            VolumePhase::Pending => {
                match place_volume(ctl, scope, name, v.metadata.uid, Some(node)).await {
                    Ok(_) | Err(PlaceError::Conflict | PlaceError::NotPending) => continue,
                    Err(e) => return Err(format!("volume {name}: {e}")),
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
            return Ok(());
        }
        let uid = v.metadata.uid;
        modify(&ctl.store, &key, |v: &mut Volume| {
            if v.metadata.uid != uid || v.status.attached_to.is_some() {
                return false;
            }
            v.status.attached_to = Some(me);
            v.metadata.etag = None;
            true
        })
        .await
        .map_err(|e| e.to_string())?;
    }
    Err(format!("volume {name} changed meanwhile"))
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn now() -> Option<OffsetDateTime> {
    Some(OffsetDateTime::now_utc())
}

/// One pass. Returns how many objects it changed.
pub async fn disks_once(ctl: &Controller) -> Result<usize, ScheduleError> {
    let Some(w) = World::read(&ctl.store).await? else {
        tracing::warn!("an object does not decode: instance disks are left as they are");
        return Ok(0);
    };
    let mut changed = 0;
    let by_uid: BTreeMap<Uuid, &Instance> =
        w.instances.iter().map(|i| (i.metadata.uid, i)).collect();

    for inst in &w.instances {
        let problem = match boot_disk(ctl, &w, inst).await {
            Ok(n) => {
                changed += n;
                None
            }
            Err(e) => Some(e),
        };
        let problem = match (problem, &inst.status.node) {
            (Some(p), _) => Some(p),
            (None, None) => None,
            (None, Some(node)) => attach_all(ctl, inst, node).await.err(),
        };
        if let Some(p) = problem {
            changed += tell(ctl, inst, &p).await?;
        }
    }

    // Released when their instance is gone or no longer lists them; boot disks of a gone instance
    // are deleted.
    for v in w.volumes.values() {
        let user = v.status.attached_to.map(|u| by_uid.get(&u));
        let release = match user {
            Some(None) => true,
            Some(Some(i)) => !i
                .spec
                .volumes(&i.metadata.name)
                .is_ok_and(|names| names.contains(&v.metadata.name)),
            None => false,
        };
        if release {
            changed += release_volume(&ctl.store, v).await?;
        }
        if let Some(o) = v.status.owner
            && o.delete_with_it
            && !by_uid.contains_key(&o.instance)
            && !v.spec.delete_protection
        {
            changed += delete_volume(&ctl.store, v).await?;
        }
    }
    Ok(changed)
}

async fn attach_all(ctl: &Controller, inst: &Instance, node: &Name) -> Result<(), String> {
    for n in inst
        .spec
        .volumes(&inst.metadata.name)
        .map_err(|e| e.to_string())?
    {
        attach(ctl, inst, &n, node).await?;
    }
    Ok(())
}

/// Makes the boot volume, or keeps it in line with the instance (size, `keep`).
async fn boot_disk(ctl: &Controller, w: &World, inst: &Instance) -> Result<usize, String> {
    let (Some(boot), Some(name)) = (
        &inst.spec.boot_disk,
        inst.spec
            .boot_volume(&inst.metadata.name)
            .map_err(|e| e.to_string())?,
    ) else {
        return Ok(0);
    };
    let scope = &inst.metadata.scope;
    let owner = VolumeOwner {
        instance: inst.metadata.uid,
        delete_with_it: !boot.keep,
    };
    let key = keys::volume(scope, &name).map_err(err)?;
    match w.volumes.get(&(scope.clone(), name.clone())) {
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
            .map_err(|e| e.to_string())?;
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
    let r = modify(&ctl.store, &key, |i: &mut Instance| {
        if i.metadata.uid != uid || i.status.message.as_deref() == Some(problem) {
            return false;
        }
        i.status.message = Some(problem.to_owned());
        i.metadata.etag = None;
        true
    })
    .await;
    match r {
        Ok(_) | Err(PlaceError::Conflict) => Ok(1),
        Err(PlaceError::Controller(e)) => Err(e),
        Err(e) => Err(ScheduleError::Store(StoreError::Raft(e.to_string()))),
    }
}

async fn release_volume(store: &Store, v: &Volume) -> Result<usize, ScheduleError> {
    let key = keys::volume(&v.metadata.scope, &v.metadata.name)?;
    let (uid, user) = (v.metadata.uid, v.status.attached_to);
    let r = modify(store, &key, |cur: &mut Volume| {
        if cur.metadata.uid != uid || cur.status.attached_to != user {
            return false;
        }
        cur.status.attached_to = None;
        cur.metadata.etag = None;
        true
    })
    .await;
    match r {
        Ok(_) | Err(PlaceError::Conflict) => Ok(1),
        Err(PlaceError::Controller(e)) => Err(e),
        Err(e) => Err(ScheduleError::Store(StoreError::Raft(e.to_string()))),
    }
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
        let mut w = World {
            instances: vec![],
            volumes: [&on_p2, &small, &big]
                .into_iter()
                .map(|v| (key_of(v), v.clone()))
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
        w.volumes.insert(key_of(&used), used);
        assert!(
            needs(&w, &inst(&["small"]))
                .unwrap_err()
                .contains("another instance")
        );
        let mut gone = big.clone();
        gone.status.phase = VolumePhase::Deleting;
        w.volumes.insert(key_of(&gone), gone);
        assert!(needs(&w, &inst(&["big"])).unwrap_err().contains("deleted"));
        let mut elsewhere = vol(
            "elsewhere",
            1,
            json!({"phase": "ready", "pool": {"name": "p1", "uid": p1.metadata.uid}}),
        );
        elsewhere.metadata.uid = Uuid::now_v7();
        w.volumes.insert(key_of(&elsewhere), elsewhere);
        assert!(
            needs(&w, &inst(&["placed", "elsewhere"]))
                .unwrap_err()
                .contains("different nodes")
        );
    }
}
