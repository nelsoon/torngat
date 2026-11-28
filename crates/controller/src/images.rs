//! Images on the controller.
//!
//! The sizes are known only on the node, so the volumes come in steps (each one a compare-and-swap
//! that the next pass repeats if it was interrupted):
//! 1. a pending image gets a node: one with a usable pool of its volume type and the most room;
//! 2. the node reports the length of the download: the staging volume `<image>-staging` is made
//!    and placed there;
//! 3. the node reports the format and the size of the disk: the volume `<image>-image` is made and
//!    placed there;
//! 4. the node reports that it is done: the image is ready and the staging volume is deleted.
//!
//! Both volumes are owned by the image (`status.owner`), are never attached to an instance, and are
//! deleted with it. Values that the node reports are checked and written once.

use std::collections::{BTreeMap, BTreeSet};

use tonic::Status;
use torngat_api::image::{Image, ImageFormat, ImagePhase, image_of, image_volume, staging_volume};
use torngat_api::storage::{
    GIB, MAX_VOLUME_GIB, StoragePool, Volume, VolumeOwner, VolumePhase, VolumeSpec, VolumeType,
};
use torngat_api::{Name, Scope};
use torngat_store::{Precondition, Store, StoreError};
use uuid::Uuid;

use crate::disks::{changed, delete_volume, new_volume};
use crate::scheduler::ScheduleError;
use crate::storage::{PlaceError, all, get, modify, place_volume, rounded, unreadable, usable};
use crate::{Controller, keys};

/// Largest download and largest disk an image may have.
pub const MAX_IMAGE_BYTES: u64 = MAX_VOLUME_GIB * GIB;

/// The node with the most room in a usable pool of `volume_type`.
fn choose_node(
    pools: &BTreeMap<Name, StoragePool>,
    types: &BTreeMap<Name, VolumeType>,
    volume_type: &Name,
    live: impl Fn(&Name) -> bool,
) -> Option<Name> {
    let t = types.get(volume_type)?;
    t.spec
        .pools
        .iter()
        .filter_map(|p| pools.get(p))
        .filter(|p| usable(p) && live(&p.spec.node))
        .map(|p| {
            let free = p
                .status
                .capacity_bytes
                .saturating_sub(p.status.reserved_bytes());
            (free, p)
        })
        // Room for at least the smallest volume.
        .filter(|(free, p)| *free >= rounded(p, GIB))
        .max_by_key(|(free, _)| *free)
        .map(|(_, p)| p.spec.node.clone())
}

/// One pass. Returns how many objects it changed.
pub async fn images_once(ctl: &Controller) -> Result<usize, ScheduleError> {
    let store = &ctl.store;
    // Volumes before images: a volume is made only for an image that exists, so the image of every
    // volume read is in the list below unless it is gone.
    let volumes = all::<Volume>(store, &keys::all_volumes()?)
        .await?
        .ok_or_else(unreadable)?;
    let images = all::<Image>(store, &keys::all_images()?)
        .await?
        .ok_or_else(unreadable)?;
    let pools: BTreeMap<Name, StoragePool> = all::<StoragePool>(store, &keys::storage_pools()?)
        .await?
        .ok_or_else(unreadable)?
        .into_iter()
        .map(|(p, _)| (p.metadata.name.clone(), p))
        .collect();
    let types: BTreeMap<Name, VolumeType> = all::<VolumeType>(store, &keys::volume_types()?)
        .await?
        .ok_or_else(unreadable)?
        .into_iter()
        .map(|(t, _)| (t.metadata.name.clone(), t))
        .collect();
    let by_name: BTreeMap<(&Scope, &Name), &Volume> = volumes
        .iter()
        .map(|(v, _)| ((&v.metadata.scope, &v.metadata.name), v))
        .collect();

    let mut count = 0;
    for (image, stored) in &images {
        let r = step(ctl, image, stored.revision, &by_name, &pools, &types).await;
        match r {
            Ok(n) => count += n,
            Err(e) => {
                tracing::warn!(image = %image.metadata.name, error = %e, "image pass failed");
            }
        }
    }

    // Volumes of images that are gone.
    let alive: BTreeSet<Uuid> = images.iter().map(|(i, _)| i.metadata.uid).collect();
    for (v, _) in &volumes {
        if let Some(VolumeOwner::Image { image }) = v.status.owner
            && !alive.contains(&image)
        {
            match delete_volume(store, v).await {
                Ok(n) => count += n,
                Err(e) => {
                    tracing::warn!(volume = %v.metadata.name, error = %e, "cannot delete a volume of a gone image");
                }
            }
        }
    }
    Ok(count)
}

async fn step(
    ctl: &Controller,
    image: &Image,
    revision: u64,
    volumes: &BTreeMap<(&Scope, &Name), &Volume>,
    pools: &BTreeMap<Name, StoragePool>,
    types: &BTreeMap<Name, VolumeType>,
) -> Result<usize, ScheduleError> {
    let store = &ctl.store;
    let scope = &image.metadata.scope;
    let uid = image.metadata.uid;
    let (Ok(staging), Ok(target)) = (
        staging_volume(&image.metadata.name),
        image_volume(&image.metadata.name),
    ) else {
        return Ok(0);
    };
    let owner = VolumeOwner::Image { image: uid };
    let own = |n: &Name| {
        volumes
            .get(&(scope, n))
            .copied()
            .filter(|v| v.status.owner == Some(owner))
    };

    if image.metadata.delete_time.is_some() {
        let mut count = 0;
        let mut left = false;
        for v in [own(&staging), own(&target)].into_iter().flatten() {
            left = true;
            count += delete_volume(store, v).await?;
        }
        if !left {
            let key = keys::image(scope, &image.metadata.name)?;
            match store.delete(key, Precondition::Revision(revision)).await {
                Ok(_) => count += 1,
                Err(StoreError::PreconditionFailed { .. }) => {}
                Err(e) => return Err(e.into()),
            }
        }
        return Ok(count);
    }

    match image.status.phase {
        ImagePhase::Pending => {
            let Some(node) = choose_node(pools, types, &image.spec.volume_type, |n| {
                ctl.live.is_live(n)
            }) else {
                return tell(store, image, "waiting for room in its volume type").await;
            };
            changed(
                modify_image(store, image, |i| {
                    if i.status.phase != ImagePhase::Pending || i.status.node.is_some() {
                        return false;
                    }
                    i.status.node = Some(node.clone());
                    i.status.phase = ImagePhase::Importing;
                    i.status.message = None;
                    true
                })
                .await,
            )
        }
        ImagePhase::Importing => {
            let Some(node) = &image.status.node else {
                return Ok(0);
            };
            let mut count = 0;
            let wanted = [
                (staging, image.status.download_bytes),
                (target, Some(image.status.size_bytes).filter(|b| *b > 0)),
            ];
            for (n, bytes) in wanted {
                let Some(bytes) = bytes else { continue };
                match volumes.get(&(scope, &n)) {
                    None => {
                        let spec = VolumeSpec {
                            volume_type: image.spec.volume_type.clone(),
                            size_gib: bytes.div_ceil(GIB).clamp(1, MAX_VOLUME_GIB),
                            delete_protection: false,
                        };
                        let v = new_volume(scope, &n, spec, owner);
                        let key = keys::volume(scope, &n)?;
                        match store
                            .put(key, serde_json::to_vec(&v)?, Precondition::Absent)
                            .await
                        {
                            Ok(_) => count += 1,
                            Err(StoreError::PreconditionFailed { .. }) => {}
                            Err(e) => return Err(e.into()),
                        }
                    }
                    Some(v) if v.status.owner == Some(owner) => {
                        if v.status.phase != VolumePhase::Pending {
                            continue;
                        }
                        match place_volume(ctl, scope, &n, v.metadata.uid, Some(node)).await {
                            Ok(_) | Err(PlaceError::Conflict | PlaceError::NotPending) => {
                                count += 1;
                            }
                            Err(PlaceError::NoRoom(_)) => {
                                count += tell(store, image, "waiting for room on its node").await?;
                            }
                            Err(PlaceError::Controller(e)) => return Err(e),
                            Err(e) => {
                                tracing::warn!(volume = %n, error = %e, "cannot place an image's volume");
                            }
                        }
                    }
                    Some(_) => {
                        let problem = format!("volume {n} already exists");
                        count += tell(store, image, &problem).await?;
                    }
                }
            }
            Ok(count)
        }
        // The staging volume is no longer needed; nor is anything of a failed image.
        ImagePhase::Ready | ImagePhase::Failed => {
            let mut done = vec![own(&staging)];
            if image.status.phase == ImagePhase::Failed {
                done.push(own(&target));
            }
            let mut count = 0;
            for v in done.into_iter().flatten() {
                count += delete_volume(store, v).await?;
            }
            Ok(count)
        }
        // Set with the delete time, handled above.
        ImagePhase::Deleting => Ok(0),
    }
}

async fn modify_image(
    store: &Store,
    image: &Image,
    mut change: impl FnMut(&mut Image) -> bool,
) -> Result<Option<Image>, PlaceError> {
    let key = keys::image(&image.metadata.scope, &image.metadata.name)?;
    let uid = image.metadata.uid;
    modify(store, &key, |i: &mut Image| {
        if i.metadata.uid != uid || i.metadata.delete_time.is_some() || !change(i) {
            return false;
        }
        i.metadata.etag = None;
        true
    })
    .await
}

/// Shows a problem in the image's status. Messages are for tenants: no node or pool names.
async fn tell(store: &Store, image: &Image, problem: &str) -> Result<usize, ScheduleError> {
    if image.status.message.as_deref() == Some(problem) {
        return Ok(0);
    }
    changed(
        modify_image(store, image, |i| {
            // Not on an image that is done meanwhile.
            let busy = matches!(i.status.phase, ImagePhase::Pending | ImagePhase::Importing);
            if !busy || i.status.message.as_deref() == Some(problem) {
                return false;
            }
            i.status.message = Some(problem.to_owned());
            true
        })
        .await,
    )
}

/// The images that `node` imports now.
pub(crate) async fn assigned_images(
    store: &Store,
    node: &Name,
) -> Result<Vec<Vec<u8>>, ScheduleError> {
    let images = all::<Image>(store, &keys::all_images()?)
        .await?
        .ok_or_else(unreadable)?;
    Ok(images
        .into_iter()
        .filter(|(i, _)| {
            i.status.node.as_ref() == Some(node)
                && i.status.phase == ImagePhase::Importing
                && i.metadata.delete_time.is_none()
        })
        .map(|(_, v)| v.value)
        .collect())
}

/// Whether `v` holds or stages an image that `node` imports now: then the node may have its key.
pub(crate) async fn importing_on(
    store: &Store,
    node: &Name,
    v: &Volume,
) -> Result<bool, PlaceError> {
    let (Some(VolumeOwner::Image { image }), Some(name)) =
        (v.status.owner, image_of(&v.metadata.name))
    else {
        return Ok(false);
    };
    let Some((i, _)) = get::<Image>(store, &keys::image(&v.metadata.scope, &name)?).await? else {
        return Ok(false);
    };
    Ok(i.metadata.uid == image
        && i.metadata.delete_time.is_none()
        && i.status.phase == ImagePhase::Importing
        && i.status.node.as_ref() == Some(node))
}

/// What a node reports about an image it imports.
#[derive(Debug, Default)]
pub(crate) struct ImageState {
    pub uid: Uuid,
    pub download_bytes: Option<u64>,
    pub format: Option<ImageFormat>,
    pub size_bytes: Option<u64>,
    pub done: bool,
    pub failed: bool,
    pub message: Option<String>,
}

pub(crate) async fn report_image(
    store: &Store,
    node: &Name,
    scope: &Scope,
    name: &Name,
    r: ImageState,
) -> Result<(), Status> {
    use crate::service::internal;
    let denied = || Status::permission_denied("the image is not imported by this node");
    let bad = |m: &str| Status::invalid_argument(m.to_owned());
    let key = keys::image(scope, name).map_err(internal)?;
    let (image, _) = get::<Image>(store, &key)
        .await
        .map_err(internal)?
        .ok_or_else(denied)?;
    if image.metadata.uid != r.uid || image.status.node.as_ref() != Some(node) {
        return Err(denied());
    }
    if image.metadata.delete_time.is_some() || image.status.phase != ImagePhase::Importing {
        return Err(Status::failed_precondition(
            "the image is not being imported",
        ));
    }
    let size_ok = |b: u64| (1..=MAX_IMAGE_BYTES).contains(&b);
    if r.download_bytes.is_some_and(|b| !size_ok(b)) || r.size_bytes.is_some_and(|b| !size_ok(b)) {
        return Err(bad("size out of range"));
    }
    if r.format.is_some() != r.size_bytes.is_some() {
        return Err(bad("format and size come together"));
    }
    if r.done && r.failed {
        return Err(bad("done or failed, not both"));
    }
    if r.failed && r.message.is_none() {
        return Err(bad("a failure needs a message"));
    }
    let target = image_volume(name).map_err(internal)?;
    if r.done {
        let v = get::<Volume>(store, &keys::volume(scope, &target).map_err(internal)?)
            .await
            .map_err(internal)?;
        let ready = v.is_some_and(|(v, _)| {
            v.status.owner == Some(VolumeOwner::Image { image: r.uid })
                && v.status.phase == VolumePhase::Ready
                && v.status.formatted
        });
        if !ready {
            return Err(Status::failed_precondition(
                "the image's volume is not ready",
            ));
        }
    }

    let mut refused: Option<Status> = None;
    let written = modify(store, &key, |i: &mut Image| {
        if i.metadata.uid != r.uid
            || i.metadata.delete_time.is_some()
            || i.status.phase != ImagePhase::Importing
            || i.status.node.as_ref() != Some(node)
        {
            refused = Some(Status::failed_precondition(
                "the image is not being imported",
            ));
            return false;
        }
        let mut new = i.status.clone();
        // Written once: what a volume was made from never changes.
        if let Some(b) = r.download_bytes {
            if new.download_bytes.is_some_and(|old| old != b) {
                refused = Some(Status::failed_precondition(
                    "the download size was reported",
                ));
                return false;
            }
            new.download_bytes = Some(b);
        }
        if let (Some(f), Some(b)) = (r.format, r.size_bytes) {
            let known = new.format.is_some() || new.size_bytes != 0;
            if known && (new.format, new.size_bytes) != (Some(f), b) {
                refused = Some(Status::failed_precondition("the format was reported"));
                return false;
            }
            if new.download_bytes.is_none() {
                refused = Some(Status::failed_precondition(
                    "report the download size first",
                ));
                return false;
            }
            new.format = Some(f);
            new.size_bytes = b;
        }
        if r.done {
            if new.size_bytes == 0 {
                refused = Some(Status::failed_precondition("report the format first"));
                return false;
            }
            new.phase = ImagePhase::Ready;
        }
        if r.failed {
            new.phase = ImagePhase::Failed;
        }
        // A report without a message keeps the controller's.
        if r.done {
            new.message = None;
        } else if r.message.is_some() {
            new.message.clone_from(&r.message);
        }
        if new == i.status {
            return false;
        }
        i.status = new;
        i.metadata.etag = None;
        true
    })
    .await;
    if let Some(s) = refused {
        return Err(s);
    }
    match written {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(denied()),
        Err(PlaceError::Conflict) => Err(Status::aborted("concurrent change, retry")),
        Err(e) => Err(internal(e)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use serde_json::json;

    fn obj<T: serde::de::DeserializeOwned>(
        name: &str,
        spec: serde_json::Value,
        status: serde_json::Value,
    ) -> T {
        serde_json::from_value(json!({
            "metadata": {"name": name, "scope": {"kind": "platform"}, "uid": Uuid::now_v7()},
            "spec": spec, "status": status,
        }))
        .unwrap()
    }

    #[test]
    fn node_with_most_room() {
        let pool = |name: &str, node: &str, cap: u64, ready: bool| -> StoragePool {
            obj(
                name,
                json!({"node": node, "driver": "lvm", "source": "data"}),
                json!({"claimed": true, "ready": ready, "capacity_bytes": cap,
                       "allocation_unit_bytes": 4 << 20}),
            )
        };
        let pools: BTreeMap<Name, StoragePool> = [
            pool("p1", "n1", 5 * GIB, true),
            pool("p2", "n2", 9 * GIB, true),
            pool("p3", "n3", 99 * GIB, false),
            pool("p4", "n4", GIB / 2, true),
        ]
        .into_iter()
        .map(|p| (p.metadata.name.clone(), p))
        .collect();
        let t = |name: &str, pools: serde_json::Value| -> (Name, VolumeType) {
            (
                Name::new(name).unwrap(),
                obj(name, json!({"pools": pools}), json!(null)),
            )
        };
        let types: BTreeMap<Name, VolumeType> = [
            t("all", json!(["p1", "p2", "p3", "p4"])),
            t("small", json!(["p4"])),
            t("missing", json!(["nope"])),
        ]
        .into_iter()
        .collect();
        let n = |s: &str| Name::new(s).unwrap();
        assert_eq!(
            choose_node(&pools, &types, &n("all"), |_| true),
            Some(n("n2"))
        );
        // Only live nodes.
        let not_n2 = |x: &Name| x.as_str() != "n2";
        assert_eq!(
            choose_node(&pools, &types, &n("all"), not_n2),
            Some(n("n1"))
        );
        assert_eq!(choose_node(&pools, &types, &n("small"), |_| true), None);
        assert_eq!(choose_node(&pools, &types, &n("missing"), |_| true), None);
        assert_eq!(choose_node(&pools, &types, &n("unknown"), |_| true), None);
    }
}
