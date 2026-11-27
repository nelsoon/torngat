//! Minimal scheduler: place each pending, desired-running instance on the live compute node with
//! the most free memory that can fit it, and where its volumes are or fit. Topology-aware placement
//! (claims, NUMA) comes later.

use std::collections::HashMap;

use torngat_api::Name;
use torngat_api::compute::{Instance, InstancePhase, PowerState};
use torngat_api::node::{Node, NodePhase, Role};
use torngat_store::{MAX_LIST, Precondition, StoreError};

use crate::disks::{self, World};
use crate::{Controller, keys};

#[derive(Debug, thiserror::Error)]
pub enum ScheduleError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Key(#[from] torngat_store::KeyError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Reads every object under a prefix, page by page.
pub(crate) async fn list_all(
    store: &torngat_store::Store,
    prefix: &torngat_store::Prefix,
) -> Result<Vec<(torngat_store::Key, torngat_store::Versioned)>, StoreError> {
    let mut out = Vec::new();
    let mut after = None;
    loop {
        let page = store.list(prefix, after.as_ref(), MAX_LIST).await?;
        let full = page.len() == MAX_LIST;
        after = page.last().map(|(k, _)| k.clone());
        out.extend(page);
        if !full {
            return Ok(out);
        }
    }
}

fn node_memory_mib(n: &Node) -> u64 {
    n.status
        .inventory
        .numa_nodes
        .iter()
        .map(|z| z.memory_bytes / (1024 * 1024))
        .sum()
}

/// One scheduling pass. Returns the number of instances placed. `world` is what the disks pass
/// read; without it (an object that does not decode), instances with disks wait.
pub async fn schedule_once(
    ctl: &Controller,
    world: Option<&World>,
) -> Result<usize, ScheduleError> {
    let nodes: Vec<Node> = list_all(&ctl.store, &keys::nodes()?)
        .await?
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice(&v.value).ok())
        .collect();
    let instances = list_all(&ctl.store, &keys::all_instances()?).await?;

    // Memory already committed per node.
    let mut used: HashMap<Name, u64> = HashMap::new();
    let mut pending = Vec::new();
    for (k, v) in instances {
        let Ok(i) = serde_json::from_slice::<Instance>(&v.value) else {
            continue;
        };
        match &i.status.node {
            Some(n) => *used.entry(n.clone()).or_default() += i.spec.memory_mib,
            None if i.spec.power_state == PowerState::Running => pending.push((k, v.revision, i)),
            None => {}
        }
    }

    let mut placed = 0;
    for (key, rev, mut inst) in pending {
        let no_disks = inst.spec.boot_disk.is_none() && inst.spec.disks.is_empty();
        let needs = match world {
            _ if no_disks => disks::Needs::default(),
            None => continue,
            Some(w) => match disks::needs(w, &inst) {
                Ok(n) => n,
                Err(problem) => {
                    disks::tell(ctl, &inst, &problem).await?;
                    continue;
                }
            },
        };
        let best = nodes
            .iter()
            .filter(|n| {
                n.spec.roles.contains(&Role::Compute)
                    && !n.spec.unschedulable
                    && n.status.phase == NodePhase::Active
                    && ctl.live.is_live(&n.metadata.name)
                    && needs.node.as_ref().is_none_or(|x| *x == n.metadata.name)
                    && (needs.pending.is_empty()
                        || world.is_some_and(|w| disks::fits(w, &n.metadata.name, &needs.pending)))
            })
            .filter_map(|n| {
                let free = node_memory_mib(n)
                    .saturating_sub(used.get(&n.metadata.name).copied().unwrap_or(0));
                (free >= inst.spec.memory_mib).then_some((free, &n.metadata.name))
            })
            .max_by_key(|(free, _)| *free);
        let Some((_, node)) = best else {
            continue;
        };
        // Its volumes first: an instance on a node always has them there.
        if let (Some(w), false) = (world, no_disks)
            && let Err(problem) = disks::attach_all(ctl, w, &inst, node).await
        {
            disks::tell(ctl, &inst, &problem).await?;
            continue;
        }
        inst.status.node = Some(node.clone());
        inst.status.phase = InstancePhase::Scheduled;
        inst.metadata.etag = None;
        match ctl
            .store
            .put(key, serde_json::to_vec(&inst)?, Precondition::Revision(rev))
            .await
        {
            Ok(_) => {
                *used.entry(node.clone()).or_default() += inst.spec.memory_mib;
                placed += 1;
            }
            // Changed concurrently (user update or delete): next pass will see it.
            Err(StoreError::PreconditionFailed { .. }) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(placed)
}
