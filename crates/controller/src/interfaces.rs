//! Interfaces of instances: a MAC and an address each.
//!
//! The address comes from the network: a private network's own range (its first address is its
//! router's), or a provider network's pool. It is recorded in that network's status with
//! compare-and-swap, so that no address is given twice, and kept as long as the instance lists the
//! network. Networks are read before instances: an address is released only if its instance is
//! not in a list read after it.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use torngat_api::compute::Instance;
use torngat_api::network::{
    HostNetwork, InterfaceStatus, Network, NetworkSpec, NetworkStatus, NodeNetworks,
    ProviderNetwork, mac_of,
};
use torngat_api::{Name, Object, Scope};
use torngat_store::{Key, Store};
use uuid::Uuid;

use crate::disks::{changed, tell};
use crate::scheduler::ScheduleError;
use crate::storage::{PlaceError, all, modify, unreadable};
use crate::{Controller, keys};

/// Where an interface gets its address.
struct Source {
    key: Key,
    uid: Uuid,
    first: Ipv4Addr,
    last: Ipv4Addr,
}

/// The lowest free address of `first..=last` for `inst` (its own if it has one), recorded in the
/// network at `key` if it is still the network `uid`.
async fn allocate(store: &Store, src: &Source, inst: Uuid) -> Result<Option<Ipv4Addr>, PlaceError> {
    let mut got = None;
    modify(
        store,
        &src.key,
        |o: &mut Object<serde_json::Value, NetworkStatus>| {
            // Again on every try: a try that lost its write recorded nothing.
            got = None;
            if o.metadata.uid != src.uid || o.metadata.delete_time.is_some() {
                return false;
            }
            let a = &mut o.status.allocations;
            if let Some((ip, _)) = a.iter().find(|(_, u)| **u == inst) {
                got = Some(*ip);
                return false;
            }
            let free = (u32::from(src.first)..=u32::from(src.last))
                .map(Ipv4Addr::from)
                .find(|ip| !a.contains_key(ip));
            let Some(ip) = free else {
                return false;
            };
            a.insert(ip, inst);
            got = Some(ip);
            o.metadata.etag = None;
            true
        },
    )
    .await?;
    Ok(got)
}

/// Removes `ip` from the network at `key` if it is still `inst`'s.
async fn release(
    store: &Store,
    key: &Key,
    ip: Ipv4Addr,
    inst: Uuid,
) -> Result<usize, ScheduleError> {
    changed(
        modify(
            store,
            key,
            |o: &mut Object<serde_json::Value, NetworkStatus>| {
                if o.status.allocations.get(&ip) != Some(&inst) {
                    return false;
                }
                o.status.allocations.remove(&ip);
                o.metadata.etag = None;
                true
            },
        )
        .await,
    )
}

/// One pass. Returns how many objects it changed.
pub async fn interfaces_once(ctl: &Controller) -> Result<usize, ScheduleError> {
    let store = &ctl.store;
    let networks = all::<Network>(store, &keys::all_networks()?)
        .await?
        .ok_or_else(unreadable)?;
    let providers = all::<ProviderNetwork>(store, &keys::provider_networks()?)
        .await?
        .ok_or_else(unreadable)?;
    let instances = all::<Instance>(store, &keys::all_instances()?)
        .await?
        .ok_or_else(unreadable)?;
    let nets: BTreeMap<(&Scope, &Name), &Network> = networks
        .iter()
        .map(|(n, _)| ((&n.metadata.scope, &n.metadata.name), n))
        .collect();
    let pnets: BTreeMap<&Name, &ProviderNetwork> = providers
        .iter()
        .map(|(p, _)| (&p.metadata.name, p))
        .collect();

    // Where each instance's interfaces have their addresses (by key), to keep them: all of them,
    // even if one of its interfaces cannot have one now.
    let mut wanted: BTreeSet<(Key, Uuid)> = BTreeSet::new();
    for (inst, _) in &instances {
        for iref in &inst.spec.interfaces {
            let key = match nets
                .get(&(&inst.metadata.scope, &iref.network))
                .map(|n| &n.spec)
            {
                Some(NetworkSpec::Private { .. }) => {
                    keys::network(&inst.metadata.scope, &iref.network)
                }
                Some(NetworkSpec::Provider { network }) => keys::provider_network(network),
                None => continue,
            };
            wanted.insert((key?, inst.metadata.uid));
        }
    }
    let mut count = 0;
    for (inst, _) in &instances {
        let r = async {
            let scope = &inst.metadata.scope;
            let mut out = Vec::new();
            // Two networks of the project on one provider network would be one address for two
            // interfaces.
            let mut sources = BTreeSet::new();
            for (i, iref) in inst.spec.interfaces.iter().enumerate() {
                let n = &iref.network;
                let Some(net) = nets
                    .get(&(scope, n))
                    .filter(|x| x.metadata.delete_time.is_none())
                else {
                    return Err(format!("there is no network {n}"));
                };
                let src = match &net.spec {
                    NetworkSpec::Private { cidr } => {
                        let (lo, hi) = cidr.hosts();
                        // The first address is the network's router.
                        Source {
                            key: keys::network(scope, n).map_err(|e| e.to_string())?,
                            uid: net.metadata.uid,
                            first: Ipv4Addr::from(u32::from(lo) + 1),
                            last: hi,
                        }
                    }
                    NetworkSpec::Provider { network } => {
                        let Some(p) = pnets
                            .get(network)
                            .filter(|p| p.spec.tenants && p.metadata.delete_time.is_none())
                        else {
                            return Err(format!("network {n} cannot be used now"));
                        };
                        Source {
                            key: keys::provider_network(network).map_err(|e| e.to_string())?,
                            uid: p.metadata.uid,
                            first: p.spec.pool.first,
                            last: p.spec.pool.last,
                        }
                    }
                };
                if !sources.insert(src.key.clone()) {
                    return Err(format!(
                        "network {n} is on the same provider network as another interface's"
                    ));
                }
                // Always through the store: an address read earlier may have been released
                // since by another controller's pass.
                let ip = allocate(store, &src, inst.metadata.uid)
                    .await
                    .map_err(|e| e.to_string())?;
                if ip.is_none() {
                    return Err(format!("network {n} has no free address"));
                }
                out.push(InterfaceStatus {
                    network: n.clone(),
                    network_uid: net.metadata.uid,
                    mac: mac_of(inst.metadata.uid, i),
                    ip,
                });
            }
            Ok(out)
        }
        .await;
        match r {
            Ok(out) if out != inst.status.interfaces => {
                let key = keys::instance(&inst.metadata.scope, &inst.metadata.name)?;
                let uid = inst.metadata.uid;
                count += changed(
                    modify(store, &key, |i: &mut Instance| {
                        if i.metadata.uid != uid || i.spec.interfaces != inst.spec.interfaces {
                            return false;
                        }
                        i.status.interfaces.clone_from(&out);
                        i.metadata.etag = None;
                        true
                    })
                    .await,
                )?;
            }
            Ok(_) => {}
            Err(problem) => count += tell(ctl, inst, &problem).await?,
        }
    }

    // Addresses no instance wants any more.
    let lists: BTreeSet<Uuid> = instances.iter().map(|(i, _)| i.metadata.uid).collect();
    let held = networks
        .iter()
        .map(|(n, _)| {
            (
                keys::network(&n.metadata.scope, &n.metadata.name),
                &n.status,
            )
        })
        .chain(
            providers
                .iter()
                .map(|(p, _)| (keys::provider_network(&p.metadata.name), &p.status)),
        );
    for (key, status) in held {
        let key = key?;
        for (ip, u) in &status.allocations {
            // Kept: a listed instance's address on a network it lists, and nodes' addresses. An
            // owner not in the list is gone: the list was read after the network, so an instance
            // made since has no address in it.
            let unwanted = if lists.contains(u) {
                !wanted.contains(&(key.clone(), *u))
            } else {
                !is_node_address(*u)
            };
            if unwanted {
                count += release(store, &key, *ip, *u).await?;
            }
        }
    }
    Ok(count)
}

/// Addresses that nodes hold for their NAT (M1.4b) are recorded under the node's uid: never
/// released here. None yet.
fn is_node_address(_owner: Uuid) -> bool {
    false
}

/// What `node` is told of networks (JSON of [`NodeNetworks`]): deleted ones too, so it can take
/// them apart.
pub(crate) async fn assigned_networks(
    store: &Store,
    node: &Name,
) -> Result<Vec<u8>, ScheduleError> {
    let instances = all::<Instance>(store, &keys::all_instances()?)
        .await?
        .ok_or_else(unreadable)?;
    let named: BTreeSet<(&Scope, &Name)> = instances
        .iter()
        .filter(|(i, _)| i.status.node.as_ref() == Some(node))
        .flat_map(|(i, _)| {
            i.spec
                .interfaces
                .iter()
                .map(|f| (&i.metadata.scope, &f.network))
        })
        .collect();
    let networks: Vec<Network> = all::<Network>(store, &keys::all_networks()?)
        .await?
        .ok_or_else(unreadable)?
        .into_iter()
        .map(|(n, _)| n)
        .filter(|n| named.contains(&(&n.metadata.scope, &n.metadata.name)))
        .collect();
    let providers_named: BTreeSet<&Name> = networks
        .iter()
        .filter_map(|n| match &n.spec {
            NetworkSpec::Provider { network } => Some(network),
            NetworkSpec::Private { .. } => None,
        })
        .collect();
    let provider_networks = all::<ProviderNetwork>(store, &keys::provider_networks()?)
        .await?
        .ok_or_else(unreadable)?
        .into_iter()
        .map(|(p, _)| p)
        .filter(|p| p.spec.egress || providers_named.contains(&p.metadata.name))
        .collect();
    let host_networks = all::<HostNetwork>(store, &keys::host_networks()?)
        .await?
        .ok_or_else(unreadable)?
        .into_iter()
        .map(|(h, _)| h)
        .filter(|h| &h.spec.node == node)
        .collect();
    Ok(serde_json::to_vec(&NodeNetworks {
        host_networks,
        provider_networks,
        networks,
    })?)
}
