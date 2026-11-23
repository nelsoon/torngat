//! Nodes and their hardware inventory.
//!
//! The inventory is typed and nested (node → NUMA node → devices, devices → child devices such as
//! SR-IOV VFs or GPU partitions) so the scheduler can express topology constraints like "a GPU
//! slice and a NIC VF on the same NUMA node".

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::meta::Object;

pub type Node = Object<NodeSpec, NodeStatus>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Controller,
    Compute,
    Storage,
    Gateway,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeSpec {
    pub roles: BTreeSet<Role>,
    /// Name of the `NodeProfile` (image flavour, kernel cmdline, reserved CPUs). `None` = default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<crate::Name>,
    /// When true, no new workloads are placed here (maintenance / drain).
    #[serde(default)]
    pub unschedulable: bool,
}

/// Lifecycle states of a node.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodePhase {
    #[default]
    Provisioning,
    Joining,
    Active,
    Maintenance,
    Draining,
    Decommissioned,
    Failed,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeStatus {
    #[serde(default)]
    pub phase: NodePhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    #[serde(default)]
    pub inventory: Inventory,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    #[default]
    X86_64,
    Aarch64,
    Riscv64,
}

/// What a node has. Reported by the agent; durable (changes rarely), so it lives in the store.
/// Liveness and utilisation are *not* here: they are soft state held in controller memory.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Inventory {
    pub arch: Arch,
    /// CPU model / feature baseline, e.g. "x86-64-v3", used for live-migration compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_model: Option<String>,
    #[serde(default)]
    pub numa_nodes: Vec<NumaNode>,
    #[serde(default)]
    pub devices: Vec<Device>,
    /// Free-form capability tags, e.g. "kvm", "tpm2", "sev-snp", "avx512".
    #[serde(default)]
    pub traits: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NumaNode {
    pub id: u32,
    /// Logical CPU ids.
    pub cpus: Vec<u32>,
    pub memory_bytes: u64,
    /// Hugepage counts keyed by page size in KiB (e.g. 2048, 1048576).
    #[serde(default)]
    pub hugepages: BTreeMap<u64, u64>,
    /// CPUs reserved for the host (agent, OVS PMD, Ceph) per the node profile.
    #[serde(default)]
    pub reserved_cpus: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    Gpu,
    /// A partition of a GPU (MIG instance, vGPU profile slot).
    GpuPartition,
    /// A physical network function.
    NicPf,
    /// An SR-IOV virtual function of a NIC.
    NicVf,
    /// Other accelerators (FPGA, DPU, crypto, AI ASIC).
    Accelerator,
    Disk,
    Tpm,
    Other,
}

/// A device. `id` is unique within the node; `parent` links VFs to PFs and partitions to GPUs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub kind: DeviceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub numa_node: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pci_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Typed attributes usable in claim selectors (e.g. memory_bytes, link_speed_mbps, profile).
    #[serde(default)]
    pub attributes: BTreeMap<String, AttrValue>,
}

/// A device attribute. Untagged: JSON `true`, `42`, `18446744073709551615`, `2.4` and `"x"` all
/// deserialize. Nulls, arrays and objects are rejected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttrValue {
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    String(String),
}

/// Bounds on agent-reported inventory, which is untrusted input to the controller.
pub const MAX_DEVICES: usize = 4096;
pub const MAX_NUMA_NODES: usize = 64;
pub const MAX_CPUS_PER_NUMA: usize = 4096;
pub const MAX_HUGEPAGE_SIZES: usize = 8;
pub const MAX_ATTRS_PER_DEVICE: usize = 64;
pub const MAX_TRAITS: usize = 1024;
pub const MAX_STR_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InventoryError {
    #[error("inventory exceeds limits")]
    TooLarge,
    #[error("device id {0:?} is duplicated")]
    DuplicateDevice(String),
    #[error("NUMA node {0} is duplicated")]
    DuplicateNuma(u32),
    #[error("NUMA node {0} reserves CPUs it does not have")]
    BadReservedCpus(u32),
    #[error("device {0:?} has unknown parent")]
    UnknownParent(String),
    #[error("device {0:?} refers to unknown NUMA node")]
    UnknownNuma(String),
    #[error("string field too long or contains control characters")]
    BadString,
    #[error("device parent chain of {0:?} contains a cycle")]
    ParentCycle(String),
}

/// True if `s` is short and free of control characters (safe to store, index and log).
fn good_str(s: &str) -> bool {
    s.len() <= MAX_STR_LEN && !s.chars().any(char::is_control)
}

impl NodeStatus {
    /// Validates the agent-reported part of a node's status.
    pub fn validate(&self) -> Result<(), InventoryError> {
        if let Some(v) = &self.agent_version
            && !good_str(v)
        {
            return Err(InventoryError::BadString);
        }
        self.inventory.validate()
    }
}

impl Inventory {
    /// Validates structure and bounds. The agent is a less-trusted component: a compromised node
    /// must not be able to exhaust controller memory, inject control characters into logs, or
    /// corrupt the topology graph the scheduler relies on.
    pub fn validate(&self) -> Result<(), InventoryError> {
        if self.devices.len() > MAX_DEVICES
            || self.numa_nodes.len() > MAX_NUMA_NODES
            || self.traits.len() > MAX_TRAITS
        {
            return Err(InventoryError::TooLarge);
        }
        if let Some(m) = &self.cpu_model
            && !good_str(m)
        {
            return Err(InventoryError::BadString);
        }
        if !self.traits.iter().all(|t| good_str(t)) {
            return Err(InventoryError::BadString);
        }

        let mut numa = BTreeSet::new();
        for n in &self.numa_nodes {
            if n.cpus.len() > MAX_CPUS_PER_NUMA
                || n.reserved_cpus.len() > MAX_CPUS_PER_NUMA
                || n.hugepages.len() > MAX_HUGEPAGE_SIZES
            {
                return Err(InventoryError::TooLarge);
            }
            if !numa.insert(n.id) {
                return Err(InventoryError::DuplicateNuma(n.id));
            }
            let cpus: BTreeSet<u32> = n.cpus.iter().copied().collect();
            if !n.reserved_cpus.iter().all(|c| cpus.contains(c)) {
                return Err(InventoryError::BadReservedCpus(n.id));
            }
        }

        let mut parents: BTreeMap<&str, Option<&str>> = BTreeMap::new();
        for d in &self.devices {
            let strs = [
                Some(&d.id),
                d.pci_address.as_ref(),
                d.vendor.as_ref(),
                d.model.as_ref(),
            ];
            if d.id.is_empty() || !strs.into_iter().flatten().all(|s| good_str(s)) {
                return Err(InventoryError::BadString);
            }
            if d.attributes.len() > MAX_ATTRS_PER_DEVICE
                || !d
                    .attributes
                    .iter()
                    .all(|(k, v)| good_str(k) && !matches!(v, AttrValue::String(s) if !good_str(s)))
            {
                return Err(InventoryError::BadString);
            }
            if parents.insert(d.id.as_str(), d.parent.as_deref()).is_some() {
                return Err(InventoryError::DuplicateDevice(d.id.clone()));
            }
            if let Some(n) = d.numa_node
                && !numa.contains(&n)
            {
                return Err(InventoryError::UnknownNuma(d.id.clone()));
            }
        }

        // Every parent must exist (reported against the device that names it).
        for (&id, &parent) in &parents {
            if let Some(p) = parent
                && !parents.contains_key(p)
            {
                return Err(InventoryError::UnknownParent(id.to_owned()));
            }
        }
        // The parent graph must be acyclic. Each device has at most one parent, so walking from
        // every unvisited device and memoising finished chains is O(devices) overall.
        let mut done: BTreeSet<&str> = BTreeSet::new();
        for &start in parents.keys() {
            let mut path: Vec<&str> = Vec::new();
            let mut on_path: BTreeSet<&str> = BTreeSet::new();
            let mut cur = Some(start);
            while let Some(id) = cur {
                if done.contains(id) {
                    break;
                }
                if !on_path.insert(id) {
                    return Err(InventoryError::ParentCycle(id.to_owned()));
                }
                path.push(id);
                cur = parents.get(id).copied().flatten();
            }
            done.extend(path);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(id: &str, kind: DeviceKind, parent: Option<&str>, numa: Option<u32>) -> Device {
        Device {
            id: id.into(),
            kind,
            parent: parent.map(Into::into),
            numa_node: numa,
            pci_address: None,
            vendor: None,
            model: None,
            attributes: BTreeMap::new(),
        }
    }

    fn inv(devices: Vec<Device>) -> Inventory {
        Inventory {
            numa_nodes: vec![NumaNode {
                id: 0,
                ..Default::default()
            }],
            devices,
            ..Default::default()
        }
    }

    #[test]
    fn valid_nested_inventory() {
        let i = inv(vec![
            dev("gpu0", DeviceKind::Gpu, None, Some(0)),
            dev("gpu0-mig1", DeviceKind::GpuPartition, Some("gpu0"), Some(0)),
            dev("nic0", DeviceKind::NicPf, None, Some(0)),
            dev("nic0-vf0", DeviceKind::NicVf, Some("nic0"), Some(0)),
        ]);
        assert_eq!(i.validate(), Ok(()));
    }

    #[test]
    fn rejects_bad_graphs() {
        let dup = inv(vec![
            dev("a", DeviceKind::Gpu, None, None),
            dev("a", DeviceKind::Gpu, None, None),
        ]);
        assert!(matches!(
            dup.validate(),
            Err(InventoryError::DuplicateDevice(_))
        ));
        let orphan = inv(vec![dev("vf", DeviceKind::NicVf, Some("nope"), None)]);
        assert!(matches!(
            orphan.validate(),
            Err(InventoryError::UnknownParent(_))
        ));
        let cycle = inv(vec![
            dev("a", DeviceKind::Other, Some("b"), None),
            dev("b", DeviceKind::Other, Some("a"), None),
        ]);
        assert!(matches!(
            cycle.validate(),
            Err(InventoryError::ParentCycle(_))
        ));
        let selfp = inv(vec![dev("a", DeviceKind::Other, Some("a"), None)]);
        assert!(matches!(
            selfp.validate(),
            Err(InventoryError::ParentCycle(_))
        ));
        let numa = inv(vec![dev("a", DeviceKind::Gpu, None, Some(9))]);
        assert!(matches!(
            numa.validate(),
            Err(InventoryError::UnknownNuma(_))
        ));
        let ctrl = inv(vec![dev("a\n", DeviceKind::Gpu, None, None)]);
        assert_eq!(ctrl.validate(), Err(InventoryError::BadString));
    }

    #[test]
    fn rejects_bad_numa_and_strings() {
        let mut i = inv(vec![]);
        i.numa_nodes.push(NumaNode {
            id: 0,
            ..Default::default()
        });
        assert_eq!(i.validate(), Err(InventoryError::DuplicateNuma(0)));
        let mut i = inv(vec![]);
        i.numa_nodes[0].cpus = vec![0, 1];
        i.numa_nodes[0].reserved_cpus = vec![5];
        assert_eq!(i.validate(), Err(InventoryError::BadReservedCpus(0)));
        let mut i = inv(vec![]);
        i.cpu_model = Some("x\u{1b}[31m".into());
        assert_eq!(i.validate(), Err(InventoryError::BadString));
        let st = NodeStatus {
            agent_version: Some("v\n".into()),
            ..Default::default()
        };
        assert_eq!(st.validate(), Err(InventoryError::BadString));
    }

    #[test]
    fn unknown_parent_names_the_offender() {
        let i = inv(vec![
            dev("a", DeviceKind::Other, Some("b"), None),
            dev("b", DeviceKind::Other, Some("missing"), None),
        ]);
        assert_eq!(i.validate(), Err(InventoryError::UnknownParent("b".into())));
    }

    #[test]
    fn long_chain_is_accepted_and_tail_cycle_rejected() {
        let n = MAX_DEVICES;
        let chain: Vec<Device> = (0..n)
            .map(|k| {
                let parent = (k + 1 < n).then(|| format!("d{}", k + 1));
                dev(&format!("d{k}"), DeviceKind::Other, parent.as_deref(), None)
            })
            .collect();
        assert_eq!(inv(chain.clone()).validate(), Ok(()));
        let mut cyc = chain;
        if let Some(last) = cyc.last_mut() {
            last.parent = Some(format!("d{}", n / 2));
        }
        assert!(matches!(
            inv(cyc).validate(),
            Err(InventoryError::ParentCycle(_))
        ));
    }

    #[test]
    fn attr_values_deserialize() {
        let v: BTreeMap<String, AttrValue> =
            serde_json::from_str(r#"{"a":true,"b":-1,"c":18446744073709551615,"d":2.4,"e":"x"}"#)
                .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(v.get("c"), Some(&AttrValue::UInt(u64::MAX)));
        assert_eq!(v.get("d"), Some(&AttrValue::Float(2.4)));
        assert!(serde_json::from_str::<AttrValue>("null").is_err());
    }

    #[test]
    fn rejects_oversized() {
        let big = inv((0..=MAX_DEVICES)
            .map(|i| dev(&format!("d{i}"), DeviceKind::Disk, None, None))
            .collect());
        assert_eq!(big.validate(), Err(InventoryError::TooLarge));
    }
}
