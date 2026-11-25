//! Hardware inventory from /proc and /sys (Linux).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use torngat_api::node::{Arch, Inventory, NodeStatus, NumaNode};

fn read(p: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

/// Parses a Linux CPU list such as `0-3,8,10-11`.
pub fn parse_cpulist(s: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for part in s.trim().split(',').filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                if let (Ok(a), Ok(b)) = (a.parse::<u32>(), b.parse::<u32>())
                    && a <= b
                    && b - a < 65536
                {
                    out.extend(a..=b);
                }
            }
            None => out.extend(part.parse::<u32>().ok()),
        }
    }
    out
}

/// Parses the `MemTotal` line of a meminfo file (system or per NUMA node) into bytes.
pub fn parse_memtotal_kb(s: &str) -> Option<u64> {
    s.lines()
        .find(|l| l.contains("MemTotal:"))?
        .split_whitespace()
        .rev()
        .nth(1)?
        .parse::<u64>()
        .ok()
        .map(|kb| kb * 1024)
}

fn numa_nodes() -> Vec<NumaNode> {
    let mut out = Vec::new();
    if let Ok(dir) = std::fs::read_dir("/sys/devices/system/node") {
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(id) = name
                .strip_prefix("node")
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            let base = e.path();
            let mut hugepages = BTreeMap::new();
            if let Ok(hp) = std::fs::read_dir(base.join("hugepages")) {
                for h in hp.flatten() {
                    let n = h.file_name().to_string_lossy().into_owned();
                    let size = n
                        .strip_prefix("hugepages-")
                        .and_then(|s| s.strip_suffix("kB"))
                        .and_then(|s| s.parse::<u64>().ok());
                    let count = read(h.path().join("nr_hugepages"))
                        .and_then(|s| s.trim().parse::<u64>().ok());
                    if let (Some(size), Some(count)) = (size, count) {
                        hugepages.insert(size, count);
                    }
                }
            }
            out.push(NumaNode {
                id,
                cpus: read(base.join("cpulist"))
                    .map(|s| parse_cpulist(&s))
                    .unwrap_or_default(),
                memory_bytes: read(base.join("meminfo"))
                    .and_then(|s| parse_memtotal_kb(&s))
                    .unwrap_or(0),
                hugepages,
                reserved_cpus: vec![],
            });
        }
    }
    if out.is_empty() {
        // Kernels without NUMA sysfs: one node with everything.
        let cpus = read("/sys/devices/system/cpu/online")
            .map(|s| parse_cpulist(&s))
            .unwrap_or_default();
        let mem = read("/proc/meminfo")
            .and_then(|s| parse_memtotal_kb(&s))
            .unwrap_or(0);
        out.push(NumaNode {
            id: 0,
            cpus,
            memory_bytes: mem,
            ..Default::default()
        });
    }
    out.sort_by_key(|n| n.id);
    out
}

/// Whether the root file system of the host image protects what is on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskProtection {
    /// Neither marker: sealed, or not the host image (its disk is the operator's business).
    NoMarker,
    /// `torngat-seal-root` has not run yet: the disk key is still next to it.
    Provisional,
    /// Made without a TPM: the disk key is on the boot partition.
    Unprotected,
}

/// Says how this host's root file system is protected. The markers are the host image's.
pub fn disk_protection() -> DiskProtection {
    // An error (e.g. no permission to look) counts as present.
    let there = |f: &str| {
        !matches!(
            Path::new("/var/lib/torngat-seal").join(f).try_exists(),
            Ok(false)
        )
    };
    if there("unprotected") {
        DiskProtection::Unprotected
    } else if there("provisional.key") {
        DiskProtection::Provisional
    } else {
        DiskProtection::NoMarker
    }
}

/// Collects this host's inventory.
pub fn collect(agent_version: &str) -> NodeStatus {
    let arch = match std::env::consts::ARCH {
        "aarch64" => Arch::Aarch64,
        "riscv64" => Arch::Riscv64,
        _ => Arch::X86_64,
    };
    let mut traits = BTreeSet::new();
    if Path::new("/dev/kvm").exists() {
        traits.insert("kvm".to_owned());
    }
    if Path::new("/dev/tpmrm0").exists() {
        traits.insert("tpm2".to_owned());
    }
    if disk_protection() != DiskProtection::NoMarker {
        traits.insert("disk-not-protected".to_owned());
    }
    NodeStatus {
        phase: Default::default(),
        agent_version: Some(agent_version.to_owned()),
        inventory: Inventory {
            arch,
            cpu_model: None,
            numa_nodes: numa_nodes(),
            devices: vec![],
            traits,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpulist() {
        assert_eq!(parse_cpulist("0-3,8,10-11\n"), vec![0, 1, 2, 3, 8, 10, 11]);
        assert_eq!(parse_cpulist(""), Vec::<u32>::new());
        assert_eq!(parse_cpulist("5-2,x,7"), vec![7]);
        assert_eq!(parse_cpulist("0-4294967295"), Vec::<u32>::new());
    }

    #[test]
    fn memtotal() {
        assert_eq!(
            parse_memtotal_kb("MemTotal:       16384 kB\nMemFree: 1 kB"),
            Some(16384 * 1024)
        );
        assert_eq!(
            parse_memtotal_kb("Node 0 MemTotal:  2048 kB"),
            Some(2048 * 1024)
        );
        assert_eq!(parse_memtotal_kb("nothing"), None);
    }

    #[test]
    fn collected_inventory_is_valid() {
        let s = collect("test");
        assert_eq!(s.validate(), Ok(()));
        assert!(!s.inventory.numa_nodes.is_empty());
    }
}
