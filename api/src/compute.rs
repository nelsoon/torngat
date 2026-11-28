//! Compute instances.
//!
//! Users request *capabilities*; the platform chooses the VMM (QEMU or Cloud Hypervisor). The
//! chosen runtime appears in `status` for diagnostics only and is not part of the contract.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::meta::Object;

pub type Instance = Object<InstanceSpec, InstanceStatus>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    LiveMigratable,
    GraphicalConsole,
    LegacyGuest,
    Gpu,
    Vgpu,
    Sriov,
    Confidential,
    Realtime,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerState {
    #[default]
    Running,
    Stopped,
}

pub const MAX_VCPUS: u32 = 1024;
pub const MAX_MEMORY_MIB: u64 = 16 * 1024 * 1024;
pub const MAX_CLAIMS: usize = 32;
/// Data volumes of one instance, the boot disk not counted.
pub const MAX_DISKS: usize = 16;

/// The instance's own disk, made with it: the volume `<instance>-boot`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootDisk {
    pub volume_type: crate::Name,
    pub size_gib: u64,
    /// The volume stays when the instance is deleted.
    #[serde(default)]
    pub keep: bool,
    /// What it holds at first: the disk of a ready image, copied once. Without one it is blank.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageRef>,
}

/// An image of the instance's project, or of the platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageRef {
    pub name: crate::Name,
    /// The platform's image of that name, not the project's.
    #[serde(default)]
    pub platform: bool,
}

impl ImageRef {
    /// Where the image is, for an instance in `scope`.
    pub fn scope(&self, scope: &crate::Scope) -> crate::Scope {
        if self.platform {
            crate::Scope::Platform
        } else {
            scope.clone()
        }
    }
}

/// An existing volume of the same project, attached as a data disk. It is never deleted with the
/// instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskRef {
    pub volume: crate::Name,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstanceSpec {
    pub vcpus: u32,
    pub memory_mib: u64,
    #[serde(default)]
    pub capabilities: BTreeSet<Capability>,
    #[serde(default)]
    pub power_state: PowerState,
    /// Claims (by name, in the same project) for devices this instance needs.
    #[serde(default)]
    pub claims: Vec<crate::Name>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_disk: Option<BootDisk>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disks: Vec<DiskRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InstanceError {
    #[error("vcpus must be between 1 and {MAX_VCPUS}")]
    Vcpus,
    #[error("memory_mib must be between 64 and {MAX_MEMORY_MIB}")]
    Memory,
    #[error("at most {MAX_CLAIMS} distinct claims")]
    Claims,
    #[error("at most {MAX_DISKS} distinct disks")]
    Disks,
    #[error(
        "boot_disk.size_gib must be between 1 and {}",
        crate::storage::MAX_VOLUME_GIB
    )]
    BootDiskSize,
    #[error("the instance's name is too long for its boot disk's (\"<name>-boot\")")]
    BootDiskName,
    #[error("disks can only be added while the instance runs; removing one needs it stopped")]
    DisksWhileRunning,
    #[error("the boot disk cannot be added, removed, change type or image; its size can only grow")]
    BootDiskChange,
}

/// Suffix of a boot disk's volume name.
const BOOT_SUFFIX: &str = "-boot";

impl InstanceSpec {
    pub fn validate(&self) -> Result<(), InstanceError> {
        if !(1..=MAX_VCPUS).contains(&self.vcpus) {
            return Err(InstanceError::Vcpus);
        }
        if !(64..=MAX_MEMORY_MIB).contains(&self.memory_mib) {
            return Err(InstanceError::Memory);
        }
        let unique: BTreeSet<&crate::Name> = self.claims.iter().collect();
        if self.claims.len() > MAX_CLAIMS || unique.len() != self.claims.len() {
            return Err(InstanceError::Claims);
        }
        let disks: BTreeSet<&crate::Name> = self.disks.iter().map(|d| &d.volume).collect();
        if self.disks.len() > MAX_DISKS || disks.len() != self.disks.len() {
            return Err(InstanceError::Disks);
        }
        if let Some(b) = &self.boot_disk
            && !(1..=crate::storage::MAX_VOLUME_GIB).contains(&b.size_gib)
        {
            return Err(InstanceError::BootDiskSize);
        }
        Ok(())
    }

    /// The volume of the boot disk of the instance `instance`, if it has one.
    pub fn boot_volume(
        &self,
        instance: &crate::Name,
    ) -> Result<Option<crate::Name>, InstanceError> {
        self.boot_disk
            .as_ref()
            .map(|_| {
                crate::Name::new(format!("{instance}{BOOT_SUFFIX}"))
                    .map_err(|_| InstanceError::BootDiskName)
            })
            .transpose()
    }

    /// Every volume the instance uses: its boot disk first.
    pub fn volumes(&self, instance: &crate::Name) -> Result<Vec<crate::Name>, InstanceError> {
        let mut out: Vec<_> = self.boot_volume(instance)?.into_iter().collect();
        out.extend(self.disks.iter().map(|d| d.volume.clone()));
        Ok(out)
    }

    /// Whether an instance may change from `self` to `new`. While it runs disks can only be added;
    /// removing one needs it stopped (or not on a node yet). The boot disk can only grow, and
    /// `keep` can change at any time.
    pub fn validate_update(
        &self,
        status: &InstanceStatus,
        new: &Self,
    ) -> Result<(), InstanceError> {
        new.validate()?;
        let same_type = match (&self.boot_disk, &new.boot_disk) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                a.volume_type == b.volume_type && a.image == b.image && b.size_gib >= a.size_gib
            }
            _ => false,
        };
        if !same_type {
            return Err(InstanceError::BootDiskChange);
        }
        let removed = self.disks.iter().any(|d| !new.disks.contains(d));
        let stopped = status.node.is_none()
            || (self.power_state == PowerState::Stopped && status.phase == InstancePhase::Stopped);
        if removed && !stopped {
            return Err(InstanceError::DisksWhileRunning);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstancePhase {
    #[default]
    Pending,
    Scheduled,
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Runtime {
    Qemu,
    CloudHypervisor,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InstanceStatus {
    #[serde(default)]
    pub phase: InstancePhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<crate::Name>,
    /// Diagnostic only; not a contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<Runtime>,
    /// `metadata.generation` last acted on by the platform.
    #[serde(default)]
    pub observed_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Operation to complete when the instance first reaches its desired power state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_operation: Option<uuid::Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_bounds() {
        let ok = InstanceSpec {
            vcpus: 2,
            memory_mib: 2048,
            capabilities: BTreeSet::new(),
            power_state: PowerState::Running,
            claims: vec![],
            boot_disk: None,
            disks: vec![],
        };
        assert_eq!(ok.validate(), Ok(()));
        assert_eq!(
            InstanceSpec {
                vcpus: 0,
                ..ok.clone()
            }
            .validate(),
            Err(InstanceError::Vcpus)
        );
        assert_eq!(
            InstanceSpec {
                memory_mib: 1,
                ..ok
            }
            .validate(),
            Err(InstanceError::Memory)
        );
    }

    fn n(s: &str) -> crate::Name {
        crate::Name::new(s).unwrap_or_else(|e| unreachable!("{e}"))
    }

    #[test]
    fn disks() {
        let boot = BootDisk {
            volume_type: n("fast"),
            size_gib: 10,
            keep: false,
            image: None,
        };
        let spec = InstanceSpec {
            vcpus: 1,
            memory_mib: 512,
            capabilities: BTreeSet::new(),
            power_state: PowerState::Running,
            claims: vec![],
            boot_disk: Some(boot.clone()),
            disks: vec![DiskRef { volume: n("data") }],
        };
        assert_eq!(spec.validate(), Ok(()));
        assert_eq!(
            spec.volumes(&n("web")).ok(),
            Some(vec![n("web-boot"), n("data")])
        );
        assert_eq!(
            spec.boot_volume(&n(&"a".repeat(60))),
            Err(InstanceError::BootDiskName)
        );
        let twice = InstanceSpec {
            disks: vec![DiskRef { volume: n("data") }, DiskRef { volume: n("data") }],
            ..spec.clone()
        };
        assert_eq!(twice.validate(), Err(InstanceError::Disks));
        let zero = InstanceSpec {
            boot_disk: Some(BootDisk {
                size_gib: 0,
                ..boot.clone()
            }),
            ..spec.clone()
        };
        assert_eq!(zero.validate(), Err(InstanceError::BootDiskSize));

        // Disks change only while stopped; the boot disk only grows.
        let running = InstanceStatus {
            node: Some(n("n1")),
            phase: InstancePhase::Running,
            ..Default::default()
        };
        let fewer = InstanceSpec {
            disks: vec![],
            ..spec.clone()
        };
        assert_eq!(
            spec.validate_update(&running, &fewer),
            Err(InstanceError::DisksWhileRunning)
        );
        assert_eq!(
            spec.validate_update(&InstanceStatus::default(), &fewer),
            Ok(())
        );
        // Added while running.
        assert_eq!(fewer.validate_update(&running, &spec), Ok(()));
        let stopped_spec = InstanceSpec {
            power_state: PowerState::Stopped,
            ..spec.clone()
        };
        let stopped = InstanceStatus {
            phase: InstancePhase::Stopped,
            ..running.clone()
        };
        assert_eq!(stopped_spec.validate_update(&stopped, &fewer), Ok(()));
        let bigger = InstanceSpec {
            boot_disk: Some(BootDisk {
                size_gib: 20,
                keep: true,
                ..boot.clone()
            }),
            ..spec.clone()
        };
        assert_eq!(spec.validate_update(&running, &bigger), Ok(()));
        assert_eq!(
            bigger.validate_update(&running, &spec),
            Err(InstanceError::BootDiskChange)
        );
        let none = InstanceSpec {
            boot_disk: None,
            ..spec.clone()
        };
        assert_eq!(
            spec.validate_update(&InstanceStatus::default(), &none),
            Err(InstanceError::BootDiskChange)
        );
    }
}
