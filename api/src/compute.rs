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
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InstanceError {
    #[error("vcpus must be between 1 and {MAX_VCPUS}")]
    Vcpus,
    #[error("memory_mib must be between 64 and {MAX_MEMORY_MIB}")]
    Memory,
    #[error("at most {MAX_CLAIMS} distinct claims")]
    Claims,
}

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
}
