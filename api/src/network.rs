//! Network interfaces (schema reserved in M0).
//!
//! An interface is its own resource with a `binding` that selects the datapath. Several network
//! backends coexist in a region. Security groups and live migration are only available for some
//! bindings, and the API says so instead of failing silently.

use serde::{Deserialize, Serialize};

use crate::meta::Object;

pub type NetworkInterface = Object<NetworkInterfaceSpec, NetworkInterfaceStatus>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Binding {
    /// Overlay (OVN), full features.
    #[default]
    Virtio,
    /// OVS-DPDK user-space datapath.
    VhostUser,
    /// SR-IOV virtual function passed to the guest.
    SriovVf,
    /// vDPA (hardware datapath, virtio control plane).
    Vdpa,
    /// Whole physical function passed to the guest.
    PfPassthrough,
    /// InfiniBand virtual function.
    IbVf,
}

impl Binding {
    /// Whether OVN security groups are enforced on this binding.
    pub fn supports_security_groups(self) -> bool {
        matches!(self, Binding::Virtio | Binding::VhostUser)
    }

    /// Whether an instance using this binding can be live-migrated.
    pub fn supports_live_migration(self) -> bool {
        matches!(self, Binding::Virtio | Binding::VhostUser | Binding::Vdpa)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkInterfaceSpec {
    pub network: crate::Name,
    #[serde(default)]
    pub binding: Binding,
    #[serde(default)]
    pub security_groups: Vec<crate::Name>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkInterfaceStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    #[serde(default)]
    pub ip_addresses: Vec<String>,
}
