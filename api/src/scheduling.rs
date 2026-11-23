//! Device claims (reserved for telco/AI placement; schema only in M0).
//!
//! A claim is separate from the workload that uses it: the scheduler
//! allocates concrete devices to a claim, and the workload references the claim. This keeps
//! accelerator and NIC allocation out of the compute resource and lets several workloads share or
//! hand over a claim.

use serde::{Deserialize, Serialize};

use crate::meta::Object;
use crate::node::DeviceKind;

pub type ResourceClaim = Object<ResourceClaimSpec, ResourceClaimStatus>;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceClaimSpec {
    pub requests: Vec<DeviceRequest>,
    /// Topology constraints across requests.
    #[serde(default)]
    pub constraints: Vec<Constraint>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceRequest {
    /// Name of this request within the claim, referenced by constraints.
    pub name: crate::Name,
    pub kind: DeviceKind,
    pub count: u32,
    /// Optional CEL expression over device attributes (evaluated by the scheduler).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Constraint {
    /// All listed requests must be satisfied from the same NUMA node.
    SameNuma { requests: Vec<crate::Name> },
}

pub const MAX_REQUESTS: usize = 32;
pub const MAX_COUNT: u32 = 1024;
pub const MAX_CONSTRAINTS: usize = 32;
pub const MAX_SELECTOR_LEN: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClaimError {
    #[error("a claim needs between 1 and {MAX_REQUESTS} requests")]
    Requests,
    #[error("request {0:?}: count must be between 1 and {MAX_COUNT}")]
    Count(String),
    #[error("request name {0:?} is duplicated")]
    DuplicateRequest(String),
    #[error("request {0:?}: selector too long or contains control characters")]
    Selector(String),
    #[error("too many constraints (max {MAX_CONSTRAINTS})")]
    Constraints,
    #[error("constraint refers to unknown request {0:?}")]
    UnknownRequest(String),
}

impl ResourceClaimSpec {
    pub fn validate(&self) -> Result<(), ClaimError> {
        if self.requests.is_empty() || self.requests.len() > MAX_REQUESTS {
            return Err(ClaimError::Requests);
        }
        if self.constraints.len() > MAX_CONSTRAINTS {
            return Err(ClaimError::Constraints);
        }
        let mut names = std::collections::BTreeSet::new();
        for r in &self.requests {
            let n = r.name.as_str();
            if !names.insert(n) {
                return Err(ClaimError::DuplicateRequest(n.to_owned()));
            }
            if !(1..=MAX_COUNT).contains(&r.count) {
                return Err(ClaimError::Count(n.to_owned()));
            }
            if let Some(sel) = &r.selector
                && (sel.len() > MAX_SELECTOR_LEN || sel.chars().any(char::is_control))
            {
                return Err(ClaimError::Selector(n.to_owned()));
            }
        }
        for c in &self.constraints {
            let Constraint::SameNuma { requests } = c;
            if requests.len() > MAX_REQUESTS {
                return Err(ClaimError::Constraints);
            }
            if let Some(bad) = requests.iter().find(|r| !names.contains(r.as_str())) {
                return Err(ClaimError::UnknownRequest(bad.as_str().to_owned()));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceClaimStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation: Option<Allocation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Allocation {
    pub node: crate::Name,
    /// (request name, device id) pairs.
    pub devices: Vec<(crate::Name, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> crate::Name {
        crate::Name::new(s).unwrap_or_else(|e| unreachable!("{e}"))
    }

    fn req(name: &str, count: u32) -> DeviceRequest {
        DeviceRequest {
            name: n(name),
            kind: DeviceKind::Gpu,
            count,
            selector: None,
        }
    }

    #[test]
    fn validate_claims() {
        let ok = ResourceClaimSpec {
            requests: vec![req("gpu", 1), req("nic", 1)],
            constraints: vec![Constraint::SameNuma {
                requests: vec![n("gpu"), n("nic")],
            }],
        };
        assert_eq!(ok.validate(), Ok(()));
        let empty = ResourceClaimSpec::default();
        assert_eq!(empty.validate(), Err(ClaimError::Requests));
        let zero = ResourceClaimSpec {
            requests: vec![req("gpu", 0)],
            constraints: vec![],
        };
        assert_eq!(zero.validate(), Err(ClaimError::Count("gpu".into())));
        let dup = ResourceClaimSpec {
            requests: vec![req("gpu", 1), req("gpu", 1)],
            constraints: vec![],
        };
        assert_eq!(
            dup.validate(),
            Err(ClaimError::DuplicateRequest("gpu".into()))
        );
        let unknown = ResourceClaimSpec {
            requests: vec![req("gpu", 1)],
            constraints: vec![Constraint::SameNuma {
                requests: vec![n("nic")],
            }],
        };
        assert_eq!(
            unknown.validate(),
            Err(ClaimError::UnknownRequest("nic".into()))
        );
    }
}
