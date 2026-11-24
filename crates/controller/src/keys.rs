//! Storage key layout shared with the API server (must stay identical).

use torngat_api::{Name, Scope};
use torngat_pki::TPM_POLICY_KEY;
use torngat_store::{Key, KeyError, Prefix};
use uuid::Uuid;

pub fn instance(scope: &Scope, name: &Name) -> Result<Key, KeyError> {
    let mut s = scope.segments();
    s.extend(["instances", name.as_str()]);
    Key::new("compute", s)
}

/// Prefix of every instance in every project (`compute/orgs`).
pub fn all_instances() -> Result<Prefix, KeyError> {
    Prefix::new("compute", ["orgs"])
}

pub fn node(name: &Name) -> Result<Key, KeyError> {
    Key::new("platform", ["nodes", name.as_str()])
}

pub fn nodes() -> Result<Prefix, KeyError> {
    Prefix::new("platform", ["nodes"])
}

pub fn operation(id: Uuid) -> Result<Key, KeyError> {
    Key::new("ops", ["operations", &id.hyphenated().to_string()])
}

/// Credential record of an enrolled node ([`torngat_pki::NodeIdentity`]).
pub fn node_identity(name: &Name) -> Result<Key, KeyError> {
    Key::new("platform", ["nodeidentities", name.as_str()])
}

/// A join token record ([`torngat_pki::JoinTokenRecord`]), by token id.
pub fn join_token(id: &str) -> Result<Key, KeyError> {
    Key::new("platform", ["jointokens", id])
}

pub fn join_tokens() -> Result<Prefix, KeyError> {
    Prefix::new("platform", ["jointokens"])
}

/// The cluster's node key policy ([`torngat_pki::TpmPolicy`]).
pub fn tpm_policy() -> Result<Key, KeyError> {
    Key::new(TPM_POLICY_KEY.0, TPM_POLICY_KEY.1)
}
