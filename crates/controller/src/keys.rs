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

/// The image settings ([`torngat_api::settings::ImageSettings`]).
pub fn image_settings() -> Result<Key, KeyError> {
    Key::new("platform", ["settings", "images"])
}

pub fn storage_pool(name: &Name) -> Result<Key, KeyError> {
    Key::new("platform", ["storagepools", name.as_str()])
}

/// Like the API server, objects of the platform have no scope segment.
fn scoped<'a>(scope: &'a Scope, kind: &'a str, name: &'a Name) -> Vec<&'a str> {
    let mut s = match scope {
        Scope::Platform => vec![],
        s => s.segments(),
    };
    s.extend([kind, name.as_str()]);
    s
}

pub fn volume(scope: &Scope, name: &Name) -> Result<Key, KeyError> {
    Key::new("storage", scoped(scope, "volumes", name))
}

pub fn image(scope: &Scope, name: &Name) -> Result<Key, KeyError> {
    Key::new("images", scoped(scope, "images", name))
}

/// Every image, of the platform and of every project.
pub fn all_images() -> Result<Prefix, KeyError> {
    Prefix::new("images", [])
}

pub fn all_keys() -> Result<Prefix, KeyError> {
    Prefix::new("keys", [])
}

/// Which platform key the cluster uses ([`crate::volume_keys::PlatformKeyRecord`]).
pub fn platform_key() -> Result<Key, KeyError> {
    Key::new("keys", ["platform"])
}

/// How backups are encrypted ([`torngat_keys::Recovery`]).
pub fn recovery() -> Result<Key, KeyError> {
    Key::new("keys", ["recovery"])
}

/// A project's wrapped key ([`crate::volume_keys::ProjectKeyRecord`]).
pub fn project_key(scope: &Scope) -> Result<Key, KeyError> {
    let mut s = vec!["projects"];
    s.extend(scope.segments());
    Key::new("keys", s)
}

/// A volume's wrapped key ([`crate::volume_keys::VolumeKeyRecord`]), by the volume's uid.
pub fn volume_key(uid: Uuid) -> Result<Key, KeyError> {
    Key::new("keys", ["volumes", &uid.hyphenated().to_string()])
}

pub fn volume_keys() -> Result<Prefix, KeyError> {
    Prefix::new("keys", ["volumes"])
}

pub fn storage_pools() -> Result<Prefix, KeyError> {
    Prefix::new("platform", ["storagepools"])
}

pub fn volume_type(name: &Name) -> Result<Key, KeyError> {
    Key::new("platform", ["volumetypes", name.as_str()])
}

pub fn volume_types() -> Result<Prefix, KeyError> {
    Prefix::new("platform", ["volumetypes"])
}

/// Every volume, of the platform and of every project.
pub fn all_volumes() -> Result<Prefix, KeyError> {
    Prefix::new("storage", [])
}

pub fn network(scope: &Scope, name: &Name) -> Result<Key, KeyError> {
    Key::new("network", scoped(scope, "networks", name))
}

/// Every network of every project.
pub fn all_networks() -> Result<Prefix, KeyError> {
    Prefix::new("network", [])
}

pub fn provider_network(name: &Name) -> Result<Key, KeyError> {
    Key::new("platform", ["providernetworks", name.as_str()])
}

pub fn provider_networks() -> Result<Prefix, KeyError> {
    Prefix::new("platform", ["providernetworks"])
}

pub fn host_networks() -> Result<Prefix, KeyError> {
    Prefix::new("platform", ["hostnetworks"])
}

pub fn host_network(name: &Name) -> Result<Key, KeyError> {
    Key::new("platform", ["hostnetworks", name.as_str()])
}
