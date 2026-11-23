//! Object metadata shared by every resource.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::name::{Name, Scope};

/// Opaque concurrency token. Changes on every write; an update carrying a stale etag is rejected
/// (AIP-154). Clients must treat it as opaque.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Etag(pub String);

/// Identifies the shard ("cell") of a region that owns a resource. Present from day one so cells
/// can be introduced later without rewriting resource identity; a region with a single cell uses
/// [`Cell::DEFAULT`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Cell(pub Name);

impl Cell {
    pub const DEFAULT: &'static str = "c0";

    /// The cell used by a region that has not been split into cells.
    pub fn default_cell() -> Self {
        // "c0" is a valid name by construction; a unit test guards the literal.
        match Name::new(Self::DEFAULT) {
            Ok(n) => Cell(n),
            Err(_) => unreachable!("Cell::DEFAULT is a valid name"),
        }
    }
}

/// Metadata common to all objects. Fields marked *server-set* are ignored on create/update and
/// filled by the platform.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub name: Name,
    pub scope: Scope,
    /// Server-set. Globally unique, never reused, survives renames of the parent hierarchy.
    #[serde(default = "Uuid::nil")]
    pub uid: Uuid,
    /// Server-set. Owning cell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell: Option<Cell>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Server-set. Incremented on every change to `spec` (not `status`), so controllers can tell
    /// whether they have observed the latest desired state.
    #[serde(default)]
    pub generation: u64,
    /// Server-set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<Etag>,
    /// Server-set.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub create_time: Option<OffsetDateTime>,
    /// Server-set.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub update_time: Option<OffsetDateTime>,
    /// Server-set. Present while a delete is in progress (finalizers pending).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub delete_time: Option<OffsetDateTime>,
}

/// Limits applied to labels, which are user-controlled and copied into indexes and metrics.
pub const MAX_LABELS: usize = 64;
pub const MAX_LABEL_KEY_LEN: usize = 63;
pub const MAX_LABEL_VALUE_LEN: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetaError {
    #[error("too many labels (max {MAX_LABELS})")]
    TooManyLabels,
    #[error("label key {0:?} is invalid")]
    BadLabelKey(String),
    #[error("label value for {0:?} is invalid")]
    BadLabelValue(String),
}

impl ObjectMeta {
    /// Validates user-controlled fields. `name` is already valid by construction.
    pub fn validate(&self) -> Result<(), MetaError> {
        if self.labels.len() > MAX_LABELS {
            return Err(MetaError::TooManyLabels);
        }
        for (k, v) in &self.labels {
            let key_ok = !k.is_empty()
                && k.len() <= MAX_LABEL_KEY_LEN
                && k.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
                });
            if !key_ok {
                return Err(MetaError::BadLabelKey(k.clone()));
            }
            if v.len() > MAX_LABEL_VALUE_LEN || v.chars().any(char::is_control) {
                return Err(MetaError::BadLabelValue(k.clone()));
            }
        }
        Ok(())
    }
}

/// A resource: metadata + desired state + observed state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Object<S, St = ()> {
    pub metadata: ObjectMeta,
    pub spec: S,
    #[serde(default)]
    pub status: St,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> ObjectMeta {
        ObjectMeta {
            name: Name::new("web").unwrap_or_else(|e| unreachable!("{e}")),
            scope: Scope::Platform,
            uid: Uuid::nil(),
            cell: None,
            labels: BTreeMap::new(),
            generation: 0,
            etag: None,
            create_time: None,
            update_time: None,
            delete_time: None,
        }
    }

    #[test]
    fn label_validation() {
        let mut m = meta();
        m.labels.insert("env".into(), "prod".into());
        assert!(m.validate().is_ok());
        m.labels.insert("Bad Key".into(), "x".into());
        assert!(matches!(m.validate(), Err(MetaError::BadLabelKey(_))));
        let mut m = meta();
        m.labels.insert("k".into(), "a\nb".into());
        assert!(matches!(m.validate(), Err(MetaError::BadLabelValue(_))));
        let mut m = meta();
        for i in 0..=MAX_LABELS {
            m.labels.insert(format!("k{i}"), String::new());
        }
        assert_eq!(m.validate(), Err(MetaError::TooManyLabels));
    }

    #[test]
    fn default_cell_is_valid() {
        assert_eq!(Cell::default_cell().0.as_str(), Cell::DEFAULT);
    }

    #[test]
    fn server_fields_default_when_absent() {
        let m: ObjectMeta = serde_json::from_str(r#"{"name":"web","scope":{"kind":"platform"}}"#)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(m.uid, Uuid::nil());
        assert!(m.etag.is_none() && m.cell.is_none());
    }
}
