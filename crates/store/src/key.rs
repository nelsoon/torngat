//! Storage keys.
//!
//! A key is `<keyspace>/<segment>/<segment>/...`. Keyspaces partition the store per service
//! (compute, network, iam…) so a service can later move to its own Raft group without changing
//! its callers. Every segment is restricted to `[a-z0-9_-]`, which excludes the separator, `.`,
//! and anything that could be interpreted as a path, an escape or a prefix trick.

use std::fmt;

use serde::{Deserialize, Serialize};

pub const MAX_SEGMENT_LEN: usize = 63;
pub const MAX_KEY_LEN: usize = 1024;
const SEP: char = '/';

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("empty key segment")]
    Empty,
    #[error("key segment {0:?} contains a forbidden character")]
    BadChar(String),
    #[error("key segment longer than {MAX_SEGMENT_LEN}")]
    SegmentTooLong,
    #[error("key longer than {MAX_KEY_LEN}")]
    TooLong,
}

fn check_segment(s: &str) -> Result<(), KeyError> {
    if s.is_empty() {
        return Err(KeyError::Empty);
    }
    if s.len() > MAX_SEGMENT_LEN {
        return Err(KeyError::SegmentTooLong);
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err(KeyError::BadChar(s.to_owned()));
    }
    Ok(())
}

/// A validated key.
///
/// Keys are re-validated when log entries and snapshots are decoded, so a peer cannot inject an
/// invalid key. Consequence: key rules may be relaxed in later releases but never tightened, or
/// committed entries would stop decoding on replay.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Key(String);

impl Key {
    /// Builds a key from a keyspace and further segments.
    pub fn new<'a>(
        keyspace: &str,
        segments: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, KeyError> {
        check_segment(keyspace)?;
        let mut k = String::from(keyspace);
        for s in segments {
            check_segment(s)?;
            k.push(SEP);
            k.push_str(s);
            if k.len() > MAX_KEY_LEN {
                return Err(KeyError::TooLong);
            }
        }
        Ok(Key(k))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn keyspace(&self) -> &str {
        self.0.split(SEP).next().unwrap_or_default()
    }

    /// True if this key is `prefix` itself or lies below it. Matches whole segments only, so
    /// `compute/orgs/a` does not match prefix `compute/orgs/ab`.
    pub fn has_prefix(&self, prefix: &Prefix) -> bool {
        match self.0.strip_prefix(prefix.0.as_str()) {
            Some("") => true,
            Some(rest) => rest.starts_with(SEP),
            None => false,
        }
    }
}

impl TryFrom<String> for Key {
    type Error = KeyError;
    fn try_from(s: String) -> Result<Self, KeyError> {
        if s.len() > MAX_KEY_LEN {
            return Err(KeyError::TooLong);
        }
        let mut parts = s.split(SEP);
        let ks = parts.next().unwrap_or_default();
        Key::new(ks, parts)
    }
}

impl From<Key> for String {
    fn from(k: Key) -> String {
        k.0
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key({})", self.0)
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated key prefix (one or more whole segments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefix(String);

impl Prefix {
    pub fn new<'a>(
        keyspace: &str,
        segments: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, KeyError> {
        Key::new(keyspace, segments).map(|k| Prefix(k.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_validates() {
        let k = Key::new(
            "compute",
            ["orgs", "acme", "projects", "web", "instances", "vm-1"],
        );
        assert_eq!(
            k.as_ref().map(Key::as_str),
            Ok("compute/orgs/acme/projects/web/instances/vm-1")
        );
        for bad in ["", "..", "a/b", "A", "a.b", "a b", "a\0"] {
            assert!(Key::new("compute", [bad]).is_err(), "{bad:?}");
        }
        assert!(Key::new("", ["a"]).is_err());
        assert_eq!(Key::new("ks", ["a"; 600]).err(), Some(KeyError::TooLong));
    }

    #[test]
    fn prefix_matches_whole_segments() -> Result<(), KeyError> {
        let k = Key::new("compute", ["orgs", "ab"])?;
        assert!(k.has_prefix(&Prefix::new("compute", ["orgs"])?));
        assert!(k.has_prefix(&Prefix::new("compute", ["orgs", "ab"])?));
        assert!(!k.has_prefix(&Prefix::new("compute", ["orgs", "a"])?));
        assert!(!k.has_prefix(&Prefix::new("network", [])?));
        Ok(())
    }

    #[test]
    fn deserialize_revalidates() {
        assert!(
            rmp_serde::from_slice::<Key>(&rmp_serde::to_vec(&"a/b").unwrap_or_default()).is_ok()
        );
        assert!(
            rmp_serde::from_slice::<Key>(&rmp_serde::to_vec(&"a/../b").unwrap_or_default())
                .is_err()
        );
        assert!(
            rmp_serde::from_slice::<Key>(&rmp_serde::to_vec(&"a//b").unwrap_or_default()).is_err()
        );
    }
}
