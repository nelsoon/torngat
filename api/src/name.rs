//! Validated resource names and scopes.
//!
//! Names end up in storage keys, URLs, file paths, certificate subjects and log lines, so they are
//! validated once, at construction, and are immutable afterwards. A valid [`Name`] is an RFC 1123
//! DNS label: 1–63 characters, lowercase ASCII letters, digits and `-`, starting with a letter and
//! not ending with `-`. This rules out path separators, `..`, whitespace, control characters,
//! Unicode confusables and empty strings by construction.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

/// Maximum length of a [`Name`], in bytes (which are also characters, since names are ASCII).
pub const MAX_NAME_LEN: usize = 63;

/// Why a string is not a valid [`Name`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    #[error("name is empty")]
    Empty,
    #[error("name is longer than {MAX_NAME_LEN} characters")]
    TooLong,
    #[error("name must start with a lowercase letter")]
    BadStart,
    #[error("name must not end with '-'")]
    BadEnd,
    #[error("name may only contain lowercase letters, digits and '-'")]
    BadChar,
}

/// A validated resource name (an RFC 1123 DNS label starting with a letter).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Name(String);

impl Name {
    /// Validates `s` and returns it as a [`Name`].
    pub fn new(s: impl Into<String>) -> Result<Self, NameError> {
        let s = s.into();
        validate(&s)?;
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate(s: &str) -> Result<(), NameError> {
    let bytes = s.as_bytes();
    let (first, last) = match (bytes.first(), bytes.last()) {
        (Some(f), Some(l)) => (*f, *l),
        _ => return Err(NameError::Empty),
    };
    if bytes.len() > MAX_NAME_LEN {
        return Err(NameError::TooLong);
    }
    if !first.is_ascii_lowercase() {
        return Err(NameError::BadStart);
    }
    if last == b'-' {
        return Err(NameError::BadEnd);
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return Err(NameError::BadChar);
    }
    Ok(())
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Name::new(s).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<&str> for Name {
    type Error = NameError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Name::new(s)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({:?})", self.0)
    }
}

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Where a resource lives in the hierarchy. Inheritance of IAM grants and policies follows this
/// chain (platform → organization → folders → project).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Scope {
    /// Infrastructure owned by the platform operator (nodes, regions, releases).
    Platform,
    /// A tenant organization.
    Organization { org: Name },
    /// A project, reached through its organization and zero or more nested folders.
    Project {
        org: Name,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        folders: Vec<Name>,
        project: Name,
    },
}

/// Maximum folder nesting depth, to bound key length and inheritance walks.
pub const MAX_FOLDER_DEPTH: usize = 8;

impl Scope {
    /// Rejects folder chains deeper than [`MAX_FOLDER_DEPTH`].
    pub fn validate(&self) -> Result<(), ScopeError> {
        match self {
            Scope::Project { folders, .. } if folders.len() > MAX_FOLDER_DEPTH => {
                Err(ScopeError::TooDeep)
            }
            _ => Ok(()),
        }
    }

    /// Path segments of this scope, outermost first. Every segment is a validated [`Name`] or a
    /// fixed literal, so joining them with `/` cannot produce `..` or empty segments.
    pub fn segments(&self) -> Vec<&str> {
        match self {
            Scope::Platform => vec!["platform"],
            Scope::Organization { org } => vec!["orgs", org.as_str()],
            Scope::Project {
                org,
                folders,
                project,
            } => {
                let mut v = vec!["orgs", org.as_str()];
                for f in folders {
                    v.push("folders");
                    v.push(f.as_str());
                }
                v.push("projects");
                v.push(project.as_str());
                v
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeError {
    #[error("folder nesting is deeper than {MAX_FOLDER_DEPTH}")]
    TooDeep,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_names() {
        for ok in ["a", "web", "web-1", "a1b2", &"a".repeat(MAX_NAME_LEN)] {
            assert!(Name::new(ok).is_ok(), "{ok:?}");
        }
    }

    #[test]
    fn rejects_invalid_names() {
        let cases = [
            ("", NameError::Empty),
            ("1web", NameError::BadStart),
            ("-web", NameError::BadStart),
            ("web-", NameError::BadEnd),
            ("Web", NameError::BadStart),
            ("we b", NameError::BadChar),
            ("we/b", NameError::BadChar),
            ("we.b", NameError::BadChar),
            ("w..", NameError::BadChar),
            ("wé", NameError::BadChar),
            ("w\0", NameError::BadChar),
        ];
        for (s, want) in cases {
            assert_eq!(Name::new(s), Err(want), "{s:?}");
        }
        assert_eq!(
            Name::new("a".repeat(MAX_NAME_LEN + 1)),
            Err(NameError::TooLong)
        );
    }

    #[test]
    fn deserialize_validates() {
        assert!(serde_json::from_str::<Name>("\"ok\"").is_ok());
        assert!(serde_json::from_str::<Name>("\"../etc\"").is_err());
    }

    #[test]
    fn scope_segments_and_depth() {
        let n = |s: &str| Name::new(s).unwrap_or_else(|e| unreachable!("{e}"));
        let s = Scope::Project {
            org: n("acme"),
            folders: vec![n("eng")],
            project: n("web"),
        };
        assert_eq!(
            s.segments(),
            ["orgs", "acme", "folders", "eng", "projects", "web"]
        );
        let deep = Scope::Project {
            org: n("acme"),
            folders: vec![n("f"); MAX_FOLDER_DEPTH + 1],
            project: n("web"),
        };
        assert_eq!(deep.validate(), Err(ScopeError::TooDeep));
    }
}
