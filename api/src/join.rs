//! Join tokens: single-use credentials that let a new node enroll.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::Name;

/// Default token lifetime.
pub const DEFAULT_TTL_SECONDS: u64 = 24 * 3600;
/// Shortest and longest token lifetime accepted.
pub const MIN_TTL_SECONDS: u64 = 60;
pub const MAX_TTL_SECONDS: u64 = 7 * 24 * 3600;
pub const MAX_DESCRIPTION: usize = 256;

/// Body of `POST /v1/platform/joinTokens`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateJoinTokenRequest {
    /// Only a node with this name may use the token.
    #[serde(default)]
    pub node: Option<Name>,
    /// Lifetime; defaults to [`DEFAULT_TTL_SECONDS`].
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    #[serde(default)]
    pub description: String,
    /// Pre-registered hardware: only a node whose TPM has this endorsement key may use the token
    /// (SHA-256 of the EK certificate's public key, 64 lowercase hex; `torngatd tpm-pin` prints
    /// it). The TPM's certificate then need not chain to a configured vendor root.
    #[serde(default)]
    pub ek_sha256: Option<String>,
}

impl CreateJoinTokenRequest {
    pub fn validate(&self) -> Result<(), String> {
        let ttl = self.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
        if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&ttl) {
            return Err(format!(
                "ttl_seconds must be between {MIN_TTL_SECONDS} and {MAX_TTL_SECONDS}"
            ));
        }
        if self.description.len() > MAX_DESCRIPTION
            || self.description.chars().any(char::is_control)
        {
            return Err(format!(
                "description must be at most {MAX_DESCRIPTION} bytes without control characters"
            ));
        }
        if let Some(p) = &self.ek_sha256
            && (p.len() != 64 || !p.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        {
            return Err("ek_sha256 must be 64 lowercase hex digits".into());
        }
        Ok(())
    }

    pub fn ttl(&self) -> time::Duration {
        let s = self.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
        time::Duration::seconds(i64::try_from(s).unwrap_or(i64::MAX))
    }
}

/// A join token as the API shows it. The secret is never stored, so `token` is only present in
/// the response to the create call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinTokenInfo {
    /// Token id (16 hex digits); the resource is `platform/joinTokens/{name}`.
    pub name: String,
    pub node: Option<Name>,
    pub description: String,
    #[serde(with = "time::serde::rfc3339")]
    pub create_time: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expire_time: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ek_sha256: Option<String>,
    /// The full token text to pass to `join`. Only returned once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn validation() {
        assert!(CreateJoinTokenRequest::default().validate().is_ok());
        let r = |ttl, d: &str| CreateJoinTokenRequest {
            node: None,
            ttl_seconds: Some(ttl),
            description: d.into(),
            ek_sha256: None,
        };
        assert!(r(59, "").validate().is_err());
        assert!(r(MAX_TTL_SECONDS + 1, "").validate().is_err());
        assert!(r(3600, "a\nb").validate().is_err());
        assert!(r(3600, &"x".repeat(257)).validate().is_err());
        assert!(r(3600, "rack 4").validate().is_ok());
        let pin = |p: &str| CreateJoinTokenRequest {
            ek_sha256: Some(p.into()),
            ..Default::default()
        };
        assert!(pin(&"a".repeat(64)).validate().is_ok());
        assert!(pin(&"A".repeat(64)).validate().is_err());
        assert!(pin(&"a".repeat(63)).validate().is_err());
        assert!(
            serde_json::from_str::<CreateJoinTokenRequest>(r#"{"secret":"x"}"#).is_err(),
            "unknown fields are rejected"
        );
    }
}
