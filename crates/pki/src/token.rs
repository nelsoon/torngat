//! Join tokens.
//!
//! Text form: `torngat1.<id>.<secret>.<ca>`
//! - `id`: 8 random bytes (16 hex), the lookup key; not secret.
//! - `secret`: 32 random bytes (64 hex). Only its SHA-256 is stored.
//! - `ca`: SHA-256 of the cluster CA certificate (64 hex). The joining node refuses a controller
//!   whose CA does not match, before sending the secret.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use torngat_api::Name;

use crate::{PkiError, digest_eq, hex, random, sha256, unhex};

pub const PREFIX: &str = "torngat1";
/// Default and longest token lifetime.
pub const DEFAULT_TTL: time::Duration = time::Duration::hours(24);
pub const MAX_TTL: time::Duration = time::Duration::days(7);

/// SHA-256 of the CA certificate (DER).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CaHash(pub [u8; 32]);

impl std::fmt::Debug for CaHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:{}", hex(&self.0))
    }
}

impl std::fmt::Display for CaHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:{}", hex(&self.0))
    }
}

impl CaHash {
    pub fn of(cert_der: &[u8]) -> Self {
        Self(sha256(cert_der))
    }

    /// Constant time, though the value is not secret.
    pub fn matches(&self, cert_der: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.0.ct_eq(&sha256(cert_der)))
    }
}

/// A join token as handed to an operator. The secret never leaves this type except through
/// [`JoinToken::encode`].
pub struct JoinToken {
    id: String,
    secret: [u8; 32],
}

impl std::fmt::Debug for JoinToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinToken")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// True for a well-formed token id (16 lowercase hex).
pub fn valid_id(s: &str) -> bool {
    unhex::<8>(s).is_some()
}

impl JoinToken {
    pub fn generate() -> Result<Self, PkiError> {
        Ok(Self {
            id: hex(&random::<8>()?),
            secret: random::<32>()?,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// The text an operator passes to `join`.
    pub fn encode(&self, ca: &CaHash) -> String {
        format!("{PREFIX}.{}.{}.{}", self.id, hex(&self.secret), hex(&ca.0))
    }

    /// Parses the text form into the token and the CA pin.
    pub fn parse(s: &str) -> Result<(Self, CaHash), PkiError> {
        let mut it = s.trim().split('.');
        let (Some(PREFIX), Some(id), Some(secret), Some(ca), None) =
            (it.next(), it.next(), it.next(), it.next(), it.next())
        else {
            return Err(PkiError::BadToken);
        };
        if !valid_id(id) {
            return Err(PkiError::BadToken);
        }
        let secret = unhex::<32>(secret).ok_or(PkiError::BadToken)?;
        let ca = unhex::<32>(ca).ok_or(PkiError::BadToken)?;
        Ok((
            Self {
                id: id.to_owned(),
                secret,
            },
            CaHash(ca),
        ))
    }

    /// The stored record for this token.
    pub fn record(
        &self,
        node: Option<Name>,
        ttl: time::Duration,
        description: String,
    ) -> JoinTokenRecord {
        let now = OffsetDateTime::now_utc();
        JoinTokenRecord {
            id: self.id.clone(),
            secret_sha256: hex(&sha256(&self.secret)),
            node,
            description,
            create_time: now,
            expire_time: now + ttl,
            ek_sha256: None,
        }
    }
}

/// What the cluster stores for a join token. Server-written only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinTokenRecord {
    pub id: String,
    /// SHA-256 of the secret, lowercase hex.
    pub secret_sha256: String,
    /// If set, the token can only enroll a node with this name.
    pub node: Option<Name>,
    pub description: String,
    #[serde(with = "time::serde::rfc3339")]
    pub create_time: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expire_time: OffsetDateTime,
    /// If set, the token can only enroll a node whose TPM has this endorsement key (SHA-256 of
    /// its SubjectPublicKeyInfo, hex): pre-registered hardware.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ek_sha256: Option<String>,
}

impl JoinTokenRecord {
    pub fn expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expire_time
    }

    /// Whether `secret` is this token's secret and the token may enroll `node` at `now`.
    /// The secret comparison is constant time and always performed.
    pub fn admits(&self, secret: &[u8], node: &Name, now: OffsetDateTime) -> bool {
        let secret_ok = digest_eq(&self.secret_sha256, &hex(&sha256(secret)));
        let node_ok = self.node.as_ref().is_none_or(|n| n == node);
        secret_ok & node_ok & !self.expired(now)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn encode_parse_roundtrip() {
        let t = JoinToken::generate().unwrap();
        let ca = CaHash([7; 32]);
        let s = t.encode(&ca);
        let (p, pc) = JoinToken::parse(&s).unwrap();
        assert_eq!(p.id(), t.id());
        assert_eq!(p.secret(), t.secret());
        assert_eq!(pc, ca);
        assert!(!format!("{t:?}").contains(&hex(t.secret())));
        for bad in [
            "",
            "torngat1",
            &s.replacen("torngat1", "torngat2", 1),
            &format!("{s}.x"),
            &s.to_uppercase(),
            &s[..s.len() - 1],
        ] {
            assert!(JoinToken::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn record_admits_only_the_right_secret_node_and_time() {
        let t = JoinToken::generate().unwrap();
        let n1 = Name::new("n1").unwrap();
        let n2 = Name::new("n2").unwrap();
        let r = t.record(Some(n1.clone()), DEFAULT_TTL, String::new());
        let now = OffsetDateTime::now_utc();
        assert!(r.admits(t.secret(), &n1, now));
        assert!(!r.admits(t.secret(), &n2, now));
        assert!(!r.admits(&[0; 32], &n1, now));
        assert!(!r.admits(t.secret(), &n1, now + DEFAULT_TTL));
        let any = t.record(None, DEFAULT_TTL, String::new());
        assert!(any.admits(t.secret(), &n2, now));
        // The stored record never contains the secret.
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains(&hex(t.secret())));
    }
}
