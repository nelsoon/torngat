//! Torngat internal PKI.
//!
//! - [`ca::Ca`]: the cluster CA. Self-signed, ECDSA P-256, path length 0, and name-constrained to
//!   the `torngat` DNS subtree, so even a misissued certificate cannot name anything outside it.
//! - Controller certificates: `controller.torngat`, server authentication only.
//! - Node certificates: exactly `<node>.node.torngat`, client authentication only, issued from a
//!   CSR whose requested names and extensions are ignored. Only its public key is used.
//! - [`token`]: single-use join tokens. The cluster stores a SHA-256 of the secret, never the
//!   secret. The token text also pins the CA, so a joining node can authenticate the controller
//!   before it sends the secret.
//!
//! A node's identity is its certificate name **and** the public key recorded at join
//! ([`NodeIdentity`]): the controller checks both on every call, which also makes deleting the
//! record a revocation.

#![forbid(unsafe_code)]

pub mod ca;
pub mod token;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

pub use ca::{Ca, Issued};
pub use token::{CaHash, JoinToken, JoinTokenRecord};

/// DNS name the controller's certificate is issued for.
pub const CONTROLLER_NAME: &str = "controller.torngat";
/// Suffix of node certificate names: `<node>.node.torngat`.
pub const NODE_SAN_SUFFIX: &str = ".node.torngat";
/// DNS subtree the CA may issue for.
pub const DNS_ROOT: &str = "torngat";

#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("certificate: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("malformed certificate")]
    BadCertificate,
    #[error("malformed or unsupported certificate signing request")]
    BadCsr,
    #[error("unsupported key type: only ECDSA P-256 is accepted")]
    UnsupportedKey,
    #[error("malformed join token")]
    BadToken,
    #[error("randomness unavailable")]
    Random,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// How a node's private key is held. Recorded at join; policy decides what is acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStorage {
    /// A file on the node's disk (lower assurance).
    File,
    /// Non-exportable key in the node's TPM.
    Tpm,
}

/// What the cluster knows about a node's credential. Server-written only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeIdentity {
    /// SHA-256 of the DER SubjectPublicKeyInfo, lowercase hex.
    pub spki_sha256: String,
    pub key_storage: KeyStorage,
    #[serde(with = "time::serde::rfc3339")]
    pub issue_time: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
}

pub(crate) fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub(crate) fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[usize::from(x >> 4)] as char);
        s.push(H[usize::from(x & 0xf)] as char);
    }
    s
}

pub(crate) fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let b = s.as_bytes();
    if b.len() != N * 2 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nib(b[2 * i])? << 4) | nib(b[2 * i + 1])?;
    }
    Some(out)
}

pub(crate) fn random<const N: usize>() -> Result<[u8; N], PkiError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| PkiError::Random)?;
    Ok(b)
}

/// A fresh random secret: 32 bytes, lowercase hex (e.g. a bootstrap admin token).
pub fn random_secret() -> Result<String, PkiError> {
    Ok(hex(&random::<32>()?))
}

/// SHA-256 of `b`, lowercase hex.
pub fn hex_sha256(b: &[u8]) -> String {
    hex(&sha256(b))
}

/// SHA-256 (lowercase hex) of a certificate's SubjectPublicKeyInfo, as recorded in
/// [`NodeIdentity::spki_sha256`].
pub fn spki_sha256(cert_der: &[u8]) -> Result<String, PkiError> {
    let (rest, cert) =
        x509_parser::parse_x509_certificate(cert_der).map_err(|_| PkiError::BadCertificate)?;
    if !rest.is_empty() {
        return Err(PkiError::BadCertificate);
    }
    Ok(hex(&sha256(cert.tbs_certificate.subject_pki.raw)))
}

/// Constant-time comparison of two hex digests.
pub fn digest_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let b = [0u8, 1, 0xab, 0xff];
        assert_eq!(hex(&b), "0001abff");
        assert_eq!(unhex::<4>("0001abff"), Some(b));
        assert_eq!(unhex::<4>("0001ABFF"), None);
        assert_eq!(unhex::<4>("0001abf"), None);
        assert_eq!(unhex::<4>("0001abfg"), None);
    }
}
