//! Node identity from mTLS client certificates.
//!
//! The TLS layer has already verified the chain against the cluster CA. Here we read the node name
//! from the leaf certificate: exactly one DNS subject alternative name of the form
//! `<node>.node.torngat`, where `<node>` is a valid [`Name`]. Then [`authenticate`] checks the
//! certificate's public key against the one recorded when the node joined: a certificate is only
//! accepted for the key it was enrolled with, and deleting the record revokes the node.
//! Message fields never carry identity.

use torngat_api::Name;
use torngat_pki::NodeIdentity;
use torngat_store::Store;
use x509_parser::prelude::*;

pub use torngat_pki::NODE_SAN_SUFFIX;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error("no client certificate")]
    NoCertificate,
    #[error("client certificate cannot be parsed")]
    Unparsable,
    #[error("client certificate must carry exactly one node name")]
    NotOneNodeName,
    #[error("node name in certificate is invalid")]
    BadName,
}

/// Extracts the node name from a DER-encoded leaf certificate.
pub fn node_name(leaf_der: &[u8]) -> Result<Name, IdentityError> {
    let (_, cert) = X509Certificate::from_der(leaf_der).map_err(|_| IdentityError::Unparsable)?;
    let san = cert
        .subject_alternative_name()
        .map_err(|_| IdentityError::Unparsable)?
        .ok_or(IdentityError::NotOneNodeName)?;
    let mut names = san.value.general_names.iter().filter_map(|g| match g {
        GeneralName::DNSName(d) => d.strip_suffix(NODE_SAN_SUFFIX),
        _ => None,
    });
    let (Some(first), None) = (names.next(), names.next()) else {
        return Err(IdentityError::NotOneNodeName);
    };
    Name::new(first).map_err(|_| IdentityError::BadName)
}

fn leaf<T>(req: &tonic::Request<T>) -> Result<Vec<u8>, tonic::Status> {
    let certs = req
        .peer_certs()
        .ok_or_else(|| tonic::Status::unauthenticated(IdentityError::NoCertificate.to_string()))?;
    let leaf = certs
        .first()
        .ok_or_else(|| tonic::Status::unauthenticated(IdentityError::NoCertificate.to_string()))?;
    Ok(leaf.as_ref().to_vec())
}

/// Extracts the caller's node name from a tonic request, without checking enrollment.
pub fn caller<T>(req: &tonic::Request<T>) -> Result<Name, tonic::Status> {
    node_name(&leaf(req)?).map_err(|e| tonic::Status::permission_denied(e.to_string()))
}

/// The caller's node name, if its certificate is for the key the node was enrolled with.
pub async fn authenticate<T>(
    store: &Store,
    req: &tonic::Request<T>,
) -> Result<Name, tonic::Status> {
    let der = leaf(req)?;
    let name = node_name(&der).map_err(|e| tonic::Status::permission_denied(e.to_string()))?;
    check_enrolled(store, &name, &der).await?;
    Ok(name)
}

/// Checks that `cert_der` carries the public key recorded for `name`.
pub async fn check_enrolled(
    store: &Store,
    name: &Name,
    cert_der: &[u8],
) -> Result<(), tonic::Status> {
    let denied = || tonic::Status::permission_denied("node is not enrolled with this key");
    let key = crate::keys::node_identity(name).map_err(|_| denied())?;
    let rec = store.get(&key).await.map_err(crate::service::store_err)?;
    let Some(rec) = rec else {
        return Err(denied());
    };
    let rec: NodeIdentity = serde_json::from_slice(&rec.value).map_err(crate::service::internal)?;
    let spki = torngat_pki::spki_sha256(cert_der).map_err(|_| denied())?;
    if torngat_pki::digest_eq(&rec.spki_sha256, &spki) {
        Ok(())
    } else {
        Err(denied())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error("node is already enrolled")]
    AlreadyEnrolled,
    #[error(transparent)]
    Store(#[from] torngat_store::StoreError),
    #[error("encoding: {0}")]
    Encoding(String),
}

/// Records `identity` for `name`, failing if the node is already enrolled.
pub async fn enroll(
    store: &Store,
    name: &Name,
    identity: &NodeIdentity,
) -> Result<u64, EnrollError> {
    let key = crate::keys::node_identity(name).map_err(|e| EnrollError::Encoding(e.to_string()))?;
    let value = serde_json::to_vec(identity).map_err(|e| EnrollError::Encoding(e.to_string()))?;
    match store
        .put(key, value, torngat_store::Precondition::Absent)
        .await
    {
        Ok(rev) => Ok(rev),
        Err(torngat_store::StoreError::PreconditionFailed { .. }) => {
            Err(EnrollError::AlreadyEnrolled)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    fn cert(sans: &[&str]) -> Vec<u8> {
        let p =
            CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        p.self_signed(&KeyPair::generate().unwrap())
            .unwrap()
            .der()
            .to_vec()
    }

    #[test]
    fn extracts_exactly_one_valid_node_name() {
        assert_eq!(
            node_name(&cert(&["n1.node.torngat"])).map(|n| n.to_string()),
            Ok("n1".into())
        );
        assert_eq!(
            node_name(&cert(&["n1.node.torngat", "x.example"])).map(|n| n.to_string()),
            Ok("n1".into())
        );
        assert_eq!(
            node_name(&cert(&["n1.node.torngat", "n2.node.torngat"])),
            Err(IdentityError::NotOneNodeName)
        );
        assert_eq!(
            node_name(&cert(&["controller.torngat"])),
            Err(IdentityError::NotOneNodeName)
        );
        assert_eq!(
            node_name(&cert(&["N1.node.torngat"])),
            Err(IdentityError::BadName)
        );
        assert_eq!(
            node_name(&cert(&["a.b.node.torngat"])),
            Err(IdentityError::BadName)
        );
        assert_eq!(
            node_name(&cert(&[".node.torngat"])),
            Err(IdentityError::BadName)
        );
        assert_eq!(
            node_name(b"not a certificate"),
            Err(IdentityError::Unparsable)
        );
    }
}
