//! Node identity from mTLS client certificates.
//!
//! The TLS layer has already verified the chain against the cluster CA. Here we read the node name
//! from the leaf certificate: exactly one DNS subject alternative name of the form
//! `<node>.node.torngat`, where `<node>` is a valid [`Name`]. Message fields never carry identity.

use torngat_api::Name;
use x509_parser::prelude::*;

pub const NODE_SAN_SUFFIX: &str = ".node.torngat";

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

/// Extracts the caller's node name from a tonic request.
pub fn caller<T>(req: &tonic::Request<T>) -> Result<Name, tonic::Status> {
    let certs = req
        .peer_certs()
        .ok_or_else(|| tonic::Status::unauthenticated(IdentityError::NoCertificate.to_string()))?;
    let leaf = certs
        .first()
        .ok_or_else(|| tonic::Status::unauthenticated(IdentityError::NoCertificate.to_string()))?;
    node_name(leaf.as_ref()).map_err(|e| tonic::Status::permission_denied(e.to_string()))
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
