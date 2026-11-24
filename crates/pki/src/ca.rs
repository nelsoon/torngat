//! The cluster certificate authority.

use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, PKCS_ECDSA_P256_SHA256, PublicKeyData, SanType, SerialNumber,
};
use time::{Duration, OffsetDateTime};
use torngat_api::Name;

use crate::{
    CONTROLLER_NAME, CaHash, DNS_ROOT, KeyStorage, NODE_SAN_SUFFIX, NodeIdentity, PkiError, random,
    sha256, spki_sha256,
};

/// Lifetime of the CA certificate.
pub const CA_LIFETIME: Duration = Duration::days(3650);
/// Lifetime of controller and node certificates (renewal comes with rotation, M1).
pub const LEAF_LIFETIME: Duration = Duration::days(365);
/// Tolerated clock skew between nodes when a certificate starts being valid.
const BACKDATE: Duration = Duration::minutes(5);
/// Largest CSR accepted.
pub const MAX_CSR: usize = 4096;

/// The cluster CA: its certificate and signing key.
pub struct Ca {
    cert_pem: String,
    cert_der: Vec<u8>,
    key_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ca")
            .field("hash", &self.hash())
            .finish_non_exhaustive()
    }
}

/// A freshly issued certificate.
#[derive(Clone)]
pub struct Issued {
    /// Leaf certificate followed by the CA certificate (PEM).
    pub chain_pem: String,
    /// The leaf alone (DER).
    pub cert_der: Vec<u8>,
    /// Private key (PEM), only when the CA generated it.
    pub key_pem: Option<String>,
    pub not_after: OffsetDateTime,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl Issued {
    /// The identity record to store for a node holding this certificate.
    pub fn identity(&self, key_storage: KeyStorage) -> Result<NodeIdentity, PkiError> {
        Ok(NodeIdentity {
            spki_sha256: spki_sha256(&self.cert_der)?,
            key_storage,
            issue_time: OffsetDateTime::now_utc(),
            not_after: self.not_after,
        })
    }
}

fn serial() -> Result<SerialNumber, PkiError> {
    let mut b = random::<16>()?;
    b[0] &= 0x7f; // positive INTEGER
    b[0] |= 0x01; // and never shortened by a leading zero
    Ok(SerialNumber::from_slice(&b))
}

fn validity(p: &mut CertificateParams, lifetime: Duration) -> OffsetDateTime {
    let now = OffsetDateTime::now_utc();
    p.not_before = now - BACKDATE;
    p.not_after = now + lifetime;
    p.not_after
}

fn leaf_params(san: &str, eku: ExtendedKeyUsagePurpose) -> Result<CertificateParams, PkiError> {
    let mut p = CertificateParams::new(Vec::<String>::new())?;
    p.subject_alt_names = vec![SanType::DnsName(san.try_into()?)];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, san);
    p.distinguished_name = dn;
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![eku];
    p.use_authority_key_identifier_extension = true;
    p.serial_number = Some(serial()?);
    Ok(p)
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), PkiError> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

impl Ca {
    /// Creates a new CA with a fresh P-256 key.
    pub fn generate() -> Result<Self, PkiError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut p = CertificateParams::new(Vec::<String>::new())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Torngat cluster CA");
        p.distinguished_name = dn;
        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.name_constraints = Some(NameConstraints {
            permitted_subtrees: vec![GeneralSubtree::DnsName(DNS_ROOT.into())],
            excluded_subtrees: vec![],
        });
        p.serial_number = Some(serial()?);
        validity(&mut p, CA_LIFETIME);
        let cert = p.self_signed(&key)?;
        let key_pem = key.serialize_pem();
        Ok(Self {
            cert_pem: cert.pem(),
            cert_der: cert.der().to_vec(),
            key_pem,
            issuer: Issuer::new(p, key),
        })
    }

    /// Loads a CA from its certificate and key (PEM).
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, PkiError> {
        let key = KeyPair::from_pem(key_pem)?;
        let der = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
            .map_err(|_| PkiError::BadCertificate)?
            .1
            .contents;
        // The key must belong to the certificate.
        let (_, cert) =
            x509_parser::parse_x509_certificate(&der).map_err(|_| PkiError::BadCertificate)?;
        if cert.tbs_certificate.subject_pki.raw != key.subject_public_key_info().as_slice() {
            return Err(PkiError::BadCertificate);
        }
        let issuer = Issuer::from_ca_cert_der(&der.as_slice().into(), key)?;
        Ok(Self {
            cert_pem: cert_pem.to_owned(),
            cert_der: der,
            key_pem: key_pem.to_owned(),
            issuer,
        })
    }

    /// Loads `ca.pem` and `ca.key` from `dir`.
    pub fn load(dir: &Path) -> Result<Self, PkiError> {
        Self::from_pem(
            &std::fs::read_to_string(dir.join("ca.pem"))?,
            &std::fs::read_to_string(dir.join("ca.key"))?,
        )
    }

    /// Writes `ca.pem` and `ca.key` (both 0600) into `dir`, refusing to overwrite.
    pub fn save(&self, dir: &Path) -> Result<(), PkiError> {
        write_private(&dir.join("ca.pem"), self.cert_pem.as_bytes())?;
        write_private(&dir.join("ca.key"), self.key_pem.as_bytes())
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// The pin a joining node checks the CA against.
    pub fn hash(&self) -> CaHash {
        CaHash(sha256(&self.cert_der))
    }

    fn sign(
        &self,
        p: &CertificateParams,
        public: &impl PublicKeyData,
        key_pem: Option<String>,
        not_after: OffsetDateTime,
    ) -> Result<Issued, PkiError> {
        let cert = p.signed_by(public, &self.issuer)?;
        Ok(Issued {
            chain_pem: format!("{}{}", cert.pem(), self.cert_pem),
            cert_der: cert.der().to_vec(),
            key_pem,
            not_after,
        })
    }

    /// Issues the controller's server certificate with a new key.
    pub fn issue_controller(&self) -> Result<Issued, PkiError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut p = leaf_params(CONTROLLER_NAME, ExtendedKeyUsagePurpose::ServerAuth)?;
        let na = validity(&mut p, LEAF_LIFETIME);
        self.sign(&p, &key, Some(key.serialize_pem()), na)
    }

    /// Issues a node client certificate with a new key (for the node running `init`).
    pub fn issue_node(&self, node: &Name) -> Result<Issued, PkiError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut p = node_params(node)?;
        let na = validity(&mut p, LEAF_LIFETIME);
        self.sign(&p, &key, Some(key.serialize_pem()), na)
    }

    /// Signs a node's CSR (DER). Only the CSR's public key is used: names, subject and
    /// extensions all come from here. The CSR's signature (proof of key possession) is checked.
    pub fn sign_node_csr(&self, csr_der: &[u8], node: &Name) -> Result<Issued, PkiError> {
        let csr = parse_csr(csr_der)?;
        let mut p = node_params(node)?;
        let na = validity(&mut p, LEAF_LIFETIME);
        self.sign(&p, &csr.public_key, None, na)
    }
}

/// Parses and checks a node CSR: size, signature (proof of key possession), P-256 key encoded
/// canonically.
fn parse_csr(csr_der: &[u8]) -> Result<CertificateSigningRequestParams, PkiError> {
    if csr_der.len() > MAX_CSR {
        return Err(PkiError::BadCsr);
    }
    let csr =
        CertificateSigningRequestParams::from_der(&csr_der.into()).map_err(|_| PkiError::BadCsr)?;
    if csr.public_key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
        return Err(PkiError::UnsupportedKey);
    }
    // The algorithm above is derived from the *signature* algorithm. Make sure the key itself
    // is a P-256 key encoded exactly as we would encode it, so the certificate is coherent.
    let (_, parsed) =
        x509_parser::certification_request::X509CertificationRequest::from_der(csr_der)
            .map_err(|_| PkiError::BadCsr)?;
    if parsed.certification_request_info.subject_pki.raw
        != csr.public_key.subject_public_key_info().as_slice()
    {
        return Err(PkiError::UnsupportedKey);
    }
    Ok(csr)
}

/// Checks a node CSR without signing anything; returns the SHA-256 (hex) of its public key, as
/// recorded in [`NodeIdentity::spki_sha256`] for a certificate issued from it.
pub fn csr_spki_sha256(csr_der: &[u8]) -> Result<String, PkiError> {
    let csr = parse_csr(csr_der)?;
    Ok(crate::hex_sha256(&csr.public_key.subject_public_key_info()))
}

use x509_parser::prelude::FromDer;

fn node_params(node: &Name) -> Result<CertificateParams, PkiError> {
    leaf_params(
        &format!("{node}{NODE_SAN_SUFFIX}"),
        ExtendedKeyUsagePurpose::ClientAuth,
    )
}

/// Builds a CSR (DER) for a node key. The CA ignores everything in it but the public key.
pub fn node_csr(key: &KeyPair) -> Result<Vec<u8>, PkiError> {
    let p = CertificateParams::new(Vec::<String>::new())?;
    Ok(p.serialize_request(key)?.der().to_vec())
}

/// Parses a node key (PEM), requiring P-256.
pub fn parse_node_key(pem: &str) -> Result<KeyPair, PkiError> {
    let k = KeyPair::from_pem(pem)?;
    if k.algorithm() != &PKCS_ECDSA_P256_SHA256 {
        return Err(PkiError::UnsupportedKey);
    }
    Ok(k)
}

/// Generates a node key (P-256).
pub fn node_key() -> Result<KeyPair, PkiError> {
    Ok(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use rcgen::BasicConstraints;
    use x509_parser::prelude::{GeneralName, X509Certificate};

    fn parse(der: &[u8]) -> X509Certificate<'_> {
        x509_parser::parse_x509_certificate(der).unwrap().1
    }

    fn dns_sans(c: &X509Certificate<'_>) -> Vec<String> {
        c.subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .iter()
            .filter_map(|g| match g {
                GeneralName::DNSName(d) => Some(d.to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn csr_names_are_ignored_and_key_is_kept() {
        let ca = Ca::generate().unwrap();
        let key = node_key().unwrap();
        // A CSR asking for the controller name and CA powers.
        let mut p = CertificateParams::new(vec![CONTROLLER_NAME.to_owned()]).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let csr = p.serialize_request(&key).unwrap();
        let issued = ca
            .sign_node_csr(csr.der(), &Name::new("n1").unwrap())
            .unwrap();
        let c = parse(&issued.cert_der);
        assert_eq!(dns_sans(&c), vec!["n1.node.torngat".to_owned()]);
        assert!(!c.is_ca());
        let eku = c.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.client_auth && !eku.server_auth);
        assert_eq!(
            c.tbs_certificate.subject_pki.raw,
            key.subject_public_key_info().as_slice()
        );
        assert!(issued.key_pem.is_none());
        // Chain: leaf then CA.
        assert!(issued.chain_pem.ends_with(ca.cert_pem()));
    }

    #[test]
    fn csr_signature_and_key_type_are_checked() {
        let ca = Ca::generate().unwrap();
        let n = Name::new("n1").unwrap();
        let key = node_key().unwrap();
        let mut der = node_csr(&key).unwrap();
        let last = der.len() - 1;
        der[last] ^= 1; // break the signature
        assert!(matches!(ca.sign_node_csr(&der, &n), Err(PkiError::BadCsr)));
        assert!(matches!(
            ca.sign_node_csr(b"junk", &n),
            Err(PkiError::BadCsr)
        ));
        let ed = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let csr = CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .serialize_request(&ed)
            .unwrap();
        assert!(matches!(
            ca.sign_node_csr(csr.der(), &n),
            Err(PkiError::UnsupportedKey)
        ));
        let p384 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let csr = CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .serialize_request(&p384)
            .unwrap();
        assert!(matches!(
            ca.sign_node_csr(csr.der(), &n),
            Err(PkiError::UnsupportedKey)
        ));
        assert!(matches!(
            ca.sign_node_csr(&vec![0u8; MAX_CSR + 1], &n),
            Err(PkiError::BadCsr)
        ));
    }

    #[test]
    fn ca_is_constrained_and_roundtrips() {
        let ca = Ca::generate().unwrap();
        let c = parse(ca.cert_der());
        let bc = c.basic_constraints().unwrap().unwrap().value;
        assert!(bc.ca && bc.path_len_constraint == Some(0));
        assert!(c.name_constraints().unwrap().is_some());

        let dir = tempfile::tempdir().unwrap();
        ca.save(dir.path()).unwrap();
        assert!(ca.save(dir.path()).is_err(), "must not overwrite");
        let loaded = Ca::load(dir.path()).unwrap();
        assert_eq!(loaded.hash(), ca.hash());
        // A loaded CA issues certificates that chain to the same root.
        let issued = loaded.issue_controller().unwrap();
        let leaf = parse(&issued.cert_der);
        assert_eq!(leaf.issuer(), c.subject());
        assert!(
            leaf.verify_signature(Some(c.public_key())).is_ok(),
            "leaf not signed by CA"
        );
        // A key that does not match the certificate is refused.
        let other = Ca::generate().unwrap();
        assert!(Ca::from_pem(ca.cert_pem(), &other.key_pem).is_err());
    }

    #[test]
    fn csr_spki_matches_the_issued_certificate() {
        let ca = Ca::generate().unwrap();
        let key = node_key().unwrap();
        let csr = node_csr(&key).unwrap();
        let issued = ca.sign_node_csr(&csr, &Name::new("n1").unwrap()).unwrap();
        assert_eq!(
            csr_spki_sha256(&csr).unwrap(),
            spki_sha256(&issued.cert_der).unwrap()
        );
        assert!(csr_spki_sha256(b"junk").is_err());
    }

    #[test]
    fn identity_pins_the_public_key() {
        let ca = Ca::generate().unwrap();
        let n = Name::new("n1").unwrap();
        let a = ca.issue_node(&n).unwrap();
        let b = ca.issue_node(&n).unwrap();
        let ia = a.identity(KeyStorage::File).unwrap();
        assert_eq!(ia.spki_sha256, spki_sha256(&a.cert_der).unwrap());
        assert_ne!(ia.spki_sha256, spki_sha256(&b.cert_der).unwrap());
    }
}
