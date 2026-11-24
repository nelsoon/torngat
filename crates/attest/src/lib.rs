//! TPM attestation of node keys, verified by the controller in pure Rust (no TPM needed there).
//!
//! What a joining node proves:
//! 1. **Its TPM is trusted:** the endorsement key (EK) certificate chains to a configured vendor
//!    anchor, or its public key matches a pin the operator put on the join token
//!    (pre-registered hardware).
//! 2. **Its attestation key (AK) lives in that TPM:** the controller wraps a random secret for the
//!    AK's name under the EK ([`credential::make_credential`]); only that TPM, with that AK loaded,
//!    can return it (`TPM2_ActivateCredential`).
//! 3. **The node key lives in that TPM and cannot leave it:** the AK certifies the node key
//!    (`TPM2_Certify`) over a fresh nonce, and the node key's attributes say fixed-TPM,
//!    fixed-parent, generated inside the TPM. Its public key must be the one in the CSR.
//!
//! Flow: [`begin`] → send [`Challenge`] → node activates and certifies → [`Pending::finish`].

#![forbid(unsafe_code)]

pub mod credential;
pub mod wire;

use rsa::PublicKey;
use rsa::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use wire::{CertifyInfo, EccPublic, attr};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestError {
    #[error("malformed attestation data")]
    Malformed,
    #[error("unsupported {0}")]
    Unsupported(&'static str),
    #[error("the TPM's endorsement certificate is not trusted")]
    UntrustedEndorsement,
    #[error("attestation check failed: {0}")]
    Failed(&'static str),
    #[error("randomness unavailable")]
    Random,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// A trusted endorsement key.
#[derive(Debug, Clone)]
pub struct Endorsement {
    /// SHA-256 (hex) of the EK certificate's SubjectPublicKeyInfo: what tokens pin.
    pub spki_sha256: String,
    key: PublicKey,
}

/// SHA-256 (hex) of an EK certificate's public key, the value an operator pins on a join token.
pub fn ek_pin(ek_cert_der: &[u8]) -> Result<String, AttestError> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(ek_cert_der).map_err(|_| AttestError::Malformed)?;
    Ok(hex(&Sha256::digest(cert.tbs_certificate.subject_pki.raw)))
}

/// Checks an RSA 2048 EK certificate. With `pin`, the key must match it (the certificate's
/// issuer then does not matter). Otherwise the certificate must be valid now and signed directly
/// by one of `anchors` (DER CA certificates: vendor roots or their intermediates).
pub fn verify_endorsement(
    ek_cert_der: &[u8],
    anchors: &[Vec<u8>],
    pin: Option<&str>,
) -> Result<Endorsement, AttestError> {
    let (rest, cert) =
        x509_parser::parse_x509_certificate(ek_cert_der).map_err(|_| AttestError::Malformed)?;
    if !rest.is_empty() {
        return Err(AttestError::Malformed);
    }
    let spki = cert.tbs_certificate.subject_pki.raw;
    let spki_sha256 = hex(&Sha256::digest(spki));
    let key = PublicKey::from_public_key_der(spki)
        .map_err(|_| AttestError::Unsupported("endorsement key type (RSA 2048 required)"))?;
    if rsa::traits::PublicKeyParts::size(&key) != 256 {
        return Err(AttestError::Unsupported(
            "endorsement key size (RSA 2048 required)",
        ));
    }
    let trusted = match pin {
        Some(p) => ct_eq(p.as_bytes(), spki_sha256.as_bytes()),
        None => {
            cert.validity().is_valid()
                && anchors.iter().any(|a| {
                    x509_parser::parse_x509_certificate(a).is_ok_and(|(_, ca)| {
                        ca.is_ca()
                            && ca.subject() == cert.issuer()
                            && cert.verify_signature(Some(ca.public_key())).is_ok()
                    })
                })
        }
    };
    if !trusted {
        return Err(AttestError::UntrustedEndorsement);
    }
    Ok(Endorsement { spki_sha256, key })
}

/// Sent to the node: what its TPM must activate, and the nonce its AK must certify over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub id_object: Vec<u8>,
    pub encrypted_secret: Vec<u8>,
    pub nonce: [u8; 32],
}

/// Kept by the controller between the two steps. Holds the expected secret: never send or log it.
pub struct Pending {
    secret: [u8; 32],
    nonce: [u8; 32],
    ak: EccPublic,
    node_key_name: Vec<u8>,
    pub ek_spki_sha256: String,
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending")
            .field("ek_spki_sha256", &self.ek_spki_sha256)
            .finish_non_exhaustive()
    }
}

fn random32() -> Result<[u8; 32], AttestError> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| AttestError::Random)?;
    Ok(b)
}

/// Checks the AK and node key descriptions and builds the challenge.
/// `ak_public` and `node_public` are marshalled `TPMT_PUBLIC`s; `csr_spki_sha256` is the SHA-256
/// (hex) of the public key in the node's CSR.
pub fn begin(
    ek: &Endorsement,
    ak_public: &[u8],
    node_public: &[u8],
    csr_spki_sha256: &str,
) -> Result<(Pending, Challenge), AttestError> {
    let ak = EccPublic::parse(ak_public)?;
    if !ak.has(
        attr::RESTRICTED
            | attr::SIGN
            | attr::FIXED_TPM
            | attr::FIXED_PARENT
            | attr::SENSITIVE_DATA_ORIGIN,
    ) || ak.has(attr::DECRYPT)
        || ak.has_symmetric
        || ak.ecdsa_hash != Some(wire::TPM_ALG_SHA256)
    {
        return Err(AttestError::Failed("attestation key attributes"));
    }
    let node = EccPublic::parse(node_public)?;
    if !node.has(attr::SIGN | attr::FIXED_TPM | attr::FIXED_PARENT | attr::SENSITIVE_DATA_ORIGIN)
        || node.has(attr::DECRYPT)
        || node.has(attr::RESTRICTED)
        || node.has_symmetric
        || node.ecdsa_hash.is_some_and(|h| h != wire::TPM_ALG_SHA256)
    {
        return Err(AttestError::Failed("node key attributes"));
    }
    let node_spki = hex(&Sha256::digest(node.spki_der()));
    if !ct_eq(node_spki.as_bytes(), csr_spki_sha256.as_bytes()) {
        return Err(AttestError::Failed("the CSR is not for the TPM key"));
    }
    let secret = random32()?;
    let nonce = random32()?;
    let blob = credential::make_credential(&ek.key, &ak.name, &secret)?;
    Ok((
        Pending {
            secret,
            nonce,
            ak,
            node_key_name: node.name,
            ek_spki_sha256: ek.spki_sha256.clone(),
        },
        Challenge {
            id_object: blob.id_object,
            encrypted_secret: blob.encrypted_secret,
            nonce,
        },
    ))
}

impl Pending {
    /// Checks the node's answer: the activated secret, and the AK's certification of the node key
    /// (marshalled `TPMS_ATTEST` and `TPMT_SIGNATURE`).
    pub fn finish(
        &self,
        activated: &[u8],
        certify_attest: &[u8],
        certify_signature: &[u8],
    ) -> Result<(), AttestError> {
        if !ct_eq(activated, &self.secret) {
            return Err(AttestError::Failed("credential activation"));
        }
        let sig = wire::parse_ecdsa_signature(certify_signature)?;
        use p256::ecdsa::signature::Verifier;
        self.ak
            .verifying_key()?
            .verify(certify_attest, &sig)
            .map_err(|_| AttestError::Failed("certification signature"))?;
        let info = CertifyInfo::parse(certify_attest)?;
        if !ct_eq(&info.extra_data, &self.nonce) {
            return Err(AttestError::Failed("certification nonce"));
        }
        if !ct_eq(&info.name, &self.node_key_name) {
            return Err(AttestError::Failed("certified object is not the node key"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::wire::tests::{certify_attest, ecc_public, ecdsa_signature};
    use super::*;
    use aes::cipher::KeyIvInit;
    use hmac::{KeyInit, Mac};
    use p256::ecdsa::SigningKey;
    use rsa::PrivateKey;

    /// Software `TPM2_ActivateCredential`, to check `make_credential` end to end.
    fn activate(ek: &PrivateKey, name: &[u8], c: &Challenge) -> Option<Vec<u8>> {
        let seed = ek
            .decrypt(
                rsa::Oaep::<Sha256>::new_with_label(&b"IDENTITY\0"[..]),
                &c.encrypted_secret,
            )
            .ok()?;
        let (hlen, rest) = c.id_object.split_at(2);
        let hlen = usize::from(u16::from_be_bytes([hlen[0], hlen[1]]));
        let (integrity, enc) = rest.split_at(hlen);
        let hk = credential::kdfa(&seed, "INTEGRITY", &[], &[], 256);
        let mut m = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(&hk).unwrap();
        m.update(enc);
        m.update(name);
        m.verify_slice(integrity).ok()?;
        let sym = credential::kdfa(&seed, "STORAGE", name, &[], 128);
        let mut plain = enc.to_vec();
        cfb_mode::Decryptor::<aes::Aes128>::new_from_slices(&sym, &[0u8; 16])
            .unwrap()
            .decrypt(&mut plain);
        let n = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
        Some(plain[2..2 + n].to_vec())
    }

    fn new_key() -> SigningKey {
        use p256::elliptic_curve::Generate;
        SigningKey::generate_from_rng(&mut getrandom::rand_core::UnwrapErr(getrandom::SysRng))
    }

    struct Tpm {
        ek: PrivateKey,
        ek_cert: Vec<u8>,
        ak: SigningKey,
        ak_public: Vec<u8>,
        node: SigningKey,
        node_public: Vec<u8>,
    }

    fn point(k: &SigningKey) -> ([u8; 32], [u8; 32]) {
        let p = k.verifying_key().to_sec1_point(false);
        (
            p.x().unwrap().as_slice().try_into().unwrap(),
            p.y().unwrap().as_slice().try_into().unwrap(),
        )
    }

    fn tpm(anchor: &rcgen::Issuer<'_, rcgen::KeyPair>) -> Tpm {
        let ek = PrivateKey::new(
            &mut getrandom::rand_core::UnwrapErr(getrandom::SysRng),
            2048,
        )
        .unwrap();
        let ek_spki = rsa::pkcs8::EncodePublicKey::to_public_key_der(&ek.to_public_key()).unwrap();
        let ek_cert = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .signed_by(
                &rcgen::SubjectPublicKeyInfo::from_der(ek_spki.as_bytes()).unwrap(),
                anchor,
            )
            .unwrap()
            .der()
            .to_vec();
        let ak = new_key();
        let (x, y) = point(&ak);
        let ak_public = ecc_public(
            attr::RESTRICTED
                | attr::SIGN
                | attr::FIXED_TPM
                | attr::FIXED_PARENT
                | attr::SENSITIVE_DATA_ORIGIN
                | attr::USER_WITH_AUTH,
            true,
            &x,
            &y,
        );
        let node = new_key();
        let (x, y) = point(&node);
        let node_public = ecc_public(
            attr::SIGN
                | attr::FIXED_TPM
                | attr::FIXED_PARENT
                | attr::SENSITIVE_DATA_ORIGIN
                | attr::USER_WITH_AUTH,
            true,
            &x,
            &y,
        );
        Tpm {
            ek,
            ek_cert,
            ak,
            ak_public,
            node,
            node_public,
        }
    }

    fn anchor() -> (Vec<u8>, rcgen::Issuer<'static, rcgen::KeyPair>) {
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = p.self_signed(&key).unwrap();
        (cert.der().to_vec(), rcgen::Issuer::new(p, key))
    }

    fn csr_spki(k: &SigningKey) -> String {
        let (x, y) = point(k);
        let p = EccPublic::parse(&ecc_public(0, false, &x, &y)).unwrap();
        hex(&Sha256::digest(p.spki_der()))
    }

    fn answer(t: &Tpm, c: &Challenge) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let ak_name = EccPublic::parse(&t.ak_public).unwrap().name;
        let node_name = EccPublic::parse(&t.node_public).unwrap().name;
        let secret = activate(&t.ek, &ak_name, c).unwrap();
        let att = certify_attest(&c.nonce, &node_name);
        use p256::ecdsa::signature::Signer;
        let sig: p256::ecdsa::Signature = t.ak.sign(&att);
        (secret, att, ecdsa_signature(&sig))
    }

    #[test]
    fn full_flow_and_tampering() {
        let (anchor_der, issuer) = anchor();
        let t = tpm(&issuer);
        let ek = verify_endorsement(&t.ek_cert, std::slice::from_ref(&anchor_der), None).unwrap();
        let (pending, ch) = begin(&ek, &t.ak_public, &t.node_public, &csr_spki(&t.node)).unwrap();
        let (secret, att, sig) = answer(&t, &ch);
        pending.finish(&secret, &att, &sig).unwrap();

        // Wrong secret, wrong nonce, other certified object, bad signature.
        assert!(pending.finish(&[0; 32], &att, &sig).is_err());
        let node_name = EccPublic::parse(&t.node_public).unwrap().name;
        use p256::ecdsa::signature::Signer;
        let resign = |a: &[u8]| ecdsa_signature(&t.ak.sign(a));
        let other_nonce = certify_attest(&[9; 32], &node_name);
        assert_eq!(
            pending.finish(&secret, &other_nonce, &resign(&other_nonce)),
            Err(AttestError::Failed("certification nonce"))
        );
        let other_obj = certify_attest(&ch.nonce, b"\x00\x0bsomething-else");
        assert!(
            pending
                .finish(&secret, &other_obj, &resign(&other_obj))
                .is_err()
        );
        let by_node_key = ecdsa_signature(&t.node.sign(&att));
        assert!(pending.finish(&secret, &att, &by_node_key).is_err());

        // A credential is bound to the AK name: another AK cannot activate it.
        let other = tpm(&issuer);
        let other_ak_name = EccPublic::parse(&other.ak_public).unwrap().name;
        assert!(activate(&t.ek, &other_ak_name, &ch).is_none());
        // And to the EK: another TPM cannot.
        let ak_name = EccPublic::parse(&t.ak_public).unwrap().name;
        assert!(activate(&other.ek, &ak_name, &ch).is_none());
    }

    #[test]
    fn keys_and_endorsements_are_checked() {
        let (anchor_der, issuer) = anchor();
        let t = tpm(&issuer);
        // Unknown anchor, then a pin instead.
        let (other_anchor, _) = anchor();
        assert_eq!(
            verify_endorsement(&t.ek_cert, std::slice::from_ref(&other_anchor), None).unwrap_err(),
            AttestError::UntrustedEndorsement
        );
        let pin = ek_pin(&t.ek_cert).unwrap();
        assert!(verify_endorsement(&t.ek_cert, &[other_anchor], Some(&pin)).is_ok());
        assert!(verify_endorsement(&t.ek_cert, &[], Some(&"0".repeat(64))).is_err());
        let ek = verify_endorsement(&t.ek_cert, &[anchor_der], None).unwrap();

        // CSR for another key.
        let stranger = new_key();
        assert!(begin(&ek, &t.ak_public, &t.node_public, &csr_spki(&stranger)).is_err());
        // An exportable (not fixed-TPM) node key.
        let (x, y) = point(&t.node);
        let soft = ecc_public(
            attr::SIGN | attr::FIXED_PARENT | attr::SENSITIVE_DATA_ORIGIN,
            true,
            &x,
            &y,
        );
        assert_eq!(
            begin(&ek, &t.ak_public, &soft, &csr_spki(&t.node)).unwrap_err(),
            AttestError::Failed("node key attributes")
        );
        // A key imported from outside (not generated in the TPM).
        let imported = ecc_public(
            attr::SIGN | attr::FIXED_TPM | attr::FIXED_PARENT,
            true,
            &x,
            &y,
        );
        assert!(begin(&ek, &t.ak_public, &imported, &csr_spki(&t.node)).is_err());
        // An AK that is not restricted (could sign anything).
        let (ax, ay) = point(&t.ak);
        let loose = ecc_public(
            attr::SIGN | attr::FIXED_TPM | attr::FIXED_PARENT | attr::SENSITIVE_DATA_ORIGIN,
            true,
            &ax,
            &ay,
        );
        assert_eq!(
            begin(&ek, &loose, &t.node_public, &csr_spki(&t.node)).unwrap_err(),
            AttestError::Failed("attestation key attributes")
        );
    }
}
