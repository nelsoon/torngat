//! `TPM2_MakeCredential` in software, for an RSA 2048 endorsement key made from the default TCG
//! template (name algorithm SHA-256, AES-128-CFB). TPM 2.0 Library Part 1, "Protected Storage"
//! and "Credential Protection".
//!
//! Only the TPM holding the private part of that EK, and the object named `name` loaded in it,
//! can recover `credential` (with `TPM2_ActivateCredential`).

use aes::cipher::KeyIvInit;
use hmac::{Hmac, KeyInit, Mac};
use rsa::{Oaep, PublicKey};
use sha2::Sha256;

use crate::AttestError;

type HmacSha256 = Hmac<Sha256>;

/// `KDFa` with SHA-256 (SP 800-108 counter mode, as the TPM defines it).
pub fn kdfa(key: &[u8], label: &str, context_u: &[u8], context_v: &[u8], bits: u32) -> Vec<u8> {
    let bytes = (bits as usize).div_ceil(8);
    let mut out = Vec::with_capacity(bytes + 32);
    let mut counter: u32 = 1;
    while out.len() < bytes {
        // HMAC accepts keys of any length: this cannot fail.
        let mut m = <HmacSha256 as KeyInit>::new_from_slice(key).unwrap_or_else(|_| unreachable!());
        m.update(&counter.to_be_bytes());
        m.update(label.as_bytes());
        m.update(&[0]);
        m.update(context_u);
        m.update(context_v);
        m.update(&bits.to_be_bytes());
        out.extend_from_slice(&m.finalize().into_bytes());
        counter += 1;
    }
    out.truncate(bytes);
    out
}

/// What the TPM needs to activate the credential: the contents of `TPM2B_ID_OBJECT` and of
/// `TPM2B_ENCRYPTED_SECRET` (without their size prefixes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialBlob {
    pub id_object: Vec<u8>,
    pub encrypted_secret: Vec<u8>,
}

/// Wraps `credential` (at most 32 bytes) for the object `name` under the EK `ek`.
pub fn make_credential(
    ek: &PublicKey,
    name: &[u8],
    credential: &[u8],
) -> Result<CredentialBlob, AttestError> {
    if credential.len() > 32 {
        return Err(AttestError::Malformed);
    }
    let mut rng = getrandom::SysRng;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| AttestError::Random)?;
    let encrypted_secret = ek
        .encrypt(
            &mut rng,
            Oaep::<Sha256>::new_with_label(&b"IDENTITY\0"[..]),
            &seed,
        )
        .map_err(|_| AttestError::Unsupported("endorsement key"))?;

    let sym = kdfa(&seed, "STORAGE", name, &[], 128);
    let mut plain = (credential.len() as u16).to_be_bytes().to_vec();
    plain.extend_from_slice(credential);
    let iv = [0u8; 16];
    cfb_mode::Encryptor::<aes::Aes128>::new_from_slices(&sym, &iv)
        .map_err(|_| AttestError::Malformed)?
        .encrypt(&mut plain);
    let enc_identity = plain;

    let hmac_key = kdfa(&seed, "INTEGRITY", &[], &[], 256);
    let mut m =
        <HmacSha256 as KeyInit>::new_from_slice(&hmac_key).unwrap_or_else(|_| unreachable!());
    m.update(&enc_identity);
    m.update(name);
    let integrity = m.finalize().into_bytes();

    let mut id_object = 32u16.to_be_bytes().to_vec();
    id_object.extend_from_slice(&integrity);
    id_object.extend_from_slice(&enc_identity);
    Ok(CredentialBlob {
        id_object,
        encrypted_secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdfa_lengths_and_determinism() {
        #[allow(clippy::unwrap_used)]
        let k = torngat_pki::random::<32>().unwrap();
        let a = kdfa(&k, "STORAGE", b"n", b"", 128);
        assert_eq!(a.len(), 16);
        assert_eq!(a, kdfa(&k, "STORAGE", b"n", b"", 128));
        assert_ne!(a, kdfa(&k, "INTEGRITY", b"n", b"", 128));
        assert_eq!(kdfa(&k, "X", b"", b"", 256).len(), 32);
        assert_eq!(kdfa(&k, "X", b"", b"", 512).len(), 64);
    }
}
