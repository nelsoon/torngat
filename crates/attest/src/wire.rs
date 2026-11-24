//! The few TPM 2.0 wire structures attestation needs, parsed strictly (TPM 2.0 Library, Part 2).
//! Every parser consumes its input exactly; trailing or missing bytes are an error.

use sha2::{Digest, Sha256};

use crate::AttestError;

pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ALG_ECDSA: u16 = 0x0018;
pub const TPM_ALG_ECC: u16 = 0x0023;
pub const TPM_ECC_NIST_P256: u16 = 0x0003;
pub const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
pub const TPM_ST_ATTEST_CERTIFY: u16 = 0x8017;

/// `TPMA_OBJECT` bits.
pub mod attr {
    pub const FIXED_TPM: u32 = 1 << 1;
    pub const FIXED_PARENT: u32 = 1 << 4;
    pub const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
    pub const USER_WITH_AUTH: u32 = 1 << 6;
    pub const RESTRICTED: u32 = 1 << 16;
    pub const DECRYPT: u32 = 1 << 17;
    pub const SIGN: u32 = 1 << 18;
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], AttestError> {
        if self.0.len() < n {
            return Err(AttestError::Malformed);
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Ok(h)
    }
    fn u8(&mut self) -> Result<u8, AttestError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, AttestError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, AttestError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, AttestError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }
    /// A `TPM2B_*`: 16-bit size, then that many bytes.
    fn tpm2b(&mut self) -> Result<&'a [u8], AttestError> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }
    fn end(&self) -> Result<(), AttestError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(AttestError::Malformed)
        }
    }
}

/// A P-256 key from a `TPMT_PUBLIC`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccPublic {
    pub attributes: u32,
    /// Signing scheme hash if a scheme is set (`TPM_ALG_ECDSA` only).
    pub ecdsa_hash: Option<u16>,
    /// Whether a symmetric algorithm is set (storage keys only).
    pub has_symmetric: bool,
    pub x: [u8; 32],
    pub y: [u8; 32],
    /// `nameAlg || SHA-256(TPMT_PUBLIC)`: how the TPM names this object.
    pub name: Vec<u8>,
}

fn coord(b: &[u8]) -> Result<[u8; 32], AttestError> {
    if b.len() > 32 {
        return Err(AttestError::Malformed);
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    Ok(out)
}

impl EccPublic {
    /// Parses a marshalled `TPMT_PUBLIC` that must be an ECC P-256 key with SHA-256 naming.
    pub fn parse(raw: &[u8]) -> Result<Self, AttestError> {
        let mut r = Reader(raw);
        if r.u16()? != TPM_ALG_ECC {
            return Err(AttestError::Unsupported("key type"));
        }
        if r.u16()? != TPM_ALG_SHA256 {
            return Err(AttestError::Unsupported("name algorithm"));
        }
        let attributes = r.u32()?;
        let _auth_policy = r.tpm2b()?;
        // TPMS_ECC_PARMS
        let sym = r.u16()?;
        let has_symmetric = sym != TPM_ALG_NULL;
        if has_symmetric {
            let _bits = r.u16()?;
            let _mode = r.u16()?;
        }
        let scheme = r.u16()?;
        let ecdsa_hash = match scheme {
            TPM_ALG_NULL => None,
            TPM_ALG_ECDSA => Some(r.u16()?),
            _ => return Err(AttestError::Unsupported("signing scheme")),
        };
        if r.u16()? != TPM_ECC_NIST_P256 {
            return Err(AttestError::Unsupported("curve"));
        }
        if r.u16()? != TPM_ALG_NULL {
            return Err(AttestError::Unsupported("kdf"));
        }
        let x = coord(r.tpm2b()?)?;
        let y = coord(r.tpm2b()?)?;
        r.end()?;
        let mut name = TPM_ALG_SHA256.to_be_bytes().to_vec();
        name.extend_from_slice(&Sha256::digest(raw));
        Ok(Self {
            attributes,
            ecdsa_hash,
            has_symmetric,
            x,
            y,
            name,
        })
    }

    pub fn has(&self, bits: u32) -> bool {
        self.attributes & bits == bits
    }

    /// DER SubjectPublicKeyInfo of this key (id-ecPublicKey, prime256v1, uncompressed point).
    pub fn spki_der(&self) -> Vec<u8> {
        const PREFIX: [u8; 26] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        let mut v = PREFIX.to_vec();
        v.push(0x04);
        v.extend_from_slice(&self.x);
        v.extend_from_slice(&self.y);
        v
    }

    pub fn verifying_key(&self) -> Result<p256::ecdsa::VerifyingKey, AttestError> {
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&self.x);
        sec1.extend_from_slice(&self.y);
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| AttestError::Malformed)
    }
}

/// The parts of a `TPMS_ATTEST` of type certify that matter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifyInfo {
    pub extra_data: Vec<u8>,
    /// Name of the certified object.
    pub name: Vec<u8>,
}

impl CertifyInfo {
    pub fn parse(raw: &[u8]) -> Result<Self, AttestError> {
        let mut r = Reader(raw);
        if r.u32()? != TPM_GENERATED_VALUE {
            return Err(AttestError::Malformed);
        }
        if r.u16()? != TPM_ST_ATTEST_CERTIFY {
            return Err(AttestError::Unsupported("attestation type"));
        }
        let _qualified_signer = r.tpm2b()?;
        let extra_data = r.tpm2b()?.to_vec();
        // TPMS_CLOCK_INFO
        let _clock = r.u64()?;
        let _reset = r.u32()?;
        let _restart = r.u32()?;
        let _safe = r.u8()?;
        let _firmware = r.u64()?;
        // TPMS_CERTIFY_INFO
        let name = r.tpm2b()?.to_vec();
        let _qualified_name = r.tpm2b()?;
        r.end()?;
        Ok(Self { extra_data, name })
    }
}

/// An ECDSA-SHA256 `TPMT_SIGNATURE`.
pub fn parse_ecdsa_signature(raw: &[u8]) -> Result<p256::ecdsa::Signature, AttestError> {
    let mut r = Reader(raw);
    if r.u16()? != TPM_ALG_ECDSA {
        return Err(AttestError::Unsupported("signature algorithm"));
    }
    if r.u16()? != TPM_ALG_SHA256 {
        return Err(AttestError::Unsupported("signature hash"));
    }
    let rr = coord(r.tpm2b()?)?;
    let ss = coord(r.tpm2b()?)?;
    r.end()?;
    p256::ecdsa::Signature::from_scalars(rr, ss).map_err(|_| AttestError::Malformed)
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Marshals a P-256 `TPMT_PUBLIC` (test helper, mirrors what a TPM produces).
    pub fn ecc_public(attributes: u32, ecdsa: bool, x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
        v.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        v.extend_from_slice(&attributes.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes()); // authPolicy
        v.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric
        if ecdsa {
            v.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
            v.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        } else {
            v.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        }
        v.extend_from_slice(&TPM_ECC_NIST_P256.to_be_bytes());
        v.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // kdf
        v.extend_from_slice(&32u16.to_be_bytes());
        v.extend_from_slice(x);
        v.extend_from_slice(&32u16.to_be_bytes());
        v.extend_from_slice(y);
        v
    }

    pub fn certify_attest(extra: &[u8], name: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
        v.extend_from_slice(&TPM_ST_ATTEST_CERTIFY.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&(extra.len() as u16).to_be_bytes());
        v.extend_from_slice(extra);
        v.extend_from_slice(&[0u8; 8 + 4 + 4 + 1 + 8]);
        v.extend_from_slice(&(name.len() as u16).to_be_bytes());
        v.extend_from_slice(name);
        v.extend_from_slice(&0u16.to_be_bytes());
        v
    }

    pub fn ecdsa_signature(sig: &p256::ecdsa::Signature) -> Vec<u8> {
        let (r, s) = sig.split_bytes();
        let mut v = Vec::new();
        v.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
        v.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        v.extend_from_slice(&32u16.to_be_bytes());
        v.extend_from_slice(&r);
        v.extend_from_slice(&32u16.to_be_bytes());
        v.extend_from_slice(&s);
        v
    }

    #[test]
    fn parsers_are_exact() {
        let p = ecc_public(attr::SIGN | attr::FIXED_TPM, true, &[1; 32], &[2; 32]);
        let k = EccPublic::parse(&p).unwrap();
        assert_eq!(k.ecdsa_hash, Some(TPM_ALG_SHA256));
        assert!(k.has(attr::SIGN | attr::FIXED_TPM) && !k.has(attr::RESTRICTED));
        assert_eq!(k.name.len(), 34);
        let mut longer = p.clone();
        longer.push(0);
        assert!(EccPublic::parse(&longer).is_err());
        assert!(EccPublic::parse(&p[..p.len() - 1]).is_err());

        let a = certify_attest(b"nonce", b"name");
        let c = CertifyInfo::parse(&a).unwrap();
        assert_eq!(
            (c.extra_data.as_slice(), c.name.as_slice()),
            (&b"nonce"[..], &b"name"[..])
        );
        assert!(CertifyInfo::parse(&a[..a.len() - 1]).is_err());
        let mut bad = a.clone();
        bad[0] = 0;
        assert!(CertifyInfo::parse(&bad).is_err());
    }
}
