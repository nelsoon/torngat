//! Recovery code and encrypted backups.
//!
//! The operator keeps a random code. From it come a P-256 key pair, whose public half the cluster
//! uses to encrypt backups, and an authentication key, which the cluster keeps wrapped under its
//! platform key. The cluster can therefore make backups but not read those it made, and nobody else
//! can make one that the code opens.
//!
//! A backup is [`MAGIC`], an ephemeral public key, and AES-256-GCM ciphertext with its tag. Its key is
//! used once: HKDF-SHA256 of the ECDH secret and the authentication key, salted with both public keys.

use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::hkdf;
use serde::{Deserialize, Serialize};
use torngat_pki::{hex, hex_sha256, unhex};
use zeroize::Zeroizing;

use crate::{KEY_LEN, KeyError, PlatformKey, Purpose, Secret, Wrapped};

const MAGIC: &[u8] = b"TORNGAT-BACKUP-1\n";
/// Uncompressed SEC1 point.
const PUBLIC_LEN: usize = 65;
const CODE_LEN: usize = 20;
const CHECK_LEN: usize = 5;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("not a recovery code, or mistyped")]
    Code,
    #[error("not a backup")]
    NotABackup,
    #[error("wrong recovery code, or a damaged or forged backup")]
    Open,
    #[error(transparent)]
    Key(#[from] KeyError),
}

/// What the operator keeps: 160 random bits.
pub struct RecoveryCode(Zeroizing<[u8; CODE_LEN]>);

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}

/// What the cluster keeps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recovery {
    public: String,
    auth: Wrapped,
}

fn hkdf(salt: &[u8], secret: &[&[u8]], info: &[u8]) -> Result<Secret, KeyError> {
    let ikm = Zeroizing::new(secret.concat());
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(&ikm);
    expand(&prk, info)
}

/// The code is already uniformly random: keys come from it directly (RFC 5869, section 3.3),
/// each with its own label.
fn from_code(code: &[u8], info: &[u8]) -> Result<Secret, KeyError> {
    expand(&hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, code), info)
}

fn expand(prk: &hkdf::Prk, info: &[u8]) -> Result<Secret, KeyError> {
    let mut out = Zeroizing::new([0; KEY_LEN]);
    prk.expand(&[info], &AES_256_GCM)
        .and_then(|okm| okm.fill(out.as_mut()))
        .map_err(|_| KeyError::Malformed)?;
    Ok(Secret(out))
}

fn private_key(bytes: &Secret) -> Result<SecretKey, KeyError> {
    // Fails for about one value in 2^32.
    SecretKey::from_slice(bytes.expose()).map_err(|_| KeyError::Malformed)
}

/// The key of one backup.
fn backup_key(
    private: &SecretKey,
    peer: &PublicKey,
    (ephemeral, recovery): (&[u8], &[u8]),
    auth: &Secret,
) -> Result<LessSafeKey, KeyError> {
    let shared = diffie_hellman(private.to_nonzero_scalar(), peer.as_affine());
    let key = hkdf(
        &[ephemeral, recovery].concat(),
        &[shared.raw_secret_bytes().as_slice(), auth.expose()],
        b"torngat/v1/backup",
    )?;
    let key = UnboundKey::new(&AES_256_GCM, key.expose()).map_err(|_| KeyError::Malformed)?;
    Ok(LessSafeKey::new(key))
}

/// Each backup has a key of its own.
fn only_nonce() -> Nonce {
    Nonce::assume_unique_for_key([0; NONCE_LEN])
}

impl RecoveryCode {
    pub fn generate() -> Result<Self, KeyError> {
        loop {
            let mut b = Zeroizing::new([0; CODE_LEN]);
            getrandom::fill(b.as_mut()).map_err(|_| KeyError::Random)?;
            let code = Self(b);
            if code.private().is_ok() {
                return Ok(code);
            }
        }
    }

    fn check(&self) -> Result<[u8; CHECK_LEN], KeyError> {
        // Independent of the keys: shown and stored only with the code.
        let k = from_code(self.0.as_ref(), b"torngat/v1/recovery/check")?;
        let mut out = [0; CHECK_LEN];
        out.copy_from_slice(&k.expose()[..CHECK_LEN]);
        Ok(out)
    }

    /// Ten groups of four letters and digits.
    pub fn encode(&self) -> Result<Zeroizing<String>, KeyError> {
        let check = self.check()?;
        let bytes: Zeroizing<Vec<u8>> = Zeroizing::new([self.0.as_ref(), check.as_ref()].concat());
        let mut s = Zeroizing::new(String::with_capacity(49));
        let (chunks, _) = bytes.as_chunks::<5>();
        for (i, c) in chunks.iter().enumerate() {
            let n = c.iter().fold(0u64, |n, b| n << 8 | u64::from(*b));
            for j in 0..8 {
                if j % 4 == 0 && i + j > 0 {
                    s.push('-');
                }
                s.push(ALPHABET[(n >> (35 - 5 * j) & 31) as usize] as char);
            }
        }
        Ok(s)
    }

    /// Case, spaces and dashes do not matter.
    pub fn parse(text: &str) -> Result<Self, RecoveryError> {
        let mut digits = Zeroizing::new([0u8; 40]);
        let mut n = 0;
        for c in text
            .bytes()
            .filter(|c| !c.is_ascii_whitespace() && *c != b'-')
        {
            let c = c.to_ascii_uppercase();
            let d = ALPHABET.iter().position(|a| *a == c);
            let (Some(d), Some(slot)) = (d, digits.get_mut(n)) else {
                return Err(RecoveryError::Code);
            };
            *slot = d as u8;
            n += 1;
        }
        if n != digits.len() {
            return Err(RecoveryError::Code);
        }
        let mut bytes = Zeroizing::new([0u8; CODE_LEN + CHECK_LEN]);
        for (out, d) in bytes.chunks_mut(5).zip(digits.chunks(8)) {
            let n = d.iter().fold(0u64, |n, d| n << 5 | u64::from(*d));
            out.copy_from_slice(&n.to_be_bytes()[3..]);
        }
        let mut code = Zeroizing::new([0; CODE_LEN]);
        code.copy_from_slice(&bytes[..CODE_LEN]);
        let code = Self(code);
        if code.check()? != bytes[CODE_LEN..] {
            return Err(RecoveryError::Code);
        }
        Ok(code)
    }

    fn derive(&self, info: &[u8]) -> Result<Secret, KeyError> {
        from_code(
            self.0.as_ref(),
            &[b"torngat/v1/recovery/".as_slice(), info].concat(),
        )
    }

    fn private(&self) -> Result<SecretKey, KeyError> {
        private_key(&self.derive(b"private")?)
    }

    fn auth(&self) -> Result<Secret, KeyError> {
        self.derive(b"auth")
    }

    /// What the cluster needs to make backups that this code opens.
    pub fn register(&self, platform: &PlatformKey) -> Result<Recovery, KeyError> {
        let public = hex(&self.private()?.public_key().to_sec1_bytes());
        let auth = platform
            .key()
            .wrap(&self.auth()?, Purpose::Recovery { public: &public })?;
        Ok(Recovery { public, auth })
    }

    /// Decrypts a backup, in place.
    pub fn open(&self, backup: Vec<u8>) -> Result<Zeroizing<Vec<u8>>, RecoveryError> {
        let mut backup = Zeroizing::new(backup);
        let (head, body) = backup
            .split_at_mut_checked(MAGIC.len() + PUBLIC_LEN)
            .ok_or(RecoveryError::NotABackup)?;
        let ephemeral = head.strip_prefix(MAGIC).ok_or(RecoveryError::NotABackup)?;
        let peer = PublicKey::from_sec1_bytes(ephemeral).map_err(|_| RecoveryError::Open)?;
        let private = self.private()?;
        let public = private.public_key().to_sec1_bytes();
        let key = backup_key(&private, &peer, (ephemeral, &public), &self.auth()?)?;
        let n = key
            .open_in_place(only_nonce(), Aad::from(MAGIC), body)
            .map_err(|_| RecoveryError::Open)?
            .len();
        let start = MAGIC.len() + PUBLIC_LEN;
        backup.truncate(start + n);
        backup.drain(..start);
        Ok(backup)
    }
}

impl Recovery {
    /// Encrypts a backup so that only the recovery code opens it.
    pub fn seal(&self, platform: &PlatformKey, plain: &[u8]) -> Result<Vec<u8>, KeyError> {
        let purpose = Purpose::Recovery {
            public: &self.public,
        };
        let auth = platform.key().unwrap(&self.auth, purpose)?;
        let public = unhex::<PUBLIC_LEN>(&self.public).ok_or(KeyError::Malformed)?;
        let peer = PublicKey::from_sec1_bytes(&public).map_err(|_| KeyError::Malformed)?;
        let private = loop {
            if let Ok(k) = private_key(&Secret::generate()?) {
                break k;
            }
        };
        let ephemeral = private.public_key().to_sec1_bytes();
        let key = backup_key(&private, &peer, (&ephemeral, &public), &auth)?;
        let start = MAGIC.len() + PUBLIC_LEN;
        // Never grows: that would leave a copy of the plain text.
        let mut out = Vec::with_capacity(start + plain.len() + AES_256_GCM.tag_len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&ephemeral);
        out.extend_from_slice(plain);
        let mut out = Zeroizing::new(out);
        let tag = key
            .seal_in_place_separate_tag(only_nonce(), Aad::from(MAGIC), &mut out[start..])
            .map_err(|_| KeyError::Malformed)?;
        out.extend_from_slice(tag.as_ref());
        Ok(std::mem::take(&mut *out))
    }

    /// Tells recovery codes apart.
    pub fn id(&self) -> String {
        hex_sha256(self.public.as_bytes())[..16].to_owned()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn codes() {
        let c = RecoveryCode::generate().unwrap();
        let text = c.encode().unwrap();
        assert_eq!(text.len(), 49);
        assert_eq!(text.split('-').count(), 10);
        assert!(text.split('-').all(|g| g.len() == 4));
        let back = RecoveryCode::parse(&text).unwrap();
        assert_eq!(back.0, c.0);
        let sloppy = format!(" {}\n", text.to_lowercase().replace('-', " "));
        assert_eq!(RecoveryCode::parse(&sloppy).unwrap().0, c.0);
        // Any wrong letter is noticed.
        for i in 0..text.len() {
            let mut b = text.as_bytes().to_vec();
            if b[i] == b'-' {
                continue;
            }
            b[i] = if b[i] == b'A' { b'B' } else { b'A' };
            assert!(RecoveryCode::parse(std::str::from_utf8(&b).unwrap()).is_err());
        }
        for bad in ["", "AAAA", &text[1..], &format!("{}A", *text), "é"] {
            assert!(RecoveryCode::parse(bad).is_err());
        }
        assert_eq!(format!("{c:?}"), "RecoveryCode(<redacted>)");
    }

    /// Codes and backups must stay readable by every later version.
    #[test]
    fn fixed() {
        let c = RecoveryCode(Zeroizing::new([7; CODE_LEN]));
        assert_eq!(
            *c.encode().unwrap(),
            "A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-EEUB-RQQV"
        );
        assert_eq!(
            hex(&c.private().unwrap().public_key().to_sec1_bytes()),
            "0417da10b875124a9c4d99e6556f53b1ab4dcb1bd4029265951004f44f9810f822\
             cb91fe426d3e0d2edbfbc540d0dec5879f138e7b7202eb03c072a7cc1b23b3b3"
        );
        assert_eq!(
            hex(c.auth().unwrap().expose()),
            "6408e738311094eed8c718afa4bb85911debff0fa554b09b3f403cd9f1bf5d52"
        );
    }

    #[test]
    fn backups() {
        let platform = PlatformKey::generate().unwrap();
        let code = RecoveryCode::generate().unwrap();
        let r = code.register(&platform).unwrap();
        for plain in [&b""[..], b"hello", &[3; 100_000]] {
            let b = r.seal(&platform, plain).unwrap();
            assert_ne!(b, r.seal(&platform, plain).unwrap());
            assert_eq!(*code.open(b).unwrap(), plain);
        }
        let b = r.seal(&platform, b"hello").unwrap();
        let other = RecoveryCode::generate().unwrap();
        assert!(matches!(other.open(b.clone()), Err(RecoveryError::Open)));
        for i in 0..b.len() {
            let mut bad = b.clone();
            bad[i] ^= 1;
            assert!(code.open(bad).is_err(), "byte {i}");
        }
        for n in 0..b.len() {
            assert!(code.open(b[..n].to_vec()).is_err(), "{n} bytes");
        }
        assert!(code.open([&b[..], b"x"].concat()).is_err());

        // Knowing the public key is not enough to make a backup that opens.
        let forger = PlatformKey::generate().unwrap();
        let auth = forger
            .key()
            .wrap(
                &Secret::generate().unwrap(),
                Purpose::Recovery { public: &r.public },
            )
            .unwrap();
        let forged = Recovery {
            public: r.public.clone(),
            auth,
        };
        let b = forged.seal(&forger, b"evil").unwrap();
        assert!(matches!(code.open(b), Err(RecoveryError::Open)));
        // Nor does changing the stored public key redirect backups.
        let swapped = Recovery {
            public: other.register(&forger).unwrap().public,
            auth: r.auth.clone(),
        };
        assert!(swapped.seal(&platform, b"x").is_err());
    }
}
