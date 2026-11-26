//! Key hierarchy: the platform key wraps project keys, which wrap volume keys.
//!
//! The platform key is a file on the controller's (sealed) root. Project keys never leave the
//! control plane; volume keys go to the node that has the volume. The store only holds wrapped keys.
//! Wrapping is AES-256-GCM with a random nonce. What a key is for is authenticated with it, so a
//! wrapped key that was moved to another record does not unwrap.

#![forbid(unsafe_code)]

mod platform;
mod recovery;

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use serde::{Deserialize, Serialize};
use torngat_pki::{hex, unhex};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub use platform::PlatformKey;
pub use recovery::{Recovery, RecoveryCode, RecoveryError};

pub const KEY_LEN: usize = 32;
const WRAPPED_LEN: usize = NONCE_LEN + KEY_LEN + 16;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// Wrong key, wrong purpose, or damaged.
    #[error("the key cannot be unwrapped")]
    Unwrap,
    #[error("malformed key")]
    Malformed,
    #[error("randomness unavailable")]
    Random,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// A 256-bit key. Erased from memory on drop and never printed.
pub struct Secret(Zeroizing<[u8; KEY_LEN]>);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// What a wrapped key is for. Never change the encoding of a variant: keys would be lost.
#[derive(Debug, Clone, Copy)]
pub enum Purpose<'a> {
    /// A project's key, under the platform key.
    Project { id: Uuid, project: &'a str },
    /// A volume's key, under its project's key.
    Volume { volume: Uuid },
    /// The authentication key of backups, under the platform key.
    Recovery { public: &'a str },
}

impl Purpose<'_> {
    fn aad(&self) -> Vec<u8> {
        match self {
            Purpose::Project { id, project } => {
                format!("torngat/v1/project-key/{id}/{project}").into_bytes()
            }
            Purpose::Volume { volume } => format!("torngat/v1/volume-key/{volume}").into_bytes(),
            Purpose::Recovery { public } => format!("torngat/v1/recovery/{public}").into_bytes(),
        }
    }
}

/// An encrypted key, as stored: nonce, ciphertext and tag in lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Wrapped(String);

impl Secret {
    pub fn generate() -> Result<Self, KeyError> {
        let mut k = Zeroizing::new([0; KEY_LEN]);
        getrandom::fill(k.as_mut()).map_err(|_| KeyError::Random)?;
        Ok(Self(k))
    }

    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    fn cipher(&self) -> Result<LessSafeKey, KeyError> {
        let k = UnboundKey::new(&AES_256_GCM, self.0.as_ref()).map_err(|_| KeyError::Malformed)?;
        Ok(LessSafeKey::new(k))
    }

    /// Encrypts `key` under this key. Random nonces are safe up to 2^32 wraps under one key.
    pub fn wrap(&self, key: &Secret, purpose: Purpose<'_>) -> Result<Wrapped, KeyError> {
        let mut nonce = [0; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| KeyError::Random)?;
        let mut buf = [0; WRAPPED_LEN];
        buf[..NONCE_LEN].copy_from_slice(&nonce);
        let body = &mut buf[NONCE_LEN..NONCE_LEN + KEY_LEN];
        body.copy_from_slice(key.expose());
        let sealed = self.cipher()?.seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(purpose.aad()),
            body,
        );
        let Ok(tag) = sealed else {
            buf.zeroize();
            return Err(KeyError::Malformed);
        };
        buf[NONCE_LEN + KEY_LEN..].copy_from_slice(tag.as_ref());
        Ok(Wrapped(hex(&buf)))
    }

    pub fn unwrap(&self, wrapped: &Wrapped, purpose: Purpose<'_>) -> Result<Secret, KeyError> {
        // Holds the plain key after opening.
        let mut buf = Zeroizing::new(unhex::<WRAPPED_LEN>(&wrapped.0).ok_or(KeyError::Malformed)?);
        let (nonce, body) = buf.split_at_mut(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| KeyError::Malformed)?;
        let plain = self
            .cipher()?
            .open_in_place(nonce, Aad::from(purpose.aad()), body)
            .map_err(|_| KeyError::Unwrap)?;
        let mut key = Zeroizing::new([0; KEY_LEN]);
        key.copy_from_slice(plain);
        Ok(Secret(key))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const A: Uuid = Uuid::from_u128(1);
    const B: Uuid = Uuid::from_u128(2);

    #[test]
    fn wrapped_keys_only_unwrap_for_their_purpose() {
        let (kek, key) = (Secret::generate().unwrap(), Secret::generate().unwrap());
        let p = Purpose::Volume { volume: A };
        let w = kek.wrap(&key, p).unwrap();
        assert_eq!(kek.unwrap(&w, p).unwrap().expose(), key.expose());
        // Never the same twice.
        assert_ne!(kek.wrap(&key, p).unwrap(), w);

        let wrong = |r: Result<Secret, KeyError>| matches!(r, Err(KeyError::Unwrap));
        assert!(wrong(kek.unwrap(&w, Purpose::Volume { volume: B })));
        let project = Purpose::Project {
            id: A,
            project: "orgs/a/projects/b",
        };
        assert!(wrong(kek.unwrap(&w, project)));
        let w2 = kek.wrap(&key, project).unwrap();
        let moved = Purpose::Project {
            id: A,
            project: "orgs/a/projects/c",
        };
        assert!(wrong(kek.unwrap(&w2, moved)));
        assert!(wrong(Secret::generate().unwrap().unwrap(&w, p)));
        // Any changed digit.
        for i in 0..w.0.len() {
            let mut s = w.0.clone().into_bytes();
            s[i] = if s[i] == b'0' { b'1' } else { b'0' };
            assert!(wrong(
                kek.unwrap(&Wrapped(String::from_utf8(s).unwrap()), p)
            ));
        }
        for bad in ["", "00", &w.0[2..], &w.0.to_uppercase()] {
            assert!(matches!(
                kek.unwrap(&Wrapped(bad.into()), p),
                Err(KeyError::Malformed)
            ));
        }
    }

    /// Stored keys must unwrap in every later version.
    #[test]
    fn purposes_are_encoded_as_ever() {
        assert_eq!(
            Purpose::Volume { volume: A }.aad(),
            b"torngat/v1/volume-key/00000000-0000-0000-0000-000000000001"
        );
        assert_eq!(
            Purpose::Project {
                id: A,
                project: "orgs/a/projects/b"
            }
            .aad(),
            b"torngat/v1/project-key/00000000-0000-0000-0000-000000000001/orgs/a/projects/b"
        );
    }

    #[test]
    fn secrets_are_not_printed() {
        assert_eq!(
            format!("{:?}", Secret::generate().unwrap()),
            "Secret(<redacted>)"
        );
    }
}
