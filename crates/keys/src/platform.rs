//! The platform key and its file.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use ring::hmac;
use zeroize::Zeroizing;

use torngat_pki::{hex, unhex};

use crate::{KEY_LEN, KeyError, Secret};

/// The root of the hierarchy. Without it every volume is lost.
#[derive(Debug)]
pub struct PlatformKey {
    key: Secret,
    id: String,
}

impl PlatformKey {
    fn new(key: Secret) -> Self {
        // Tells keys apart without giving anything away about them.
        let mac = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, key.expose()),
            b"torngat/v1/platform-key-id",
        );
        let id = hex(&mac.as_ref()[..16]);
        Self { key, id }
    }

    pub fn generate() -> Result<Self, KeyError> {
        Ok(Self::new(Secret::generate()?))
    }

    /// Public: recorded in the store, so that another key is never taken for this one.
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn key(&self) -> &Secret {
        &self.key
    }

    /// Loads the key, or `None` if there is no file. A damaged file is an error.
    pub fn load(path: &Path) -> Result<Option<Self>, KeyError> {
        let mut f = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if f.metadata()?.mode() & 0o077 != 0 {
            return Err(std::io::Error::other(format!(
                "{} must not be accessible to others",
                path.display()
            ))
            .into());
        }
        // A crash while saving can leave a second copy.
        remove_tmp(path)?;
        // One byte more than a whole file, to notice a longer one.
        let mut text = Zeroizing::new([0; KEY_LEN * 2 + 2]);
        let mut n = 0;
        while n < text.len() {
            match f.read(&mut text[n..])? {
                0 => break,
                m => n += m,
            }
        }
        let text = std::str::from_utf8(&text[..n]).map_err(|_| KeyError::Malformed)?;
        let text = text.strip_suffix('\n').unwrap_or(text);
        let key = Zeroizing::new(unhex::<KEY_LEN>(text).ok_or(KeyError::Malformed)?);
        Ok(Some(Self::new(Secret(key))))
    }

    /// Writes the key to a new 0600 file, whole or not at all. [`PlatformKey::sync`] it afterwards.
    pub fn save(&self, path: &Path) -> Result<(), KeyError> {
        let tmp = remove_tmp(path)?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        let text = Zeroizing::new(hex(self.key.expose()));
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        // Unlike a rename, never replaces a key.
        let linked = std::fs::hard_link(&tmp, path);
        std::fs::remove_file(&tmp)?;
        linked?;
        Ok(())
    }

    /// Puts the file at `path` on stable storage, with the directories that lead to it.
    pub fn sync(path: &Path) -> Result<(), KeyError> {
        for p in std::path::absolute(path)?.ancestors().take(3) {
            File::open(p)?.sync_all()?;
        }
        Ok(())
    }
}

fn remove_tmp(path: &Path) -> std::io::Result<PathBuf> {
    let tmp = path.with_extension("tmp");
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(tmp),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("platform.key");
        assert!(PlatformKey::load(&path).unwrap().is_none());
        let k = PlatformKey::generate().unwrap();
        // Left by a crash; not touched without a key file.
        std::fs::write(path.with_extension("tmp"), "x").unwrap();
        assert!(PlatformKey::load(&path).unwrap().is_none());
        assert!(path.with_extension("tmp").exists());
        k.save(&path).unwrap();
        assert!(!path.with_extension("tmp").exists());
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        PlatformKey::sync(&path).unwrap();
        std::fs::hard_link(&path, path.with_extension("tmp")).unwrap();
        let l = PlatformKey::load(&path).unwrap().unwrap();
        assert!(!path.with_extension("tmp").exists());
        assert_eq!(l.id(), k.id());
        assert_eq!(l.key().expose(), k.key().expose());

        // Never replaced.
        assert!(PlatformKey::generate().unwrap().save(&path).is_err());
        assert_eq!(PlatformKey::load(&path).unwrap().unwrap().id(), k.id());

        let set = |text: &str| std::fs::write(&path, text).unwrap();
        let good = hex(k.key().expose());
        set(&format!("{good}\n"));
        assert!(PlatformKey::load(&path).is_ok());
        for bad in ["", &good[1..], &format!("{good}0"), &format!("{good}\n\n")] {
            set(bad);
            assert!(matches!(PlatformKey::load(&path), Err(KeyError::Malformed)));
        }
        set(&good);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(PlatformKey::load(&path).is_err());
    }
}
