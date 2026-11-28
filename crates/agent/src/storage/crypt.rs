//! Encryption of volumes (LUKS2), on top of the devices that drivers give.
//!
//! The key is the controller's, given for the volume while an instance uses it. It opens the
//! volume's only key slot; the data is encrypted with a key that LUKS makes at formatting.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use torngat_api::storage::LUKS_HEADER_BYTES;
use uuid::Uuid;

/// Names of the decrypted mappings: `torngat-vol-<uid>`. The udev rule
/// `59-torngat-volumes.rules` keeps them from being probed: their content is the tenant's.
pub const MAPPING_PREFIX: &str = "torngat-vol-";

pub fn mapping(uid: Uuid) -> String {
    format!("{MAPPING_PREFIX}{uid}")
}

/// The decrypted device of volume `uid`.
pub fn device(uid: Uuid) -> PathBuf {
    PathBuf::from(format!("/dev/mapper/{}", mapping(uid)))
}

/// What is where the encryption header goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Header {
    /// Only zeros: never formatted.
    Blank,
    Luks,
    /// Something else: never formatted over.
    Other,
}

pub trait Crypt: Send + Sync + 'static {
    fn header(&self, dev: &Path) -> impl Future<Output = Result<Header, String>> + Send;
    /// Formats a blank device. The caller checked that it is blank.
    fn format(&self, dev: &Path, key: &[u8]) -> impl Future<Output = Result<(), String>> + Send;
    fn open(
        &self,
        dev: &Path,
        name: &str,
        key: &[u8],
    ) -> impl Future<Output = Result<(), String>> + Send;
    /// Follows the device after it grew.
    fn resize(&self, name: &str, key: &[u8]) -> impl Future<Output = Result<(), String>> + Send;
    fn close(&self, name: &str) -> impl Future<Output = Result<(), String>> + Send;
    /// The open mappings named [`MAPPING_PREFIX`]`*`, with their size in bytes.
    fn opened(&self) -> impl Future<Output = Result<BTreeMap<String, u64>, String>> + Send;
    /// Where the open mapping of volume `uid` is read and written.
    fn device_of(&self, uid: Uuid) -> PathBuf {
        device(uid)
    }
}

/// `cryptsetup` on block devices.
#[derive(Debug, Clone, Copy, Default)]
pub struct Cryptsetup;

const SYS_BLOCK: &str = "/sys/block";

/// Refuses anything but a block device: a driver could answer with a path to any file.
async fn block_device(dev: &Path) -> Result<(), String> {
    use std::os::unix::fs::FileTypeExt;
    let m = tokio::fs::metadata(dev)
        .await
        .map_err(|e| format!("{}: {e}", dev.display()))?;
    if !m.file_type().is_block_device() {
        return Err(format!("{} is not a block device", dev.display()));
    }
    Ok(())
}

/// Whether the first [`LUKS_HEADER_BYTES`] of `dev` are zeros. A shorter device is not blank.
async fn blank(dev: &Path) -> Result<bool, String> {
    let err = |e: std::io::Error| format!("{}: {e}", dev.display());
    let mut f = tokio::fs::File::open(dev).await.map_err(err)?;
    let mut buf = vec![0u8; 1 << 20];
    let mut left = LUKS_HEADER_BYTES;
    while left > 0 {
        let want = left.min(buf.len() as u64) as usize;
        let n = f.read(&mut buf[..want]).await.map_err(err)?;
        if n == 0 {
            return Ok(false);
        }
        if buf[..n].iter().any(|&b| b != 0) {
            return Ok(false);
        }
        left -= n as u64;
    }
    Ok(true)
}

/// Runs cryptsetup with `key` (if any) on its standard input.
async fn cryptsetup(args: &[&std::ffi::OsStr], key: Option<&[u8]>) -> Result<(), String> {
    use std::process::Stdio;
    let mut child = tokio::process::Command::new("cryptsetup")
        .args(args)
        .stdin(if key.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("cryptsetup: {e}"))?;
    if let (Some(key), Some(mut stdin)) = (key, child.stdin.take()) {
        stdin
            .write_all(key)
            .await
            .map_err(|e| format!("cryptsetup: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| format!("cryptsetup: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cryptsetup {}: {}",
            args.first()
                .map(|a| a.to_string_lossy())
                .unwrap_or_default(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

fn os(s: &str) -> &std::ffi::OsStr {
    std::ffi::OsStr::new(s)
}

impl Crypt for Cryptsetup {
    async fn header(&self, dev: &Path) -> Result<Header, String> {
        block_device(dev).await?;
        if blank(dev).await? {
            return Ok(Header::Blank);
        }
        let luks = cryptsetup(
            &[os("isLuks"), os("--type"), os("luks2"), dev.as_os_str()],
            None,
        )
        .await
        .is_ok();
        Ok(if luks { Header::Luks } else { Header::Other })
    }

    async fn format(&self, dev: &Path, key: &[u8]) -> Result<(), String> {
        block_device(dev).await?;
        let offset = (LUKS_HEADER_BYTES / 512).to_string();
        // The key is 32 random bytes: no slow key derivation is needed.
        let args = [
            "luksFormat",
            "--batch-mode",
            "--type",
            "luks2",
            "--cipher",
            "aes-xts-plain64",
            "--key-size",
            "512",
            "--hash",
            "sha256",
            "--pbkdf",
            "pbkdf2",
            "--pbkdf-force-iterations",
            "1000",
            "--sector-size",
            "512",
            "--offset",
            &offset,
            "--key-file",
            "-",
        ];
        let mut a: Vec<&std::ffi::OsStr> = args.iter().map(|s| os(s)).collect();
        a.push(dev.as_os_str());
        cryptsetup(&a, Some(key)).await
    }

    async fn open(&self, dev: &Path, name: &str, key: &[u8]) -> Result<(), String> {
        block_device(dev).await?;
        cryptsetup(
            &[
                os("open"),
                os("--type"),
                os("luks2"),
                os("--key-file"),
                os("-"),
                dev.as_os_str(),
                os(name),
            ],
            Some(key),
        )
        .await
    }

    async fn resize(&self, name: &str, key: &[u8]) -> Result<(), String> {
        cryptsetup(
            &[os("resize"), os("--key-file"), os("-"), os(name)],
            Some(key),
        )
        .await
    }

    async fn close(&self, name: &str) -> Result<(), String> {
        cryptsetup(&[os("close"), os(name)], None).await
    }

    async fn opened(&self) -> Result<BTreeMap<String, u64>, String> {
        let err = |e: std::io::Error| format!("{SYS_BLOCK}: {e}");
        let mut out = BTreeMap::new();
        let mut entries = tokio::fs::read_dir(SYS_BLOCK).await.map_err(err)?;
        while let Some(e) = entries.next_entry().await.map_err(err)? {
            if !e.file_name().to_string_lossy().starts_with("dm-") {
                continue;
            }
            // A mapping may go away meanwhile.
            let Ok(name) = tokio::fs::read_to_string(e.path().join("dm/name")).await else {
                continue;
            };
            let name = name.trim();
            if !name.starts_with(MAPPING_PREFIX) {
                continue;
            }
            let Ok(sectors) = tokio::fs::read_to_string(e.path().join("size")).await else {
                continue;
            };
            let sectors: u64 = sectors.trim().parse().map_err(|_| "bad size".to_owned())?;
            out.insert(name.to_owned(), sectors.saturating_mul(512));
        }
        Ok(out)
    }
}

/// In-memory encryption for tests, on devices that are files.
#[derive(Debug, Clone, Default)]
pub struct FakeCrypt(Arc<Mutex<FakeState>>);

#[derive(Debug, Default)]
pub struct FakeState {
    /// Formatted devices and their key.
    pub formatted: BTreeMap<PathBuf, Vec<u8>>,
    /// Open mappings and their device.
    pub open: BTreeMap<String, PathBuf>,
    /// Calls that fail.
    pub fail: bool,
}

impl FakeCrypt {
    pub fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn check(&self) -> Result<(), String> {
        if self.state().fail {
            return Err("simulated failure".into());
        }
        Ok(())
    }
}

async fn file_len(dev: &Path) -> Result<u64, String> {
    tokio::fs::metadata(dev)
        .await
        .map(|m| m.len())
        .map_err(|e| format!("{}: {e}", dev.display()))
}

impl Crypt for FakeCrypt {
    async fn header(&self, dev: &Path) -> Result<Header, String> {
        self.check()?;
        if self.state().formatted.contains_key(dev) {
            return Ok(Header::Luks);
        }
        Ok(if blank(dev).await? {
            Header::Blank
        } else {
            Header::Other
        })
    }

    async fn format(&self, dev: &Path, key: &[u8]) -> Result<(), String> {
        self.check()?;
        file_len(dev).await?;
        self.state().formatted.insert(dev.to_owned(), key.to_vec());
        Ok(())
    }

    async fn open(&self, dev: &Path, name: &str, key: &[u8]) -> Result<(), String> {
        self.check()?;
        let mut s = self.state();
        if s.formatted.get(dev).map(Vec::as_slice) != Some(key) {
            return Err("no key slot matches".into());
        }
        s.open.insert(name.to_owned(), dev.to_owned());
        Ok(())
    }

    async fn resize(&self, name: &str, _key: &[u8]) -> Result<(), String> {
        self.check()?;
        if !self.state().open.contains_key(name) {
            return Err("not open".into());
        }
        Ok(())
    }

    async fn close(&self, name: &str) -> Result<(), String> {
        self.check()?;
        self.state().open.remove(name);
        Ok(())
    }

    fn device_of(&self, uid: Uuid) -> PathBuf {
        self.state()
            .open
            .get(&mapping(uid))
            .cloned()
            .unwrap_or_else(|| device(uid))
    }

    async fn opened(&self) -> Result<BTreeMap<String, u64>, String> {
        self.check()?;
        let open: Vec<_> = self.state().open.clone().into_iter().collect();
        let mut out = BTreeMap::new();
        for (name, dev) in open {
            let len = file_len(&dev).await.unwrap_or(0);
            out.insert(name, len.saturating_sub(LUKS_HEADER_BYTES));
        }
        Ok(out)
    }
}
