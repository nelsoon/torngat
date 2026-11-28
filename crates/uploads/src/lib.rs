//! Image uploads, on the controller's disk.
//!
//! An upload comes in numbered parts (any order; a part sent again replaces it), then is put
//! together and checked against the image's checksum. The image's node then reads it. Each image
//! has a directory named by its uid under the root; nothing in it is named by the tenant.
//!
//! This is the one place that knows where uploads are kept: shared or object storage replaces it
//! when there are several controllers.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use sha2::Digest;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use torngat_api::image::Checksum;
use uuid::Uuid;

/// Largest part.
pub const MAX_PART_BYTES: u64 = 64 << 20;
/// Parts are numbered 1 to this.
pub const MAX_PARTS: u32 = 10_000;
const FILE: &str = "file";

#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    #[error("parts are numbered 1 to {MAX_PARTS}")]
    PartNumber,
    #[error("a part is at most {MAX_PART_BYTES} bytes")]
    PartTooLarge,
    #[error("no parts were uploaded")]
    Empty,
    #[error("part {0} is missing")]
    Missing(u32),
    #[error("the upload is larger than {0} bytes")]
    TooLarge(u64),
    #[error("the checksum does not match")]
    Checksum,
    #[error("the upload was put together already")]
    Finished,
    #[error("the upload is not complete")]
    NotFinished,
    #[error("upload storage: {0}")]
    Io(#[from] std::io::Error),
}

/// Uploads under one directory.
#[derive(Debug, Clone)]
pub struct Uploads {
    root: PathBuf,
}

/// Removes a temporary file unless kept: also when the request that writes it is dropped.
struct Tmp(Option<PathBuf>);

impl Tmp {
    fn path(&self) -> &Path {
        self.0.as_deref().unwrap_or(Path::new(""))
    }

    fn keep(mut self) {
        self.0 = None;
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// An image's upload that its controller did not record yet is not removed for this long.
const GRACE: Duration = Duration::from_secs(3600);

fn part_name(n: u32) -> String {
    format!("part-{n:05}")
}

fn part_number(name: &str) -> Option<u32> {
    name.strip_prefix("part-")?.parse().ok()
}

impl Uploads {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn dir(&self, image: Uuid) -> PathBuf {
        self.root.join(image.hyphenated().to_string())
    }

    /// Writes part `n` of `image`'s upload from `body`. The part replaces one of the same number
    /// only once it is all there.
    pub async fn put_part(
        &self,
        image: Uuid,
        n: u32,
        mut body: impl AsyncRead + Unpin,
    ) -> Result<u64, UploadError> {
        if !(1..=MAX_PARTS).contains(&n) {
            return Err(UploadError::PartNumber);
        }
        let dir = self.dir(image);
        if tokio::fs::try_exists(dir.join(FILE)).await? {
            return Err(UploadError::Finished);
        }
        tokio::fs::create_dir_all(&dir).await?;
        let tmp = Tmp(Some(dir.join(format!(
            "{}.{}.tmp",
            part_name(n),
            Uuid::now_v7()
        ))));
        let mut f = tokio::fs::File::create(tmp.path()).await?;
        let mut buf = vec![0u8; 1 << 20];
        let mut total: u64 = 0;
        loop {
            let got = body.read(&mut buf).await?;
            if got == 0 {
                break;
            }
            total += got as u64;
            if total > MAX_PART_BYTES {
                return Err(UploadError::PartTooLarge);
            }
            f.write_all(&buf[..got]).await?;
        }
        f.sync_all().await?;
        tokio::fs::rename(tmp.path(), dir.join(part_name(n))).await?;
        tmp.keep();
        Ok(total)
    }

    /// The parts received, with their sizes, in order.
    pub async fn parts(&self, image: Uuid) -> Result<Vec<(u32, u64)>, UploadError> {
        let mut out = Vec::new();
        let mut rd = match tokio::fs::read_dir(self.dir(image)).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        while let Some(e) = rd.next_entry().await? {
            let name = e.file_name();
            if let Some(n) = name.to_str().and_then(part_number) {
                out.push((n, e.metadata().await?.len()));
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    /// Puts parts 1 to the last together, if none is missing, the whole is at most `max` bytes
    /// and matches `checksum`. Returns its length. The parts are removed then. Once done, it
    /// answers the same again (the caller may not have recorded it).
    pub async fn finish(
        &self,
        image: Uuid,
        checksum: &Checksum,
        max: u64,
    ) -> Result<u64, UploadError> {
        let dir = self.dir(image);
        match tokio::fs::metadata(dir.join(FILE)).await {
            Ok(m) => return Ok(m.len()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let parts = self.parts(image).await?;
        if parts.is_empty() {
            return Err(UploadError::Empty);
        }
        for (i, (n, _)) in parts.iter().enumerate() {
            let want = u32::try_from(i + 1).unwrap_or(u32::MAX);
            if *n != want {
                return Err(UploadError::Missing(want));
            }
        }
        let listed: u64 = parts.iter().map(|(_, s)| s).sum();
        if listed > max {
            return Err(UploadError::TooLarge(max));
        }
        let tmp = Tmp(Some(dir.join(format!("{FILE}.{}.tmp", Uuid::now_v7()))));
        let joined = async {
            let mut out = tokio::fs::File::create(tmp.path()).await?;
            let mut copied: u64 = 0;
            let mut h256 = sha2::Sha256::new();
            let mut h512 = sha2::Sha512::new();
            let mut buf = vec![0u8; 1 << 20];
            for (n, _) in &parts {
                let mut f = tokio::fs::File::open(dir.join(part_name(*n))).await?;
                loop {
                    let got = f.read(&mut buf).await?;
                    if got == 0 {
                        break;
                    }
                    match checksum {
                        Checksum::Sha256(_) => h256.update(&buf[..got]),
                        Checksum::Sha512(_) => h512.update(&buf[..got]),
                    }
                    copied += got as u64;
                    if copied > max {
                        return Err(UploadError::TooLarge(max));
                    }
                    out.write_all(&buf[..got]).await?;
                }
            }
            out.sync_all().await?;
            let ok = match checksum {
                Checksum::Sha256(w) => torngat_pki::hex(&h256.finalize()) == *w,
                Checksum::Sha512(w) => torngat_pki::hex(&h512.finalize()) == *w,
            };
            if ok {
                Ok(copied)
            } else {
                Err(UploadError::Checksum)
            }
        }
        .await;
        let copied = joined?;
        tokio::fs::rename(tmp.path(), dir.join(FILE)).await?;
        tmp.keep();
        for (n, _) in parts {
            let _ = tokio::fs::remove_file(dir.join(part_name(n))).await;
        }
        Ok(copied)
    }

    /// The finished upload of `image`, positioned at `offset`.
    pub async fn open(&self, image: Uuid, offset: u64) -> Result<tokio::fs::File, UploadError> {
        use tokio::io::AsyncSeekExt;
        let mut f = match tokio::fs::File::open(self.dir(image).join(FILE)).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(UploadError::NotFinished);
            }
            Err(e) => return Err(e.into()),
        };
        f.seek(std::io::SeekFrom::Start(offset)).await?;
        Ok(f)
    }

    /// Removes everything of `image`'s upload.
    pub async fn remove(&self, image: Uuid) -> Result<(), UploadError> {
        match tokio::fs::remove_dir_all(self.dir(image)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Removes the uploads of images that `keep` does not want, and unfinished ones untouched for
    /// `stale`. Returns how many it removed.
    pub async fn sweep(
        &self,
        keep: impl Fn(Uuid) -> bool,
        stale: Duration,
    ) -> Result<usize, UploadError> {
        let mut rd = match tokio::fs::read_dir(&self.root).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        let mut removed = 0;
        while let Some(e) = rd.next_entry().await? {
            let Some(uid) = e.file_name().to_str().and_then(|n| Uuid::parse_str(n).ok()) else {
                continue;
            };
            // One that cannot be looked at does not hold back the others.
            let gone = async {
                let finished = tokio::fs::try_exists(e.path().join(FILE)).await?;
                let idle = untouched_for(&e.path()).await?;
                // An image made since its caller read the images may not be in `keep` yet.
                let unwanted = !keep(uid) && idle > GRACE;
                if unwanted || (!finished && idle > stale) {
                    self.remove(uid).await?;
                    return Ok::<_, UploadError>(true);
                }
                Ok(false)
            }
            .await;
            match gone {
                Ok(true) => removed += 1,
                Ok(false) => {}
                Err(_) => {}
            }
        }
        Ok(removed)
    }
}

/// How long nothing in `dir` changed.
async fn untouched_for(dir: &Path) -> Result<Duration, UploadError> {
    let mut newest = tokio::fs::metadata(dir).await?.modified()?;
    let mut rd = tokio::fs::read_dir(dir).await?;
    while let Some(e) = rd.next_entry().await? {
        newest = newest.max(e.metadata().await?.modified()?);
    }
    Ok(SystemTime::now()
        .duration_since(newest)
        .unwrap_or(Duration::ZERO))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Makes `dir` and what is in it look two hours old.
    fn age(dir: &Path) {
        let old = SystemTime::now() - Duration::from_secs(7200);
        for e in std::fs::read_dir(dir).unwrap() {
            let f = std::fs::File::options()
                .write(true)
                .open(e.unwrap().path())
                .unwrap();
            f.set_modified(old).unwrap();
        }
        std::fs::File::open(dir).unwrap().set_modified(old).unwrap();
    }

    #[tokio::test]
    async fn parts_put_together() {
        let dir = tempfile::TempDir::new().unwrap();
        let u = Uploads::new(dir.path());
        let img = Uuid::now_v7();
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let sha = Checksum::Sha256(torngat_pki::hex_sha256(&data));
        // Out of order, one sent again.
        u.put_part(img, 2, &data[100_000..200_000]).await.unwrap();
        u.put_part(img, 1, &b"wrong"[..]).await.unwrap();
        u.put_part(img, 1, &data[..100_000]).await.unwrap();
        assert!(matches!(
            u.finish(img, &sha, 1 << 30).await,
            Err(UploadError::Checksum)
        ));
        assert!(matches!(
            u.put_part(img, 0, &b""[..]).await,
            Err(UploadError::PartNumber)
        ));
        u.put_part(img, 4, &b"x"[..]).await.unwrap();
        assert!(matches!(
            u.finish(img, &sha, 1 << 30).await,
            Err(UploadError::Missing(3))
        ));
        std::fs::remove_file(dir.path().join(img.to_string()).join(part_name(4))).unwrap();
        u.put_part(img, 3, &data[200_000..]).await.unwrap();
        assert_eq!(
            u.parts(img).await.unwrap(),
            vec![(1, 100_000), (2, 100_000), (3, 100_000)]
        );
        assert!(matches!(
            u.finish(img, &sha, 1000).await,
            Err(UploadError::TooLarge(1000))
        ));
        assert_eq!(u.finish(img, &sha, 1 << 30).await.unwrap(), 300_000);
        assert!(u.parts(img).await.unwrap().is_empty());
        assert!(matches!(
            u.put_part(img, 1, &b""[..]).await,
            Err(UploadError::Finished)
        ));
        // Finished again: the same answer.
        assert_eq!(u.finish(img, &sha, 1 << 30).await.unwrap(), 300_000);
        let mut f = u.open(img, 299_990).await.unwrap();
        let mut tail = Vec::new();
        f.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, &data[299_990..]);

        // Swept once its image is gone.
        let other = Uuid::now_v7();
        u.put_part(other, 1, &b"a"[..]).await.unwrap();
        let hour = Duration::from_secs(3600);
        // Not at once: its image may be new.
        assert_eq!(u.sweep(|i| i == img, hour).await.unwrap(), 0);
        age(&dir.path().join(other.to_string()));
        assert_eq!(u.sweep(|i| i == img, hour).await.unwrap(), 1);
        assert!(u.open(img, 0).await.is_ok());
        // An unfinished one left alone too long.
        u.put_part(other, 1, &b"a"[..]).await.unwrap();
        assert_eq!(u.sweep(|_| true, Duration::ZERO).await.unwrap(), 1);
        assert!(u.parts(other).await.unwrap().is_empty());
        u.remove(img).await.unwrap();
        assert!(matches!(
            u.open(img, 0).await,
            Err(UploadError::NotFinished)
        ));
    }

    #[tokio::test]
    async fn parts_have_a_limit() {
        let dir = tempfile::TempDir::new().unwrap();
        let u = Uploads::new(dir.path());
        let img = Uuid::now_v7();
        let big = tokio::io::repeat(0).take(MAX_PART_BYTES + 1);
        assert!(matches!(
            u.put_part(img, 1, big).await,
            Err(UploadError::PartTooLarge)
        ));
        assert!(u.parts(img).await.unwrap().is_empty());
    }
}
