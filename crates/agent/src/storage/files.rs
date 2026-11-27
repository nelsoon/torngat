//! A driver for tests and labs: a pool is a directory, a volume a sparse file in it, attached as a
//! loop device. Never for real use: nothing is reserved on the file system, so it can fill up under
//! the volumes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use tokio::io::AsyncWriteExt;
use tonic::Status;
use torngat_api::storage::LUKS_HEADER_BYTES;
use torngat_proto::storage::v1::attach_volume_response::Device;
use torngat_proto::storage::v1::*;
use uuid::Uuid;

use super::driver::Driver;

const MARK: &str = ".torngat-pool";
const SUFFIX: &str = ".img";
/// Sizes are rounded up to this, like LVM extents.
pub const ALLOCATION_UNIT: u64 = 4 << 20;

#[derive(Debug)]
pub struct FileDriver {
    root: PathBuf,
    capacity: u64,
    /// Attach as loop devices (needs root); otherwise the file itself is the device.
    loop_devices: bool,
    /// Attached files, without loop devices.
    attached: Mutex<BTreeSet<PathBuf>>,
}

impl FileDriver {
    /// Pools are the directories under `root`, each with room for `capacity` bytes of volumes.
    pub fn new(root: impl Into<PathBuf>, capacity: u64, loop_devices: bool) -> Self {
        Self {
            root: root.into(),
            capacity,
            loop_devices,
            attached: Mutex::default(),
        }
    }

    /// The pool's directory. `NOT_FOUND` if it is missing: the operator makes it.
    async fn dir(&self, pool: &Option<Pool>) -> Result<(PathBuf, String), Status> {
        let pool = pool
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("no pool"))?;
        let ok = !pool.source.is_empty()
            && pool
                .source
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
            && !pool.source.starts_with(['-', '_']);
        if !ok {
            return Err(Status::invalid_argument("invalid pool source"));
        }
        let dir = self.root.join(&pool.source);
        if !tokio::fs::metadata(&dir).await.is_ok_and(|m| m.is_dir()) {
            return Err(Status::not_found("no such pool"));
        }
        Ok((dir, format!("{} {}\n", pool.cluster_uid, pool.uid)))
    }

    async fn mark(dir: &Path) -> Result<Option<String>, Status> {
        match tokio::fs::read_to_string(dir.join(MARK)).await {
            Ok(m) => Ok(Some(m)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io(e)),
        }
    }

    /// The pool's directory, if it carries this pool's mark.
    async fn marked(&self, pool: &Option<Pool>) -> Result<PathBuf, Status> {
        let (dir, mark) = self.dir(pool).await?;
        if Self::mark(&dir).await?.as_deref() != Some(mark.as_str()) {
            return Err(Status::failed_precondition(
                "the pool is not marked as this one",
            ));
        }
        Ok(dir)
    }

    async fn volumes(dir: &Path) -> Result<Vec<(Uuid, PathBuf, u64)>, Status> {
        let mut out = Vec::new();
        let mut entries = tokio::fs::read_dir(dir).await.map_err(io)?;
        while let Some(e) = entries.next_entry().await.map_err(io)? {
            let name = e.file_name();
            let Some(uid) = name
                .to_str()
                .and_then(|n| n.strip_suffix(SUFFIX))
                .and_then(|n| Uuid::parse_str(n).ok())
            else {
                continue;
            };
            let len = e.metadata().await.map_err(io)?.len();
            out.push((uid, e.path(), len));
        }
        Ok(out)
    }

    fn file(dir: &Path, uid: &str) -> Result<PathBuf, Status> {
        let uid =
            Uuid::parse_str(uid).map_err(|_| Status::invalid_argument("invalid volume uid"))?;
        Ok(dir.join(format!("{uid}{SUFFIX}")))
    }

    /// Fails if `more` bytes do not fit.
    async fn room(&self, dir: &Path, more: u64) -> Result<(), Status> {
        let used: u64 = Self::volumes(dir).await?.iter().map(|v| v.2).sum();
        if used.saturating_add(more) > self.capacity {
            return Err(Status::resource_exhausted("no space in the pool"));
        }
        Ok(())
    }

    /// Loop devices of `file`.
    async fn loops(file: &Path) -> Result<Vec<String>, Status> {
        let out = losetup(
            &["--list", "--noheadings", "--output", "NAME", "--associated"],
            file,
        )
        .await?;
        Ok(out
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect())
    }

    async fn is_attached(&self, file: &Path) -> Result<bool, Status> {
        if self.loop_devices {
            Ok(!Self::loops(file).await?.is_empty())
        } else {
            Ok(self.attached().contains(file))
        }
    }

    fn attached(&self) -> std::sync::MutexGuard<'_, BTreeSet<PathBuf>> {
        self.attached.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn io(e: std::io::Error) -> Status {
    Status::internal(e.to_string())
}

fn rounded(bytes: u64) -> u64 {
    bytes
        .div_ceil(ALLOCATION_UNIT)
        .saturating_mul(ALLOCATION_UNIT)
}

async fn losetup(args: &[&str], file: &Path) -> Result<String, Status> {
    let out = tokio::process::Command::new("losetup")
        .args(args)
        .arg(file)
        .output()
        .await
        .map_err(io)?;
    if !out.status.success() {
        return Err(Status::internal(format!(
            "losetup: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

impl Driver for FileDriver {
    async fn claim_pool(&self, r: ClaimPoolRequest) -> Result<ClaimPoolResponse, Status> {
        let (dir, mark) = self.dir(&r.pool).await?;
        match Self::mark(&dir).await? {
            Some(m) if m == mark => {}
            Some(_) => return Err(Status::failed_precondition("the pool carries another mark")),
            None => {
                // Written whole under another name, then moved, so that a crash leaves no half mark.
                let tmp = dir.join(format!("{MARK}.tmp"));
                let mut f = tokio::fs::File::create(&tmp).await.map_err(io)?;
                f.write_all(mark.as_bytes()).await.map_err(io)?;
                f.sync_all().await.map_err(io)?;
                tokio::fs::rename(&tmp, dir.join(MARK)).await.map_err(io)?;
            }
        }
        Ok(ClaimPoolResponse {})
    }

    async fn release_pool(&self, r: ReleasePoolRequest) -> Result<ReleasePoolResponse, Status> {
        let (dir, mark) = self.dir(&r.pool).await?;
        match Self::mark(&dir).await? {
            None => {}
            Some(m) if m != mark => {
                return Err(Status::failed_precondition("the pool carries another mark"));
            }
            Some(_) => {
                if !Self::volumes(&dir).await?.is_empty() {
                    return Err(Status::failed_precondition("the pool holds volumes"));
                }
                tokio::fs::remove_file(dir.join(MARK)).await.map_err(io)?;
            }
        }
        Ok(ReleasePoolResponse {})
    }

    async fn get_pool(&self, r: GetPoolRequest) -> Result<GetPoolResponse, Status> {
        self.marked(&r.pool).await?;
        Ok(GetPoolResponse {
            capacity_bytes: self.capacity,
            capabilities: Some(Capabilities::default()),
            allocation_unit_bytes: ALLOCATION_UNIT,
        })
    }

    async fn list_volumes(&self, r: ListVolumesRequest) -> Result<ListVolumesResponse, Status> {
        let dir = self.marked(&r.pool).await?;
        let mut volumes = Vec::new();
        for (uid, file, size) in Self::volumes(&dir).await? {
            volumes.push(VolumeInfo {
                uid: uid.to_string(),
                size_bytes: size,
                attached: self.is_attached(&file).await?,
            });
        }
        Ok(ListVolumesResponse { volumes })
    }

    async fn create_volume(&self, r: CreateVolumeRequest) -> Result<CreateVolumeResponse, Status> {
        let dir = self.marked(&r.pool).await?;
        let file = Self::file(&dir, &r.uid)?;
        if let Ok(m) = tokio::fs::metadata(&file).await {
            return Ok(CreateVolumeResponse {
                size_bytes: m.len(),
            });
        }
        let size = rounded(r.size_bytes.max(2 * LUKS_HEADER_BYTES));
        self.room(&dir, size).await?;
        // A new sparse file reads as zeros: its first and last 16 MiB are blank.
        let tmp = file.with_extension("tmp");
        let f = tokio::fs::File::create(&tmp).await.map_err(io)?;
        f.set_len(size).await.map_err(io)?;
        f.sync_all().await.map_err(io)?;
        tokio::fs::rename(&tmp, &file).await.map_err(io)?;
        Ok(CreateVolumeResponse { size_bytes: size })
    }

    async fn grow_volume(&self, r: GrowVolumeRequest) -> Result<GrowVolumeResponse, Status> {
        let dir = self.marked(&r.pool).await?;
        let file = Self::file(&dir, &r.uid)?;
        let have = match tokio::fs::metadata(&file).await {
            Ok(m) => m.len(),
            Err(_) => return Err(Status::not_found("no such volume")),
        };
        let want = rounded(r.size_bytes);
        if want <= have {
            return Ok(GrowVolumeResponse { size_bytes: have });
        }
        self.room(&dir, want - have).await?;
        let f = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&file)
            .await
            .map_err(io)?;
        f.set_len(want).await.map_err(io)?;
        f.sync_all().await.map_err(io)?;
        if self.loop_devices {
            for dev in Self::loops(&file).await? {
                losetup(&["--set-capacity"], Path::new(&dev)).await?;
            }
        }
        Ok(GrowVolumeResponse { size_bytes: want })
    }

    async fn delete_volume(&self, r: DeleteVolumeRequest) -> Result<DeleteVolumeResponse, Status> {
        let dir = self.marked(&r.pool).await?;
        let file = Self::file(&dir, &r.uid)?;
        if tokio::fs::metadata(&file).await.is_err() {
            return Ok(DeleteVolumeResponse {});
        }
        if self.is_attached(&file).await? {
            return Err(Status::failed_precondition("the volume is attached"));
        }
        // The header goes first: what is left of the file cannot be opened.
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&file)
            .await
            .map_err(io)?;
        let len = f.metadata().await.map_err(io)?.len().min(LUKS_HEADER_BYTES);
        super::driver::write_zeros(&mut f, 0, len)
            .await
            .map_err(io)?;
        tokio::fs::remove_file(&file).await.map_err(io)?;
        Ok(DeleteVolumeResponse {})
    }

    async fn attach_volume(&self, r: AttachVolumeRequest) -> Result<AttachVolumeResponse, Status> {
        let dir = self.marked(&r.pool).await?;
        let file = Self::file(&dir, &r.uid)?;
        if tokio::fs::metadata(&file).await.is_err() {
            return Err(Status::not_found("no such volume"));
        }
        let path = if self.loop_devices {
            match Self::loops(&file).await?.into_iter().next() {
                Some(dev) => dev,
                None => losetup(&["--find", "--show", "--nooverlap"], &file)
                    .await?
                    .trim()
                    .to_owned(),
            }
        } else {
            self.attached().insert(file.clone());
            file.to_string_lossy().into_owned()
        };
        Ok(AttachVolumeResponse {
            device: Some(Device::Block(BlockDevice { path })),
        })
    }

    async fn detach_volume(&self, r: DetachVolumeRequest) -> Result<DetachVolumeResponse, Status> {
        let dir = self.marked(&r.pool).await?;
        let file = Self::file(&dir, &r.uid)?;
        if tokio::fs::metadata(&file).await.is_err() {
            return Ok(DetachVolumeResponse {});
        }
        if self.loop_devices {
            for dev in Self::loops(&file).await? {
                losetup(&["--detach"], Path::new(&dev)).await?;
            }
        } else {
            self.attached().remove(&file);
        }
        Ok(DetachVolumeResponse {})
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use tonic::Code;

    const MIB: u64 = 1 << 20;

    fn pool(cluster: &str) -> Option<Pool> {
        Some(Pool {
            uid: "p1".into(),
            cluster_uid: cluster.into(),
            source: "data".into(),
        })
    }

    fn create(pool: &Option<Pool>, uid: Uuid, size: u64) -> CreateVolumeRequest {
        CreateVolumeRequest {
            pool: pool.clone(),
            uid: uid.to_string(),
            size_bytes: size,
        }
    }

    #[tokio::test]
    async fn the_contract() {
        let root = tempfile::TempDir::new().unwrap();
        let d = FileDriver::new(root.path(), 100 * MIB, false);
        let p = pool("c1");
        let code = |s: Status| s.code();

        // The operator makes the pool; it is never made here.
        let err = d.claim_pool(ClaimPoolRequest { pool: p.clone() }).await;
        assert_eq!(err.map_err(code).unwrap_err(), Code::NotFound);
        std::fs::create_dir(root.path().join("data")).unwrap();
        let bad = Some(Pool {
            source: "../data".into(),
            ..p.clone().unwrap()
        });
        let err = d.claim_pool(ClaimPoolRequest { pool: bad }).await;
        assert_eq!(err.map_err(code).unwrap_err(), Code::InvalidArgument);

        // Unmarked: only claiming works. Another cluster's mark is refused.
        let err = d.get_pool(GetPoolRequest { pool: p.clone() }).await;
        assert_eq!(err.map_err(code).unwrap_err(), Code::FailedPrecondition);
        d.claim_pool(ClaimPoolRequest { pool: p.clone() })
            .await
            .unwrap();
        d.claim_pool(ClaimPoolRequest { pool: p.clone() })
            .await
            .unwrap();
        let err = d.claim_pool(ClaimPoolRequest { pool: pool("c2") }).await;
        assert_eq!(err.map_err(code).unwrap_err(), Code::FailedPrecondition);
        let err = d
            .list_volumes(ListVolumesRequest { pool: pool("c2") })
            .await;
        assert_eq!(err.map_err(code).unwrap_err(), Code::FailedPrecondition);

        // Rounded up; whatever exists is left as it is; space is counted.
        let v = Uuid::now_v7();
        let r = d.create_volume(create(&p, v, 33 * MIB)).await.unwrap();
        assert_eq!(r.size_bytes, 36 * MIB);
        let r = d.create_volume(create(&p, v, 80 * MIB)).await.unwrap();
        assert_eq!(r.size_bytes, 36 * MIB);
        let err = d.create_volume(create(&p, Uuid::now_v7(), 80 * MIB)).await;
        assert_eq!(err.map_err(code).unwrap_err(), Code::ResourceExhausted);
        let err = d
            .create_volume(CreateVolumeRequest {
                uid: "../x".into(),
                ..create(&p, v, MIB)
            })
            .await;
        assert_eq!(err.map_err(code).unwrap_err(), Code::InvalidArgument);

        // Grows, never shrinks.
        let grow = |size| GrowVolumeRequest {
            pool: p.clone(),
            uid: v.to_string(),
            size_bytes: size,
        };
        assert_eq!(
            d.grow_volume(grow(40 * MIB)).await.unwrap().size_bytes,
            40 * MIB
        );
        assert_eq!(d.grow_volume(grow(MIB)).await.unwrap().size_bytes, 40 * MIB);
        let err = d.grow_volume(grow(200 * MIB)).await;
        assert_eq!(err.map_err(code).unwrap_err(), Code::ResourceExhausted);

        // Attached: not deleted, listed as attached. The pool keeps its mark while it holds one.
        let file = root.path().join("data").join(format!("{v}.img"));
        std::fs::write(&file, vec![1u8; 40 * MIB as usize]).unwrap();
        let at = AttachVolumeRequest {
            pool: p.clone(),
            uid: v.to_string(),
        };
        let Some(Device::Block(b)) = d.attach_volume(at).await.unwrap().device else {
            unreachable!()
        };
        assert_eq!(Path::new(&b.path), file);
        let list = d
            .list_volumes(ListVolumesRequest { pool: p.clone() })
            .await
            .unwrap();
        assert_eq!(list.volumes.len(), 1);
        assert!(list.volumes[0].attached);
        let del = DeleteVolumeRequest {
            pool: p.clone(),
            uid: v.to_string(),
        };
        let err = d.delete_volume(del.clone()).await;
        assert_eq!(err.map_err(code).unwrap_err(), Code::FailedPrecondition);
        let err = d.release_pool(ReleasePoolRequest { pool: p.clone() }).await;
        assert_eq!(err.map_err(code).unwrap_err(), Code::FailedPrecondition);
        let det = DetachVolumeRequest {
            pool: p.clone(),
            uid: v.to_string(),
        };
        d.detach_volume(det.clone()).await.unwrap();
        // The header is overwritten before the file goes: seen through another link.
        let kept = root.path().join("kept");
        std::fs::hard_link(&file, &kept).unwrap();
        d.delete_volume(del.clone()).await.unwrap();
        assert!(!file.exists());
        let left = std::fs::read(&kept).unwrap();
        let header = LUKS_HEADER_BYTES as usize;
        assert!(left[..header].iter().all(|&b| b == 0));
        assert!(left[header..].iter().all(|&b| b == 1));
        std::fs::remove_file(&kept).unwrap();
        d.delete_volume(del).await.unwrap();
        d.detach_volume(det).await.unwrap();

        d.release_pool(ReleasePoolRequest { pool: p.clone() })
            .await
            .unwrap();
        d.release_pool(ReleasePoolRequest { pool: p })
            .await
            .unwrap();
        assert!(!root.path().join("data").join(MARK).exists());
    }
}
