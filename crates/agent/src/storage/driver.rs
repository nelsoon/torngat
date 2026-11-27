//! The storage driver contract (`proto/storage.proto`) as an in-process trait.

use std::future::Future;
use std::sync::Arc;

use tonic::Status;
use torngat_api::storage::StorageDriver;
use torngat_proto::storage::v1::*;

/// A storage driver. See `proto/storage.proto` for what each call must do; the requests and answers
/// are its messages, so that a driver behind a socket fits the same trait.
pub trait Driver: Send + Sync + 'static {
    fn claim_pool(
        &self,
        r: ClaimPoolRequest,
    ) -> impl Future<Output = Result<ClaimPoolResponse, Status>> + Send;
    fn release_pool(
        &self,
        r: ReleasePoolRequest,
    ) -> impl Future<Output = Result<ReleasePoolResponse, Status>> + Send;
    fn get_pool(
        &self,
        r: GetPoolRequest,
    ) -> impl Future<Output = Result<GetPoolResponse, Status>> + Send;
    fn list_volumes(
        &self,
        r: ListVolumesRequest,
    ) -> impl Future<Output = Result<ListVolumesResponse, Status>> + Send;
    fn create_volume(
        &self,
        r: CreateVolumeRequest,
    ) -> impl Future<Output = Result<CreateVolumeResponse, Status>> + Send;
    fn grow_volume(
        &self,
        r: GrowVolumeRequest,
    ) -> impl Future<Output = Result<GrowVolumeResponse, Status>> + Send;
    fn delete_volume(
        &self,
        r: DeleteVolumeRequest,
    ) -> impl Future<Output = Result<DeleteVolumeResponse, Status>> + Send;
    fn attach_volume(
        &self,
        r: AttachVolumeRequest,
    ) -> impl Future<Output = Result<AttachVolumeResponse, Status>> + Send;
    fn detach_volume(
        &self,
        r: DetachVolumeRequest,
    ) -> impl Future<Output = Result<DetachVolumeResponse, Status>> + Send;
}

/// A node without storage: every call fails, so its pools are shown as not ready.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDriver;

fn none() -> Status {
    Status::unavailable("no storage driver on this node")
}

impl Driver for NoDriver {
    async fn claim_pool(&self, _: ClaimPoolRequest) -> Result<ClaimPoolResponse, Status> {
        Err(none())
    }
    async fn release_pool(&self, _: ReleasePoolRequest) -> Result<ReleasePoolResponse, Status> {
        Err(none())
    }
    async fn get_pool(&self, _: GetPoolRequest) -> Result<GetPoolResponse, Status> {
        Err(none())
    }
    async fn list_volumes(&self, _: ListVolumesRequest) -> Result<ListVolumesResponse, Status> {
        Err(none())
    }
    async fn create_volume(&self, _: CreateVolumeRequest) -> Result<CreateVolumeResponse, Status> {
        Err(none())
    }
    async fn grow_volume(&self, _: GrowVolumeRequest) -> Result<GrowVolumeResponse, Status> {
        Err(none())
    }
    async fn delete_volume(&self, _: DeleteVolumeRequest) -> Result<DeleteVolumeResponse, Status> {
        Err(none())
    }
    async fn attach_volume(&self, _: AttachVolumeRequest) -> Result<AttachVolumeResponse, Status> {
        Err(none())
    }
    async fn detach_volume(&self, _: DetachVolumeRequest) -> Result<DetachVolumeResponse, Status> {
        Err(none())
    }
}

/// The drivers of a node, by the kind that pools name.
pub trait Drivers: Send + Sync + 'static {
    type Driver: Driver;
    fn get(&self, kind: StorageDriver) -> &Self::Driver;
}

impl Drivers for NoDriver {
    type Driver = Self;
    fn get(&self, _: StorageDriver) -> &Self {
        self
    }
}

/// Tests: one driver for every kind.
impl Drivers for super::files::FileDriver {
    type Driver = Self;
    fn get(&self, _: StorageDriver) -> &Self {
        self
    }
}

/// One of the drivers built in.
#[derive(Debug, Clone)]
pub enum AnyDriver {
    None(NoDriver),
    Files(Arc<super::files::FileDriver>),
    Lvm(super::lvm::LvmDriver),
}

/// The drivers built in: LVM; ZFS later. With `fake`, every pool uses it instead (tests only).
#[derive(Debug)]
pub struct Builtin {
    lvm: AnyDriver,
    zfs: AnyDriver,
}

impl Builtin {
    pub fn new(fake: Option<super::files::FileDriver>) -> Self {
        match fake {
            Some(f) => {
                let f = AnyDriver::Files(Arc::new(f));
                Self {
                    lvm: f.clone(),
                    zfs: f,
                }
            }
            None => Self {
                lvm: AnyDriver::Lvm(super::lvm::LvmDriver),
                zfs: AnyDriver::None(NoDriver),
            },
        }
    }
}

impl Drivers for Builtin {
    type Driver = AnyDriver;
    fn get(&self, kind: StorageDriver) -> &AnyDriver {
        match kind {
            StorageDriver::Lvm => &self.lvm,
            StorageDriver::Zfs => &self.zfs,
        }
    }
}

macro_rules! delegate {
    ($($f:ident($req:ty) -> $resp:ty;)*) => {
        impl Driver for AnyDriver {
            $(async fn $f(&self, r: $req) -> Result<$resp, Status> {
                match self {
                    AnyDriver::None(d) => d.$f(r).await,
                    AnyDriver::Files(d) => d.$f(r).await,
                    AnyDriver::Lvm(d) => d.$f(r).await,
                }
            })*
        }
    };
}

delegate! {
    claim_pool(ClaimPoolRequest) -> ClaimPoolResponse;
    release_pool(ReleasePoolRequest) -> ReleasePoolResponse;
    get_pool(GetPoolRequest) -> GetPoolResponse;
    list_volumes(ListVolumesRequest) -> ListVolumesResponse;
    create_volume(CreateVolumeRequest) -> CreateVolumeResponse;
    grow_volume(GrowVolumeRequest) -> GrowVolumeResponse;
    delete_volume(DeleteVolumeRequest) -> DeleteVolumeResponse;
    attach_volume(AttachVolumeRequest) -> AttachVolumeResponse;
    detach_volume(DetachVolumeRequest) -> DetachVolumeResponse;
}

/// The request's pool, if its source is a plain name: lowercase letters, digits, `-` and `_`, not
/// starting with `-` or `_` (never an option or a path).
pub(crate) fn pool_of(pool: &Option<Pool>) -> Result<&Pool, Status> {
    let p = pool
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("no pool"))?;
    let ok = !p.source.is_empty()
        && p.source
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        && !p.source.starts_with(['-', '_']);
    if !ok {
        return Err(Status::invalid_argument("invalid pool source"));
    }
    Ok(p)
}

pub(crate) fn volume_uid(uid: &str) -> Result<uuid::Uuid, Status> {
    uuid::Uuid::parse_str(uid).map_err(|_| Status::invalid_argument("invalid volume uid"))
}

/// Writes `len` zero bytes at `offset` of `f`, and flushes them to the device.
pub(crate) async fn write_zeros(
    f: &mut tokio::fs::File,
    offset: u64,
    len: u64,
) -> std::io::Result<()> {
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};
    f.seek(std::io::SeekFrom::Start(offset)).await?;
    let zeros = vec![0u8; 1 << 20];
    let mut left = len;
    while left > 0 {
        let n = left.min(zeros.len() as u64);
        f.write_all(&zeros[..n as usize]).await?;
        left -= n;
    }
    f.sync_all().await
}
