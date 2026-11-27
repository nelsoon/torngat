//! The storage driver contract (`proto/storage.proto`) as an in-process trait.

use std::future::Future;

use tonic::Status;
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

/// One of the drivers built in, chosen at start.
#[derive(Debug)]
pub enum AnyDriver {
    None(NoDriver),
    Files(super::files::FileDriver),
}

macro_rules! delegate {
    ($($f:ident($req:ty) -> $resp:ty;)*) => {
        impl Driver for AnyDriver {
            $(async fn $f(&self, r: $req) -> Result<$resp, Status> {
                match self {
                    AnyDriver::None(d) => d.$f(r).await,
                    AnyDriver::Files(d) => d.$f(r).await,
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
