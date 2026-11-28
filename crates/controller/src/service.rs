//! The control service agents talk to.

use std::collections::{BTreeSet, HashMap};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use time::OffsetDateTime;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use torngat_api::compute::{Instance, InstancePhase, Runtime};
use torngat_api::image::ImageFormat;
use torngat_api::meta::Cell;
use torngat_api::node::{Node, NodePhase, NodeSpec, NodeStatus, Role};
use torngat_api::{Name, Object, ObjectMeta, Scope};
use torngat_proto::API_VERSION;
use torngat_proto::v1::control_server::Control;
use torngat_proto::v1::*;
use torngat_store::{Precondition, StoreError};
use uuid::Uuid;

use crate::scheduler::list_all;
use torngat_api::storage::StorageCapabilities;

use crate::{Controller, identity, images, keys, storage, volume_keys};

/// How often an agent's assignment set is recomputed.
const ASSIGNMENT_POLL: Duration = Duration::from_millis(500);
/// Retries for compare-and-swap loops.
const CAS_RETRIES: usize = 8;
/// Longest status message accepted from an agent.
const MAX_MESSAGE: usize = 1024;

#[derive(Debug, Clone)]
pub struct ControlService {
    ctl: Controller,
    /// The newest assignment stream of each node.
    streams: Arc<Mutex<HashMap<Name, u64>>>,
}

impl ControlService {
    pub fn new(ctl: Controller) -> Self {
        Self {
            ctl,
            streams: Arc::default(),
        }
    }
}

pub(crate) fn internal(e: impl std::fmt::Display) -> Status {
    tracing::error!(error = %e, "control service internal error");
    Status::internal("internal error")
}

pub(crate) fn store_err(e: StoreError) -> Status {
    match e {
        StoreError::NotLeader { .. } | StoreError::Closed => Status::unavailable("retry"),
        e => internal(e),
    }
}

fn check_version(v: &str) -> Result<(), Status> {
    if v == API_VERSION {
        Ok(())
    } else {
        Err(Status::failed_precondition(format!(
            "unsupported api_version {v:?}, controller speaks {API_VERSION}"
        )))
    }
}

/// An agent's message, or `None` if empty.
fn message(m: String) -> Result<Option<String>, Status> {
    if m.len() > MAX_MESSAGE || m.chars().any(torngat_api::is_hidden) {
        return Err(bad("message"));
    }
    Ok((!m.is_empty()).then_some(m))
}

fn bad(what: &str) -> Status {
    Status::invalid_argument(format!("invalid {what}"))
}

/// The platform or project object that a request is about: empty org and project are the
/// platform's.
fn scoped_object(
    org: String,
    project: String,
    name: String,
    uid: &str,
) -> Result<(Scope, Name, Uuid), Status> {
    if org.is_empty() && project.is_empty() {
        let name = Name::new(name).map_err(|_| bad("name"))?;
        let uid = Uuid::parse_str(uid).map_err(|_| bad("uid"))?;
        return Ok((Scope::Platform, name, uid));
    }
    project_object(org, project, name, uid)
}

/// The project object that a request is about.
fn project_object(
    org: String,
    project: String,
    name: String,
    uid: &str,
) -> Result<(Scope, Name, Uuid), Status> {
    let scope = Scope::Project {
        org: Name::new(org).map_err(|_| bad("org"))?,
        project: Name::new(project).map_err(|_| bad("project"))?,
    };
    let name = Name::new(name).map_err(|_| bad("name"))?;
    let uid = Uuid::parse_str(uid).map_err(|_| bad("uid"))?;
    Ok((scope, name, uid))
}

type AssignmentStream = Pin<Box<dyn Stream<Item = Result<AssignmentSet, Status>> + Send>>;

#[tonic::async_trait]
impl Control for ControlService {
    async fn register(
        &self,
        req: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let me = identity::authenticate(&self.ctl.store, &req).await?;
        let req = req.into_inner();
        check_version(&req.api_version)?;
        let mut reported: NodeStatus = serde_json::from_slice(&req.node_status_json)
            .map_err(|_| Status::invalid_argument("malformed node status"))?;
        reported
            .validate()
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let key = keys::node(&me).map_err(internal)?;

        for _ in 0..CAS_RETRIES {
            let cur = self.ctl.store.get(&key).await.map_err(store_err)?;
            let (node, pre) = match cur {
                None => {
                    // Lifecycle phase is server-set, never taken from the agent.
                    reported.phase = NodePhase::Active;
                    let now = OffsetDateTime::now_utc();
                    let node: Node = Object {
                        metadata: ObjectMeta {
                            name: me.clone(),
                            scope: Scope::Platform,
                            uid: Uuid::now_v7(),
                            cell: Some(Cell::default_cell()),
                            labels: Default::default(),
                            generation: 1,
                            etag: None,
                            create_time: Some(now),
                            update_time: Some(now),
                            delete_time: None,
                        },
                        spec: NodeSpec {
                            roles: BTreeSet::from([Role::Compute]),
                            ..Default::default()
                        },
                        status: reported.clone(),
                    };
                    (node, Precondition::Absent)
                }
                Some(v) => {
                    let mut node: Node = serde_json::from_slice(&v.value).map_err(internal)?;
                    let phase = match node.status.phase {
                        NodePhase::Provisioning | NodePhase::Joining => NodePhase::Active,
                        p => p,
                    };
                    node.status = NodeStatus {
                        phase,
                        ..reported.clone()
                    };
                    node.metadata.update_time = Some(OffsetDateTime::now_utc());
                    (node, Precondition::Revision(v.revision))
                }
            };
            match self
                .ctl
                .store
                .put(
                    key.clone(),
                    serde_json::to_vec(&node).map_err(internal)?,
                    pre,
                )
                .await
            {
                Ok(_) => {
                    self.ctl.live.touch(&me);
                    return Ok(Response::new(RegisterResponse {}));
                }
                Err(StoreError::PreconditionFailed { .. }) => continue,
                Err(e) => return Err(store_err(e)),
            }
        }
        Err(Status::aborted("concurrent node update, retry"))
    }

    async fn heartbeat(
        &self,
        req: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let me = identity::authenticate(&self.ctl.store, &req).await?;
        // Only registered nodes count as live.
        let key = keys::node(&me).map_err(internal)?;
        if self.ctl.store.get(&key).await.map_err(store_err)?.is_none() {
            return Err(Status::failed_precondition("register first"));
        }
        self.ctl.live.touch(&me);
        Ok(Response::new(HeartbeatResponse {}))
    }

    type AssignmentsStream = AssignmentStream;

    async fn assignments(
        &self,
        req: Request<AssignmentsRequest>,
    ) -> Result<Response<Self::AssignmentsStream>, Status> {
        let me = identity::authenticate(&self.ctl.store, &req).await?;
        // One stream per node: each reads every instance, pool and volume twice a second.
        let generation = {
            let mut s = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
            let g = s.entry(me.clone()).or_default();
            *g += 1;
            *g
        };
        let streams = self.streams.clone();
        // Kept to re-check enrollment while the stream is open: revoking a node ends it.
        let cert = req
            .peer_certs()
            .and_then(|c| c.first().map(|c| c.as_ref().to_vec()))
            .ok_or_else(|| Status::unauthenticated("no client certificate"))?;
        let store = self.ctl.store.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let mut last = None;
            loop {
                let current = streams
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&me)
                    == Some(&generation);
                if !current {
                    let _ = tx
                        .send(Err(Status::aborted("replaced by a newer stream")))
                        .await;
                    return;
                }
                if let Err(e) = identity::check_enrolled(&store, &me, &cert).await {
                    let _ = tx.send(Err(e)).await;
                    return;
                }
                let set = match assigned_to(&store, &me).await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                };
                // Instances keep flowing when storage objects cannot be read: then the node is
                // told to ignore the storage lists, never given a partial one.
                let storage = match storage::assigned_storage(&store, &me).await {
                    Ok((pools, volumes)) => match images::assigned_images(&store, &me).await {
                        Ok((images, settings)) => Some((pools, volumes, images, settings)),
                        Err(e) => {
                            tracing::error!(node = %me, error = %e, "image assignments unavailable");
                            None
                        }
                    },
                    Err(e) => {
                        tracing::error!(node = %me, error = %e, "storage assignments unavailable");
                        None
                    }
                };
                let set = (set, storage);
                if last.as_ref() != Some(&set) {
                    let msg = AssignmentSet {
                        api_version: API_VERSION.into(),
                        instances_json: set.0.clone(),
                        pools_json: set.1.as_ref().map(|s| s.0.clone()).unwrap_or_default(),
                        volumes_json: set.1.as_ref().map(|s| s.1.clone()).unwrap_or_default(),
                        images_json: set.1.as_ref().map(|s| s.2.clone()).unwrap_or_default(),
                        image_settings_json: set
                            .1
                            .as_ref()
                            .map(|s| s.3.clone())
                            .unwrap_or_default(),
                        storage_unavailable: set.1.is_none(),
                    };
                    if tx.send(Ok(msg)).await.is_err() {
                        return; // agent went away
                    }
                    last = Some(set);
                }
                tokio::select! {
                    _ = tokio::time::sleep(ASSIGNMENT_POLL) => {}
                    _ = tx.closed() => return, // agent disconnected
                }
            }
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }

    async fn report_instance(
        &self,
        req: Request<InstanceReport>,
    ) -> Result<Response<ReportResponse>, Status> {
        let me = identity::authenticate(&self.ctl.store, &req).await?;
        let r = req.into_inner();
        let (scope, name, uid) = project_object(r.org, r.project, r.name, &r.uid)?;
        let phase = match r.phase.as_str() {
            "starting" => InstancePhase::Starting,
            "running" => InstancePhase::Running,
            "stopping" => InstancePhase::Stopping,
            "stopped" => InstancePhase::Stopped,
            "failed" => InstancePhase::Failed,
            _ => return Err(bad("phase")),
        };
        let runtime = match r.runtime.as_str() {
            "" => None,
            "qemu" => Some(Runtime::Qemu),
            "cloud_hypervisor" => Some(Runtime::CloudHypervisor),
            _ => return Err(bad("runtime")),
        };
        let msg = message(r.message)?;
        let key = keys::instance(&scope, &name).map_err(internal)?;

        for _ in 0..CAS_RETRIES {
            // Same answer for "missing" and "not yours": no existence oracle for other nodes.
            let denied = || Status::permission_denied("instance is not assigned to this node");
            let Some(v) = self.ctl.store.get(&key).await.map_err(store_err)? else {
                return Err(denied());
            };
            let mut inst: Instance = serde_json::from_slice(&v.value).map_err(internal)?;
            // An agent may only report on what is assigned to it, and only for this incarnation.
            if inst.metadata.uid != uid || inst.status.node.as_ref() != Some(&me) {
                return Err(denied());
            }
            inst.status.phase = phase;
            inst.status.runtime = runtime;
            inst.status.observed_generation = r.observed_generation.min(inst.metadata.generation);
            inst.status.message = msg.clone();
            inst.metadata.etag = None;
            match self
                .ctl
                .store
                .put(
                    key.clone(),
                    serde_json::to_vec(&inst).map_err(internal)?,
                    Precondition::Revision(v.revision),
                )
                .await
            {
                // Operations are completed by the controller's reconcile pass, from state.
                Ok(_) => return Ok(Response::new(ReportResponse {})),
                Err(StoreError::PreconditionFailed { .. }) => continue,
                Err(e) => return Err(store_err(e)),
            }
        }
        Err(Status::aborted("concurrent instance update, retry"))
    }

    async fn report_pool(
        &self,
        req: Request<PoolReport>,
    ) -> Result<Response<ReportResponse>, Status> {
        let me = identity::authenticate(&self.ctl.store, &req).await?;
        let r = req.into_inner();
        let name = Name::new(r.name).map_err(|_| bad("name"))?;
        let state = storage::PoolState {
            uid: Uuid::parse_str(&r.uid).map_err(|_| bad("uid"))?,
            ready: r.ready,
            capacity_bytes: r.capacity_bytes,
            allocation_unit_bytes: r.allocation_unit_bytes,
            capabilities: StorageCapabilities {
                snapshots: r.snapshots,
                checksums: r.checksums,
            },
            message: message(r.message)?,
            released: r.released,
        };
        storage::report_pool(&self.ctl.store, &me, &name, state).await?;
        Ok(Response::new(ReportResponse {}))
    }

    async fn report_volume(
        &self,
        req: Request<VolumeReport>,
    ) -> Result<Response<ReportResponse>, Status> {
        let me = identity::authenticate(&self.ctl.store, &req).await?;
        let r = req.into_inner();
        let (scope, name, uid) = scoped_object(r.org, r.project, r.name, &r.uid)?;
        let state = storage::VolumeState {
            uid,
            created: r.created,
            size_bytes: r.size_bytes,
            deleted: r.deleted,
            formatted: r.formatted,
            open: r.open,
            filled: r.filled,
            message: message(r.message)?,
        };
        storage::report_volume(&self.ctl.store, &me, &scope, &name, state).await?;
        Ok(Response::new(ReportResponse {}))
    }

    async fn report_image(
        &self,
        req: Request<ImageReport>,
    ) -> Result<Response<ReportResponse>, Status> {
        let me = identity::authenticate(&self.ctl.store, &req).await?;
        let r = req.into_inner();
        let (scope, name, uid) = scoped_object(r.org, r.project, r.name, &r.uid)?;
        let format = match r.format.as_str() {
            "" => None,
            f => Some(ImageFormat::parse(f).ok_or_else(|| bad("format"))?),
        };
        let state = images::ImageState {
            uid,
            download_bytes: Some(r.download_bytes).filter(|b| *b > 0),
            format,
            size_bytes: Some(r.size_bytes).filter(|b| *b > 0),
            done: r.done,
            failed: r.failed,
            message: message(r.message)?,
        };
        images::report_image(&self.ctl.store, &me, &scope, &name, state).await?;
        Ok(Response::new(ReportResponse {}))
    }

    async fn get_volume_key(
        &self,
        req: Request<VolumeKeyRequest>,
    ) -> Result<Response<VolumeKeyResponse>, Status> {
        let me = identity::authenticate(&self.ctl.store, &req).await?;
        let r = req.into_inner();
        let (scope, name, uid) = scoped_object(r.org, r.project, r.name, &r.uid)?;
        let key = volume_keys::volume_key(&self.ctl, &me, &scope, &name, uid).await?;
        Ok(Response::new(VolumeKeyResponse {
            key: key.expose().to_vec(),
        }))
    }
}

/// Serialized instances currently assigned to `node`, in key order.
async fn assigned_to(store: &torngat_store::Store, node: &Name) -> Result<Vec<Vec<u8>>, Status> {
    let rows = list_all(store, &keys::all_instances().map_err(internal)?)
        .await
        .map_err(store_err)?;
    Ok(rows
        .into_iter()
        .filter_map(|(_, v)| {
            let i: Instance = serde_json::from_slice(&v.value).ok()?;
            (i.status.node.as_ref() == Some(node)).then_some(v.value)
        })
        .collect())
}
