//! The control service agents talk to.

use std::collections::BTreeSet;
use std::pin::Pin;
use std::time::Duration;

use time::OffsetDateTime;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use torngat_api::compute::{Instance, InstancePhase, PowerState, Runtime};
use torngat_api::meta::Cell;
use torngat_api::node::{Node, NodePhase, NodeSpec, NodeStatus, Role};
use torngat_api::operation::{Operation, OperationError};
use torngat_api::{Name, Object, ObjectMeta, Scope};
use torngat_proto::API_VERSION;
use torngat_proto::v1::control_server::Control;
use torngat_proto::v1::*;
use torngat_store::{Precondition, StoreError};
use uuid::Uuid;

use crate::scheduler::list_all;
use crate::{Controller, identity, keys};

/// How often an agent's assignment set is recomputed.
const ASSIGNMENT_POLL: Duration = Duration::from_millis(500);
/// Retries for compare-and-swap loops.
const CAS_RETRIES: usize = 8;
/// Longest status message accepted from an agent.
const MAX_MESSAGE: usize = 1024;

#[derive(Debug, Clone)]
pub struct ControlService {
    ctl: Controller,
}

impl ControlService {
    pub fn new(ctl: Controller) -> Self {
        Self { ctl }
    }
}

fn internal(e: impl std::fmt::Display) -> Status {
    tracing::error!(error = %e, "control service internal error");
    Status::internal("internal error")
}

fn store_err(e: StoreError) -> Status {
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

type AssignmentStream = Pin<Box<dyn Stream<Item = Result<AssignmentSet, Status>> + Send>>;

#[tonic::async_trait]
impl Control for ControlService {
    async fn register(
        &self,
        req: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let me = identity::caller(&req)?;
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
        let me = identity::caller(&req)?;
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
        let me = identity::caller(&req)?;
        let store = self.ctl.store.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let mut last: Option<Vec<Vec<u8>>> = None;
            loop {
                let set = match assigned_to(&store, &me).await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                };
                if last.as_ref() != Some(&set) {
                    let msg = AssignmentSet {
                        api_version: API_VERSION.into(),
                        instances_json: set.clone(),
                    };
                    if tx.send(Ok(msg)).await.is_err() {
                        return; // agent went away
                    }
                    last = Some(set);
                }
                tokio::time::sleep(ASSIGNMENT_POLL).await;
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
        let me = identity::caller(&req)?;
        let r = req.into_inner();
        let bad = |what: &str| Status::invalid_argument(format!("invalid {what}"));
        let scope = Scope::Project {
            org: Name::new(r.org).map_err(|_| bad("org"))?,
            project: Name::new(r.project).map_err(|_| bad("project"))?,
        };
        let name = Name::new(r.name).map_err(|_| bad("name"))?;
        let uid = Uuid::parse_str(&r.uid).map_err(|_| bad("uid"))?;
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
        if r.message.len() > MAX_MESSAGE || r.message.chars().any(char::is_control) {
            return Err(bad("message"));
        }
        let key = keys::instance(&scope, &name).map_err(internal)?;

        for _ in 0..CAS_RETRIES {
            let Some(v) = self.ctl.store.get(&key).await.map_err(store_err)? else {
                return Err(Status::not_found("instance"));
            };
            let mut inst: Instance = serde_json::from_slice(&v.value).map_err(internal)?;
            // An agent may only report on what is assigned to it, and only for this incarnation.
            if inst.metadata.uid != uid || inst.status.node.as_ref() != Some(&me) {
                return Err(Status::permission_denied(
                    "instance is not assigned to this node",
                ));
            }
            inst.status.phase = phase;
            inst.status.runtime = runtime;
            inst.status.observed_generation = r.observed_generation.min(inst.metadata.generation);
            inst.status.message = (!r.message.is_empty()).then(|| r.message.clone());
            let reached = matches!(
                (inst.spec.power_state, phase),
                (PowerState::Running, InstancePhase::Running)
                    | (PowerState::Stopped, InstancePhase::Stopped)
            );
            let done_op = match (
                reached || phase == InstancePhase::Failed,
                inst.status.pending_operation,
            ) {
                (true, Some(op)) => {
                    inst.status.pending_operation = None;
                    Some(op)
                }
                _ => None,
            };
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
                Ok(_) => {
                    if let Some(op) = done_op {
                        let failed = (phase == InstancePhase::Failed).then(|| r.message.clone());
                        complete_operation(&self.ctl, op, failed).await?;
                    }
                    return Ok(Response::new(ReportResponse {}));
                }
                Err(StoreError::PreconditionFailed { .. }) => continue,
                Err(e) => return Err(store_err(e)),
            }
        }
        Err(Status::aborted("concurrent instance update, retry"))
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

async fn complete_operation(
    ctl: &Controller,
    id: Uuid,
    failure: Option<String>,
) -> Result<(), Status> {
    let key = keys::operation(id).map_err(internal)?;
    for _ in 0..CAS_RETRIES {
        let Some(v) = ctl.store.get(&key).await.map_err(store_err)? else {
            return Ok(()); // operation record not written (yet); nothing to complete
        };
        let mut op: Operation = serde_json::from_slice(&v.value).map_err(internal)?;
        if op.done {
            return Ok(());
        }
        op.done = true;
        op.error = failure.clone().map(|m| OperationError {
            code: "INTERNAL".into(),
            message: if m.is_empty() {
                "instance failed".into()
            } else {
                m
            },
        });
        match ctl
            .store
            .put(
                key.clone(),
                serde_json::to_vec(&op).map_err(internal)?,
                Precondition::Revision(v.revision),
            )
            .await
        {
            Ok(_) => return Ok(()),
            Err(StoreError::PreconditionFailed { .. }) => continue,
            Err(e) => return Err(store_err(e)),
        }
    }
    Err(Status::aborted("concurrent operation update, retry"))
}
