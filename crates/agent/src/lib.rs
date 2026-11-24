//! Torngat node agent.
//!
//! Connects out to a controller over mTLS (its client certificate is its identity), registers
//! the node's inventory, sends heartbeats, and reconciles the instances assigned to it against
//! the local runtime. Reconnects with backoff; running workloads are untouched by disconnects.

#![forbid(unsafe_code)]

pub mod inventory;
pub mod join;
pub mod qemu;
pub mod runtime;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use torngat_api::Scope;
use torngat_api::compute::{Instance, PowerState, Runtime as RuntimeKind};
use torngat_proto::API_VERSION;
use torngat_proto::v1::control_client::ControlClient;
use torngat_proto::v1::*;
use uuid::Uuid;

pub use runtime::{FakeRuntime, Runtime};

pub const HEARTBEAT_EVERY: Duration = Duration::from_secs(2);

/// Where and how to reach the controller.
#[derive(Clone)]
pub struct AgentConfig {
    /// e.g. `https://10.0.0.1:7443`
    pub controller_url: String,
    /// Name the controller's certificate is issued for.
    pub controller_name: String,
    pub ca_pem: Vec<u8>,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentConfig")
            .field("controller_url", &self.controller_url)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("transport: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("rpc: {0}")]
    Rpc(#[from] tonic::Status),
    #[error("encoding: {0}")]
    Json(#[from] serde_json::Error),
}

async fn connect(cfg: &AgentConfig) -> Result<ControlClient<Channel>, AgentError> {
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&cfg.ca_pem))
        .identity(Identity::from_pem(&cfg.cert_pem, &cfg.key_pem))
        .domain_name(cfg.controller_name.clone());
    let channel = Channel::from_shared(cfg.controller_url.clone())
        .map_err(|e| AgentError::Rpc(tonic::Status::invalid_argument(e.to_string())))?
        .tls_config(tls)?
        .connect_timeout(Duration::from_secs(5))
        .connect()
        .await?;
    Ok(ControlClient::new(channel))
}

/// Runs the agent forever, reconnecting on errors.
pub async fn run<R: Runtime>(cfg: AgentConfig, runtime: R) {
    const MIN: Duration = Duration::from_millis(200);
    let mut backoff = MIN;
    loop {
        let started = std::time::Instant::now();
        if let Err(e) = session(&cfg, &runtime).await {
            tracing::warn!(error = %e, "controller session ended");
        }
        // A session that ran for a while was healthy: start backing off from scratch.
        if started.elapsed() > Duration::from_secs(30) {
            backoff = MIN;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(10));
    }
}

/// What the agent last told the controller about an instance, to avoid repeating itself.
type Reported = BTreeMap<Uuid, (String, u64)>;

/// One connected session: register, heartbeat, follow assignments.
pub async fn session<R: Runtime>(cfg: &AgentConfig, runtime: &R) -> Result<(), AgentError> {
    let mut client = connect(cfg).await?;
    let status = inventory::collect(env!("CARGO_PKG_VERSION"));
    client
        .register(RegisterRequest {
            api_version: API_VERSION.into(),
            node_status_json: serde_json::to_vec(&status)?,
        })
        .await?;

    let mut hb = client.clone();
    // Heartbeats keep going through transient errors (e.g. a controller leader change).
    let heartbeat = tokio::spawn(async move {
        loop {
            if let Err(e) = hb.heartbeat(HeartbeatRequest {}).await {
                tracing::warn!(error = %e, "heartbeat failed");
            }
            tokio::time::sleep(HEARTBEAT_EVERY).await;
        }
    });

    let mut stream = client
        .assignments(AssignmentsRequest {})
        .await?
        .into_inner();
    let mut reported = Reported::new();
    let result = async {
        while let Some(set) = stream.message().await? {
            if set.api_version != API_VERSION {
                return Err(tonic::Status::failed_precondition("api_version mismatch").into());
            }
            // An undecodable entry (e.g. a newer controller) must not look "unassigned", or its
            // workload would be stopped: give up on this session instead.
            let instances = set
                .instances_json
                .iter()
                .map(|b| serde_json::from_slice::<Instance>(b))
                .collect::<Result<Vec<_>, _>>()?;
            reconcile(&mut client, runtime, &instances, &mut reported).await?;
        }
        Ok(())
    }
    .await;
    heartbeat.abort();
    result
}

/// Brings the runtime in line with the assigned set and reports changes.
pub async fn reconcile<R: Runtime>(
    client: &mut ControlClient<Channel>,
    runtime: &R,
    assigned: &[Instance],
    reported: &mut Reported,
) -> Result<(), AgentError> {
    let running: BTreeSet<Uuid> = runtime.running().await.into_iter().collect();
    let wanted: BTreeSet<Uuid> = assigned.iter().map(|i| i.metadata.uid).collect();

    // Anything running that is no longer assigned here is stopped.
    for uid in running.difference(&wanted) {
        if let Err(e) = runtime.stop(*uid).await {
            tracing::warn!(%uid, error = %e, "failed to stop unassigned instance");
        }
        reported.remove(uid);
    }

    for inst in assigned {
        let uid = inst.metadata.uid;
        let gen_ = inst.metadata.generation;
        let (phase, message) = match inst.spec.power_state {
            PowerState::Running if running.contains(&uid) => ("running", String::new()),
            PowerState::Running => match runtime.start(inst).await {
                Ok(()) => ("running", String::new()),
                Err(e) => ("failed", e),
            },
            PowerState::Stopped => match runtime.stop(uid).await {
                Ok(()) => ("stopped", String::new()),
                Err(e) => ("failed", e),
            },
        };
        if reported.get(&uid) == Some(&(phase.to_owned(), gen_)) {
            continue;
        }
        let Scope::Project { org, project } = &inst.metadata.scope else {
            continue;
        };
        let runtime_name = match runtime.kind() {
            Some(RuntimeKind::Qemu) => "qemu",
            Some(RuntimeKind::CloudHypervisor) => "cloud_hypervisor",
            None => "",
        };
        let report = client
            .report_instance(InstanceReport {
                org: org.to_string(),
                project: project.to_string(),
                name: inst.metadata.name.to_string(),
                uid: uid.to_string(),
                phase: phase.into(),
                observed_generation: gen_,
                runtime: runtime_name.into(),
                message: sanitize(&message),
            })
            .await;
        match report {
            Ok(_) => {
                reported.insert(uid, (phase.to_owned(), gen_));
            }
            // A rejected report concerns this instance only (e.g. just reassigned or deleted):
            // keep reconciling the others.
            Err(s)
                if matches!(
                    s.code(),
                    tonic::Code::InvalidArgument
                        | tonic::Code::PermissionDenied
                        | tonic::Code::NotFound
                ) =>
            {
                tracing::warn!(%uid, status = %s, "report rejected");
            }
            Err(s) => return Err(s.into()),
        }
    }
    Ok(())
}

/// Longest message the controller accepts.
const MAX_MESSAGE: usize = 1024;

/// Makes runtime error text acceptable to the controller: no control characters, bounded length.
pub fn sanitize(m: &str) -> String {
    let mut out = String::new();
    for c in m.chars() {
        let c = if c.is_control() { ' ' } else { c };
        if out.len() + c.len_utf8() > MAX_MESSAGE {
            break;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_bounds_and_strips() {
        assert_eq!(sanitize("a\nb\tc"), "a b c");
        let long = "é".repeat(2000);
        let s = sanitize(&long);
        assert!(s.len() <= MAX_MESSAGE && s.chars().all(|c| c == 'é'));
    }
}
