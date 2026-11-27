//! Torngat node agent.
//!
//! Connects out to a controller over mTLS (its client certificate is its identity), registers
//! the node's inventory, sends heartbeats, and reconciles the instances assigned to it against
//! the local runtime. Reconnects with backoff; running workloads are untouched by disconnects.

#![forbid(unsafe_code)]

pub mod inventory;
pub mod join;
pub mod qemu;
pub mod qmp;
pub mod runtime;
pub mod storage;
#[cfg(feature = "tpm")]
pub mod tpm;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use tonic::transport::Channel;
use torngat_api::Scope;
use torngat_api::compute::{Instance, PowerState, Runtime as RuntimeKind};
use torngat_proto::API_VERSION;
use torngat_proto::v1::control_client::ControlClient;
use torngat_proto::v1::*;
use uuid::Uuid;

pub use runtime::{Disk, FakeRuntime, Runtime};
pub use storage::Storage;
use storage::{Crypt, Drivers};

pub const HEARTBEAT_EVERY: Duration = Duration::from_secs(2);
/// Storage steps that failed or wait are tried again this often, also without a change.
/// Instances waiting for their disks, or that failed to start, are looked at again as often.
pub const STORAGE_RETRY: Duration = Duration::from_secs(10);

/// The cluster's uid, which marks its pools: from the CA certificate (the first in `ca_pem`), the
/// same for every node and across restores.
pub fn cluster_uid(ca_pem: &[u8]) -> Result<Uuid, AgentError> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let ca = CertificateDer::pem_slice_iter(ca_pem)
        .next()
        .ok_or_else(|| tls_err("no CA certificate"))?
        .map_err(tls_err)?;
    Ok(Uuid::new_v5(&Uuid::NAMESPACE_OID, ca.as_ref()))
}

/// Runs slow synchronous work (TPM operations) so the runtime can move other tasks, such as
/// heartbeats, to other workers meanwhile. Inline on a single-threaded runtime.
pub fn blocking<T>(f: impl FnOnce() -> T) -> T {
    if multi_thread() {
        tokio::task::block_in_place(f)
    } else {
        f()
    }
}

fn multi_thread() -> bool {
    tokio::runtime::Handle::try_current()
        .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
}

/// Default TPM: the kernel's resource manager.
pub const DEFAULT_TPM_TCTI: &str = "device:/dev/tpmrm0";

/// The node's private key.
#[derive(Clone)]
pub enum NodeKey {
    /// PKCS#8 PEM, from a file (lower assurance).
    File(Vec<u8>),
    /// Held by the TPM; never leaves it.
    #[cfg(feature = "tpm")]
    Tpm(tpm::TpmKey),
}

impl std::fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeKey::File(_) => f.write_str("NodeKey::File(<redacted>)"),
            #[cfg(feature = "tpm")]
            NodeKey::Tpm(k) => write!(f, "NodeKey::Tpm({k:?})"),
        }
    }
}

impl NodeKey {
    /// How the key is held, as recorded at enrollment.
    pub fn storage(&self) -> torngat_pki::KeyStorage {
        match self {
            NodeKey::File(_) => torngat_pki::KeyStorage::File,
            #[cfg(feature = "tpm")]
            NodeKey::Tpm(_) => torngat_pki::KeyStorage::Tpm,
        }
    }

    /// A CSR (DER) for this key. Slow for TPM keys: call off the async runtime.
    pub fn csr(&self) -> Result<Vec<u8>, String> {
        match self {
            NodeKey::File(pem) => {
                let pem = std::str::from_utf8(pem).map_err(|e| e.to_string())?;
                let key = torngat_pki::ca::parse_node_key(pem).map_err(|e| e.to_string())?;
                torngat_pki::ca::node_csr(&key).map_err(|e| e.to_string())
            }
            #[cfg(feature = "tpm")]
            NodeKey::Tpm(k) => k.csr().map_err(|e| e.to_string()),
        }
    }

    fn tls_key(
        &self,
        provider: &rustls::crypto::CryptoProvider,
    ) -> Result<std::sync::Arc<dyn rustls::sign::SigningKey>, AgentError> {
        match self {
            NodeKey::File(pem) => {
                use rustls::pki_types::PrivateKeyDer;
                use rustls::pki_types::pem::PemObject;
                let der = PrivateKeyDer::from_pem_slice(pem).map_err(tls_err)?;
                provider.key_provider.load_private_key(der).map_err(tls_err)
            }
            #[cfg(feature = "tpm")]
            NodeKey::Tpm(k) => Ok(std::sync::Arc::new(tpm::TlsKey(k.clone()))),
        }
    }
}

/// Where and how to reach the controller.
#[derive(Clone)]
pub struct AgentConfig {
    /// e.g. `https://10.0.0.1:7443`
    pub controller_url: String,
    /// Name the controller's certificate is issued for.
    pub controller_name: String,
    pub ca_pem: Vec<u8>,
    /// Node certificate chain (PEM).
    pub cert_pem: Vec<u8>,
    pub key: NodeKey,
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
    #[error("tls: {0}")]
    Tls(String),
}

fn tls_err(e: impl std::fmt::Display) -> AgentError {
    AgentError::Tls(e.to_string())
}

/// Dials the controller over mTLS. Built once per agent so TLS sessions can be resumed across
/// reconnects (a resumed handshake needs no signature: no TPM operation).
#[derive(Clone)]
pub struct Connector {
    tls: tokio_rustls::TlsConnector,
    name: rustls::pki_types::ServerName<'static>,
    addr: String,
    /// The key signs synchronously and slowly (TPM).
    slow_key: bool,
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connector")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl Connector {
    /// Trusts only the cluster CA and authenticates with the node key.
    pub fn new(cfg: &AgentConfig) -> Result<Self, AgentError> {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;
        use std::sync::Arc;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(&cfg.ca_pem) {
            roots.add(c.map_err(tls_err)?).map_err(tls_err)?;
        }
        let chain = CertificateDer::pem_slice_iter(&cfg.cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(tls_err)?;
        let certified = rustls::sign::CertifiedKey::new(chain, cfg.key.tls_key(&provider)?);
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(tls_err)?
            .with_root_certificates(roots)
            .with_client_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certified)));
        config.alpn_protocols = vec![b"h2".to_vec()];
        let addr = cfg
            .controller_url
            .strip_prefix("https://")
            .ok_or_else(|| tls_err("controller_url must start with https://"))?
            .trim_end_matches('/')
            .to_owned();
        Ok(Self {
            tls: tokio_rustls::TlsConnector::from(Arc::new(config)),
            name: rustls::pki_types::ServerName::try_from(cfg.controller_name.clone())
                .map_err(tls_err)?,
            addr,
            slow_key: cfg.key.storage() == torngat_pki::KeyStorage::Tpm,
        })
    }

    /// Opens the mTLS control channel. TLS is done here (tonic's own TLS cannot use a TPM-held
    /// key), so tonic sees plain HTTP/2.
    pub async fn connect(&self) -> Result<ControlClient<Channel>, AgentError> {
        let this = self.clone();
        let connector = tower::service_fn(move |_: tonic::codegen::http::Uri| {
            let this = this.clone();
            async move {
                let tcp = tokio::net::TcpStream::connect(&this.addr).await?;
                let handshake = this.tls.connect(this.name, tcp);
                let stream = if this.slow_key && multi_thread() {
                    // A TPM signs synchronously (~100 ms) inside the handshake: tell the runtime,
                    // so other tasks (heartbeats) move to other workers meanwhile.
                    let rt = tokio::runtime::Handle::current();
                    tokio::task::block_in_place(|| rt.block_on(handshake))?
                } else {
                    handshake.await?
                };
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        });
        let channel = tonic::transport::Endpoint::from_static("http://controller.invalid")
            .connect_timeout(Duration::from_secs(5))
            .connect_with_connector(connector)
            .await?;
        Ok(ControlClient::new(channel))
    }
}

/// Opens the mTLS control channel to the controller (one-off; [`run`] keeps a [`Connector`]).
pub async fn connect(cfg: &AgentConfig) -> Result<ControlClient<Channel>, AgentError> {
    Connector::new(cfg)?.connect().await
}

/// Runs the agent forever, reconnecting on errors.
pub async fn run<R: Runtime, D: Drivers, C: Crypt>(
    cfg: AgentConfig,
    runtime: R,
    drivers: D,
    crypt: C,
) {
    let setup = Connector::new(&cfg).and_then(|c| Ok((c, cluster_uid(&cfg.ca_pem)?)));
    let (connector, cluster) = match setup {
        Ok(c) => c,
        Err(e) => {
            // Bad local credentials: retrying cannot help.
            tracing::error!(error = %e, "cannot set up the controller connection");
            return;
        }
    };
    let mut storage = Storage::new(drivers, crypt, cluster);
    const MIN: Duration = Duration::from_millis(200);
    let mut backoff = MIN;
    loop {
        let started = std::time::Instant::now();
        if let Err(e) = session(&connector, &runtime, &mut storage).await {
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

/// What the agent last told the controller about an instance (phase, generation, message), to
/// avoid repeating itself.
type Reported = BTreeMap<Uuid, (String, u64, String)>;

/// One connected session: register, heartbeat, follow assignments.
pub async fn session<R: Runtime, D: Drivers, C: Crypt>(
    connector: &Connector,
    runtime: &R,
    storage: &mut Storage<D, C>,
) -> Result<(), AgentError> {
    storage.new_session();
    let mut client = connector.connect().await?;
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
    let mut retry =
        tokio::time::interval_at(tokio::time::Instant::now() + STORAGE_RETRY, STORAGE_RETRY);
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // What the controller last assigned: instances, and storage (`None` if it could not be read).
    let mut instances: Vec<Instance> = vec![];
    let mut assigned: Option<storage::Assigned> = None;
    // Some instance waits for its disks or failed to start: tried again.
    let mut waiting = false;
    let result = async {
        loop {
            let mut changed = false;
            tokio::select! {
                // Assignments first: retries can take a while.
                biased;
                set = stream.message() => {
                    let Some(set) = set? else { return Ok(()) };
                    if set.api_version != API_VERSION {
                        return Err(tonic::Status::failed_precondition("api_version mismatch").into());
                    }
                    // An undecodable entry (e.g. a newer controller) must not look "unassigned", or
                    // its workload would be stopped: give up on this session instead.
                    instances = set
                        .instances_json
                        .iter()
                        .map(|b| serde_json::from_slice::<Instance>(b))
                        .collect::<Result<Vec<_>, _>>()?;
                    changed = true;
                    assigned = storage::Assigned::decode(
                        &set.pools_json,
                        &set.volumes_json,
                        set.storage_unavailable,
                        storage::Assigned::instances(&instances),
                    );
                }
                _ = retry.tick(), if assigned.is_some() || waiting => {}
            }
            // Storage first: it opens the disks that instances start with.
            if let Some(a) = &assigned {
                storage.reconcile(&mut client, a).await?;
            }
            if changed || waiting {
                let disks = |i: &Instance| storage.disks(assigned.as_ref(), i);
                waiting = reconcile(&mut client, runtime, &instances, disks, &mut reported).await?;
            }
            // The next retry comes a full interval after this pass, however long it took.
            retry.reset();
        }
    }
    .await;
    heartbeat.abort();
    result
}

/// Brings the runtime in line with the assigned set and reports changes. An instance starts once
/// `disks` has them all; returns whether one should be looked at again soon (it waits for its
/// disks, failed to start, or the runtime could not tell whether it runs).
pub async fn reconcile<R: Runtime>(
    client: &mut ControlClient<Channel>,
    runtime: &R,
    assigned: &[Instance],
    disks: impl Fn(&Instance) -> Result<Vec<Disk>, String>,
    reported: &mut Reported,
) -> Result<bool, AgentError> {
    let mut waiting = false;
    let running: BTreeSet<Uuid> = runtime.running().await.into_iter().collect();
    waiting |= runtime.unsettled();
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
            PowerState::Running => match disks(inst) {
                Err(e) => {
                    waiting = true;
                    ("starting", e)
                }
                Ok(d) => match runtime.start(inst, &d).await {
                    Ok(()) => ("running", String::new()),
                    Err(e) => {
                        tracing::warn!(%uid, error = %e, "instance failed to start");
                        waiting = true;
                        ("failed", e)
                    }
                },
            },
            PowerState::Stopped => match runtime.stop(uid).await {
                Ok(()) => ("stopped", String::new()),
                Err(e) => {
                    tracing::warn!(%uid, error = %e, "instance failed to stop");
                    waiting = true;
                    ("failed", e)
                }
            },
        };
        let message = sanitize(&message);
        let now = (phase.to_owned(), gen_, message);
        if reported.get(&uid) == Some(&now) {
            continue;
        }
        let (_, _, message) = &now;
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
                message: message.clone(),
            })
            .await;
        match report {
            Ok(_) => {
                reported.insert(uid, now);
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
    Ok(waiting)
}

/// Longest message the controller accepts.
const MAX_MESSAGE: usize = 1024;

/// Makes runtime error text acceptable to the controller: no control characters, bounded length.
pub fn sanitize(m: &str) -> String {
    let mut out = String::new();
    for c in m.chars() {
        let c = if torngat_api::is_hidden(c) { ' ' } else { c };
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
