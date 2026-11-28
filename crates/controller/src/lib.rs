//! Torngat controller.
//!
//! - Serves the internal control protocol to node agents over mTLS.
//! - Keeps node liveness as soft state in memory (never in Raft).
//! - Schedules pending instances onto live compute nodes.
//! - Applies agent reports to instance status and completes create operations.
//!
//! Agents are less trusted than controllers: every agent-reported value is validated, and an
//! agent may only report on instances assigned to it.

#![forbid(unsafe_code)]

mod disks;
pub mod identity;
mod images;
pub mod join;
pub mod keys;
mod ops;
mod scheduler;
mod service;
pub mod storage;
pub mod volume_keys;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use torngat_api::Name;
use torngat_keys::PlatformKey;
use torngat_store::Store;

pub use disks::disks_once;
pub use images::images_once;
pub use join::{JoinService, expire_join_tokens_once, serve_join};
pub use ops::complete_operations_once;
pub use scheduler::schedule_once;
pub use service::ControlService;
pub use volume_keys::destroy_volume_keys_once;

/// A node is considered alive if it sent a heartbeat within this window.
pub const LIVENESS_TIMEOUT: Duration = Duration::from_secs(10);

/// In-memory liveness table. Rebuilt from heartbeats after a controller restart or failover.
#[derive(Debug, Clone, Default)]
pub struct Liveness(Arc<Mutex<HashMap<Name, Instant>>>);

impl Liveness {
    pub fn touch(&self, n: &Name) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(n.clone(), Instant::now());
    }

    pub fn is_live(&self, n: &Name) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(n)
            .is_some_and(|t| t.elapsed() < LIVENESS_TIMEOUT)
    }
}

#[derive(Debug, Clone)]
pub struct Controller {
    pub store: Store,
    pub live: Liveness,
    platform_key: Arc<PlatformKey>,
    /// Image uploads, if this controller keeps them.
    pub uploads: Option<torngat_uploads::Uploads>,
}

impl Controller {
    pub fn new(store: Store, platform_key: Arc<PlatformKey>) -> Self {
        Self {
            store,
            live: Liveness::default(),
            platform_key,
            uploads: None,
        }
    }

    /// Keeps image uploads in `uploads`.
    pub fn with_uploads(mut self, uploads: torngat_uploads::Uploads) -> Self {
        self.uploads = Some(uploads);
        self
    }

    /// Runs the reconcile loops (scheduling, operation completion, housekeeping) forever.
    pub async fn run_scheduler(self, every: Duration) {
        const HOUSEKEEPING_EVERY: Duration = Duration::from_secs(60);
        let mut last_housekeeping: Option<Instant> = None;
        loop {
            let world = match disks::disks_once(&self).await {
                Ok((w, 0)) => w,
                // What it changed (such as a boot disk it made) is read again.
                Ok(_) => disks::World::read(&self.store).await.unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "cannot read instances and volumes");
                    None
                }),
                Err(e) => {
                    tracing::warn!(error = %e, "disks pass failed");
                    None
                }
            };
            if let Err(e) = schedule_once(&self, world.as_ref()).await {
                tracing::warn!(error = %e, "scheduling pass failed");
            }
            if let Err(e) = storage::storage_once(&self).await {
                tracing::warn!(error = %e, "storage pass failed");
            }
            if let Err(e) = images::images_once(&self).await {
                tracing::warn!(error = %e, "image pass failed");
            }
            if let Err(e) = complete_operations_once(&self).await {
                tracing::warn!(error = %e, "operation pass failed");
            }
            if last_housekeeping.is_none_or(|t| t.elapsed() >= HOUSEKEEPING_EVERY) {
                last_housekeeping = Some(Instant::now());
                // Expired tokens are already refused.
                if let Err(e) = expire_join_tokens_once(&self.store).await {
                    tracing::warn!(error = %e, "join token expiry pass failed");
                }
                if let Err(e) = destroy_volume_keys_once(&self.store).await {
                    tracing::warn!(error = %e, "volume key pass failed");
                }
            }
            tokio::time::sleep(every).await;
        }
    }
}

/// TLS material for the control endpoint (PEM).
#[derive(Clone)]
pub struct TlsConfig {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    /// CA that signs node certificates; clients must present one.
    pub client_ca_pem: Vec<u8>,
}

impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsConfig(<redacted>)")
    }
}

/// Serves the control protocol on a bound listener, with mandatory client certificates signed
/// by `tls.client_ca_pem`. Callers must also be enrolled (see [`identity::authenticate`]).
pub async fn serve(
    ctl: Controller,
    listener: tokio::net::TcpListener,
    tls: TlsConfig,
) -> Result<(), tonic::transport::Error> {
    use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(tls.cert_pem, tls.key_pem))
        .client_ca_root(Certificate::from_pem(tls.client_ca_pem));
    Server::builder()
        .tls_config(tls)?
        // Per connection; a node has one assignment stream at a time.
        .max_concurrent_streams(32)
        .add_service(torngat_proto::v1::control_server::ControlServer::new(
            ControlService::new(ctl),
        ))
        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
        .await
}
