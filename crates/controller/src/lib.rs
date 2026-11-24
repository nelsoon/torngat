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

pub mod identity;
pub mod join;
pub mod keys;
mod ops;
mod scheduler;
mod service;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use torngat_api::Name;
use torngat_store::Store;

pub use join::{JoinService, expire_join_tokens_once, serve_join};
pub use ops::complete_operations_once;
pub use scheduler::schedule_once;
pub use service::ControlService;

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
}

impl Controller {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            live: Liveness::default(),
        }
    }

    /// Runs the reconcile loops (scheduling, operation completion) forever.
    pub async fn run_scheduler(self, every: Duration) {
        loop {
            if let Err(e) = schedule_once(&self).await {
                tracing::warn!(error = %e, "scheduling pass failed");
            }
            if let Err(e) = complete_operations_once(&self).await {
                tracing::warn!(error = %e, "operation pass failed");
            }
            if let Err(e) = expire_join_tokens_once(&self.store).await {
                tracing::warn!(error = %e, "join token expiry pass failed");
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
        .add_service(torngat_proto::v1::control_server::ControlServer::new(
            ControlService::new(ctl),
        ))
        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
        .await
}
