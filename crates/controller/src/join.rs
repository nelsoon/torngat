//! Node enrollment: a join token plus a CSR become a node certificate and an identity record.
//!
//! Order matters. Everything that can be checked without side effects is checked before the token
//! is consumed: a malformed request never burns a token. Then:
//! 1. the token is deleted with a compare-and-swap on the revision that was checked (single use,
//!    even under concurrent joins);
//! 2. the identity record is created only if absent (a name is enrolled at most once). If another
//!    join took the name in between, the token is put back.
//!
//! Retries: a node whose join committed but whose response was lost retries with the same key.
//! A CSR for exactly the enrolled key gets a fresh certificate without a token. That is safe: the
//! certificate is useless without the private key, and the CSR signature proves the caller holds
//! it.

use std::sync::Arc;

use time::OffsetDateTime;
use tonic::{Request, Response, Status};
use torngat_api::Name;
use torngat_pki::{Ca, JoinTokenRecord, KeyStorage, NodeIdentity};
use torngat_proto::API_VERSION;
use torngat_proto::v1::join_server::Join;
use torngat_proto::v1::{JoinRequest, JoinResponse};
use torngat_store::{Precondition, Store, StoreError};

use crate::identity::{self, EnrollError};
use crate::keys;
use crate::service::{internal, store_err};

/// Largest join request accepted (a CSR is well under 1 KiB).
pub const MAX_JOIN_REQUEST: usize = 16 * 1024;
/// Join requests handled at once across all callers; more are shed.
pub const MAX_CONCURRENT_JOINS: usize = 16;

#[derive(Debug, Clone)]
pub struct JoinService {
    store: Store,
    ca: Arc<Ca>,
}

impl JoinService {
    pub fn new(store: Store, ca: Arc<Ca>) -> Self {
        Self { store, ca }
    }
}

/// One answer for every token problem (unknown, wrong secret, expired, other node, already used),
/// so the endpoint tells a caller nothing about which tokens exist.
fn denied() -> Status {
    Status::permission_denied("invalid join token")
}

#[tonic::async_trait]
impl Join for JoinService {
    async fn join(&self, req: Request<JoinRequest>) -> Result<Response<JoinResponse>, Status> {
        let peer = req.remote_addr();
        let r = req.into_inner();
        if r.api_version != API_VERSION {
            return Err(Status::failed_precondition(format!(
                "unsupported api_version {:?}, controller speaks {API_VERSION}",
                r.api_version
            )));
        }
        let node =
            Name::new(r.node_name).map_err(|_| Status::invalid_argument("invalid node name"))?;
        match r.key_storage.as_str() {
            "file" => {}
            // Claiming a TPM key needs attestation, which is not implemented yet.
            "tpm" => {
                return Err(Status::failed_precondition(
                    "TPM enrollment is not supported yet",
                ));
            }
            _ => return Err(Status::invalid_argument("invalid key_storage")),
        }
        if !torngat_pki::token::valid_id(&r.token_id) {
            return Err(denied());
        }

        // Pure checks first: the CSR (signature, key type) and what it would be issued as.
        let issued = self
            .ca
            .sign_node_csr(&r.csr_der, &node)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let ident = issued.identity(KeyStorage::File).map_err(internal)?;

        // A retry of a join that already committed, with the same key.
        let ikey = keys::node_identity(&node).map_err(internal)?;
        if let Some(v) = self.store.get(&ikey).await.map_err(store_err)? {
            let cur: NodeIdentity = serde_json::from_slice(&v.value).map_err(internal)?;
            if torngat_pki::digest_eq(&cur.spki_sha256, &ident.spki_sha256) {
                tracing::info!(%node, ?peer, "node certificate re-issued for its enrolled key");
                return Ok(Response::new(JoinResponse {
                    cert_chain_pem: issued.chain_pem,
                }));
            }
        }

        let tkey = keys::join_token(&r.token_id).map_err(|_| denied())?;
        let Some(tv) = self.store.get(&tkey).await.map_err(store_err)? else {
            return Err(denied());
        };
        let rec: JoinTokenRecord = serde_json::from_slice(&tv.value).map_err(internal)?;
        if !rec.admits(&r.token_secret, &node, OffsetDateTime::now_utc()) {
            return Err(denied());
        }

        // Refuse a name in use before burning the token.
        let nkey = keys::node(&node).map_err(internal)?;
        if self.store.get(&ikey).await.map_err(store_err)?.is_some()
            || self.store.get(&nkey).await.map_err(store_err)?.is_some()
        {
            return Err(Status::already_exists("node name is already in use"));
        }

        match self
            .store
            .delete(tkey.clone(), Precondition::Revision(tv.revision))
            .await
        {
            Ok(_) => {}
            // Someone else used it in the meantime.
            Err(StoreError::PreconditionFailed { .. }) => return Err(denied()),
            Err(e) => return Err(store_err(e)),
        }
        match identity::enroll(&self.store, &node, &ident).await {
            Ok(_) => {}
            Err(EnrollError::AlreadyEnrolled) => {
                // Lost a race for the name: the token enrolled nothing, give it back.
                if let Err(e) = self.store.put(tkey, tv.value, Precondition::Absent).await {
                    tracing::warn!(error = %e, token = %rec.id, "could not restore join token");
                }
                return Err(Status::already_exists("node name is already in use"));
            }
            Err(EnrollError::Store(e)) => return Err(store_err(e)),
            Err(e) => return Err(internal(e)),
        }
        tracing::info!(%node, token = %rec.id, ?peer, "node enrolled");
        Ok(Response::new(JoinResponse {
            cert_chain_pem: issued.chain_pem,
        }))
    }
}

/// Serves enrollment on `listener` with server-only TLS (`cert_pem` must be the controller's
/// certificate chain).
pub async fn serve_join(
    svc: JoinService,
    listener: tokio::net::TcpListener,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
) -> Result<(), tonic::transport::Error> {
    use tonic::transport::{Identity, Server, ServerTlsConfig};
    let tls = ServerTlsConfig::new().identity(Identity::from_pem(cert_pem, key_pem));
    // Unauthenticated endpoint: bound the work any caller can create.
    Server::builder()
        .tls_config(tls)?
        .timeout(std::time::Duration::from_secs(30))
        .concurrency_limit_per_connection(2)
        .max_concurrent_streams(2)
        // Outermost first: shed what the concurrency limit cannot take right now.
        .layer(tower::load_shed::LoadShedLayer::new())
        .layer(tower::limit::GlobalConcurrencyLimitLayer::new(
            MAX_CONCURRENT_JOINS,
        ))
        .add_service(
            torngat_proto::v1::join_server::JoinServer::new(svc)
                .max_decoding_message_size(MAX_JOIN_REQUEST),
        )
        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
        .await
}

/// Deletes expired join tokens. Returns how many were removed.
pub async fn expire_join_tokens_once(store: &Store) -> Result<usize, StoreError> {
    let now = OffsetDateTime::now_utc();
    let prefix =
        keys::join_tokens().map_err(|e| StoreError::Raft(format!("join token prefix: {e}")))?;
    let mut n = 0;
    for (k, v) in crate::scheduler::list_all(store, &prefix).await? {
        let expired = serde_json::from_slice::<JoinTokenRecord>(&v.value)
            .map(|r| r.expired(now))
            // Possibly written by a newer controller: leave it alone.
            .unwrap_or(false);
        if expired {
            match store.delete(k, Precondition::Revision(v.revision)).await {
                Ok(_) => n += 1,
                Err(StoreError::PreconditionFailed { .. }) => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(n)
}
