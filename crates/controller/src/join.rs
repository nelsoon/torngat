//! Node enrollment: a join token plus a CSR become a node certificate and an identity record.
//!
//! Two ways in:
//! - `Join`: the key is in a file. Only allowed when the cluster's [`TpmPolicy`] does not
//!   require TPMs.
//! - `BeginTpmJoin` / `FinishTpmJoin`: the key is in a TPM, proven by attestation
//!   (`torngat-attest`): the TPM's endorsement key is trusted (vendor anchor, or a pin on the
//!   token), an attestation key in that TPM answers a credential challenge, and certifies the node
//!   key as non-exportable.
//!
//! Order matters. Everything that can be checked without side effects is checked before the token
//! is consumed: a malformed or unproven request never burns a token. Then:
//! 1. the token is deleted with a compare-and-swap on the revision that was checked (single use,
//!    even under concurrent joins);
//! 2. the identity record is created only if absent (a name is enrolled at most once). If another
//!    join took the name in between, the token is put back.
//!
//! Retries: a node whose join committed but whose response was lost calls `ResumeJoin` with the
//! same key. Within [`RETRY_WINDOW`] of enrollment, a CSR for exactly the enrolled key gets a fresh
//! certificate without a token. That is safe: the certificate is useless without the private key,
//! and the CSR signature proves the caller holds it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use tonic::{Request, Response, Status};
use torngat_api::Name;
use torngat_pki::{Ca, Issued, JoinTokenRecord, KeyStorage, NodeIdentity, TpmPolicy};
use torngat_proto::API_VERSION;
use torngat_proto::v1::join_server::Join;
use torngat_proto::v1::{
    JoinRequest, JoinResponse, ResumeJoinRequest, TpmChallenge, TpmJoinAnswer, TpmJoinRequest,
};
use torngat_store::{Key, Precondition, Store, StoreError, Versioned};

use crate::identity::{self, EnrollError};
use crate::keys;
use crate::service::{internal, store_err};

/// Largest join request accepted (a CSR is well under 1 KiB, an EK certificate a few KiB).
pub const MAX_JOIN_REQUEST: usize = 16 * 1024;
/// How long after enrolling a node may fetch its certificate again without a token (lost answer).
pub const RETRY_WINDOW: time::Duration = time::Duration::hours(1);
/// Join requests handled at once across all callers; more are shed.
pub const MAX_CONCURRENT_JOINS: usize = 16;
/// How long a TPM challenge stays open, and how many may be open at once.
pub const CHALLENGE_TTL: Duration = Duration::from_secs(120);
pub const MAX_CHALLENGES: usize = 64;

/// A TPM join between its two steps.
struct PendingJoin {
    attest: torngat_attest::Pending,
    node: Name,
    csr_der: Vec<u8>,
    token_key: Key,
    token: Versioned,
    token_id: String,
    ek_sha256: String,
    expires: Instant,
}

#[derive(Clone)]
pub struct JoinService {
    store: Store,
    ca: Arc<Ca>,
    /// DER CA certificates trusted to issue TPM endorsement key certificates.
    tpm_anchors: Arc<Vec<Vec<u8>>>,
    pending: Arc<Mutex<HashMap<String, PendingJoin>>>,
}

impl std::fmt::Debug for JoinService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinService")
            .field("tpm_anchors", &self.tpm_anchors.len())
            .finish_non_exhaustive()
    }
}

impl JoinService {
    pub fn new(store: Store, ca: Arc<Ca>, tpm_anchors: Vec<Vec<u8>>) -> Self {
        Self {
            store,
            ca,
            tpm_anchors: Arc::new(tpm_anchors),
            pending: Arc::default(),
        }
    }

    async fn policy(&self) -> Result<TpmPolicy, Status> {
        let k = keys::tpm_policy().map_err(internal)?;
        match self.store.get(&k).await.map_err(store_err)? {
            Some(v) => serde_json::from_slice(&v.value).map_err(internal),
            None => Ok(TpmPolicy::default()),
        }
    }

    /// The token, if it admits `node` with `secret` now; and the name must be free.
    async fn check_token(
        &self,
        token_id: &str,
        secret: &[u8],
        node: &Name,
    ) -> Result<(Key, Versioned, JoinTokenRecord), Status> {
        if !torngat_pki::token::valid_id(token_id) {
            return Err(denied());
        }
        let tkey = keys::join_token(token_id).map_err(|_| denied())?;
        let Some(tv) = self.store.get(&tkey).await.map_err(store_err)? else {
            return Err(denied());
        };
        let rec: JoinTokenRecord = serde_json::from_slice(&tv.value).map_err(internal)?;
        if !rec.admits(secret, node, OffsetDateTime::now_utc()) {
            return Err(denied());
        }
        let ikey = keys::node_identity(node).map_err(internal)?;
        let nkey = keys::node(node).map_err(internal)?;
        if self.store.get(&ikey).await.map_err(store_err)?.is_some()
            || self.store.get(&nkey).await.map_err(store_err)?.is_some()
        {
            return Err(Status::already_exists("node name is already in use"));
        }
        Ok((tkey, tv, rec))
    }

    /// Consumes the token (single use) and records the identity; puts the token back if the name
    /// was taken in between.
    async fn consume_and_enroll(
        &self,
        tkey: Key,
        tv: Versioned,
        token_id: &str,
        node: &Name,
        ident: &NodeIdentity,
    ) -> Result<(), Status> {
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
        match identity::enroll(&self.store, node, ident).await {
            Ok(_) => Ok(()),
            Err(EnrollError::AlreadyEnrolled) => {
                // Lost a race for the name: the token enrolled nothing, give it back.
                if let Err(e) = self.store.put(tkey, tv.value, Precondition::Absent).await {
                    tracing::warn!(error = %e, token = %token_id, "could not restore join token");
                }
                Err(Status::already_exists("node name is already in use"))
            }
            Err(EnrollError::Store(e)) => Err(store_err(e)),
            Err(e) => Err(internal(e)),
        }
    }

    fn issue(&self, csr_der: &[u8], node: &Name) -> Result<Issued, Status> {
        self.ca
            .sign_node_csr(csr_der, node)
            .map_err(|e| Status::invalid_argument(e.to_string()))
    }
}

/// One answer for every token problem (unknown, wrong secret, expired, other node, already used),
/// so the endpoint tells a caller nothing about which tokens exist.
fn denied() -> Status {
    Status::permission_denied("invalid join token")
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

fn node_name(s: String) -> Result<Name, Status> {
    Name::new(s).map_err(|_| Status::invalid_argument("invalid node name"))
}

/// Checks a CSR (signature, key type) without signing anything; its key's SHA-256 (hex).
fn csr_spki(csr_der: &[u8]) -> Result<String, Status> {
    torngat_pki::ca::csr_spki_sha256(csr_der).map_err(|e| Status::invalid_argument(e.to_string()))
}

fn response(issued: Issued) -> Response<JoinResponse> {
    Response::new(JoinResponse {
        cert_chain_pem: issued.chain_pem,
    })
}

#[tonic::async_trait]
impl Join for JoinService {
    async fn join(&self, req: Request<JoinRequest>) -> Result<Response<JoinResponse>, Status> {
        let peer = req.remote_addr();
        let r = req.into_inner();
        check_version(&r.api_version)?;
        let node = node_name(r.node_name)?;
        csr_spki(&r.csr_der)?;
        if self.policy().await?.required {
            return Err(Status::failed_precondition(
                "this cluster requires TPM-held node keys",
            ));
        }
        let (tkey, tv, rec) = self
            .check_token(&r.token_id, &r.token_secret, &node)
            .await?;
        let issued = self.issue(&r.csr_der, &node)?;
        let ident = issued.identity(KeyStorage::File).map_err(internal)?;
        self.consume_and_enroll(tkey, tv, &rec.id, &node, &ident)
            .await?;
        tracing::info!(%node, token = %rec.id, ?peer, key = "file", "node enrolled");
        Ok(response(issued))
    }

    async fn resume_join(
        &self,
        req: Request<ResumeJoinRequest>,
    ) -> Result<Response<JoinResponse>, Status> {
        let peer = req.remote_addr();
        let r = req.into_inner();
        check_version(&r.api_version)?;
        let node = node_name(r.node_name)?;
        // The CSR signature proves the caller holds the key; the certificate is useless without
        // it. Bounded in time, so this is not a token-less renewal path.
        let spki = csr_spki(&r.csr_der)?;
        let not_found = || Status::not_found("no recent enrollment for this key");
        let ikey = keys::node_identity(&node).map_err(internal)?;
        let Some(v) = self.store.get(&ikey).await.map_err(store_err)? else {
            return Err(not_found());
        };
        let cur: NodeIdentity = serde_json::from_slice(&v.value).map_err(internal)?;
        let recent = OffsetDateTime::now_utc() - cur.issue_time < RETRY_WINDOW;
        if !recent || !torngat_pki::digest_eq(&cur.spki_sha256, &spki) {
            return Err(not_found());
        }
        tracing::info!(%node, ?peer, "node certificate re-issued for its enrolled key");
        Ok(response(self.issue(&r.csr_der, &node)?))
    }

    async fn begin_tpm_join(
        &self,
        req: Request<TpmJoinRequest>,
    ) -> Result<Response<TpmChallenge>, Status> {
        let r = req.into_inner();
        check_version(&r.api_version)?;
        let node = node_name(r.node_name)?;
        let spki = csr_spki(&r.csr_der)?;
        let (tkey, tv, rec) = self
            .check_token(&r.token_id, &r.token_secret, &node)
            .await?;
        let untrusted = |e: torngat_attest::AttestError| {
            Status::permission_denied(format!("TPM attestation refused: {e}"))
        };
        let ek = torngat_attest::verify_endorsement(
            &r.ek_cert_der,
            &self.tpm_anchors,
            rec.ek_sha256.as_deref(),
        )
        .map_err(untrusted)?;
        let (attest, challenge) =
            torngat_attest::begin(&ek, &r.ak_public, &r.node_key_public, &spki)
                .map_err(untrusted)?;
        let id = torngat_pki::random_secret().map_err(internal)?;
        {
            let mut p = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            let now = Instant::now();
            p.retain(|_, j| j.expires > now);
            if p.len() >= MAX_CHALLENGES {
                return Err(Status::resource_exhausted(
                    "too many joins in progress, retry",
                ));
            }
            p.insert(
                id.clone(),
                PendingJoin {
                    attest,
                    node,
                    csr_der: r.csr_der,
                    token_key: tkey,
                    token: tv,
                    token_id: rec.id,
                    ek_sha256: ek.spki_sha256,
                    expires: now + CHALLENGE_TTL,
                },
            );
        }
        Ok(Response::new(TpmChallenge {
            challenge_id: id,
            id_object: challenge.id_object,
            encrypted_secret: challenge.encrypted_secret,
            nonce: challenge.nonce.to_vec(),
        }))
    }

    async fn finish_tpm_join(
        &self,
        req: Request<TpmJoinAnswer>,
    ) -> Result<Response<JoinResponse>, Status> {
        let peer = req.remote_addr();
        let r = req.into_inner();
        // One attempt per challenge: it is removed whatever the outcome.
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&r.challenge_id)
            .filter(|j| j.expires > Instant::now())
            .ok_or_else(|| Status::permission_denied("unknown or expired challenge"))?;
        pending
            .attest
            .finish(&r.activated_secret, &r.certify_attest, &r.certify_signature)
            .map_err(|e| Status::permission_denied(format!("TPM attestation refused: {e}")))?;
        let issued = self.issue(&pending.csr_der, &pending.node)?;
        let mut ident = issued.identity(KeyStorage::Tpm).map_err(internal)?;
        ident.ek_sha256 = Some(pending.ek_sha256.clone());
        self.consume_and_enroll(
            pending.token_key,
            pending.token,
            &pending.token_id,
            &pending.node,
            &ident,
        )
        .await?;
        tracing::info!(node = %pending.node, token = %pending.token_id, ?peer, key = "tpm",
            ek = %pending.ek_sha256, "node enrolled");
        Ok(response(issued))
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
