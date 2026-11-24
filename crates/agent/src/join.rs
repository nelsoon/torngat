//! Joining a cluster: from a join token to a node certificate.
//!
//! 1. Parse the token: id, secret and the pin (SHA-256) of the cluster CA.
//! 2. Open a TLS connection to the controller's join endpoint and accept it only if the chain
//!    contains a CA matching the pin **and** the controller certificate verifies against that CA
//!    for `controller.torngat`. Nothing is sent on this connection; it only discovers the CA.
//! 3. Call `Join` over a normally verified TLS connection (trusting that CA alone) with the token
//!    and a CSR for a fresh key. The secret therefore only ever goes to the pinned cluster.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use torngat_api::Name;
use torngat_pki::{CONTROLLER_NAME, CaHash, JoinToken};
use torngat_proto::API_VERSION;
use torngat_proto::v1::join_client::JoinClient;
use torngat_proto::v1::{JoinRequest, ResumeJoinRequest};

use crate::blocking;
#[cfg(feature = "tpm")]
use torngat_proto::v1::{TpmJoinAnswer, TpmJoinRequest};

const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("malformed join token")]
    BadToken,
    #[error("cannot reach the controller: {0}")]
    Connect(String),
    #[error("the controller's CA does not match the join token")]
    CaMismatch,
    #[error("join refused: {0}")]
    Refused(String),
    #[error("controller returned an unusable certificate")]
    BadCertificate,
    #[error("key: {0}")]
    Key(String),
    #[error("{0}")]
    Tpm(String),
}

/// Credentials obtained by joining (the key stays where it was).
pub struct Enrolled {
    pub ca_pem: String,
    /// Node certificate followed by the CA.
    pub cert_chain_pem: String,
}

impl std::fmt::Debug for Enrolled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Enrolled(<redacted>)")
    }
}

/// Accepts a server only if its chain holds the pinned CA and verifies against it. Remembers the
/// CA it found.
#[derive(Debug)]
struct PinnedCa {
    pin: CaHash,
    provider: Arc<rustls::crypto::CryptoProvider>,
    found: Mutex<Option<CertificateDer<'static>>>,
    /// Set when the presented chain held no CA matching the pin.
    mismatch: AtomicBool,
}

impl ServerCertVerifier for PinnedCa {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let ca = intermediates
            .iter()
            .find(|c| self.pin.matches(c.as_ref()))
            .ok_or_else(|| {
                self.mismatch.store(true, Ordering::SeqCst);
                rustls::Error::General("CA pin mismatch".into())
            })?;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(ca.clone().into_owned())
            .map_err(|_| rustls::Error::General("pinned CA is unusable".into()))?;
        let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            self.provider.clone(),
        )
        .build()
        .map_err(|e| rustls::Error::General(e.to_string()))?;
        let ok = inner.verify_server_cert(end_entity, &[], server_name, ocsp, now)?;
        *self.found.lock().unwrap_or_else(PoisonError::into_inner) = Some(ca.clone().into_owned());
        Ok(ok)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Finds the cluster CA behind `addr` (`host:port` of the join endpoint), checked against `pin`.
pub async fn discover_ca(addr: &str, pin: CaHash) -> Result<CertificateDer<'static>, JoinError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedCa {
        pin,
        provider: provider.clone(),
        found: Mutex::new(None),
        mismatch: AtomicBool::new(false),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| JoinError::Connect(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let name = ServerName::try_from(CONTROLLER_NAME).map_err(|_| JoinError::BadCertificate)?;
    let handshake = async {
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
    };
    let res = tokio::time::timeout(TIMEOUT, handshake)
        .await
        .map_err(|_| JoinError::Connect("timed out".into()))?;
    let found = verifier
        .found
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if verifier.mismatch.load(Ordering::SeqCst) {
        return Err(JoinError::CaMismatch);
    }
    match (res, found) {
        (Ok(_), Some(ca)) => Ok(ca),
        (Err(e), _) => Err(JoinError::Connect(e.to_string())),
        (Ok(_), None) => Err(JoinError::CaMismatch),
    }
}

/// A verified channel to the join endpoint, trusting only the pinned CA.
async fn join_channel(addr: &str, pin: CaHash) -> Result<(JoinClient<Channel>, String), JoinError> {
    let ca_der = discover_ca(addr, pin).await?;
    let ca_pem = pem::encode(&pem::Pem::new("CERTIFICATE", ca_der.to_vec()));
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&ca_pem))
        .domain_name(CONTROLLER_NAME);
    let channel = Channel::from_shared(format!("https://{addr}"))
        .map_err(|e| JoinError::Connect(e.to_string()))?
        .tls_config(tls)
        .map_err(|e| JoinError::Connect(e.to_string()))?
        .connect_timeout(TIMEOUT)
        .timeout(TIMEOUT)
        .connect()
        .await
        .map_err(|e| JoinError::Connect(e.to_string()))?;
    Ok((JoinClient::new(channel), ca_pem))
}

fn refused(s: tonic::Status) -> JoinError {
    JoinError::Refused(s.message().to_owned())
}

/// The returned certificate must be for the key in our CSR.
fn check_chain(chain_pem: &str, csr: &[u8]) -> Result<(), JoinError> {
    let leaf = pem::parse_many(chain_pem)
        .ok()
        .and_then(|v| v.into_iter().next())
        .ok_or(JoinError::BadCertificate)?;
    let spki = torngat_pki::spki_sha256(leaf.contents()).map_err(|_| JoinError::BadCertificate)?;
    let ours = torngat_pki::ca::csr_spki_sha256(csr).map_err(|e| JoinError::Key(e.to_string()))?;
    if torngat_pki::digest_eq(&spki, &ours) {
        Ok(())
    } else {
        Err(JoinError::BadCertificate)
    }
}

/// Joins the cluster whose join endpoint is `addr` (`host:port`), as `node`, with `key`.
///
/// Persist the key before calling. If an earlier call may have gone through but its answer was
/// lost, pass `resume: true`: the node first asks for a fresh certificate for its enrolled key
/// (no token needed shortly after enrolling), and only enrolls if there is none.
///
/// File keys enroll with `Join`; TPM keys prove themselves with `BeginTpmJoin`/`FinishTpmJoin`.
pub async fn join(
    addr: &str,
    token: &str,
    node: &Name,
    key: &crate::NodeKey,
    resume: bool,
) -> Result<Enrolled, JoinError> {
    let (token, pin) = JoinToken::parse(token).map_err(|_| JoinError::BadToken)?;
    let (mut client, ca_pem) = join_channel(addr, pin).await?;
    let csr = blocking(|| key.csr()).map_err(JoinError::Key)?;
    let done = |chain: String| -> Result<Enrolled, JoinError> {
        check_chain(&chain, &csr)?;
        Ok(Enrolled {
            ca_pem: ca_pem.clone(),
            cert_chain_pem: chain,
        })
    };

    if resume {
        match client
            .resume_join(ResumeJoinRequest {
                api_version: API_VERSION.into(),
                node_name: node.to_string(),
                csr_der: csr.clone(),
            })
            .await
        {
            Ok(r) => return done(r.into_inner().cert_chain_pem),
            // Nothing to resume (or a controller without ResumeJoin): enroll normally.
            Err(s) if matches!(s.code(), tonic::Code::NotFound | tonic::Code::Unimplemented) => {}
            Err(s) => return Err(refused(s)),
        }
    }

    let chain = match key {
        crate::NodeKey::File(_) => {
            client
                .join(JoinRequest {
                    api_version: API_VERSION.into(),
                    token_id: token.id().into(),
                    token_secret: token.secret().to_vec(),
                    node_name: node.to_string(),
                    csr_der: csr.clone(),
                })
                .await
                .map_err(refused)?
                .into_inner()
                .cert_chain_pem
        }
        #[cfg(feature = "tpm")]
        crate::NodeKey::Tpm(k) => tpm_join(&mut client, &token, node, k, &csr).await?,
    };
    done(chain)
}

#[cfg(feature = "tpm")]
async fn tpm_join(
    client: &mut JoinClient<Channel>,
    token: &JoinToken,
    node: &Name,
    key: &crate::tpm::TpmKey,
    csr: &[u8],
) -> Result<String, JoinError> {
    let tpm = |e: crate::tpm::TpmError| JoinError::Tpm(e.to_string());
    let (att, node_key_public) =
        blocking(|| Ok::<_, crate::tpm::TpmError>((key.attest()?, key.public_marshalled()?)))
            .map_err(tpm)?;
    let ch = client
        .begin_tpm_join(TpmJoinRequest {
            api_version: API_VERSION.into(),
            token_id: token.id().into(),
            token_secret: token.secret().to_vec(),
            node_name: node.to_string(),
            csr_der: csr.to_vec(),
            ek_cert_der: att.ek_cert.clone(),
            ak_public: att.ak_public.clone(),
            node_key_public,
        })
        .await;
    let ch = match ch {
        Ok(c) => c.into_inner(),
        Err(s) => {
            blocking(|| drop(att)); // flushing the EK and AK talks to the TPM
            return Err(refused(s));
        }
    };
    let ans = blocking(|| {
        let ans = att.answer(&ch.id_object, &ch.encrypted_secret, &ch.nonce);
        drop(att); // flushes the EK and AK from the TPM
        ans
    })
    .map_err(tpm)?;
    Ok(client
        .finish_tpm_join(TpmJoinAnswer {
            challenge_id: ch.challenge_id,
            activated_secret: ans.activated_secret,
            certify_attest: ans.certify_attest,
            certify_signature: ans.certify_signature,
        })
        .await
        .map_err(refused)?
        .into_inner()
        .cert_chain_pem)
}
