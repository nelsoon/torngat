//! Enrollment end to end: join token → pinned CA discovery → CSR → certificate → running agent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{env, n, set_policy};
use torngat_agent::join::{Enrolled, JoinError};
use torngat_agent::{AgentConfig, FakeRuntime, NodeKey};
use torngat_api::Name;
use torngat_controller::keys;
use torngat_pki::{CaHash, JoinToken};
use torngat_proto::API_VERSION;
use torngat_proto::v1::JoinRequest;
use torngat_proto::v1::join_client::JoinClient;
use torngat_store::Precondition;

fn fresh_key() -> String {
    torngat_pki::ca::node_key().unwrap().serialize_pem()
}

async fn join_with(
    addr: &str,
    token: &str,
    node: &Name,
    key_pem: &str,
    resume: bool,
) -> Result<Enrolled, JoinError> {
    let key = NodeKey::File(key_pem.as_bytes().to_vec());
    torngat_agent::join::join(addr, token, node, &key, resume).await
}

/// Joins with a fresh key.
async fn join(addr: &str, token: &str, node: &Name) -> Result<Enrolled, JoinError> {
    join_with(addr, token, node, &fresh_key(), false).await
}

const DAY: time::Duration = time::Duration::hours(24);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_then_run_as_an_enrolled_node() {
    let e = env(Vec::new(), false).await;
    let text = e.token(None, DAY, None).await;
    let key = fresh_key();
    let creds = join_with(&e.join, &text, &n("n2"), &key, false)
        .await
        .unwrap();
    assert!(!e.token_exists(&text).await, "token must be consumed");
    assert!(creds.ca_pem.contains("BEGIN CERTIFICATE"));

    // The new credentials work on the control endpoint.
    tokio::spawn(torngat_agent::run(
        AgentConfig {
            controller_url: format!("https://{}", e.control),
            controller_name: torngat_pki::CONTROLLER_NAME.into(),
            ca_pem: creds.ca_pem.into_bytes(),
            cert_pem: creds.cert_chain_pem.into_bytes(),
            key: NodeKey::File(key.into_bytes()),
        },
        FakeRuntime::default(),
        torngat_agent::storage::NoDriver,
        torngat_agent::storage::FakeCrypt::default(),
    ));
    e.wait_active("n2").await;

    // Single use.
    let err = join(&e.join, &text, &n("n3")).await.unwrap_err();
    assert!(matches!(err, JoinError::Refused(_)), "{err}");
    // A name is enrolled once: a fresh token cannot take over n2, and is not burned trying.
    let other = e.token(None, DAY, None).await;
    let err = join(&e.join, &other, &n("n2")).await.unwrap_err();
    assert!(
        matches!(&err, JoinError::Refused(m) if m.contains("in use")),
        "{err}"
    );
    assert!(e.token_exists(&other).await);
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_tokens_are_refused_without_burning_good_ones() {
    let e = env(Vec::new(), false).await;
    let text = e.token(Some("n2"), DAY, None).await;

    // Wrong secret.
    let (t, ca) = JoinToken::parse(&text).unwrap();
    let mut parts: Vec<String> = text.split('.').map(str::to_owned).collect();
    parts[2] = "0".repeat(64);
    let forged = parts.join(".");
    assert!(matches!(
        join(&e.join, &forged, &n("n2")).await.unwrap_err(),
        JoinError::Refused(_)
    ));
    // Bound to another node.
    assert!(matches!(
        join(&e.join, &text, &n("n3")).await.unwrap_err(),
        JoinError::Refused(_)
    ));
    // Unknown id.
    let unknown = JoinToken::generate().unwrap().encode(&ca);
    assert!(matches!(
        join(&e.join, &unknown, &n("n2")).await.unwrap_err(),
        JoinError::Refused(_)
    ));
    // A CA pin that does not match: refused before anything is sent.
    let wrong_ca = t.encode(&CaHash([9; 32]));
    assert!(matches!(
        join(&e.join, &wrong_ca, &n("n2")).await.unwrap_err(),
        JoinError::CaMismatch
    ));
    // A malformed CSR does not burn the token.
    let ca_pem = e.ca.cert_pem().to_owned();
    let raw = |csr: Vec<u8>| {
        let ca_pem = ca_pem.clone();
        let addr = e.join.clone();
        let req = JoinRequest {
            api_version: API_VERSION.into(),
            token_id: t.id().into(),
            token_secret: t.secret().to_vec(),
            node_name: "n2".into(),
            csr_der: csr,
        };
        async move {
            let tls = tonic::transport::ClientTlsConfig::new()
                .ca_certificate(tonic::transport::Certificate::from_pem(ca_pem))
                .domain_name(torngat_pki::CONTROLLER_NAME);
            let ch = tonic::transport::Channel::from_shared(format!("https://{addr}"))
                .unwrap()
                .tls_config(tls)
                .unwrap()
                .connect()
                .await
                .unwrap();
            JoinClient::new(ch).join(req).await.unwrap_err().code()
        }
    };
    assert_eq!(raw(b"junk".to_vec()).await, tonic::Code::InvalidArgument);
    assert!(e.token_exists(&text).await);

    // The real thing still works.
    join(&e.join, &text, &n("n2")).await.unwrap();

    // Expired.
    let expired = e.token(None, time::Duration::seconds(-1), None).await;
    assert!(matches!(
        join(&e.join, &expired, &n("n4")).await.unwrap_err(),
        JoinError::Refused(_)
    ));
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_enrolls_exactly_one_node_under_concurrency() {
    let e = env(Vec::new(), false).await;
    let text = e.token(None, DAY, None).await;
    let mut tasks = Vec::new();
    for i in 0..8 {
        let (addr, text) = (e.join.clone(), text.clone());
        tasks.push(tokio::spawn(async move {
            join(&addr, &text, &n(&format!("c{i}"))).await.is_ok()
        }));
    }
    let mut ok = 0;
    for t in tasks {
        ok += usize::from(t.await.unwrap());
    }
    assert_eq!(ok, 1);
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_tokens_are_cleaned_up() {
    let e = env(Vec::new(), false).await;
    let expired = e.token(None, time::Duration::seconds(-1), None).await;
    let live = e.token(None, DAY, None).await;
    // The controller runs this pass on a slow timer (its first run may already have caught the
    // token); call it directly.
    let removed = torngat_controller::expire_join_tokens_once(&e.store)
        .await
        .unwrap();
    assert!(removed <= 1);
    assert!(!e.token_exists(&expired).await);
    assert!(e.token_exists(&live).await);
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_answer_can_be_retried_with_the_same_key() {
    let e = env(Vec::new(), false).await;
    let text = e.token(None, DAY, None).await;
    let key = fresh_key();
    let first = join_with(&e.join, &text, &n("n2"), &key, false)
        .await
        .unwrap();
    assert!(!e.token_exists(&text).await);
    // Same key, used-up token, resuming: a new certificate for the same key.
    let again = join_with(&e.join, &text, &n("n2"), &key, true)
        .await
        .unwrap();
    let spki = |c: &str| {
        let der = pem::parse_many(c).unwrap().remove(0);
        torngat_pki::spki_sha256(der.contents()).unwrap()
    };
    assert_eq!(spki(&first.cert_chain_pem), spki(&again.cert_chain_pem));
    // Another key cannot use that path.
    assert!(matches!(
        join_with(&e.join, &text, &n("n2"), &fresh_key(), true)
            .await
            .unwrap_err(),
        JoinError::Refused(_)
    ));
    // Only shortly after enrollment: it is a retry, not a token-less renewal.
    let ikey = keys::node_identity(&n("n2")).unwrap();
    let v = e.store.get(&ikey).await.unwrap().unwrap();
    let mut rec: torngat_pki::NodeIdentity = serde_json::from_slice(&v.value).unwrap();
    rec.issue_time -= torngat_controller::join::RETRY_WINDOW;
    e.store
        .put(
            ikey,
            serde_json::to_vec(&rec).unwrap(),
            Precondition::Revision(v.revision),
        )
        .await
        .unwrap();
    assert!(matches!(
        join_with(&e.join, &text, &n("n2"), &key, true)
            .await
            .unwrap_err(),
        JoinError::Refused(_)
    ));
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_for_one_name_burns_only_the_winning_token() {
    let e = env(Vec::new(), false).await;
    let mut texts = Vec::new();
    for _ in 0..6 {
        texts.push(e.token(None, DAY, None).await);
    }
    let mut tasks = Vec::new();
    for t in &texts {
        let (addr, t) = (e.join.clone(), t.clone());
        tasks.push(tokio::spawn(async move {
            join(&addr, &t, &n("same")).await.is_ok()
        }));
    }
    let mut ok = 0;
    for t in tasks {
        ok += usize::from(t.await.unwrap());
    }
    assert_eq!(ok, 1);
    let mut left = 0;
    for t in &texts {
        left += usize::from(e.token_exists(t).await);
    }
    assert_eq!(left, texts.len() - 1, "losing tokens must survive");
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tpm_required_cluster_refuses_file_keys() {
    let e = env(Vec::new(), false).await;
    set_policy(&e.store, true).await;
    let text = e.token(None, DAY, None).await;
    let err = join(&e.join, &text, &n("n2")).await.unwrap_err();
    assert!(
        matches!(&err, JoinError::Refused(m) if m.contains("requires TPM")),
        "{err}"
    );
    assert!(
        e.token_exists(&text).await,
        "a refused join must not burn the token"
    );
    // No policy recorded at all means required too.
    e.store
        .delete(keys::tpm_policy().unwrap(), Precondition::None)
        .await
        .unwrap();
    assert!(join(&e.join, &text, &n("n2")).await.is_err());
    e.store.shutdown().await.unwrap();
}
