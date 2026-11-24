//! Enrollment end to end: join token → pinned CA discovery → CSR → certificate → running agent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use torngat_agent::join::{JoinError, join};
use torngat_agent::{AgentConfig, FakeRuntime};
use torngat_api::Name;
use torngat_controller::{Controller, JoinService, TlsConfig, keys};
use torngat_pki::{Ca, CaHash, JoinToken};
use torngat_proto::API_VERSION;
use torngat_proto::v1::JoinRequest;
use torngat_proto::v1::join_client::JoinClient;
use torngat_store::testnet::TestNet;
use torngat_store::{Node, Precondition, Store, default_config};

struct Env {
    store: Store,
    ca: Arc<Ca>,
    control: String,
    join: String,
    _dir: TempDir,
}

async fn env() -> Env {
    let dir = TempDir::new().unwrap();
    let net = TestNet::default();
    let store = Store::open(dir.path(), 1, default_config(), net.factory(1))
        .await
        .unwrap();
    net.register(1, store.raft().clone());
    store
        .initialize(BTreeMap::from([(1, Node::default())]))
        .await
        .unwrap();
    store
        .raft()
        .wait(Some(Duration::from_secs(10)))
        .current_leader(1, "leader")
        .await
        .unwrap();
    let ca = Arc::new(Ca::generate().unwrap());
    let ctl_cert = ca.issue_controller().unwrap();
    let tls = TlsConfig {
        cert_pem: ctl_cert.chain_pem.clone().into_bytes(),
        key_pem: ctl_cert.key_pem.clone().unwrap().into_bytes(),
        client_ca_pem: ca.cert_pem().as_bytes().to_vec(),
    };
    let ctl = Controller::new(store.clone());
    let cl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let jl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control = cl.local_addr().unwrap().to_string();
    let join = jl.local_addr().unwrap().to_string();
    tokio::spawn(torngat_controller::serve(ctl.clone(), cl, tls.clone()));
    tokio::spawn(torngat_controller::serve_join(
        JoinService::new(store.clone(), ca.clone()),
        jl,
        tls.cert_pem,
        tls.key_pem,
    ));
    tokio::spawn(ctl.run_scheduler(Duration::from_millis(100)));
    Env {
        store,
        ca,
        control,
        join,
        _dir: dir,
    }
}

impl Env {
    /// Creates a token as the API would, returning its text.
    async fn token(&self, node: Option<&str>, ttl: time::Duration) -> String {
        let t = JoinToken::generate().unwrap();
        let rec = t.record(node.map(|n| Name::new(n).unwrap()), ttl, String::new());
        self.store
            .put(
                keys::join_token(t.id()).unwrap(),
                serde_json::to_vec(&rec).unwrap(),
                Precondition::Absent,
            )
            .await
            .unwrap();
        t.encode(&self.ca.hash())
    }

    async fn token_exists(&self, text: &str) -> bool {
        let (t, _) = JoinToken::parse(text).unwrap();
        self.store
            .get(&keys::join_token(t.id()).unwrap())
            .await
            .unwrap()
            .is_some()
    }
}

fn n(s: &str) -> Name {
    Name::new(s).unwrap()
}

const DAY: time::Duration = time::Duration::hours(24);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_then_run_as_an_enrolled_node() {
    let e = env().await;
    let text = e.token(None, DAY).await;
    let creds = join(&e.join, &text, &n("n2")).await.unwrap();
    assert!(!e.token_exists(&text).await, "token must be consumed");
    assert!(creds.ca_pem.contains("BEGIN CERTIFICATE"));

    // The new credentials work on the control endpoint.
    let store = e.store.clone();
    tokio::spawn(torngat_agent::run(
        AgentConfig {
            controller_url: format!("https://{}", e.control),
            controller_name: torngat_pki::CONTROLLER_NAME.into(),
            ca_pem: creds.ca_pem.into_bytes(),
            cert_pem: creds.cert_chain_pem.into_bytes(),
            key_pem: creds.key_pem.into_bytes(),
        },
        FakeRuntime::default(),
    ));
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(v) = store.get(&keys::node(&n("n2")).unwrap()).await.unwrap() {
            let node: torngat_api::node::Node = serde_json::from_slice(&v.value).unwrap();
            if node.status.phase == torngat_api::node::NodePhase::Active {
                break;
            }
        }
        assert!(Instant::now() < deadline, "n2 never became active");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Single use.
    let err = join(&e.join, &text, &n("n3")).await.unwrap_err();
    assert!(matches!(err, JoinError::Refused(_)), "{err}");
    // A name is enrolled once: a fresh token cannot take over n2, and is not burned trying.
    let other = e.token(None, DAY).await;
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
    let e = env().await;
    let text = e.token(Some("n2"), DAY).await;

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
    // A malformed CSR or unsupported key storage does not burn the token.
    let ca_pem = e.ca.cert_pem().to_owned();
    let raw = |csr: Vec<u8>, storage: &str| {
        let ca_pem = ca_pem.clone();
        let addr = e.join.clone();
        let req = JoinRequest {
            api_version: API_VERSION.into(),
            token_id: t.id().into(),
            token_secret: t.secret().to_vec(),
            node_name: "n2".into(),
            csr_der: csr,
            key_storage: storage.into(),
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
    assert_eq!(
        raw(b"junk".to_vec(), "file").await,
        tonic::Code::InvalidArgument
    );
    let key = torngat_pki::ca::node_key().unwrap();
    let csr = torngat_pki::ca::node_csr(&key).unwrap();
    assert_eq!(raw(csr, "tpm").await, tonic::Code::FailedPrecondition);
    assert!(e.token_exists(&text).await);

    // The real thing still works.
    join(&e.join, &text, &n("n2")).await.unwrap();

    // Expired.
    let expired = e.token(None, time::Duration::seconds(-1)).await;
    assert!(matches!(
        join(&e.join, &expired, &n("n4")).await.unwrap_err(),
        JoinError::Refused(_)
    ));
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_enrolls_exactly_one_node_under_concurrency() {
    let e = env().await;
    let text = e.token(None, DAY).await;
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
    let e = env().await;
    let expired = e.token(None, time::Duration::seconds(-1)).await;
    let live = e.token(None, DAY).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while e.token_exists(&expired).await {
        assert!(Instant::now() < deadline, "expired token not removed");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(e.token_exists(&live).await);
    e.store.shutdown().await.unwrap();
}
