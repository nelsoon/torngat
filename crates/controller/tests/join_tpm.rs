//! TPM enrollment end to end, against a real (software) TPM: attested join, then mTLS with the
//! TPM-held key. Needs `--features tpm-tests` and `TORNGAT_TEST_TCTI` / `TORNGAT_TEST_EK_CA`
//! (`eval "$(scripts/swtpm.sh start)"`); skipped without them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use torngat_agent::join::{JoinError, join_tpm};
use torngat_agent::tpm::TpmKey;
use torngat_agent::{AgentConfig, FakeRuntime, NodeKey};
use torngat_api::Name;
use torngat_controller::{Controller, JoinService, TlsConfig, keys};
use torngat_pki::{Ca, JoinToken, KeyStorage, NodeIdentity, TpmPolicy};
use torngat_store::testnet::TestNet;
use torngat_store::{Node, Precondition, Store, default_config};

struct Env {
    store: Store,
    ca: Arc<Ca>,
    control: String,
    join: String,
    _dir: TempDir,
}

async fn env(anchors: Vec<Vec<u8>>) -> Env {
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
    store
        .put(
            keys::tpm_policy().unwrap(),
            serde_json::to_vec(&TpmPolicy { required: true }).unwrap(),
            Precondition::Absent,
        )
        .await
        .unwrap();
    let ca = Arc::new(Ca::generate().unwrap());
    let c = ca.issue_controller().unwrap();
    let tls = TlsConfig {
        cert_pem: c.chain_pem.into_bytes(),
        key_pem: c.key_pem.unwrap().into_bytes(),
        client_ca_pem: ca.cert_pem().as_bytes().to_vec(),
    };
    let ctl = Controller::new(store.clone());
    let cl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let jl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control = cl.local_addr().unwrap().to_string();
    let join = jl.local_addr().unwrap().to_string();
    tokio::spawn(torngat_controller::serve(ctl.clone(), cl, tls.clone()));
    tokio::spawn(torngat_controller::serve_join(
        JoinService::new(store.clone(), ca.clone(), anchors),
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
    async fn token(&self, pin: Option<String>) -> String {
        let t = JoinToken::generate().unwrap();
        let mut rec = t.record(None, time::Duration::hours(1), String::new());
        rec.ek_sha256 = pin;
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

    async fn identity(&self, node: &str) -> NodeIdentity {
        let v = self
            .store
            .get(&keys::node_identity(&n(node)).unwrap())
            .await
            .unwrap()
            .unwrap();
        serde_json::from_slice(&v.value).unwrap()
    }
}

fn n(s: &str) -> Name {
    Name::new(s).unwrap()
}

fn anchors() -> Vec<Vec<u8>> {
    let path = std::env::var("TORNGAT_TEST_EK_CA").expect("TORNGAT_TEST_EK_CA");
    pem::parse_many(std::fs::read(path).unwrap())
        .unwrap()
        .into_iter()
        .map(|p| p.into_contents())
        .collect()
}

// One test: a TPM without a resource manager serves one connection with few object slots.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tpm_join_and_mtls_with_the_tpm_key() {
    let Ok(tcti) = std::env::var("TORNGAT_TEST_TCTI") else {
        eprintln!("TORNGAT_TEST_TCTI not set: skipping TPM test");
        return;
    };
    let (key, _blob) = TpmKey::create(&tcti).unwrap();

    // Vendor anchors configured.
    let e = env(anchors()).await;
    // A token pinned to another TPM refuses this one, and survives.
    let wrong = e.token(Some("a".repeat(64))).await;
    let err = join_tpm(&e.join, &wrong, &n("n2"), &key).await.unwrap_err();
    assert!(
        matches!(&err, JoinError::Refused(m) if m.contains("not trusted")),
        "{err}"
    );
    assert!(e.token_exists(&wrong).await);

    let text = e.token(None).await;
    let creds = join_tpm(&e.join, &text, &n("n2"), &key).await.unwrap();
    assert!(!e.token_exists(&text).await);
    let ident = e.identity("n2").await;
    assert_eq!(ident.key_storage, KeyStorage::Tpm);
    let ek = ident.ek_sha256.clone().unwrap();

    // Running with the TPM key: mTLS handshakes are signed inside the TPM.
    tokio::spawn(torngat_agent::run(
        AgentConfig {
            controller_url: format!("https://{}", e.control),
            controller_name: torngat_pki::CONTROLLER_NAME.into(),
            ca_pem: creds.ca_pem.into_bytes(),
            cert_pem: creds.cert_chain_pem.into_bytes(),
            key: NodeKey::Tpm(key.clone()),
        },
        FakeRuntime::default(),
    ));
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(v) = e.store.get(&keys::node(&n("n2")).unwrap()).await.unwrap() {
            let node: torngat_api::node::Node = serde_json::from_slice(&v.value).unwrap();
            if node.status.phase == torngat_api::node::NodePhase::Active {
                break;
            }
        }
        assert!(Instant::now() < deadline, "n2 never became active");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Re-running join (lost answer) gets a certificate without a new token.
    join_tpm(&e.join, &text, &n("n2"), &key).await.unwrap();

    // Pre-registered hardware: no vendor anchors, but the token pins this TPM's EK.
    let e2 = env(Vec::new()).await;
    let unpinned = e2.token(None).await;
    let err = join_tpm(&e2.join, &unpinned, &n("n3"), &key)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, JoinError::Refused(m) if m.contains("not trusted")),
        "{err}"
    );
    let pinned = e2.token(Some(ek.clone())).await;
    join_tpm(&e2.join, &pinned, &n("n3"), &key).await.unwrap();
    assert_eq!(e2.identity("n3").await.ek_sha256, Some(ek));
    e2.store.shutdown().await.unwrap();
    e.store.shutdown().await.unwrap();
}
