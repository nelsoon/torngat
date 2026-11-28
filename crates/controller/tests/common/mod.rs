//! Shared test cluster for the enrollment tests: a single-node store, the control endpoint and
//! the join endpoint on loopback.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use torngat_api::Name;
use torngat_controller::{Controller, JoinService, TlsConfig, keys};
use torngat_pki::{Ca, JoinToken, NodeIdentity, TpmPolicy};
use torngat_store::testnet::TestNet;
use torngat_store::{Node, Precondition, Store, default_config};

pub struct Env {
    pub store: Store,
    pub ca: Arc<Ca>,
    pub control: String,
    pub join: String,
    /// The controller's image uploads.
    #[allow(dead_code)]
    pub uploads: torngat_uploads::Uploads,
    _dir: TempDir,
}

/// A cluster trusting `tpm_anchors` for TPM endorsement certificates, with the given policy.
pub async fn env(tpm_anchors: Vec<Vec<u8>>, tpm_required: bool) -> Env {
    env_with(tpm_anchors, tpm_required, true).await
}

/// Without the controller's background passes if `passes` is false: for tests that set states by hand.
pub async fn env_with(tpm_anchors: Vec<Vec<u8>>, tpm_required: bool, passes: bool) -> Env {
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
    set_policy(&store, tpm_required).await;
    let ca = Arc::new(Ca::generate().unwrap());
    let c = ca.issue_controller().unwrap();
    let tls = TlsConfig {
        cert_pem: c.chain_pem.into_bytes(),
        key_pem: c.key_pem.unwrap().into_bytes(),
        client_ca_pem: ca.cert_pem().as_bytes().to_vec(),
    };
    let uploads = torngat_uploads::Uploads::new(dir.path().join("uploads"));
    let ctl = Controller::new(
        store.clone(),
        std::sync::Arc::new(torngat_keys::PlatformKey::generate().unwrap()),
    )
    .with_uploads(uploads.clone());
    let cl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let jl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control = cl.local_addr().unwrap().to_string();
    let join = jl.local_addr().unwrap().to_string();
    tokio::spawn(torngat_controller::serve(ctl.clone(), cl, tls.clone()));
    tokio::spawn(torngat_controller::serve_join(
        JoinService::new(store.clone(), ca.clone(), tpm_anchors),
        jl,
        tls.cert_pem,
        tls.key_pem,
    ));
    if passes {
        tokio::spawn(ctl.run_scheduler(Duration::from_millis(100)));
    }
    Env {
        store,
        ca,
        control,
        join,
        uploads,
        _dir: dir,
    }
}

pub async fn set_policy(store: &Store, required: bool) {
    store
        .put(
            keys::tpm_policy().unwrap(),
            serde_json::to_vec(&TpmPolicy { required }).unwrap(),
            Precondition::None,
        )
        .await
        .unwrap();
}

pub fn n(s: &str) -> Name {
    Name::new(s).unwrap()
}

impl Env {
    /// Creates a token as the API would, returning its text.
    pub async fn token(
        &self,
        node: Option<&str>,
        ttl: time::Duration,
        ek_pin: Option<String>,
    ) -> String {
        let t = JoinToken::generate().unwrap();
        let mut rec = t.record(node.map(n), ttl, String::new());
        rec.ek_sha256 = ek_pin;
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

    pub async fn token_exists(&self, text: &str) -> bool {
        let (t, _) = JoinToken::parse(text).unwrap();
        self.store
            .get(&keys::join_token(t.id()).unwrap())
            .await
            .unwrap()
            .is_some()
    }

    pub async fn identity(&self, node: &str) -> NodeIdentity {
        let v = self
            .store
            .get(&keys::node_identity(&n(node)).unwrap())
            .await
            .unwrap()
            .unwrap();
        serde_json::from_slice(&v.value).unwrap()
    }

    /// Waits until `node` is registered and active.
    pub async fn wait_active(&self, node: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(v) = self
                .store
                .get(&keys::node(&n(node)).unwrap())
                .await
                .unwrap()
            {
                let node: torngat_api::node::Node = serde_json::from_slice(&v.value).unwrap();
                if node.status.phase == torngat_api::node::NodePhase::Active {
                    return;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{node} never became active"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// Marks `name` a compute node in `phase`.
pub async fn set_phase(e: &Env, name: &str, phase: &str) {
    let o = serde_json::json!({
        "metadata": {"name": name, "scope": torngat_api::Scope::Platform, "uid": uuid::Uuid::now_v7(),
                     "generation": 1},
        "spec": {"roles": ["compute"]}, "status": {"phase": phase}});
    e.store
        .put(
            keys::node(&n(name)).unwrap(),
            serde_json::to_vec(&o).unwrap(),
            Precondition::None,
        )
        .await
        .unwrap();
}

/// An enrolled node in `phase`: its credentials.
pub async fn node_cfg(e: &Env, name: &str, phase: &str) -> torngat_agent::AgentConfig {
    let issued = e.ca.issue_node(&n(name)).unwrap();
    torngat_controller::identity::enroll(
        &e.store,
        &n(name),
        &issued.identity(torngat_pki::KeyStorage::File).unwrap(),
    )
    .await
    .unwrap();
    set_phase(e, name, phase).await;
    torngat_agent::AgentConfig {
        controller_url: format!("https://{}", e.control),
        controller_name: torngat_pki::CONTROLLER_NAME.into(),
        ca_pem: e.ca.cert_pem().as_bytes().to_vec(),
        cert_pem: issued.chain_pem.into_bytes(),
        key: torngat_agent::NodeKey::File(issued.key_pem.unwrap().into_bytes()),
    }
}
