//! End to end on localhost: API → store → scheduler → controller ↔ agent (mTLS) → runtime.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use serde_json::{Value, json};
use tempfile::TempDir;
use torngat_agent::{AgentConfig, FakeRuntime, Runtime};
use torngat_apiserver::{AdminToken, AppState};
use torngat_controller::{Controller, TlsConfig};
use torngat_proto::v1::InstanceReport;
use torngat_proto::v1::control_client::ControlClient;
use torngat_store::testnet::TestNet;
use torngat_store::{Node, Store, default_config};
use tower::ServiceExt;

const TOKEN: &str = "e2e-token-0123456789-0123456789-abcdef";
const BASE: &str = "/v1/orgs/acme/projects/web/instances";

struct Pki {
    ca: CertifiedIssuer<'static, KeyPair>,
}

impl Pki {
    fn new() -> Self {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        Self {
            ca: CertifiedIssuer::self_signed(p, KeyPair::generate().unwrap()).unwrap(),
        }
    }
    fn ca_pem(&self) -> Vec<u8> {
        self.ca.pem().into_bytes()
    }
    /// Leaf certificate with the given DNS SANs: (cert, key).
    fn leaf(&self, sans: &[&str]) -> (Vec<u8>, Vec<u8>) {
        let key = KeyPair::generate().unwrap();
        let p =
            CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let cert = p.signed_by(&key, &self.ca).unwrap();
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    }
}

struct Env {
    api: axum::Router,
    store: Store,
    url: String,
    pki: Pki,
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

    let pki = Pki::new();
    let (cert, key) = pki.leaf(&["controller.torngat"]);
    let ctl = Controller::new(store.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    tokio::spawn(torngat_controller::serve(
        ctl.clone(),
        listener,
        TlsConfig {
            cert_pem: cert,
            key_pem: key,
            client_ca_pem: pki.ca_pem(),
        },
    ));
    tokio::spawn(ctl.run_scheduler(Duration::from_millis(100)));
    let api = torngat_apiserver::router(AppState {
        store: store.clone(),
        token: AdminToken::new(TOKEN).unwrap(),
    });
    Env {
        api,
        store,
        url,
        pki,
        _dir: dir,
    }
}

fn agent_cfg(e: &Env, node: &str) -> AgentConfig {
    let (cert, key) = e.pki.leaf(&[&format!("{node}.node.torngat")]);
    AgentConfig {
        controller_url: e.url.clone(),
        controller_name: "controller.torngat".into(),
        ca_pem: e.pki.ca_pem(),
        cert_pem: cert,
        key_pem: key,
    }
}

async fn call(
    api: &axum::Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"));
    let req = match body {
        Some(v) => {
            b = b.header("content-type", "application/json");
            b.body(Body::from(v.to_string())).unwrap()
        }
        None => b.body(Body::empty()).unwrap(),
    };
    let r = api.clone().oneshot(req).await.unwrap();
    let s = r.status();
    let bytes = r.into_body().collect().await.unwrap().to_bytes();
    (s, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn eventually(
    api: &axum::Router,
    uri: &str,
    what: &str,
    pred: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let (s, v) = call(api, "GET", uri, None).await;
        if s == StatusCode::OK && pred(&v) {
            return v;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}: last {s} {v}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn instance_lifecycle_through_agent() {
    let e = env().await;
    let runtime = FakeRuntime::default();
    tokio::spawn(torngat_agent::run(agent_cfg(&e, "n1"), runtime.clone()));

    // Node registers with inventory; identity comes from its certificate.
    let node = eventually(&e.api, "/v1/platform/nodes/n1", "node n1", |v| {
        v["status"]["phase"] == "active"
    })
    .await;
    assert!(
        !node["status"]["inventory"]["numa_nodes"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // Create → scheduled on n1 → running; operation completes.
    let (s, op) = call(
        &e.api,
        "POST",
        &format!("{BASE}?instance_id=vm-1"),
        Some(json!({"spec": {"vcpus": 1, "memory_mib": 256}})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{op}");
    let vm = eventually(&e.api, &format!("{BASE}/vm-1"), "vm-1 running", |v| {
        v["status"]["phase"] == "running"
    })
    .await;
    assert_eq!(vm["status"]["node"], "n1");
    assert_eq!(vm["status"]["observed_generation"], 1);
    assert!(vm["status"].get("pending_operation").is_none());
    let op = eventually(
        &e.api,
        &format!("/v1/operations/{}", op["id"].as_str().unwrap()),
        "op done",
        |v| v["done"] == true,
    )
    .await;
    assert!(op.get("error").is_none());
    assert_eq!(runtime.running().await.len(), 1);

    // A failing start completes the operation with an error.
    let (_, op2) = call(
        &e.api,
        "POST",
        &format!("{BASE}?instance_id=fail-1"),
        Some(json!({"spec": {"vcpus": 1, "memory_mib": 256}})),
    )
    .await;
    eventually(&e.api, &format!("{BASE}/fail-1"), "fail-1 failed", |v| {
        v["status"]["phase"] == "failed"
    })
    .await;
    let op2 = eventually(
        &e.api,
        &format!("/v1/operations/{}", op2["id"].as_str().unwrap()),
        "op2 done",
        |v| v["done"] == true,
    )
    .await;
    assert!(op2.get("error").is_some());

    // Stop via update: the node stops it and reports the new generation.
    let (s, _) = call(
        &e.api,
        "PATCH",
        &format!("{BASE}/vm-1"),
        Some(json!({"spec": {"vcpus": 1, "memory_mib": 256, "power_state": "stopped"}})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let vm = eventually(&e.api, &format!("{BASE}/vm-1"), "vm-1 stopped", |v| {
        v["status"]["phase"] == "stopped"
    })
    .await;
    assert_eq!(vm["status"]["observed_generation"], 2);
    assert!(runtime.running().await.is_empty());
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agents_cannot_impersonate_or_touch_others() {
    let e = env().await;
    tokio::spawn(torngat_agent::run(
        agent_cfg(&e, "n1"),
        FakeRuntime::default(),
    ));
    eventually(&e.api, "/v1/platform/nodes/n1", "node n1", |v| {
        v["status"]["phase"] == "active"
    })
    .await;
    let (_, _) = call(
        &e.api,
        "POST",
        &format!("{BASE}?instance_id=vm-1"),
        Some(json!({"spec": {"vcpus": 1, "memory_mib": 256}})),
    )
    .await;
    let vm = eventually(&e.api, &format!("{BASE}/vm-1"), "running", |v| {
        v["status"]["phase"] == "running"
    })
    .await;

    // A different, legitimately enrolled node cannot report on n1's instance.
    let n2 = agent_cfg(&e, "n2");
    let tls = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(&n2.ca_pem))
        .identity(tonic::transport::Identity::from_pem(
            &n2.cert_pem,
            &n2.key_pem,
        ))
        .domain_name("controller.torngat");
    let ch = tonic::transport::Channel::from_shared(e.url.clone())
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut c = ControlClient::new(ch);
    let err = c
        .report_instance(InstanceReport {
            org: "acme".into(),
            project: "web".into(),
            name: "vm-1".into(),
            uid: vm["metadata"]["uid"].as_str().unwrap().into(),
            phase: "stopped".into(),
            observed_generation: 1,
            runtime: String::new(),
            message: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // A certificate without a node name is refused.
    let (cert, key) = e.pki.leaf(&["something.else"]);
    let tls = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(e.pki.ca_pem()))
        .identity(tonic::transport::Identity::from_pem(cert, key))
        .domain_name("controller.torngat");
    let ch = tonic::transport::Channel::from_shared(e.url.clone())
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let err = ControlClient::new(ch)
        .heartbeat(torngat_proto::v1::HeartbeatRequest {})
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // A certificate from another CA cannot even complete the handshake.
    let other = Pki::new();
    let (cert, key) = other.leaf(&["n1.node.torngat"]);
    let tls = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(e.pki.ca_pem()))
        .identity(tonic::transport::Identity::from_pem(cert, key))
        .domain_name("controller.torngat");
    let ch = tonic::transport::Channel::from_shared(e.url.clone())
        .unwrap()
        .tls_config(tls)
        .unwrap();
    let res = match ch.connect().await {
        Err(_) => true,
        Ok(ch) => ControlClient::new(ch)
            .heartbeat(torngat_proto::v1::HeartbeatRequest {})
            .await
            .is_err(),
    };
    assert!(res, "foreign certificate was accepted");
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operations_complete_without_a_node_or_after_delete() {
    let e = env().await; // no agent: nothing can be scheduled
    // Created stopped: nothing to run, the operation completes anyway.
    let (_, op) = call(
        &e.api,
        "POST",
        &format!("{BASE}?instance_id=vm-off"),
        Some(json!({"spec": {"vcpus": 1, "memory_mib": 256, "power_state": "stopped"}})),
    )
    .await;
    let op = eventually(
        &e.api,
        &format!("/v1/operations/{}", op["id"].as_str().unwrap()),
        "stopped create done",
        |v| v["done"] == true,
    )
    .await;
    assert!(op.get("error").is_none());
    // Deleted while still pending: the operation ends as cancelled.
    let (_, op) = call(
        &e.api,
        "POST",
        &format!("{BASE}?instance_id=vm-pending"),
        Some(json!({"spec": {"vcpus": 1, "memory_mib": 256}})),
    )
    .await;
    let (s, _) = call(&e.api, "DELETE", &format!("{BASE}/vm-pending"), None).await;
    assert_eq!(s, StatusCode::OK);
    let op = eventually(
        &e.api,
        &format!("/v1/operations/{}", op["id"].as_str().unwrap()),
        "cancelled",
        |v| v["done"] == true,
    )
    .await;
    assert_eq!(op["error"]["code"], "CANCELLED");
    e.store.shutdown().await.unwrap();
}
