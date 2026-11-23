//! API tests against a real single-node store.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tempfile::TempDir;
use torngat_apiserver::{AdminToken, AppState, router};
use torngat_store::testnet::TestNet;
use torngat_store::{Node, Store, default_config};
use tower::ServiceExt;

const TOKEN: &str = "test-token-0123456789-0123456789-abcdef";
const BASE: &str = "/v1/orgs/acme/projects/web/instances";

struct Env {
    app: Router,
    store: Store,
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
    let app = router(AppState {
        store: store.clone(),
        token: AdminToken::new(TOKEN).unwrap(),
    });
    Env {
        app,
        store,
        _dir: dir,
    }
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    auth: bool,
) -> (StatusCode, Value) {
    let mut b = Request::builder().method(method).uri(uri);
    if auth {
        b = b.header("authorization", format!("Bearer {TOKEN}"));
    }
    let req = match body {
        Some(v) => b
            .header("content-type", "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into()))
    };
    (status, v)
}

fn spec() -> Value {
    json!({"vcpus": 2, "memory_mib": 2048})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requires_authentication() {
    let e = env().await;
    let (s, v) = call(&e.app, "GET", BASE, None, false).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["error"]["status"], "UNAUTHENTICATED");
    // Wrong token.
    let req = Request::builder()
        .uri(BASE)
        .header(
            "authorization",
            "Bearer wrong-token-wrong-token-wrong-token",
        )
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        e.app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_get_update_delete() {
    let e = env().await;
    // Server-set fields in the body are ignored; unknown top-level fields too.
    let (s, op) = call(
        &e.app,
        "POST",
        &format!("{BASE}?instance_id=vm-1"),
        Some(json!({"spec": spec(), "labels": {"env": "dev"}, "status": {"phase": "running"}, "metadata": {"uid": "00000000-0000-0000-0000-000000000001"}})),
        true,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{op}");
    assert_eq!(op["target"], "orgs/acme/projects/web/instances/vm-1");
    assert_eq!(op["done"], false);

    let (s, vm) = call(&e.app, "GET", &format!("{BASE}/vm-1"), None, true).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(vm["status"]["phase"], "pending");
    assert_ne!(
        vm["metadata"]["uid"],
        "00000000-0000-0000-0000-000000000001"
    );
    assert_eq!(vm["metadata"]["generation"], 1);
    assert_eq!(vm["metadata"]["cell"], "c0");
    let etag = vm["metadata"]["etag"].as_str().unwrap().to_owned();

    // Duplicate create.
    let (s, v) = call(
        &e.app,
        "POST",
        &format!("{BASE}?instance_id=vm-1"),
        Some(json!({"spec": spec()})),
        true,
    )
    .await;
    assert_eq!(
        (s, v["error"]["status"].as_str()),
        (StatusCode::CONFLICT, Some("ALREADY_EXISTS"))
    );

    // Update with the right etag bumps generation; with a stale one is rejected.
    let (s, vm2) = call(
        &e.app,
        "PATCH",
        &format!("{BASE}/vm-1"),
        Some(json!({"etag": etag, "spec": {"vcpus": 4, "memory_mib": 2048}})),
        true,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{vm2}");
    assert_eq!(vm2["metadata"]["generation"], 2);
    assert_ne!(vm2["metadata"]["etag"], etag);
    let (s, v) = call(
        &e.app,
        "PATCH",
        &format!("{BASE}/vm-1"),
        Some(json!({"etag": etag, "labels": {}})),
        true,
    )
    .await;
    assert_eq!(
        (s, v["error"]["status"].as_str()),
        (StatusCode::CONFLICT, Some("ABORTED"))
    );

    // Label-only change does not bump generation.
    let (_, vm3) = call(
        &e.app,
        "PATCH",
        &format!("{BASE}/vm-1"),
        Some(json!({"labels": {"env": "prod"}})),
        true,
    )
    .await;
    assert_eq!(vm3["metadata"]["generation"], 2);

    // Operation is retrievable.
    let (s, o) = call(
        &e.app,
        "GET",
        &format!("/v1/operations/{}", op["id"].as_str().unwrap()),
        None,
        true,
    )
    .await;
    assert_eq!((s, &o["target"]), (StatusCode::OK, &op["target"]));

    // Delete, then 404.
    let (s, _) = call(&e.app, "DELETE", &format!("{BASE}/vm-1"), None, true).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&e.app, "GET", &format!("{BASE}/vm-1"), None, true).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(&e.app, "DELETE", &format!("{BASE}/vm-1"), None, true).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_id_makes_create_idempotent() {
    let e = env().await;
    let rid = "6f1c2f3e-0a4b-4c5d-8e9f-0123456789ab";
    let uri = format!("{BASE}?instance_id=vm-r&request_id={rid}");
    let (s1, op1) = call(&e.app, "POST", &uri, Some(json!({"spec": spec()})), true).await;
    let (s2, op2) = call(&e.app, "POST", &uri, Some(json!({"spec": spec()})), true).await;
    assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK));
    assert_eq!(op1["id"], op2["id"]);
    // Same request_id for another resource is refused.
    let (s, _) = call(
        &e.app,
        "POST",
        &format!("{BASE}?instance_id=vm-other&request_id={rid}"),
        Some(json!({"spec": spec()})),
        true,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_invalid_input() {
    let e = env().await;
    for (uri, body) in [
        (
            format!("{BASE}?instance_id=Bad_Name"),
            json!({"spec": spec()}),
        ),
        (
            format!("{BASE}?instance_id=vm-x"),
            json!({"spec": {"vcpus": 0, "memory_mib": 2048}}),
        ),
        (
            format!("{BASE}?instance_id=vm-x"),
            json!({"spec": spec(), "labels": {"Bad Key": "v"}}),
        ),
        (format!("{BASE}?instance_id=vm-x"), json!({"nospec": 1})),
        (
            format!("{BASE}?instance_id=vm-x&request_id=not-a-uuid"),
            json!({"spec": spec()}),
        ),
        (
            "/v1/orgs/ACME/projects/web/instances?instance_id=vm-x".to_owned(),
            json!({"spec": spec()}),
        ),
    ] {
        let (s, v) = call(&e.app, "POST", &uri, Some(body), true).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{uri}: {v}");
        assert_eq!(v["error"]["status"], "INVALID_ARGUMENT", "{uri}");
    }
    // Oversized body.
    let big = json!({"spec": spec(), "labels": {"k": "x".repeat(300 * 1024)}});
    let (s, _) = call(
        &e.app,
        "POST",
        &format!("{BASE}?instance_id=vm-big"),
        Some(big),
        true,
    )
    .await;
    assert!(
        s == StatusCode::PAYLOAD_TOO_LARGE || s == StatusCode::BAD_REQUEST,
        "{s}"
    );
    // Path names are validated (no traversal into other keys).
    let (s, _) = call(
        &e.app,
        "GET",
        &format!("{BASE}/..%2F..%2Fplatform"),
        None,
        true,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_paginates_and_isolates_projects() {
    let e = env().await;
    for i in 0..5 {
        call(
            &e.app,
            "POST",
            &format!("{BASE}?instance_id=vm-{i}"),
            Some(json!({"spec": spec()})),
            true,
        )
        .await;
    }
    // Another project with a name that extends this one must not leak in.
    call(
        &e.app,
        "POST",
        "/v1/orgs/acme/projects/web-2/instances?instance_id=vm-z",
        Some(json!({"spec": spec()})),
        true,
    )
    .await;
    let (_, p1) = call(&e.app, "GET", &format!("{BASE}?page_size=2"), None, true).await;
    assert_eq!(p1["items"].as_array().unwrap().len(), 2);
    let tok = p1["next_page_token"].as_str().unwrap();
    let (_, p2) = call(
        &e.app,
        "GET",
        &format!("{BASE}?page_size=10&page_token={tok}"),
        None,
        true,
    )
    .await;
    let names: Vec<&str> = p2["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["metadata"]["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["vm-2", "vm-3", "vm-4"]);
    assert!(p2.get("next_page_token").is_none());
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_paths_need_auth_and_bearer_is_case_insensitive() {
    let e = env().await;
    let (s, _) = call(&e.app, "GET", "/v1/nope", None, false).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = call(&e.app, "GET", "/v1/nope", None, true).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let req = Request::builder()
        .uri(BASE)
        .header("authorization", format!("bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        e.app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_etags_are_rejected() {
    let e = env().await;
    call(
        &e.app,
        "POST",
        &format!("{BASE}?instance_id=vm-e"),
        Some(json!({"spec": spec()})),
        true,
    )
    .await;
    let (_, vm) = call(&e.app, "GET", &format!("{BASE}/vm-e"), None, true).await;
    let good = vm["metadata"]["etag"]
        .as_str()
        .unwrap()
        .trim_matches('"')
        .to_owned();
    for bad in [
        good.clone(),
        format!("\"+{good}\""),
        format!("\"\"{good}\"\""),
        "\"\"".into(),
    ] {
        let (s, v) = call(
            &e.app,
            "PATCH",
            &format!("{BASE}/vm-e"),
            Some(json!({"etag": bad, "labels": {}})),
            true,
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {v}");
    }
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_duplicate_creates_share_one_operation() {
    let e = env().await;
    let rid = "0a1b2c3d-0000-4000-8000-000000000001";
    let uri = format!("{BASE}?instance_id=vm-c&request_id={rid}");
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let app = e.app.clone();
        let uri = uri.clone();
        set.spawn(
            async move { call(&app, "POST", &uri, Some(json!({"spec": spec()})), true).await },
        );
    }
    let mut ids = std::collections::BTreeSet::new();
    while let Some(r) = set.join_next().await {
        let (s, op) = r.unwrap();
        // Every duplicate either gets the operation or is told to retry; never ALREADY_EXISTS.
        assert!(
            s == StatusCode::OK || s == StatusCode::SERVICE_UNAVAILABLE,
            "{s} {op}"
        );
        if s == StatusCode::OK {
            ids.insert(op["id"].as_str().unwrap().to_owned());
        }
    }
    assert_eq!(ids.len(), 1);
    // A retry after the dust settles returns the same operation.
    let (s, op) = call(&e.app, "POST", &uri, Some(json!({"spec": spec()})), true).await;
    assert_eq!(s, StatusCode::OK);
    assert!(ids.contains(op["id"].as_str().unwrap()));
    // The same request id in another project is independent.
    let (s, _) = call(
        &e.app,
        "POST",
        &format!("/v1/orgs/acme/projects/other/instances?instance_id=vm-c&request_id={rid}"),
        Some(json!({"spec": spec()})),
        true,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    e.store.shutdown().await.unwrap();
}
