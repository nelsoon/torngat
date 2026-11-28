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
        ca_hash: torngat_pki::CaHash([7; 32]),
        backup: torngat_apiserver::Backup::new(|| async { Ok(None) }),
        uploads: Some(torngat_uploads::Uploads::new(dir.path().join("uploads"))),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn join_tokens_show_the_secret_once() {
    let e = env().await;
    const T: &str = "/v1/platform/joinTokens";
    let (s, _) = call(&e.app, "POST", T, Some(json!({})), false).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, t) = call(
        &e.app,
        "POST",
        T,
        Some(json!({"node": "n2", "ttl_seconds": 3600, "description": "rack 4"})),
        true,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{t}");
    let text = t["token"].as_str().unwrap();
    let (tok, ca) = torngat_pki::JoinToken::parse(text).unwrap();
    assert_eq!(ca, torngat_pki::CaHash([7; 32]));
    assert_eq!(tok.id(), t["name"].as_str().unwrap());
    assert_eq!(t["node"], "n2");

    // Never shown again.
    let (s, l) = call(&e.app, "GET", T, None, true).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(l["items"].as_array().unwrap().len(), 1);
    assert!(l["items"][0].get("token").is_none());
    assert!(!l.to_string().contains(text.split('.').nth(2).unwrap()));
    let one = format!("{T}/{}", tok.id());
    let (s, g) = call(&e.app, "GET", &one, None, true).await;
    assert_eq!(s, StatusCode::OK);
    assert!(g.get("token").is_none());

    // Validation.
    for bad in [
        json!({"ttl_seconds": 1}),
        json!({"ttl_seconds": 99_999_999}),
        json!({"node": "Bad_Name"}),
        json!({"description": "a\nb"}),
        json!({"secret_sha256": "00"}),
    ] {
        let (s, v) = call(&e.app, "POST", T, Some(bad.clone()), true).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad} -> {v}");
    }
    let (s, _) = call(&e.app, "GET", &format!("{T}/not-an-id"), None, true).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Revoke.
    let (s, _) = call(&e.app, "DELETE", &one, None, true).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&e.app, "GET", &one, None, true).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(&e.app, "DELETE", &one, None, true).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tpm_policy_can_be_read_and_changed() {
    let e = env().await;
    const T: &str = "/v1/platform/settings/tpm";
    let (s, _) = call(&e.app, "GET", T, None, false).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = call(&e.app, "PUT", T, Some(json!({"required": false})), false).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, v) = call(&e.app, "GET", T, None, true).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v, json!({"required": true}));

    let (s, v) = call(&e.app, "PUT", T, Some(json!({"required": false})), true).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v, json!({"required": false}));
    let (s, v) = call(&e.app, "GET", T, None, true).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v, json!({"required": false}));

    let (s, _) = call(
        &e.app,
        "PUT",
        T,
        Some(json!({"required": true, "extra": 1})),
        true,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (_, v) = call(&e.app, "GET", T, None, true).await;
    assert_eq!(v, json!({"required": false}));
    e.store.shutdown().await.unwrap();
}

const POOLS: &str = "/v1/platform/storagePools";
const TYPES: &str = "/v1/platform/volumeTypes";
const UID: &str = "0193a000-0000-7000-8000-000000000001";
const VOLUMES: &str = "/v1/orgs/acme/projects/web/volumes";

/// Adds a node to the store, as the controller does.
async fn add_node(store: &Store, n: &str) {
    let node =
        json!({"metadata": {"name": n, "scope": {"kind": "platform"}}, "spec": {}, "status": {}});
    store
        .put(
            torngat_store::Key::new("platform", ["nodes", n]).unwrap(),
            serde_json::to_vec(&node).unwrap(),
            torngat_store::Precondition::Absent,
        )
        .await
        .unwrap();
}

async fn storage_env() -> Env {
    let e = env().await;
    add_node(&e.store, "n1").await;
    let pool = json!({"spec": {"node": "n1", "driver": "lvm", "source": "data"}});
    let uri = format!("{POOLS}?storage_pool_id=n1-data");
    let (s, v) = call(&e.app, "POST", &uri, Some(pool), true).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let t = json!({"spec": {"pools": ["n1-data"]}});
    let uri = format!("{TYPES}?volume_type_id=fast");
    let (s, v) = call(&e.app, "POST", &uri, Some(t), true).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    e
}

/// Changes a stored object, as the controller does.
async fn edit(store: &Store, segs: &[&str], keyspace: &str, f: impl Fn(&mut Value)) {
    let key = torngat_store::Key::new(keyspace, segs.iter().copied()).unwrap();
    let cur = store.get(&key).await.unwrap().unwrap();
    let mut v: Value = serde_json::from_slice(&cur.value).unwrap();
    f(&mut v);
    store
        .put(
            key,
            serde_json::to_vec(&v).unwrap(),
            torngat_store::Precondition::Revision(cur.revision),
        )
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn storage_needs_authentication() {
    let e = storage_env().await;
    for uri in [POOLS, TYPES, VOLUMES] {
        for method in ["GET", "POST"] {
            let (s, _) = call(&e.app, method, uri, None, false).await;
            assert_eq!(s, StatusCode::UNAUTHORIZED, "{method} {uri}");
        }
    }
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn storage_pools() {
    let e = storage_env().await;
    let post = async |id: &str, spec: Value| {
        let uri = format!("{POOLS}?storage_pool_id={id}");
        call(&e.app, "POST", &uri, Some(json!({"spec": spec})), true).await
    };
    let spec = json!({"node": "n1", "driver": "lvm", "source": "data"});
    // The same name; the same storage under another name; another driver is other storage.
    assert_eq!(post("n1-data", spec.clone()).await.0, StatusCode::CONFLICT);
    assert_eq!(post("again", spec).await.0, StatusCode::CONFLICT);
    let zfs = json!({"node": "n1", "driver": "zfs", "source": "data"});
    assert_eq!(post("n1-zfs", zfs).await.0, StatusCode::OK);
    for bad in [
        json!({"node": "n2", "driver": "lvm", "source": "data"}),
        json!({"node": "n1", "driver": "lvm", "source": "../data"}),
        json!({"node": "n1", "driver": "lvm", "source": "-f"}),
        json!({"node": "n1", "driver": "tape", "source": "x"}),
        json!({"node": "n1", "driver": "lvm", "source": "x", "extra": 1}),
    ] {
        let (s, v) = post("bad", bad.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {v}");
    }

    // The platform's part cannot be set by a client.
    let uri = format!("{POOLS}?storage_pool_id=forged");
    let forged = json!({"spec": {"node": "n1", "driver": "lvm", "source": "forged"},
        "status": {"ready": true, "capacity_bytes": 1}});
    let (s, v) = call(&e.app, "POST", &uri, Some(forged), true).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["status"]["ready"], false);
    assert_eq!(v["status"]["capacity_bytes"], 0);

    let one = format!("{POOLS}/n1-data");
    let patch = |spec: Value| call(&e.app, "PATCH", &one, Some(json!({"spec": spec})), true);
    let moved = json!({"node": "n1", "driver": "lvm", "source": "other"});
    assert_eq!(patch(moved).await.0, StatusCode::BAD_REQUEST);
    let closed = json!({"node": "n1", "driver": "lvm", "source": "data", "unschedulable": true});
    let (s, v) = patch(closed).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["metadata"]["generation"], 2);

    // Fields written by a newer version do not get in the way.
    edit(&e.store, &["storagepools", "n1-data"], "platform", |v| {
        v["spec"]["later"] = json!(1);
    })
    .await;
    assert_eq!(
        call(&e.app, "GET", &one, None, true).await.0,
        StatusCode::OK
    );

    // Not deleted while it holds volumes, nor while a type has it.
    edit(&e.store, &["storagepools", "n1-data"], "platform", |v| {
        v["status"]["reservations"] = json!({UID: 5});
    })
    .await;
    let (s, v) = call(&e.app, "DELETE", &one, None, true).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"]["status"], "FAILED_PRECONDITION");
    edit(&e.store, &["storagepools", "n1-data"], "platform", |v| {
        v["status"]["reservations"] = json!({});
    })
    .await;
    let (_, v) = call(&e.app, "DELETE", &one, None, true).await;
    assert_eq!(v["error"]["message"], "n1-data is in a volume type");
    let t = format!("{TYPES}/fast");
    assert_eq!(
        call(&e.app, "DELETE", &t, None, true).await.0,
        StatusCode::OK
    );
    let stale = format!("{one}?etag=%221%22");
    assert_eq!(
        call(&e.app, "DELETE", &stale, None, true).await.0,
        StatusCode::CONFLICT
    );
    // A pool that its node may have marked waits for it.
    edit(&e.store, &["storagepools", "n1-data"], "platform", |v| {
        v["status"]["claimed"] = json!(true);
    })
    .await;
    assert_eq!(
        call(&e.app, "DELETE", &one, None, true).await.0,
        StatusCode::OK
    );
    let (_, v) = call(&e.app, "GET", &one, None, true).await;
    assert!(v["metadata"]["delete_time"].is_string());
    let b = json!({"spec": {"pools": ["n1-data"]}});
    let uri = format!("{TYPES}?volume_type_id=late");
    assert_eq!(
        call(&e.app, "POST", &uri, Some(b), true).await.0,
        StatusCode::BAD_REQUEST
    );
    edit(&e.store, &["storagepools", "n1-data"], "platform", |v| {
        v["status"]["claimed"] = json!(false);
    })
    .await;
    assert_eq!(
        call(&e.app, "DELETE", &one, None, true).await.0,
        StatusCode::OK
    );
    // The controller removes it (crates/controller/tests/storage.rs).
    let (status, v) = call(&e.app, "GET", &one, None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(v["metadata"]["delete_time"].is_string());
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn volume_types() {
    let e = storage_env().await;
    for pools in [json!([]), json!(["nope"]), json!(["n1-data", "nope"])] {
        let uri = format!("{TYPES}?volume_type_id=bad");
        let b = json!({"spec": {"pools": pools}});
        assert_eq!(
            call(&e.app, "POST", &uri, Some(b), true).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    let one = format!("{TYPES}/fast");
    let b = json!({"spec": {"pools": ["nope"]}});
    assert_eq!(
        call(&e.app, "PATCH", &one, Some(b), true).await.0,
        StatusCode::BAD_REQUEST
    );
    let uri = format!("{VOLUMES}?volume_id=v1");
    let b = json!({"spec": {"volume_type": "fast", "size_gib": 1}});
    assert_eq!(
        call(&e.app, "POST", &uri, Some(b), true).await.0,
        StatusCode::OK
    );
    let (s, v) = call(&e.app, "DELETE", &one, None, true).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"]["status"], "FAILED_PRECONDITION");
    let vol = format!("{VOLUMES}/v1");
    assert_eq!(
        call(&e.app, "DELETE", &vol, None, true).await.0,
        StatusCode::OK
    );
    assert_eq!(
        call(&e.app, "DELETE", &one, None, true).await.0,
        StatusCode::OK
    );
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn volumes() {
    let e = storage_env().await;
    let post = async |id: &str, spec: Value| {
        let uri = format!("{VOLUMES}?volume_id={id}");
        call(&e.app, "POST", &uri, Some(json!({"spec": spec})), true).await
    };
    let (s, v) = post("v1", json!({"volume_type": "fast", "size_gib": 10})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"]["phase"], "pending");
    assert_eq!(v["status"].get("pool"), None);
    for bad in [
        json!({"volume_type": "nope", "size_gib": 10}),
        json!({"volume_type": "fast", "size_gib": 0}),
        json!({"volume_type": "fast", "size_gib": 65537}),
        json!({"volume_type": "fast", "size_gib": 1, "pool": "n1-data"}),
        json!(["fast", 1, true]),
    ] {
        let (s, v) = post("bad", bad.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {v}");
    }
    let one = format!("{VOLUMES}/v1");
    let patch = |spec: Value| call(&e.app, "PATCH", &one, Some(json!({"spec": spec})), true);
    // Nothing was granted yet.
    let smaller = json!({"volume_type": "fast", "size_gib": 9});
    let (s, v) = patch(smaller.clone()).await;
    assert_eq!(s, StatusCode::OK);
    // No change: no write.
    assert_eq!(
        patch(smaller).await.1["metadata"]["etag"],
        v["metadata"]["etag"]
    );
    let other = json!({"volume_type": "slow", "size_gib": 10});
    assert_eq!(patch(other).await.0, StatusCode::BAD_REQUEST);
    let grown = json!({"volume_type": "fast", "size_gib": 11, "delete_protection": true});
    assert_eq!(patch(grown).await.0, StatusCode::OK);
    let (_, v) = call(&e.app, "DELETE", &one, None, true).await;
    assert_eq!(v["error"]["message"], "v1 is protected from deletion");
    let open = json!({"volume_type": "fast", "size_gib": 11});
    assert_eq!(patch(open).await.0, StatusCode::OK);

    // Other projects do not see it.
    let other = "/v1/orgs/acme/projects/other/volumes";
    let (_, v) = call(&e.app, "GET", other, None, true).await;
    assert_eq!(v["items"], json!([]));

    // A placed volume is deleted by the platform, and cannot change meanwhile.
    let segs = ["orgs", "acme", "projects", "web", "volumes", "v1"];
    edit(&e.store, &segs, "storage", |v| {
        v["status"] = json!({"phase": "ready", "granted_bytes": 11u64 << 30, "attached_to": UID,
            "pool": {"name": "n1-data", "uid": UID}});
    })
    .await;
    let smaller = json!({"volume_type": "fast", "size_gib": 10});
    assert_eq!(patch(smaller).await.0, StatusCode::BAD_REQUEST);
    // Not while an instance uses it.
    let (_, v) = call(&e.app, "DELETE", &one, None, true).await;
    assert_eq!(v["error"]["message"], "v1 is used by an instance");
    edit(&e.store, &segs, "storage", |v| {
        v["status"]["attached_to"] = Value::Null;
    })
    .await;
    for _ in 0..2 {
        assert_eq!(
            call(&e.app, "DELETE", &one, None, true).await.0,
            StatusCode::OK
        );
    }
    let (s, v) = call(&e.app, "GET", &one, None, true).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["status"]["phase"], "deleting");
    assert!(v["metadata"]["delete_time"].is_string());
    let grown = json!({"volume_type": "fast", "size_gib": 12});
    assert_eq!(patch(grown).await.1["error"]["message"], "being deleted");
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn volume_request_ids() {
    let e = storage_env().await;
    let rid = "0193a000-0000-7000-8000-000000000002";
    let post_size = async |id: &str, gib: u64| {
        let uri = format!("{VOLUMES}?volume_id={id}&request_id={rid}");
        let b = json!({"spec": {"volume_type": "fast", "size_gib": gib}});
        call(&e.app, "POST", &uri, Some(b), true).await
    };
    let post = async |id: &str| post_size(id, 1).await;
    let (s, first) = post("v1").await;
    assert_eq!(s, StatusCode::OK);
    let (s, again) = post("v1").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(first["metadata"]["uid"], again["metadata"]["uid"]);
    assert_eq!(post("v2").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(post_size("v1", 2).await.0, StatusCode::BAD_REQUEST);
    // A late retry does not bring a deleted volume back.
    let one = format!("{VOLUMES}/v1");
    assert_eq!(
        call(&e.app, "DELETE", &one, None, true).await.0,
        StatusCode::OK
    );
    assert_eq!(post("v1").await.0, StatusCode::NOT_FOUND);
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_attempts_share_a_request_id() {
    let e = storage_env().await;
    for i in 0..30u32 {
        let uri =
            format!("{VOLUMES}?volume_id=v{i}&request_id=0193a000-0000-7000-8000-0000000001{i:02}");
        let b = json!({"spec": {"volume_type": "fast", "size_gib": 1}});
        let attempts: Vec<_> = (0..4)
            .map(|_| {
                let (app, uri, b) = (e.app.clone(), uri.clone(), b.clone());
                tokio::spawn(async move { call(&app, "POST", &uri, Some(b), true).await })
            })
            .collect();
        let mut uids = std::collections::BTreeSet::new();
        for a in attempts {
            let (s, v) = a.await.unwrap();
            assert_eq!(s, StatusCode::OK, "{v}");
            uids.insert(v["metadata"]["uid"].to_string());
        }
        assert_eq!(uids.len(), 1);
    }
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_id_waits_for_a_name_in_use() {
    let e = storage_env().await;
    let b = json!({"spec": {"volume_type": "fast", "size_gib": 1}});
    let plain = format!("{VOLUMES}?volume_id=v1");
    let with_id = format!("{plain}&request_id=0193a000-0000-7000-8000-000000000003");
    let one = format!("{VOLUMES}/v1");
    let post = async |uri: &str| call(&e.app, "POST", uri, Some(b.clone()), true).await;
    assert_eq!(post(&plain).await.0, StatusCode::OK);
    let (s, v) = post(&with_id).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(v["error"]["status"], "ALREADY_EXISTS");
    assert_eq!(
        call(&e.app, "DELETE", &one, None, true).await.0,
        StatusCode::OK
    );
    assert_eq!(post(&with_id).await.0, StatusCode::OK);

    // As after a crash between creating the volume and recording it.
    let segs = [
        "volumerequests",
        "orgs",
        "acme",
        "projects",
        "web",
        "0193a000-0000-7000-8000-000000000003",
    ];
    edit(&e.store, &segs, "ops", |v| v["created"] = Value::Null).await;
    assert_eq!(post(&with_id).await.0, StatusCode::OK);
    assert_eq!(
        call(&e.app, "DELETE", &one, None, true).await.0,
        StatusCode::OK
    );
    assert_eq!(post(&with_id).await.0, StatusCode::NOT_FOUND);
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn updates_survive_status_changes() {
    let e = storage_env().await;
    let uri = format!("{VOLUMES}?volume_id=v1");
    let b = json!({"spec": {"volume_type": "fast", "size_gib": 1}});
    assert_eq!(
        call(&e.app, "POST", &uri, Some(b), true).await.0,
        StatusCode::OK
    );
    let key = torngat_store::Key::new(
        "storage",
        ["orgs", "acme", "projects", "web", "volumes", "v1"],
    )
    .unwrap();
    let store = e.store.clone();
    let platform = tokio::spawn(async move {
        for i in 0..200 {
            let cur = store.get(&key).await.unwrap().unwrap();
            let mut v: Value = serde_json::from_slice(&cur.value).unwrap();
            v["status"]["message"] = json!(format!("{i}"));
            let _ = store
                .put(
                    key.clone(),
                    serde_json::to_vec(&v).unwrap(),
                    torngat_store::Precondition::Revision(cur.revision),
                )
                .await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });
    let one = format!("{VOLUMES}/v1");
    for gib in 2..40 {
        let b = json!({"spec": {"volume_type": "fast", "size_gib": gib}});
        let (s, v) = call(&e.app, "PATCH", &one, Some(b), true).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["spec"]["size_gib"], gib);
    }
    platform.await.unwrap();
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn instance_disks() {
    let e = storage_env().await;
    let post = async |id: &str, spec: Value| {
        let uri = format!("{BASE}?instance_id={id}");
        call(&e.app, "POST", &uri, Some(json!({ "spec": spec })), true).await
    };
    let boot = |t: &str| json!({"vcpus": 1, "memory_mib": 512, "boot_disk": {"volume_type": t, "size_gib": 10}});
    // An unknown type, a name too long for "<name>-boot", a disk twice.
    let (s, v) = post("a", boot("nope")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("volume type")
    );
    let (s, _) = post(&"a".repeat(60), boot("fast")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let twice = json!({"vcpus": 1, "memory_mib": 512, "disks": [{"volume": "d"}, {"volume": "d"}]});
    assert_eq!(post("a", twice).await.0, StatusCode::BAD_REQUEST);
    let (s, v) = post("web", boot("fast")).await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // On a node and running: disks do not change, the boot disk only grows.
    edit(
        &e.store,
        &["orgs", "acme", "projects", "web", "instances", "web"],
        "compute",
        |v| {
            v["status"]["node"] = json!("n1");
            v["status"]["phase"] = json!("running");
        },
    )
    .await;
    let one = format!("{BASE}/web");
    let patch =
        async |spec: Value| call(&e.app, "PATCH", &one, Some(json!({ "spec": spec })), true).await;
    // Added while it runs; removed only while stopped.
    let mut with_disk = boot("fast");
    with_disk["disks"] = json!([{"volume": "data"}]);
    let (s, v) = patch(with_disk.clone()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = patch(boot("fast")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["error"]["status"], "FAILED_PRECONDITION");
    let mut smaller = boot("fast");
    smaller["boot_disk"]["size_gib"] = json!(5);
    assert_eq!(patch(smaller).await.0, StatusCode::BAD_REQUEST);
    let mut bigger = with_disk.clone();
    bigger["boot_disk"]["size_gib"] = json!(20);
    bigger["boot_disk"]["keep"] = json!(true);
    let (s, v) = patch(bigger.clone()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["spec"]["boot_disk"]["keep"], true);

    // Stopped: they can.
    let mut stopped = bigger.clone();
    stopped["power_state"] = json!("stopped");
    assert_eq!(patch(stopped.clone()).await.0, StatusCode::OK);
    edit(
        &e.store,
        &["orgs", "acme", "projects", "web", "instances", "web"],
        "compute",
        |v| v["status"]["phase"] = json!("stopped"),
    )
    .await;
    stopped["disks"] = json!([]);
    let (s, v) = patch(stopped).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn images() {
    let e = storage_env().await;
    let sha = "a".repeat(64);
    let spec = |url: &str| json!({"source": {"url": url, "checksum": {"sha256": sha}}, "volume_type": "fast"});
    let platform = "/v1/platform/images";
    let project = "/v1/orgs/acme/projects/web/images";
    for base in [platform, project] {
        let post = async |id: &str, spec: Value| {
            let uri = format!("{base}?image_id={id}");
            call(&e.app, "POST", &uri, Some(json!({"spec": spec})), true).await
        };
        let (s, v) = post("debian", spec("https://cloud.example/debian.qcow2")).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["status"]["phase"], "pending");
        let mut no_type = spec("https://h/x");
        no_type["volume_type"] = json!("nope");
        let mut extra = spec("https://h/x");
        extra["node"] = json!("n1");
        for bad in [
            spec("http://cloud.example/x"),
            spec("https://user:pw@cloud.example/x"),
            json!({"source": {"url": "https://h/x", "checksum": {"md5": sha}}, "volume_type": "fast"}),
            json!({"source": {"url": "https://h/x", "checksum": {"sha256": "ab"}}, "volume_type": "fast"}),
            no_type,
            extra,
        ] {
            let (s, v) = post("bad", bad.clone()).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {v}");
        }
        // Room for "<name>-staging".
        let (s, _) = post(&"a".repeat(56), spec("https://h/x")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(
            post(&"a".repeat(55), spec("https://h/x")).await.0,
            StatusCode::OK
        );

        // Only the description changes.
        let one = format!("{base}/debian");
        let patch = |spec: Value| call(&e.app, "PATCH", &one, Some(json!({"spec": spec})), true);
        let mut described = spec("https://cloud.example/debian.qcow2");
        described["description"] = json!("Debian 13");
        assert_eq!(patch(described).await.0, StatusCode::OK);
        assert_eq!(patch(spec("https://h/y")).await.0, StatusCode::BAD_REQUEST);
        let (_, v) = call(&e.app, "GET", base, None, true).await;
        assert_eq!(v["items"].as_array().unwrap().len(), 2);
    }

    // Projects see only theirs.
    let (_, v) = call(
        &e.app,
        "GET",
        "/v1/orgs/acme/projects/other/images",
        None,
        true,
    )
    .await;
    assert_eq!(v["items"], json!([]));

    // A type used by an image stays.
    let (_, v) = call(&e.app, "DELETE", &format!("{TYPES}/fast"), None, true).await;
    assert_eq!(v["error"]["message"], "fast is used by images");

    // Without a node yet, an image goes at once; with one, the platform deletes its volumes first.
    let one = format!("{project}/debian");
    assert_eq!(
        call(&e.app, "DELETE", &one, None, true).await.0,
        StatusCode::OK
    );
    assert_eq!(
        call(&e.app, "GET", &one, None, true).await.0,
        StatusCode::NOT_FOUND
    );
    let one = format!("{platform}/debian");
    edit(&e.store, &["images", "debian"], "images", |v| {
        v["status"] = json!({"phase": "importing", "node": "n1"});
    })
    .await;
    assert_eq!(
        call(&e.app, "DELETE", &one, None, true).await.0,
        StatusCode::OK
    );
    let (_, v) = call(&e.app, "GET", &one, None, true).await;
    assert_eq!(v["status"]["phase"], "deleting");
    assert!(v["metadata"]["delete_time"].is_string());

    // An image's volume is changed only through its image.
    let uri = format!("{VOLUMES}?volume_id=web-image");
    let b = json!({"spec": {"volume_type": "fast", "size_gib": 1}});
    assert_eq!(
        call(&e.app, "POST", &uri, Some(b), true).await.0,
        StatusCode::OK
    );
    let segs = ["orgs", "acme", "projects", "web", "volumes", "web-image"];
    edit(&e.store, &segs, "storage", |v| {
        v["status"]["owner"] = json!({"image": UID});
    })
    .await;
    let vol = format!("{VOLUMES}/web-image");
    let b = json!({"spec": {"volume_type": "fast", "size_gib": 2}});
    let (s, v) = call(&e.app, "PATCH", &vol, Some(b), true).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(
        v["error"]["message"],
        "web-image belongs to an image: delete the image instead"
    );
    let (_, v) = call(&e.app, "DELETE", &vol, None, true).await;
    assert_eq!(
        v["error"]["message"],
        "web-image belongs to an image: delete the image instead"
    );
    e.store.shutdown().await.unwrap();
}

/// PUTs raw bytes.
async fn put_bytes(app: &Router, uri: &str, data: Vec<u8>) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("PUT")
        .uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("content-type", "application/octet-stream")
        .body(Body::from(data))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn image_uploads() {
    let e = storage_env().await;
    let disk: Vec<u8> = (0..1_000_000u32).map(|i| (i % 249) as u8).collect();
    let sha = torngat_pki::hex_sha256(&disk);
    let base = "/v1/orgs/acme/projects/web/images";
    let spec = json!({"spec": {"source": {"checksum": {"sha256": sha}}, "volume_type": "fast"}});
    let (s, v) = call(
        &e.app,
        "POST",
        &format!("{base}?image_id=up"),
        Some(spec),
        true,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["spec"]["source"].get("url").is_none());
    let part = |n: u32| format!("{base}/up/upload/parts/{n}");

    // Larger than the body limit of other requests; any order; one sent again.
    assert_eq!(
        put_bytes(&e.app, &part(2), disk[600_000..].to_vec())
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        put_bytes(&e.app, &part(1), b"wrong".to_vec()).await.0,
        StatusCode::OK
    );
    let (s, v) = put_bytes(&e.app, &part(1), disk[..600_000].to_vec()).await;
    assert_eq!((s, &v["bytes"]), (StatusCode::OK, &json!(600_000)));
    assert_eq!(
        put_bytes(&e.app, &part(0), vec![1]).await.0,
        StatusCode::BAD_REQUEST
    );
    let (_, v) = call(&e.app, "GET", &format!("{base}/up/upload"), None, true).await;
    assert_eq!(
        v["parts"],
        json!([{"part": 1, "bytes": 600_000}, {"part": 2, "bytes": 400_000}])
    );

    let finish = format!("{base}/up/upload:finish");
    let (s, v) = call(&e.app, "POST", &finish, None, true).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"]["uploaded"], true);
    assert_eq!(v["status"]["download_bytes"], 1_000_000);
    // Once only.
    assert_eq!(
        put_bytes(&e.app, &part(3), vec![1]).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(&e.app, "POST", &finish, None, true).await.0,
        StatusCode::BAD_REQUEST
    );

    // A wrong checksum is refused at the finish, and the parts can be sent again.
    let spec = json!({"spec": {"source": {"checksum": {"sha256": "0".repeat(64)}}, "volume_type": "fast"}});
    call(
        &e.app,
        "POST",
        &format!("{base}?image_id=bad"),
        Some(spec),
        true,
    )
    .await;
    put_bytes(&e.app, &format!("{base}/bad/upload/parts/1"), disk.clone()).await;
    let (s, v) = call(
        &e.app,
        "POST",
        &format!("{base}/bad/upload:finish"),
        None,
        true,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"]["message"], "the checksum does not match");

    // An image with a URL takes no upload.
    let spec = json!({"spec": {"source": {"url": "https://h/x", "checksum": {"sha256": sha}}, "volume_type": "fast"}});
    call(
        &e.app,
        "POST",
        &format!("{base}?image_id=url"),
        Some(spec),
        true,
    )
    .await;
    let (s, v) = put_bytes(&e.app, &format!("{base}/url/upload/parts/1"), vec![1]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"]["message"], "url is downloaded from its URL");
    // Nor one that is not there.
    let (s, _) = put_bytes(&e.app, &format!("{base}/nope/upload/parts/1"), vec![1]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn networks() {
    let e = storage_env().await;
    let post = async |uri: String, spec: Value| {
        call(&e.app, "POST", &uri, Some(json!({"spec": spec})), true).await
    };
    // Host networks.
    let host = json!({"node": "n1", "uplink": "eno1", "vlan": 100, "roles": ["provider"], "physnet": "physnet1"});
    let (s, v) = post(
        "/v1/platform/hostNetworks?host_network_id=n1-prov".into(),
        host.clone(),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["spec"]["mtu"], 1500);
    let (s, _) = post(
        "/v1/platform/hostNetworks?host_network_id=again".into(),
        host.clone(),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    for bad in [
        json!({"node": "nope", "uplink": "eno1", "roles": ["platform"]}),
        json!({"node": "n1", "uplink": "eno1;x", "roles": ["platform"]}),
        json!({"node": "n1", "uplink": "eno2", "roles": ["provider"]}),
        json!({"node": "n1", "uplink": "eno2", "roles": []}),
    ] {
        let (s, v) = post(
            "/v1/platform/hostNetworks?host_network_id=bad".into(),
            bad.clone(),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {v}");
    }
    // Provider networks.
    let pool = json!({"scope": "external", "cidr": "203.0.113.0/24", "gateway": "203.0.113.1",
                      "first": "203.0.113.10", "last": "203.0.113.20"});
    let (s, v) = post(
        "/v1/platform/providerNetworks?provider_network_id=public".into(),
        json!({"physnet": "physnet1", "pool": pool, "tenants": false}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let mut bad_pool = pool.clone();
    bad_pool["gateway"] = json!("203.0.113.15");
    let (s, _) = post(
        "/v1/platform/providerNetworks?provider_network_id=bad".into(),
        json!({"physnet": "physnet1", "pool": bad_pool}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Networks of a project: a provider network only once the operator opens it.
    let nets = "/v1/orgs/acme/projects/web/networks";
    let wan = json!({"provider": {"network": "public"}});
    let (s, _) = post(format!("{nets}?network_id=wan"), wan.clone()).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let one = "/v1/platform/providerNetworks/public";
    let (_, cur) = call(&e.app, "GET", one, None, true).await;
    let mut spec = cur["spec"].clone();
    spec["tenants"] = json!(true);
    assert_eq!(
        call(&e.app, "PATCH", one, Some(json!({"spec": spec})), true)
            .await
            .0,
        StatusCode::OK
    );
    spec["pool"]["last"] = json!("203.0.113.30");
    assert_eq!(
        call(&e.app, "PATCH", one, Some(json!({"spec": spec})), true)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(format!("{nets}?network_id=wan"), wan).await.0,
        StatusCode::OK
    );
    let (s, v) = post(
        format!("{nets}?network_id=lan"),
        json!({"private": {"cidr": "10.0.0.0/24"}}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    for bad in [
        json!({"private": {"cidr": "10.0.0.1/24"}}),
        json!({"private": {"cidr": "10.0.0.0/8"}}),
    ] {
        assert_eq!(
            post(format!("{nets}?network_id=bad"), bad).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    // Not while in use: by a project's network, or an instance.
    let (_, v) = call(&e.app, "DELETE", one, None, true).await;
    assert_eq!(
        v["error"]["message"],
        "public is used by networks of projects"
    );
    let inst = json!({"spec": {"vcpus": 1, "memory_mib": 64, "interfaces": [{"network": "lan"}]}});
    call(
        &e.app,
        "POST",
        &format!("{BASE}?instance_id=vm"),
        Some(inst),
        true,
    )
    .await;
    let (_, v) = call(&e.app, "DELETE", &format!("{nets}/lan"), None, true).await;
    assert_eq!(v["error"]["message"], "lan is used by instances");
    assert_eq!(
        call(&e.app, "DELETE", &format!("{nets}/wan"), None, true)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&e.app, "DELETE", one, None, true).await.0,
        StatusCode::OK
    );
    e.store.shutdown().await.unwrap();
}
