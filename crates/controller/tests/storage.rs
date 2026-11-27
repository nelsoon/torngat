//! Storage over the control protocol: pools, placement, growth, deletion, volume keys.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{Env, env, env_with, n};
use serde::Serialize;
use serde_json::json;
use tonic::Code;
use tonic::transport::Channel;
use torngat_agent::{AgentConfig, NodeKey};
use torngat_api::storage::{StoragePool, Volume, VolumePhase};
use torngat_api::{Name, Scope};
use torngat_controller::storage::{PlaceError, place_volume};
use torngat_controller::volume_keys::{self, PlatformKeyError, VolumeKeyRecord};
use torngat_controller::{Controller, destroy_volume_keys_once, keys};
use torngat_proto::v1::control_client::ControlClient;
use torngat_proto::v1::{AssignmentsRequest, PoolReport, VolumeKeyRequest, VolumeReport};
use torngat_store::{Key, Precondition, Store};
use uuid::Uuid;

type Client = ControlClient<Channel>;

fn scope() -> Scope {
    Scope::Project {
        org: n("acme"),
        project: n("web"),
    }
}

async fn put(store: &Store, key: Key, v: &impl Serialize) {
    store
        .put(key, serde_json::to_vec(v).unwrap(), Precondition::None)
        .await
        .unwrap();
}

fn object(
    name: &str,
    scope: &Scope,
    spec: serde_json::Value,
    status: serde_json::Value,
) -> serde_json::Value {
    json!({
        "metadata": {"name": name, "scope": scope, "uid": Uuid::now_v7(), "generation": 1},
        "spec": spec,
        "status": status,
    })
}

/// An enrolled and registered node's credentials.
async fn node_cfg(e: &Env, name: &str, phase: &str) -> AgentConfig {
    let issued = e.ca.issue_node(&n(name)).unwrap();
    torngat_controller::identity::enroll(
        &e.store,
        &n(name),
        &issued.identity(torngat_pki::KeyStorage::File).unwrap(),
    )
    .await
    .unwrap();
    set_phase(e, name, phase).await;
    AgentConfig {
        controller_url: format!("https://{}", e.control),
        controller_name: torngat_pki::CONTROLLER_NAME.into(),
        ca_pem: e.ca.cert_pem().as_bytes().to_vec(),
        cert_pem: issued.chain_pem.into_bytes(),
        key: NodeKey::File(issued.key_pem.unwrap().into_bytes()),
    }
}

/// An enrolled and registered node, and its connection.
async fn node(e: &Env, name: &str, phase: &str) -> Client {
    torngat_agent::connect(&node_cfg(e, name, phase).await)
        .await
        .unwrap()
}

async fn set_phase(e: &Env, name: &str, phase: &str) {
    let o = object(
        name,
        &Scope::Platform,
        json!({"roles": ["compute"]}),
        json!({"phase": phase}),
    );
    put(&e.store, keys::node(&n(name)).unwrap(), &o).await;
}

async fn pool(e: &Env, name: &str, node: &str) -> StoragePool {
    let o = object(
        name,
        &Scope::Platform,
        json!({"node": node, "driver": "lvm", "source": "data"}),
        json!({}),
    );
    put(&e.store, keys::storage_pool(&n(name)).unwrap(), &o).await;
    serde_json::from_value(o).unwrap()
}

async fn save(e: &Env, scope: &Scope, v: &Volume) {
    put(&e.store, keys::volume(scope, &v.metadata.name).unwrap(), v).await;
}

/// A volume that has space in the pool.
async fn volume(e: &Env, scope: &Scope, name: &str, pool: &StoragePool) -> Volume {
    let v = object(
        name,
        scope,
        json!({"volume_type": "fast", "size_gib": 1}),
        json!({
            "phase": "placed",
            "pool": {"name": pool.metadata.name, "uid": pool.metadata.uid},
            "attached_to": Uuid::now_v7(),
        }),
    );
    let v: Volume = serde_json::from_value(v).unwrap();
    save(e, scope, &v).await;
    v
}

async fn ask(c: &mut Client, project: &str, name: &str, uid: Uuid) -> Result<Vec<u8>, Code> {
    c.get_volume_key(VolumeKeyRequest {
        org: "acme".into(),
        project: project.into(),
        name: name.into(),
        uid: uid.to_string(),
    })
    .await
    .map(|r| r.into_inner().key)
    .map_err(|s| s.code())
}

async fn key(c: &mut Client, v: &Volume) -> Result<Vec<u8>, Code> {
    ask(c, "web", v.metadata.name.as_str(), v.metadata.uid).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_node_that_has_the_volume_gets_its_key() {
    // States are set by hand: no background passes.
    let e = env_with(Vec::new(), false, false).await;
    let mut n1 = node(&e, "n1", "active").await;
    let mut n2 = node(&e, "n2", "active").await;
    let p = pool(&e, "n1-data", "n1").await;
    let v = volume(&e, &scope(), "a", &p).await;
    let w = volume(&e, &scope(), "b", &p).await;

    // Two first calls at once get the same key.
    let mut other = n1.clone();
    let (a, b) = tokio::join!(key(&mut n1, &v), key(&mut other, &v));
    let a = a.unwrap();
    assert_eq!(a.len(), 32);
    assert_eq!(Ok(&a), b.as_ref());
    assert_eq!(key(&mut n1, &v).await.as_ref(), Ok(&a));
    assert_ne!(key(&mut n1, &w).await.unwrap(), a);

    // Another node, a volume that does not exist, and one of another project: the same answer.
    assert_eq!(key(&mut n2, &v).await, Err(Code::PermissionDenied));
    let uid = v.metadata.uid;
    for (project, name, uid) in [
        ("web", "nope", uid),
        ("web", "a", Uuid::now_v7()),
        ("web", "a", w.metadata.uid),
        ("other", "a", uid),
    ] {
        assert_eq!(
            ask(&mut n1, project, name, uid).await,
            Err(Code::PermissionDenied)
        );
    }
    assert_eq!(
        ask(&mut n1, "../x", "a", uid).await,
        Err(Code::InvalidArgument)
    );

    // Nothing in the store is the key itself.
    let hex = torngat_pki::hex(&a);
    for (_, row) in e.store.local_dump().unwrap() {
        let text = String::from_utf8_lossy(&row.value).into_owned();
        assert!(!text.contains(&hex));
        assert!(!row.value.windows(32).any(|x| x == a));
    }

    // A pool made anew under the same name is not the volume's pool.
    pool(&e, "n1-data", "n1").await;
    assert_eq!(key(&mut n1, &v).await, Err(Code::PermissionDenied));

    // A revoked node gets nothing, on an open connection.
    let p = pool(&e, "n2-data", "n2").await;
    let x = volume(&e, &scope(), "c", &p).await;
    key(&mut n2, &x).await.unwrap();
    e.store
        .delete(keys::node_identity(&n("n2")).unwrap(), Precondition::None)
        .await
        .unwrap();
    assert_eq!(key(&mut n2, &x).await, Err(Code::PermissionDenied));
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn states() {
    // States are set by hand: no background passes.
    let e = env_with(Vec::new(), false, false).await;
    let mut n1 = node(&e, "n1", "active").await;
    let p = pool(&e, "n1-data", "n1").await;
    let mut v = volume(&e, &scope(), "a", &p).await;
    let no = Err(Code::FailedPrecondition);

    for phase in [
        VolumePhase::Pending,
        VolumePhase::Placing,
        VolumePhase::Deleting,
        VolumePhase::Failed,
    ] {
        v.status.phase = phase;
        save(&e, &scope(), &v).await;
        assert_eq!(key(&mut n1, &v).await, no, "{phase:?}");
    }
    v.status.phase = VolumePhase::Ready;

    // With data on it but without a key record, another key is never made.
    v.status.formatted = true;
    v.status.attached_to = Some(Uuid::now_v7());
    save(&e, &scope(), &v).await;
    assert_eq!(key(&mut n1, &v).await, Err(Code::Internal));

    // Only while an instance uses it, also the first time; the node reports when it formatted it.
    v.status.formatted = false;
    v.status.attached_to = None;
    save(&e, &scope(), &v).await;
    assert_eq!(key(&mut n1, &v).await, no);
    v.status.attached_to = Some(Uuid::now_v7());
    save(&e, &scope(), &v).await;
    let k = key(&mut n1, &v).await;
    assert!(k.is_ok());
    let stored = |e: &Env| {
        let at = keys::volume(&scope(), &n("a")).unwrap();
        let store = e.store.clone();
        async move {
            let v = store.get(&at).await.unwrap().unwrap();
            serde_json::from_slice::<Volume>(&v.value).unwrap()
        }
    };
    assert!(!stored(&e).await.status.formatted);
    v.status.formatted = true;
    save(&e, &scope(), &v).await;
    assert_eq!(key(&mut n1, &v).await, k);
    v.status.attached_to = None;
    save(&e, &scope(), &v).await;
    assert_eq!(key(&mut n1, &v).await, no);
    v.status.attached_to = Some(Uuid::now_v7());
    save(&e, &scope(), &v).await;

    for (phase, ok) in [
        ("draining", true),
        ("maintenance", true),
        ("decommissioned", false),
        ("failed", false),
        ("joining", false),
        ("active", true),
    ] {
        set_phase(&e, "n1", phase).await;
        assert_eq!(key(&mut n1, &v).await.is_ok(), ok, "{phase}");
    }

    v.metadata.delete_time = Some(time::OffsetDateTime::now_utc());
    save(&e, &scope(), &v).await;
    assert_eq!(key(&mut n1, &v).await, no);
    v.metadata.delete_time = None;
    save(&e, &scope(), &v).await;

    // The project key is never replaced either.
    e.store
        .delete(keys::project_key(&scope()).unwrap(), Precondition::None)
        .await
        .unwrap();
    assert_eq!(key(&mut n1, &v).await, Err(Code::Internal));
    let w = volume(&e, &scope(), "b", &p).await;
    assert!(key(&mut n1, &w).await.is_ok());
    assert_eq!(key(&mut n1, &v).await, Err(Code::Internal));
    e.store.shutdown().await.unwrap();
}

async fn record(e: &Env, v: &Volume) -> VolumeKeyRecord {
    let at = keys::volume_key(v.metadata.uid).unwrap();
    serde_json::from_slice(&e.store.get(&at).await.unwrap().unwrap().value).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keys_are_destroyed_with_their_volumes() {
    // States are set by hand: no background passes.
    let e = env_with(Vec::new(), false, false).await;
    let mut n1 = node(&e, "n1", "active").await;
    let p = pool(&e, "n1-data", "n1").await;
    let mut kept = volume(&e, &scope(), "kept", &p).await;
    let gone = volume(&e, &scope(), "gone", &p).await;
    let again = volume(&e, &scope(), "again", &p).await;
    for v in [&kept, &gone, &again] {
        key(&mut n1, v).await.unwrap();
    }
    // Still being deleted: kept.
    kept.metadata.delete_time = Some(time::OffsetDateTime::now_utc());
    kept.status.phase = VolumePhase::Deleting;
    save(&e, &scope(), &kept).await;
    let name: &Name = &gone.metadata.name;
    e.store
        .delete(keys::volume(&scope(), name).unwrap(), Precondition::None)
        .await
        .unwrap();
    // Another volume under the same name.
    let new = volume(&e, &scope(), "again", &p).await;
    key(&mut n1, &new).await.unwrap();

    // The controller's own pass may come first.
    destroy_volume_keys_once(&e.store).await.unwrap();
    assert_eq!(destroy_volume_keys_once(&e.store).await.unwrap(), 0);
    assert!(record(&e, &kept).await.wrapped.is_some());
    assert!(record(&e, &new).await.wrapped.is_some());
    assert!(record(&e, &gone).await.wrapped.is_none());
    assert!(record(&e, &again).await.wrapped.is_none());

    // The uid comes back: no key.
    save(&e, &scope(), &gone).await;
    e.store
        .delete(keys::project_key(&scope()).unwrap(), Precondition::None)
        .await
        .unwrap();
    assert_eq!(key(&mut n1, &gone).await, Err(Code::FailedPrecondition));
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_platform_key_is_never_replaced() {
    let e = env(Vec::new(), false).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("platform.key");
    let load = || volume_keys::load_platform_key(&e.store, &path);
    let id = load().await.unwrap().id().to_owned();
    assert_eq!(load().await.unwrap().id(), id);

    // A crash before the record was written.
    e.store
        .delete(keys::platform_key().unwrap(), Precondition::None)
        .await
        .unwrap();
    assert_eq!(load().await.unwrap().id(), id);

    // Other keys in the store, but no record: neither a new key nor the file is trusted.
    put(&e.store, keys::project_key(&scope()).unwrap(), &json!({})).await;
    e.store
        .delete(keys::platform_key().unwrap(), Precondition::None)
        .await
        .unwrap();
    assert!(matches!(load().await, Err(PlatformKeyError::NoRecord)));
    e.store
        .delete(keys::project_key(&scope()).unwrap(), Precondition::None)
        .await
        .unwrap();
    assert_eq!(load().await.unwrap().id(), id);

    let aside = dir.path().join("aside");
    std::fs::rename(&path, &aside).unwrap();
    assert!(matches!(load().await, Err(PlatformKeyError::Missing(_))));
    assert!(!path.exists());
    torngat_keys::PlatformKey::generate()
        .unwrap()
        .save(&path)
        .unwrap();
    assert!(matches!(load().await, Err(PlatformKeyError::Wrong(_))));
    std::fs::rename(&aside, &path).unwrap();
    assert_eq!(load().await.unwrap().id(), id);
    e.store.shutdown().await.unwrap();
}

const GIB: u64 = 1 << 30;
const HEADER: u64 = torngat_api::storage::LUKS_HEADER_BYTES;

async fn read<T: serde::de::DeserializeOwned>(e: &Env, key: Key) -> Option<T> {
    let v = e.store.get(&key).await.unwrap()?;
    Some(serde_json::from_slice(&v.value).unwrap())
}

async fn pool_now(e: &Env, name: &str) -> Option<StoragePool> {
    read(e, keys::storage_pool(&n(name)).unwrap()).await
}

async fn volume_now(e: &Env, name: &str) -> Option<Volume> {
    read(e, keys::volume(&scope(), &n(name)).unwrap()).await
}

/// Until `f` holds; the controller's passes run every 100 ms.
async fn until<F: Future<Output = bool>>(what: &str, mut f: impl FnMut() -> F) {
    // The agent also retries every 10 s.
    let end = std::time::Instant::now() + std::time::Duration::from_secs(25);
    while !f().await {
        assert!(std::time::Instant::now() < end, "never: {what}");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

fn report(name: &str, uid: Uuid, capacity: u64) -> PoolReport {
    PoolReport {
        name: name.into(),
        uid: uid.to_string(),
        ready: true,
        capacity_bytes: capacity,
        allocation_unit_bytes: 4 << 20,
        snapshots: false,
        checksums: true,
        message: String::new(),
        released: false,
    }
}

/// A pool that its node reported as ready.
async fn ready_pool(e: &Env, c: &mut Client, name: &str, node: &str, capacity: u64) -> StoragePool {
    let p = pool(e, name, node).await;
    until("claimed", || async {
        pool_now(e, name).await.unwrap().status.claimed
    })
    .await;
    c.report_pool(report(name, p.metadata.uid, capacity))
        .await
        .unwrap();
    pool_now(e, name).await.unwrap()
}

async fn volume_type(e: &Env, name: &str, pools: &[&str]) {
    let o = object(name, &Scope::Platform, json!({"pools": pools}), json!(null));
    put(&e.store, keys::volume_type(&n(name)).unwrap(), &o).await;
}

async fn pending(e: &Env, name: &str, gib: u64) -> Volume {
    let o = object(
        name,
        &scope(),
        json!({"volume_type": "fast", "size_gib": gib}),
        json!({}),
    );
    let v: Volume = serde_json::from_value(o).unwrap();
    save(e, &scope(), &v).await;
    v
}

fn ctl(e: &Env) -> Controller {
    Controller::new(
        e.store.clone(),
        std::sync::Arc::new(torngat_keys::PlatformKey::generate().unwrap()),
    )
}

async fn place(e: &Env, v: &Volume, node: Option<&str>) -> Result<Volume, PlaceError> {
    let node = node.map(n);
    place_volume(
        &ctl(e),
        &scope(),
        &v.metadata.name,
        v.metadata.uid,
        node.as_ref(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pools_are_claimed_reported_and_released() {
    let e = env(Vec::new(), false).await;
    let mut n1 = node(&e, "n1", "active").await;
    let mut n2 = node(&e, "n2", "active").await;
    let p = pool(&e, "data", "n1").await;
    let uid = p.metadata.uid;
    until("claimed", || async {
        pool_now(&e, "data").await.unwrap().status.claimed
    })
    .await;

    // Only its node sees it and reports on it, for this pool only.
    let mut stream = n1
        .assignments(AssignmentsRequest {})
        .await
        .unwrap()
        .into_inner();
    let set = stream.message().await.unwrap().unwrap();
    assert_eq!(set.pools_json.len(), 1);
    // One stream per node: a newer one ends it.
    let mut newer = n1
        .assignments(AssignmentsRequest {})
        .await
        .unwrap()
        .into_inner();
    newer.message().await.unwrap().unwrap();
    let ended = tokio::time::timeout(std::time::Duration::from_secs(5), stream.message())
        .await
        .unwrap();
    assert_eq!(ended.unwrap_err().code(), Code::Aborted);
    let mut s2 = n2
        .assignments(AssignmentsRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(s2.message().await.unwrap().unwrap().pools_json.is_empty());
    let code = |r: Result<tonic::Response<_>, tonic::Status>| r.map(|_| ()).map_err(|s| s.code());
    assert_eq!(
        code(n2.report_pool(report("data", uid, GIB)).await),
        Err(Code::PermissionDenied)
    );
    let other = report("data", Uuid::now_v7(), GIB);
    assert_eq!(
        code(n1.report_pool(other).await),
        Err(Code::PermissionDenied)
    );
    for unit in [0, 3, 2 << 30] {
        let r = PoolReport {
            allocation_unit_bytes: unit,
            ..report("data", uid, GIB)
        };
        assert_eq!(
            code(n1.report_pool(r).await),
            Err(Code::InvalidArgument),
            "{unit}"
        );
    }
    let early = PoolReport {
        released: true,
        ..report("data", uid, GIB)
    };
    assert_eq!(
        code(n1.report_pool(early.clone()).await),
        Err(Code::FailedPrecondition)
    );

    // A node never sets reservations. One held by a volume, and one by nothing.
    n1.report_pool(report("data", uid, 10 * GIB)).await.unwrap();
    let mut held = pending(&e, "held", 1).await;
    held.status.pool = Some(torngat_api::storage::PoolRef {
        name: n("data"),
        uid,
    });
    held.status.phase = VolumePhase::Placed;
    save(&e, &scope(), &held).await;
    let mut with = pool_now(&e, "data").await.unwrap();
    with.status.reservations.insert(held.metadata.uid, GIB);
    with.status.reservations.insert(Uuid::from_u128(7), 5);
    put(&e.store, keys::storage_pool(&n("data")).unwrap(), &with).await;
    n1.report_pool(report("data", uid, 10 * GIB)).await.unwrap();
    let now = pool_now(&e, "data").await.unwrap();
    assert!(now.status.ready && now.status.claimed);
    assert!(now.status.reservations.contains_key(&held.metadata.uid));
    assert_eq!(now.status.capacity_bytes, 10 * GIB);
    assert!(now.status.capabilities.checksums);
    let other_unit = PoolReport {
        allocation_unit_bytes: 8 << 20,
        ..report("data", uid, 10 * GIB)
    };
    assert_eq!(
        code(n1.report_pool(other_unit).await),
        Err(Code::FailedPrecondition)
    );
    let broken = PoolReport {
        ready: false,
        allocation_unit_bytes: 0,
        message: "volume group not found".into(),
        ..report("data", uid, 0)
    };
    n1.report_pool(broken).await.unwrap();
    assert!(!pool_now(&e, "data").await.unwrap().status.ready);
    for hidden in ["a\u{202E}b", "a\nb", "\u{200B}", "\u{061C}", "\u{E0041}"] {
        let r = PoolReport {
            message: hidden.into(),
            ..report("data", uid, GIB)
        };
        assert_eq!(
            code(n1.report_pool(r).await),
            Err(Code::InvalidArgument),
            "{hidden:?}"
        );
    }
    n1.report_pool(report("data", uid, 10 * GIB)).await.unwrap();
    // Released, as no volume names it; the volume's stays.
    until("swept", || async {
        let r = pool_now(&e, "data").await.unwrap().status.reservations;
        r.len() == 1 && r.contains_key(&held.metadata.uid)
    })
    .await;
    // Gone, its space too.
    e.store
        .delete(
            keys::volume(&scope(), &n("held")).unwrap(),
            Precondition::None,
        )
        .await
        .unwrap();
    until("swept", || async {
        pool_now(&e, "data")
            .await
            .unwrap()
            .status
            .reservations
            .is_empty()
    })
    .await;

    // Deleted: not ready any more, removed once released, but not while a type lists it.
    volume_type(&e, "fast", &["data"]).await;
    let mut deleting = pool_now(&e, "data").await.unwrap();
    deleting.metadata.delete_time = Some(time::OffsetDateTime::now_utc());
    put(&e.store, keys::storage_pool(&n("data")).unwrap(), &deleting).await;
    n1.report_pool(report("data", uid, 10 * GIB)).await.unwrap();
    assert!(!pool_now(&e, "data").await.unwrap().status.ready);
    // Not while a volume names it.
    let mut v = pending(&e, "on-it", 1).await;
    v.status.pool = Some(torngat_api::storage::PoolRef {
        name: n("data"),
        uid,
    });
    v.status.phase = VolumePhase::Deleting;
    save(&e, &scope(), &v).await;
    assert_eq!(
        code(n1.report_pool(early.clone()).await),
        Err(Code::FailedPrecondition)
    );
    e.store
        .delete(
            keys::volume(&scope(), &n("on-it")).unwrap(),
            Precondition::None,
        )
        .await
        .unwrap();
    n1.report_pool(early).await.unwrap();
    assert!(!pool_now(&e, "data").await.unwrap().status.claimed);
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert!(pool_now(&e, "data").await.is_some());
    e.store
        .delete(keys::volume_type(&n("fast")).unwrap(), Precondition::None)
        .await
        .unwrap();
    until("removed", || async { pool_now(&e, "data").await.is_none() }).await;
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_is_never_promised_twice() {
    let e = env(Vec::new(), false).await;
    let mut n1 = node(&e, "n1", "active").await;
    let mut n2 = node(&e, "n2", "active").await;
    // Room for exactly five 1 GiB volumes on p1.
    ready_pool(&e, &mut n1, "p1", "n1", 5 * (GIB + HEADER)).await;
    ready_pool(&e, &mut n2, "p2", "n2", 100 * GIB).await;
    volume_type(&e, "fast", &["p1", "p2"]).await;

    // The pool with the most room, or the one on the node asked for.
    let a = place(&e, &pending(&e, "a", 1).await, None).await.unwrap();
    assert_eq!(a.status.pool.as_ref().unwrap().name, n("p2"));
    assert_eq!(a.status.phase, VolumePhase::Placed);
    assert_eq!(a.status.granted_bytes, GIB);
    let p2 = pool_now(&e, "p2").await.unwrap();
    assert_eq!(p2.status.reservations[&a.metadata.uid], GIB + HEADER);
    assert!(matches!(
        place(&e, &a, None).await,
        Err(PlaceError::NotPending)
    ));
    let big = pending(&e, "big", 1000).await;
    assert!(matches!(
        place(&e, &big, None).await,
        Err(PlaceError::NoRoom(None))
    ));

    let many: Vec<Volume> = futures::future::join_all((0..10).map(|i| {
        let e = &e;
        async move { pending(e, &format!("v{i}"), 1).await }
    }))
    .await;
    let results = futures::future::join_all(many.iter().map(|v| {
        let e = &e;
        async move {
            loop {
                match place(e, v, Some("n1")).await {
                    Err(PlaceError::Conflict) => continue,
                    r => return r,
                }
            }
        }
    }))
    .await;
    let placed = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(placed, 5, "{results:?}");
    let p1 = pool_now(&e, "p1").await.unwrap();
    assert_eq!(p1.status.reservations.len(), 5);
    assert!(p1.status.reserved_bytes() <= p1.status.capacity_bytes);
    for (v, r) in many.iter().zip(&results) {
        let now = volume_now(&e, v.metadata.name.as_str()).await.unwrap();
        match r {
            Ok(_) => assert_eq!(now.status.phase, VolumePhase::Placed),
            Err(_) => {
                assert_eq!(now.status.phase, VolumePhase::Pending);
                assert!(now.status.pool.is_none() && now.status.granted_bytes == 0);
            }
        }
    }

    // Not on a pool being deleted, nor for a uid whose key was destroyed.
    let back = pending(&e, "back", 1).await;
    let tomb =
        json!({"scope": scope(), "name": "back", "project_key": Uuid::nil(), "wrapped": null});
    put(
        &e.store,
        keys::volume_key(back.metadata.uid).unwrap(),
        &tomb,
    )
    .await;
    assert!(matches!(
        place(&e, &back, None).await,
        Err(PlaceError::Destroyed)
    ));
    let mut p2 = pool_now(&e, "p2").await.unwrap();
    p2.metadata.delete_time = Some(time::OffsetDateTime::now_utc());
    put(&e.store, keys::storage_pool(&n("p2")).unwrap(), &p2).await;
    let late = pending(&e, "late", 1).await;
    assert!(matches!(
        place(&e, &late, None).await,
        Err(PlaceError::NoRoom(_))
    ));
    e.store.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_placement_growth_and_deletion() {
    let e = env(Vec::new(), false).await;
    let mut n1 = node(&e, "n1", "active").await;
    let mut n2 = node(&e, "n2", "active").await;
    let p = ready_pool(&e, &mut n1, "p1", "n1", 4 * (GIB + HEADER)).await;
    volume_type(&e, "fast", &["p1"]).await;
    let pool_ref = json!({"name": "p1", "uid": p.metadata.uid});

    // Placing, as after a crash: the pass reserves, or gives the pool back without room.
    let mut a = pending(&e, "a", 1).await;
    a.status.phase = VolumePhase::Placing;
    a.status.pool = serde_json::from_value(pool_ref.clone()).unwrap();
    a.status.granted_bytes = GIB;
    save(&e, &scope(), &a).await;
    until("placed", || async {
        volume_now(&e, "a").await.unwrap().status.phase == VolumePhase::Placed
    })
    .await;
    let mut b = pending(&e, "b", 10).await;
    b.status = a.status.clone();
    b.status.phase = VolumePhase::Placing;
    save(&e, &scope(), &b).await;
    until("back to pending", || async {
        let v = volume_now(&e, "b").await.unwrap();
        v.status.phase == VolumePhase::Pending && v.status.pool.is_none()
    })
    .await;

    // Growth: reserved first, then granted; too much waits.
    let mut a = volume_now(&e, "a").await.unwrap();
    a.spec.size_gib = 3;
    save(&e, &scope(), &a).await;
    until("grown", || async {
        volume_now(&e, "a").await.unwrap().status.granted_bytes == 3 * GIB
    })
    .await;
    let uid = a.metadata.uid;
    assert_eq!(
        pool_now(&e, "p1").await.unwrap().status.reservations[&uid],
        3 * GIB + HEADER
    );
    let mut a = volume_now(&e, "a").await.unwrap();
    a.spec.size_gib = 100;
    save(&e, &scope(), &a).await;
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(
        volume_now(&e, "a").await.unwrap().status.granted_bytes,
        3 * GIB
    );
    assert_eq!(
        pool_now(&e, "p1").await.unwrap().status.reservations[&uid],
        3 * GIB + HEADER
    );

    // The node reports it created: ready, and never larger than granted.
    let vr = |created, size, deleted| VolumeReport {
        org: "acme".into(),
        project: "web".into(),
        name: "a".into(),
        uid: uid.to_string(),
        created,
        size_bytes: size,
        deleted,
        message: String::new(),
        formatted: false,
        open: false,
    };
    let code = |r: Result<tonic::Response<_>, tonic::Status>| r.map(|_| ()).map_err(|s| s.code());
    assert_eq!(
        code(n2.report_volume(vr(true, GIB, false)).await),
        Err(Code::PermissionDenied)
    );
    n1.report_volume(vr(true, 50 * GIB, false)).await.unwrap();
    let now = volume_now(&e, "a").await.unwrap();
    assert_eq!(now.status.phase, VolumePhase::Ready);
    assert_eq!(now.status.size_bytes, 3 * GIB);
    assert_eq!(
        code(n1.report_volume(vr(false, 0, true)).await),
        Err(Code::FailedPrecondition)
    );

    // Deletion: once the node deleted the blocks, the space, the key and the object go.
    let mut a = now;
    a.status.attached_to = Some(Uuid::now_v7());
    save(&e, &scope(), &a).await;
    key(&mut n1, &a).await.unwrap();
    a = volume_now(&e, "a").await.unwrap();
    a.metadata.delete_time = Some(time::OffsetDateTime::now_utc());
    a.status.phase = VolumePhase::Deleting;
    save(&e, &scope(), &a).await;
    let set = n1
        .assignments(AssignmentsRequest {})
        .await
        .unwrap()
        .into_inner()
        .message()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(set.volumes_json.len(), 1);
    n1.report_volume(vr(false, 0, true)).await.unwrap();
    assert!(volume_now(&e, "a").await.is_none());
    assert!(
        !pool_now(&e, "p1")
            .await
            .unwrap()
            .status
            .reservations
            .contains_key(&uid)
    );
    assert!(record(&e, &a).await.wrapped.is_none());
    // Repeated: nothing left to do, and the name may be used again.
    assert_eq!(
        code(n1.report_volume(vr(false, 0, true)).await),
        Err(Code::PermissionDenied)
    );
    e.store.shutdown().await.unwrap();
}

/// Changes an object with compare-and-swap.
async fn change<T: Serialize + serde::de::DeserializeOwned>(e: &Env, key: Key, f: impl Fn(&mut T)) {
    loop {
        let v = e.store.get(&key).await.unwrap().unwrap();
        let mut o: T = serde_json::from_slice(&v.value).unwrap();
        f(&mut o);
        let r = e
            .store
            .put(
                key.clone(),
                serde_json::to_vec(&o).unwrap(),
                Precondition::Revision(v.revision),
            )
            .await;
        match r {
            Ok(_) => return,
            Err(torngat_store::StoreError::PreconditionFailed { .. }) => continue,
            Err(e) => panic!("{e}"),
        }
    }
}

async fn change_volume(e: &Env, name: &str, f: impl Fn(&mut Volume)) {
    change(e, keys::volume(&scope(), &n(name)).unwrap(), f).await;
}

/// An instance placed on `node`, with these data disks.
async fn instance(e: &Env, name: &str, node: &str, disks: &[&str]) -> Uuid {
    let disks: Vec<_> = disks.iter().map(|d| json!({"volume": d})).collect();
    let o = object(
        name,
        &scope(),
        json!({"vcpus": 1, "memory_mib": 256, "disks": disks}),
        json!({"phase": "scheduled", "node": node}),
    );
    put(&e.store, keys::instance(&scope(), &n(name)).unwrap(), &o).await;
    serde_json::from_value(o["metadata"]["uid"].clone()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_agent_looks_after_its_storage() {
    use torngat_agent::storage::{FakeCrypt, FileDriver, mapping};
    let e = env(Vec::new(), false).await;
    let root = tempfile::TempDir::new().unwrap();
    let dir = root.path().join("data");
    std::fs::create_dir(&dir).unwrap();
    let crypt = FakeCrypt::default();
    tokio::spawn(torngat_agent::run(
        node_cfg(&e, "n1", "active").await,
        torngat_agent::FakeRuntime::default(),
        FileDriver::new(root.path(), 8 * GIB, false),
        crypt.clone(),
    ));

    // Claimed and marked as this cluster's pool.
    let p = pool(&e, "data", "n1").await;
    until("pool ready", || async {
        let s = pool_now(&e, "data").await.unwrap().status;
        s.ready && s.capacity_bytes == 8 * GIB && s.allocation_unit_bytes == 4 << 20
    })
    .await;
    let mark = std::fs::read_to_string(dir.join(".torngat-pool")).unwrap();
    assert!(mark.contains(&p.metadata.uid.to_string()));

    // Something the platform does not know is shown and left alone.
    let stray = dir.join(format!("{}.img", Uuid::now_v7()));
    std::fs::write(&stray, b"not ours").unwrap();
    until("stray volume shown", || async {
        let m = pool_now(&e, "data").await.unwrap().status.message;
        m.is_some_and(|m| m.contains("does not know"))
    })
    .await;

    // Created on the node; not opened while no instance uses it.
    volume_type(&e, "fast", &["data"]).await;
    let v = pending(&e, "v1", 1).await;
    let uid = v.metadata.uid;
    place(&e, &v, Some("n1")).await.unwrap();
    let file = dir.join(format!("{uid}.img"));
    until("volume ready", || async {
        let s = volume_now(&e, "v1").await.unwrap().status;
        s.phase == VolumePhase::Ready && s.size_bytes == GIB
    })
    .await;
    assert!(std::fs::metadata(&file).unwrap().len() >= GIB + (16 << 20));
    assert!(crypt.state().open.is_empty() && crypt.state().formatted.is_empty());

    // Used by an instance on this node: formatted once, then opened.
    let i1 = instance(&e, "i1", "n1", &["v1"]).await;
    let disks = |list: &'static [&'static str]| {
        let e = &e;
        async move {
            change(
                e,
                keys::instance(&scope(), &n("i1")).unwrap(),
                |i: &mut torngat_api::compute::Instance| {
                    i.spec.disks = list
                        .iter()
                        .map(|d| torngat_api::compute::DiskRef { volume: n(d) })
                        .collect();
                },
            )
            .await;
        }
    };
    until("opened", || async {
        crypt.state().open.contains_key(&mapping(uid))
    })
    .await;
    assert!(crypt.state().formatted.contains_key(&file));
    assert_eq!(
        volume_now(&e, "v1").await.unwrap().status.attached_to,
        Some(i1)
    );
    until("formatted reported", || async {
        volume_now(&e, "v1").await.unwrap().status.formatted
    })
    .await;

    // Grown while open.
    change_volume(&e, "v1", |v| v.spec.size_gib = 2).await;
    until("grown", || async {
        volume_now(&e, "v1").await.unwrap().status.size_bytes == 2 * GIB
    })
    .await;
    assert!(std::fs::metadata(&file).unwrap().len() >= 2 * GIB + (16 << 20));

    // Closed when no longer used, and when left open by an agent that stopped.
    let other = mapping(Uuid::now_v7());
    crypt.state().open.insert(other.clone(), file.clone());
    disks(&[]).await;
    until("closed", || async { crypt.state().open.is_empty() }).await;
    until("released", || async {
        volume_now(&e, "v1")
            .await
            .unwrap()
            .status
            .attached_to
            .is_none()
    })
    .await;

    // A header that is gone is not made again.
    let key = crypt.state().formatted.remove(&file).unwrap();
    disks(&["v1"]).await;
    until("refused to format again", || async {
        let m = volume_now(&e, "v1").await.unwrap().status.message;
        m.is_some_and(|m| m.contains("not formatted again"))
    })
    .await;
    assert!(crypt.state().open.is_empty());
    crypt.state().formatted.insert(file.clone(), key);

    // Deleted: blocks, then the object; the stray file stays.
    disks(&[]).await;
    until("released", || async {
        volume_now(&e, "v1")
            .await
            .unwrap()
            .status
            .attached_to
            .is_none()
    })
    .await;
    change_volume(&e, "v1", |v| {
        v.status.phase = VolumePhase::Deleting;
        v.metadata.delete_time = Some(time::OffsetDateTime::now_utc());
    })
    .await;
    until("volume gone", || async {
        volume_now(&e, "v1").await.is_none()
    })
    .await;
    assert!(!file.exists());
    assert!(stray.exists());

    // The pool is released once only the stray file is left and that is removed.
    e.store
        .delete(keys::volume_type(&n("fast")).unwrap(), Precondition::None)
        .await
        .unwrap();
    change(
        &e,
        keys::storage_pool(&n("data")).unwrap(),
        |p: &mut StoragePool| {
            p.metadata.delete_time = Some(time::OffsetDateTime::now_utc());
        },
    )
    .await;
    until("release refused", || async {
        let m = pool_now(&e, "data").await.unwrap().status.message;
        m.is_some_and(|m| m.contains("holds volumes"))
    })
    .await;
    std::fs::remove_file(&stray).unwrap();
    until("pool gone", || async {
        pool_now(&e, "data").await.is_none()
    })
    .await;
    assert!(!dir.join(".torngat-pool").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn instances_get_their_disks() {
    use torngat_agent::storage::{FakeCrypt, FileDriver, mapping};
    use torngat_api::compute::Instance;
    let e = env(Vec::new(), false).await;
    let root = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(root.path().join("data")).unwrap();
    let crypt = FakeCrypt::default();
    let runtime = torngat_agent::FakeRuntime::default();
    tokio::spawn(torngat_agent::run(
        node_cfg(&e, "n1", "active").await,
        runtime.clone(),
        FileDriver::new(root.path(), 8 * GIB, false),
        crypt.clone(),
    ));
    pool(&e, "data", "n1").await;
    until("pool ready", || async {
        pool_now(&e, "data").await.unwrap().status.ready
    })
    .await;
    volume_type(&e, "fast", &["data"]).await;
    let data = pending(&e, "data-1", 1).await;

    // A boot disk made for it, and a data volume: both placed on its node, attached and opened.
    let o = object(
        "web",
        &scope(),
        json!({"vcpus": 1, "memory_mib": 64,
               "boot_disk": {"volume_type": "fast", "size_gib": 2},
               "disks": [{"volume": "data-1"}]}),
        json!({}),
    );
    put(&e.store, keys::instance(&scope(), &n("web")).unwrap(), &o).await;
    let web: Instance = serde_json::from_value(o).unwrap();
    let inst =
        || async { read::<Instance>(&e, keys::instance(&scope(), &n("web")).unwrap()).await };
    until("scheduled", || async {
        inst().await.unwrap().status.node == Some(n("n1"))
    })
    .await;
    let boot = volume_now(&e, "web-boot").await.unwrap();
    let owner = boot.status.owner.unwrap();
    assert!(owner.instance == web.metadata.uid && owner.delete_with_it);
    assert_eq!(boot.spec.size_gib, 2);
    for v in ["web-boot", "data-1"] {
        until("attached", || async {
            let v = volume_now(&e, v).await.unwrap();
            v.status.attached_to == Some(web.metadata.uid) && v.status.phase == VolumePhase::Ready
        })
        .await;
    }
    until("both open", || async {
        let open = crypt.state().open.clone();
        open.contains_key(&mapping(boot.metadata.uid))
            && open.contains_key(&mapping(data.metadata.uid))
    })
    .await;

    until("open reported", || async {
        volume_now(&e, "data-1").await.unwrap().status.open
    })
    .await;
    // Started once both were open, with its boot disk first.
    until("running", || async {
        inst().await.unwrap().status.phase == torngat_api::compute::InstancePhase::Running
    })
    .await;
    let disks = runtime.disks(web.metadata.uid).unwrap();
    let got: Vec<_> = disks.iter().map(|d| (d.volume, d.boot)).collect();
    assert_eq!(got, [(boot.metadata.uid, true), (data.metadata.uid, false)]);
    assert_eq!(
        disks[0].path,
        torngat_agent::storage::device(boot.metadata.uid)
    );

    // Added while it runs: placed on its node, attached and opened.
    let data2 = pending(&e, "data-2", 1).await;
    change(
        &e,
        keys::instance(&scope(), &n("web")).unwrap(),
        |i: &mut Instance| {
            i.spec.disks.push(torngat_api::compute::DiskRef {
                volume: n("data-2"),
            });
        },
    )
    .await;
    until("added", || async {
        crypt
            .state()
            .open
            .contains_key(&mapping(data2.metadata.uid))
    })
    .await;
    // The running instance gets it.
    until("given to the instance", || async {
        runtime
            .disks(web.metadata.uid)
            .is_some_and(|d| d.iter().any(|d| d.volume == data2.metadata.uid))
    })
    .await;
    // Grown while it runs: the instance gets the new size.
    let before = runtime.disks(web.metadata.uid).unwrap()[1].size;
    change(
        &e,
        keys::volume(&scope(), &n("data-1")).unwrap(),
        |v: &mut torngat_api::storage::Volume| v.spec.size_gib = 2,
    )
    .await;
    until("grown in the instance", || async {
        runtime.disks(web.metadata.uid).unwrap()[1].size > before
    })
    .await;

    // Another instance cannot have a volume in use, nor another's boot disk; neither is taken.
    let other = async |disk: &str| {
        let o = object(
            "other",
            &scope(),
            json!({"vcpus": 1, "memory_mib": 64, "disks": [{"volume": disk}]}),
            json!({}),
        );
        put(&e.store, keys::instance(&scope(), &n("other")).unwrap(), &o).await;
    };
    let told = async |what: &str| {
        read::<Instance>(&e, keys::instance(&scope(), &n("other")).unwrap())
            .await
            .unwrap()
            .status
            .message
            .is_some_and(|m| m.contains(what))
    };
    other("data-1").await;
    until("told: in use", || told("used by another instance")).await;
    other("web-boot").await;
    until("told: boot disk", || told("another instance's boot disk")).await;
    assert_eq!(
        volume_now(&e, "web-boot").await.unwrap().status.attached_to,
        Some(web.metadata.uid)
    );
    e.store
        .delete(
            keys::instance(&scope(), &n("other")).unwrap(),
            Precondition::None,
        )
        .await
        .unwrap();

    // Gone: its boot disk is deleted, the data volume released and kept; both closed.
    e.store
        .delete(
            keys::instance(&scope(), &n("web")).unwrap(),
            Precondition::None,
        )
        .await
        .unwrap();
    until("boot disk deleted", || async {
        volume_now(&e, "web-boot").await.is_none()
    })
    .await;
    // Released only once closed on the node.
    until("data volumes released", || async {
        let a = volume_now(&e, "data-1").await.unwrap();
        let b = volume_now(&e, "data-2").await.unwrap();
        a.status.attached_to.is_none() && b.status.attached_to.is_none()
    })
    .await;
    assert!(crypt.state().open.is_empty());
    assert!(!volume_now(&e, "data-1").await.unwrap().status.open);
    assert_eq!(
        volume_now(&e, "data-1").await.unwrap().status.phase,
        VolumePhase::Ready
    );
}
