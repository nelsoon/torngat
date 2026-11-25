//! Volume keys over the control protocol.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{Env, env, n};
use serde::Serialize;
use serde_json::json;
use tonic::Code;
use tonic::transport::Channel;
use torngat_agent::{AgentConfig, NodeKey};
use torngat_api::storage::{StoragePool, Volume, VolumePhase};
use torngat_api::{Name, Scope};
use torngat_controller::volume_keys::{self, PlatformKeyError, VolumeKeyRecord};
use torngat_controller::{destroy_volume_keys_once, keys};
use torngat_proto::v1::VolumeKeyRequest;
use torngat_proto::v1::control_client::ControlClient;
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

/// An enrolled and registered node, and its connection.
async fn node(e: &Env, name: &str, phase: &str) -> Client {
    let issued = e.ca.issue_node(&n(name)).unwrap();
    torngat_controller::identity::enroll(
        &e.store,
        &n(name),
        &issued.identity(torngat_pki::KeyStorage::File).unwrap(),
    )
    .await
    .unwrap();
    set_phase(e, name, phase).await;
    torngat_agent::connect(&AgentConfig {
        controller_url: format!("https://{}", e.control),
        controller_name: torngat_pki::CONTROLLER_NAME.into(),
        ca_pem: e.ca.cert_pem().as_bytes().to_vec(),
        cert_pem: issued.chain_pem.into_bytes(),
        key: NodeKey::File(issued.key_pem.unwrap().into_bytes()),
    })
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
        json!({"phase": "placed", "pool": {"name": pool.metadata.name, "uid": pool.metadata.uid}}),
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
    let e = env(Vec::new(), false).await;
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
    let e = env(Vec::new(), false).await;
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

    v.status.formatted = false;
    save(&e, &scope(), &v).await;
    let k = key(&mut n1, &v).await;
    assert!(k.is_ok());
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
    let e = env(Vec::new(), false).await;
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
