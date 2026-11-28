//! Images on the controller: a node is chosen, the node's reports make the volumes, and deleting the
//! image deletes them. The node is played by hand.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use common::{Env, env, n};
use serde::Serialize;
use serde_json::json;
use tonic::Code;
use tonic::transport::Channel;
use torngat_api::Scope;
use torngat_api::image::{Image, ImageFormat, ImagePhase};
use torngat_api::storage::{StoragePool, Volume, VolumeOwner, VolumePhase};
use torngat_controller::keys;
use torngat_proto::v1::control_client::ControlClient;
use torngat_proto::v1::{
    AssignmentsRequest, ImageReport, PoolReport, VolumeKeyRequest, VolumeReport,
};
use torngat_store::{Key, Precondition, Store};
use uuid::Uuid;

type Client = ControlClient<Channel>;
const GIB: u64 = 1 << 30;

async fn put(store: &Store, key: Key, v: &impl Serialize) {
    store
        .put(key, serde_json::to_vec(v).unwrap(), Precondition::None)
        .await
        .unwrap();
}

async fn read<T: serde::de::DeserializeOwned>(e: &Env, key: Key) -> Option<T> {
    let v = e.store.get(&key).await.unwrap()?;
    Some(serde_json::from_slice(&v.value).unwrap())
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

/// Until `f` holds; the controller's passes run every 100 ms.
async fn until<F: Future<Output = bool>>(what: &str, mut f: impl FnMut() -> F) {
    let end = Instant::now() + Duration::from_secs(25);
    while !f().await {
        assert!(Instant::now() < end, "never: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// An enrolled, active node, and its connection.
async fn node(e: &Env, name: &str) -> Client {
    let issued = e.ca.issue_node(&n(name)).unwrap();
    torngat_controller::identity::enroll(
        &e.store,
        &n(name),
        &issued.identity(torngat_pki::KeyStorage::File).unwrap(),
    )
    .await
    .unwrap();
    let o = object(
        name,
        &Scope::Platform,
        json!({"roles": ["compute"]}),
        json!({"phase": "active"}),
    );
    put(&e.store, keys::node(&n(name)).unwrap(), &o).await;
    let mut c = torngat_agent::connect(&torngat_agent::AgentConfig {
        controller_url: format!("https://{}", e.control),
        controller_name: torngat_pki::CONTROLLER_NAME.into(),
        ca_pem: e.ca.cert_pem().as_bytes().to_vec(),
        cert_pem: issued.chain_pem.into_bytes(),
        key: torngat_agent::NodeKey::File(issued.key_pem.unwrap().into_bytes()),
    })
    .await
    .unwrap();
    // Images go only to live nodes.
    c.heartbeat(torngat_proto::v1::HeartbeatRequest {})
        .await
        .unwrap();
    c
}

/// A pool of `node` that the node reported as ready, in the volume type `fast`.
async fn ready_pool(e: &Env, c: &mut Client, name: &str, node: &str, capacity: u64) {
    let o = object(
        name,
        &Scope::Platform,
        json!({"node": node, "driver": "lvm", "source": "data"}),
        json!({}),
    );
    put(&e.store, keys::storage_pool(&n(name)).unwrap(), &o).await;
    let key = || keys::storage_pool(&n(name)).unwrap();
    until("claimed", || async {
        read::<StoragePool>(e, key()).await.unwrap().status.claimed
    })
    .await;
    let uid: Uuid = serde_json::from_value(o["metadata"]["uid"].clone()).unwrap();
    c.report_pool(PoolReport {
        name: name.into(),
        uid: uid.to_string(),
        ready: true,
        capacity_bytes: capacity,
        allocation_unit_bytes: 4 << 20,
        ..Default::default()
    })
    .await
    .unwrap();
    let t = object(
        "fast",
        &Scope::Platform,
        json!({"pools": [name]}),
        json!(null),
    );
    put(&e.store, keys::volume_type(&n("fast")).unwrap(), &t).await;
}

fn org_project(scope: &Scope) -> (String, String) {
    match scope {
        Scope::Project { org, project } => (org.to_string(), project.to_string()),
        _ => (String::new(), String::new()),
    }
}

async fn image(e: &Env, scope: &Scope, name: &str) -> Image {
    let o = object(
        name,
        scope,
        json!({
            "source": {"url": "https://cloud.example/debian.qcow2",
                       "checksum": {"sha256": "0".repeat(64)}},
            "volume_type": "fast",
        }),
        json!({}),
    );
    put(&e.store, keys::image(scope, &n(name)).unwrap(), &o).await;
    serde_json::from_value(o).unwrap()
}

async fn image_now(e: &Env, i: &Image) -> Option<Image> {
    read(e, keys::image(&i.metadata.scope, &i.metadata.name).unwrap()).await
}

async fn volume_now(e: &Env, scope: &Scope, name: &str) -> Option<Volume> {
    read(e, keys::volume(scope, &n(name)).unwrap()).await
}

fn report(i: &Image) -> ImageReport {
    let (org, project) = org_project(&i.metadata.scope);
    ImageReport {
        org,
        project,
        name: i.metadata.name.to_string(),
        uid: i.metadata.uid.to_string(),
        ..Default::default()
    }
}

async fn send(c: &mut Client, r: ImageReport) -> Result<(), Code> {
    c.report_image(r).await.map(|_| ()).map_err(|s| s.code())
}

fn volume_report(v: &Volume) -> VolumeReport {
    let (org, project) = org_project(&v.metadata.scope);
    VolumeReport {
        org,
        project,
        name: v.metadata.name.to_string(),
        uid: v.metadata.uid.to_string(),
        ..Default::default()
    }
}

async fn key(c: &mut Client, v: &Volume) -> Result<Vec<u8>, Code> {
    let (org, project) = org_project(&v.metadata.scope);
    c.get_volume_key(VolumeKeyRequest {
        org,
        project,
        name: v.metadata.name.to_string(),
        uid: v.metadata.uid.to_string(),
    })
    .await
    .map(|r| r.into_inner().key)
    .map_err(|s| s.code())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_platform_image_is_imported_and_deleted() {
    let e = env(Vec::new(), false).await;
    let mut n1 = node(&e, "n1").await;
    let mut n2 = node(&e, "n2").await;
    ready_pool(&e, &mut n1, "data", "n1", 10 * GIB).await;
    let p = Scope::Platform;
    let img = image(&e, &p, "debian").await;
    let owner = Some(VolumeOwner::Image {
        image: img.metadata.uid,
    });

    until("given a node", || async {
        let i = image_now(&e, &img).await.unwrap();
        i.status.phase == ImagePhase::Importing && i.status.node == Some(n("n1"))
    })
    .await;
    // Its node is told to import it.
    let mut stream = n1
        .assignments(AssignmentsRequest {})
        .await
        .unwrap()
        .into_inner();
    let set = stream.message().await.unwrap().unwrap();
    assert!(!set.storage_unavailable);
    let told: Vec<Image> = set
        .images_json
        .iter()
        .map(|j| serde_json::from_slice(j).unwrap())
        .collect();
    assert_eq!(told.len(), 1);
    assert_eq!(told[0].metadata.uid, img.metadata.uid);

    // Only that node reports, about that image.
    let mut r = report(&img);
    r.download_bytes = 300 << 20;
    assert_eq!(send(&mut n2, r.clone()).await, Err(Code::PermissionDenied));
    let mut other = r.clone();
    other.uid = Uuid::now_v7().to_string();
    assert_eq!(send(&mut n1, other).await, Err(Code::PermissionDenied));
    let mut huge = r.clone();
    huge.download_bytes = u64::MAX;
    assert_eq!(send(&mut n1, huge).await, Err(Code::InvalidArgument));
    // The format comes after the download size.
    let mut early = report(&img);
    early.format = "qcow2".into();
    early.size_bytes = GIB;
    assert_eq!(send(&mut n1, early).await, Err(Code::FailedPrecondition));
    send(&mut n1, r.clone()).await.unwrap();
    // Written once.
    let mut changed = r.clone();
    changed.download_bytes = 400 << 20;
    assert_eq!(send(&mut n1, changed).await, Err(Code::FailedPrecondition));
    send(&mut n1, r.clone()).await.unwrap();

    // The staging volume, placed on that node; its key goes to that node only.
    until("staging placed", || async {
        volume_now(&e, &p, "debian-staging")
            .await
            .is_some_and(|v| v.status.phase == VolumePhase::Placed)
    })
    .await;
    let staging = volume_now(&e, &p, "debian-staging").await.unwrap();
    assert_eq!(staging.status.owner, owner);
    assert_eq!(staging.spec.size_gib, 1);
    assert_eq!(key(&mut n1, &staging).await.unwrap().len(), 32);
    assert_eq!(key(&mut n2, &staging).await, Err(Code::PermissionDenied));

    // Format and size: the image's volume, of the size rounded up.
    let mut info = report(&img);
    info.format = "vmdk".into();
    info.size_bytes = 2 * GIB + 1;
    assert_eq!(
        send(&mut n1, info.clone()).await,
        Err(Code::InvalidArgument)
    );
    info.format = "qcow2".into();
    let mut alone = info.clone();
    alone.size_bytes = 0;
    assert_eq!(send(&mut n1, alone).await, Err(Code::InvalidArgument));
    send(&mut n1, info.clone()).await.unwrap();
    until("image volume placed", || async {
        volume_now(&e, &p, "debian-image")
            .await
            .is_some_and(|v| v.status.phase == VolumePhase::Placed)
    })
    .await;
    let target = volume_now(&e, &p, "debian-image").await.unwrap();
    assert_eq!((target.status.owner, target.spec.size_gib), (owner, 3));
    let i = image_now(&e, &img).await.unwrap();
    assert_eq!(
        (i.status.format, i.status.size_bytes),
        (Some(ImageFormat::Qcow2), 2 * GIB + 1)
    );

    // Done only once the volume holds it.
    let mut done = report(&img);
    done.done = true;
    assert_eq!(
        send(&mut n1, done.clone()).await,
        Err(Code::FailedPrecondition)
    );
    let mut created = volume_report(&target);
    created.created = true;
    created.formatted = true;
    created.size_bytes = 3 * GIB;
    n1.report_volume(created).await.unwrap();
    send(&mut n1, done.clone()).await.unwrap();
    let i = image_now(&e, &img).await.unwrap();
    assert_eq!(i.status.phase, ImagePhase::Ready);
    // No more reports, no more keys; the staging volume goes.
    assert_eq!(send(&mut n1, r).await, Err(Code::FailedPrecondition));
    until("staging deleted", || async {
        volume_now(&e, &p, "debian-staging")
            .await
            .is_some_and(|v| v.status.phase == VolumePhase::Deleting)
    })
    .await;
    assert_eq!(key(&mut n1, &target).await, Err(Code::FailedPrecondition));
    let mut gone = volume_report(&staging);
    gone.deleted = true;
    n1.report_volume(gone).await.unwrap();
    assert!(volume_now(&e, &p, "debian-staging").await.is_none());

    // Deleting the image deletes its volume first.
    let mut deleting = image_now(&e, &img).await.unwrap();
    deleting.metadata.delete_time = Some(time::OffsetDateTime::now_utc());
    deleting.status.phase = ImagePhase::Deleting;
    put(&e.store, keys::image(&p, &n("debian")).unwrap(), &deleting).await;
    until("image volume deleted", || async {
        volume_now(&e, &p, "debian-image")
            .await
            .is_some_and(|v| v.status.phase == VolumePhase::Deleting)
    })
    .await;
    assert!(image_now(&e, &img).await.is_some());
    let mut gone = volume_report(&target);
    gone.deleted = true;
    n1.report_volume(gone).await.unwrap();
    until("image gone", || async {
        image_now(&e, &img).await.is_none()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn image_volumes_are_never_disks() {
    let e = env(Vec::new(), false).await;
    let mut n1 = node(&e, "n1").await;
    ready_pool(&e, &mut n1, "data", "n1", 10 * GIB).await;
    let s = Scope::Project {
        org: n("acme"),
        project: n("web"),
    };
    let img = image(&e, &s, "debian").await;
    until("given a node", || async {
        image_now(&e, &img).await.unwrap().status.phase == ImagePhase::Importing
    })
    .await;
    let mut r = report(&img);
    r.download_bytes = GIB;
    send(&mut n1, r).await.unwrap();
    until("staging made", || async {
        volume_now(&e, &s, "debian-staging").await.is_some()
    })
    .await;

    // An instance that lists it is told why it cannot have it.
    let o = object(
        "vm",
        &s,
        json!({"vcpus": 1, "memory_mib": 64, "disks": [{"volume": "debian-staging"}]}),
        json!({}),
    );
    put(&e.store, keys::instance(&s, &n("vm")).unwrap(), &o).await;
    until("refused", || async {
        let i: torngat_api::compute::Instance = read(&e, keys::instance(&s, &n("vm")).unwrap())
            .await
            .unwrap();
        i.status.message.as_deref() == Some("volume debian-staging belongs to an image")
    })
    .await;
    let v = volume_now(&e, &s, "debian-staging").await.unwrap();
    assert_eq!(v.status.attached_to, None);

    // A failure deletes what the import made.
    let mut both = report(&img);
    both.done = true;
    both.failed = true;
    both.message = "x".into();
    assert_eq!(send(&mut n1, both).await, Err(Code::InvalidArgument));
    let mut failed = report(&img);
    failed.failed = true;
    assert_eq!(
        send(&mut n1, failed.clone()).await,
        Err(Code::InvalidArgument)
    );
    failed.message = "the checksum does not match".into();
    send(&mut n1, failed).await.unwrap();
    let i = image_now(&e, &img).await.unwrap();
    assert_eq!(i.status.phase, ImagePhase::Failed);
    assert_eq!(
        i.status.message.as_deref(),
        Some("the checksum does not match")
    );
    until("staging deleted", || async {
        volume_now(&e, &s, "debian-staging")
            .await
            .is_none_or(|v| v.status.phase == VolumePhase::Deleting)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn volumes_of_gone_images_are_deleted() {
    let e = env(Vec::new(), false).await;
    let p = Scope::Platform;
    let o = object(
        "old-image",
        &p,
        json!({"volume_type": "fast", "size_gib": 1}),
        json!({"owner": {"image": Uuid::now_v7()}}),
    );
    put(&e.store, keys::volume(&p, &n("old-image")).unwrap(), &o).await;
    until("deleted", || async {
        volume_now(&e, &p, "old-image").await.is_none()
    })
    .await;
    // Waiting images say why.
    let img = image(&e, &p, "debian").await;
    until("told", || async {
        image_now(&e, &img).await.unwrap().status.message.as_deref()
            == Some("waiting for a live node with room in its volume type")
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn imports_are_bounded() {
    let e = env(Vec::new(), false).await;
    let mut n1 = node(&e, "n1").await;
    ready_pool(&e, &mut n1, "data", "n1", 10 * GIB).await;
    let settings = torngat_api::settings::ImageSettings {
        max_image_gib: 1,
        platform_private_sources: true,
    };
    put(&e.store, keys::image_settings().unwrap(), &settings).await;
    let p = Scope::Platform;
    let img = image(&e, &p, "debian").await;
    until("given a node", || async {
        image_now(&e, &img).await.unwrap().status.phase == ImagePhase::Importing
    })
    .await;
    // The node is told the settings.
    let mut stream = n1
        .assignments(AssignmentsRequest {})
        .await
        .unwrap()
        .into_inner();
    let set = stream.message().await.unwrap().unwrap();
    let told: torngat_api::settings::ImageSettings =
        serde_json::from_slice(&set.image_settings_json).unwrap();
    assert_eq!(told, settings);

    // Larger than the operator allows.
    let mut r = report(&img);
    r.download_bytes = GIB + 1;
    assert_eq!(send(&mut n1, r.clone()).await, Err(Code::InvalidArgument));
    // Each report moves the deadline.
    let before = image_now(&e, &img).await.unwrap().status.progress_time.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    send(&mut n1, report(&img)).await.unwrap();
    let after = image_now(&e, &img).await.unwrap().status.progress_time.unwrap();
    assert!(after > before);

    // No progress for too long: failed.
    let mut stale = image_now(&e, &img).await.unwrap();
    stale.status.progress_time =
        Some(time::OffsetDateTime::now_utc() - time::Duration::minutes(16));
    put(&e.store, keys::image(&p, &n("debian")).unwrap(), &stale).await;
    until("failed", || async {
        image_now(&e, &img).await.unwrap().status.phase == ImagePhase::Failed
    })
    .await;
    let i = image_now(&e, &img).await.unwrap();
    assert_eq!(
        i.status.message.as_deref(),
        Some("the import stopped: no progress for 15 minutes")
    );
}
