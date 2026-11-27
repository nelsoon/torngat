//! Storage on the node: claims the pools the controller assigns, creates, grows and deletes their
//! volumes through the pool's driver, and encrypts them (LUKS2) with keys from the controller.
//!
//! - A volume is formatted only if its header area is blank and it was never formatted before
//!   (`formatted`, which the node reports); never over anything else.
//! - Its decrypted mapping is open only while an instance on this node uses it. Keys are asked for
//!   when needed and dropped (zeroed) right after.
//! - Volumes that the controller does not list are never deleted: they are reported to the operator.
//! - When the controller cannot read storage objects, nothing is changed.

pub mod crypt;
pub mod driver;
pub mod files;
pub mod lvm;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use tonic::transport::Channel;
use torngat_api::compute::Instance;
use torngat_api::storage::{LUKS_HEADER_BYTES, StorageDriver, StoragePool, Volume, VolumePhase};
use torngat_api::{Name, Scope};
use torngat_proto::storage::v1 as drv;
use torngat_proto::v1::control_client::ControlClient;
use torngat_proto::v1::{PoolReport, ReportResponse, VolumeKeyRequest, VolumeReport};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use crypt::{Crypt, Cryptsetup, FakeCrypt, device, mapping};
pub use driver::{AnyDriver, Builtin, Driver, Drivers, NoDriver};
pub use files::FileDriver;
pub use lvm::LvmDriver;

use crate::runtime::Disk;
use crate::{AgentError, sanitize};

/// Wait after a refused key, doubled up to [`MAX_KEY_WAIT`].
const KEY_WAIT: Duration = Duration::from_secs(5);
const MAX_KEY_WAIT: Duration = Duration::from_secs(300);

/// An instance's disks: those open on this node, and what it waits for if not all are.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Disks {
    pub ready: Vec<Disk>,
    pub waiting: Option<String>,
}

/// What the controller assigned: decoded, or nothing at all.
#[derive(Debug, Default, Clone)]
pub struct Assigned {
    pub pools: Vec<StoragePool>,
    pub volumes: Vec<Volume>,
    /// Instances on this node, with the volumes each lists (in its project).
    pub instances: BTreeMap<Uuid, (Scope, BTreeSet<Name>)>,
}

impl Assigned {
    /// The instances' volumes, by instance uid.
    pub fn instances(
        list: &[torngat_api::compute::Instance],
    ) -> BTreeMap<Uuid, (Scope, BTreeSet<Name>)> {
        list.iter()
            .map(|i| {
                let names = i
                    .spec
                    .volumes(&i.metadata.name)
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                (i.metadata.uid, (i.metadata.scope.clone(), names))
            })
            .collect()
    }
}

impl Assigned {
    /// `None` if the controller could not read storage, or an entry does not decode (a newer
    /// controller): then storage is left alone.
    pub fn decode(
        pools: &[Vec<u8>],
        volumes: &[Vec<u8>],
        unavailable: bool,
        instances: BTreeMap<Uuid, (Scope, BTreeSet<Name>)>,
    ) -> Option<Self> {
        if unavailable {
            return None;
        }
        let decode = |what: &str, e: serde_json::Error| {
            tracing::error!(error = %e, "undecodable {what}: storage is left as it is");
        };
        let pools = pools
            .iter()
            .map(|b| serde_json::from_slice(b))
            .collect::<Result<Vec<StoragePool>, _>>()
            .map_err(|e| decode("pool", e))
            .ok()?;
        let volumes = volumes
            .iter()
            .map(|b| serde_json::from_slice(b))
            .collect::<Result<Vec<Volume>, _>>()
            .map_err(|e| decode("volume", e))
            .ok()?;
        Some(Self {
            pools,
            volumes,
            instances,
        })
    }
}

/// The node's storage and what it last told the controller.
#[derive(Debug)]
pub struct Storage<D, C> {
    drivers: D,
    crypt: C,
    cluster: Uuid,
    /// Volumes whose key was refused: when to ask again, and the next wait.
    refused: HashMap<Uuid, (Instant, Duration)>,
    pools_reported: HashMap<Uuid, PoolReport>,
    volumes_reported: HashMap<Uuid, VolumeReport>,
    /// Volumes open for an instance on this node, with their size, as of the last pass.
    open: BTreeMap<Uuid, u64>,
}

impl<D: Drivers, C: Crypt> Storage<D, C> {
    /// `cluster` marks the pools as this cluster's: see [`cluster_uid`](crate::cluster_uid).
    pub fn new(drivers: D, crypt: C, cluster: Uuid) -> Self {
        Self {
            drivers,
            crypt,
            cluster,
            refused: HashMap::new(),
            pools_reported: HashMap::new(),
            volumes_reported: HashMap::new(),
            open: BTreeMap::new(),
        }
    }

    /// Reports are repeated in a new session: the controller may have missed them.
    pub fn new_session(&mut self) {
        self.pools_reported.clear();
        self.volumes_reported.clear();
        self.open.clear();
    }

    /// `inst`'s disks that are open on this node, in order (its boot disk first), and what it
    /// still waits for. `a` is `None` while storage is not available.
    pub fn disks(&self, a: Option<&Assigned>, inst: &Instance) -> Disks {
        let mut out = Disks::default();
        let name = &inst.metadata.name;
        let names = match inst.spec.volumes(name) {
            Ok(n) => n,
            Err(e) => {
                out.waiting = Some(e.to_string());
                return out;
            }
        };
        if names.is_empty() {
            return out;
        }
        let Some(a) = a else {
            out.waiting = Some("waiting for storage".into());
            return out;
        };
        let boot = inst.spec.boot_volume(name).ok().flatten();
        for n in &names {
            let open = a
                .volumes
                .iter()
                .find(|v| {
                    v.metadata.scope == inst.metadata.scope
                        && v.metadata.name == *n
                        && v.status.attached_to == Some(inst.metadata.uid)
                })
                .and_then(|v| Some((v.metadata.uid, *self.open.get(&v.metadata.uid)?)));
            match open {
                Some((uid, size)) => out.ready.push(Disk {
                    volume: uid,
                    path: device(uid),
                    boot: boot.as_ref() == Some(n),
                    size,
                }),
                None => {
                    out.waiting
                        .get_or_insert_with(|| format!("waiting for volume {n}"));
                }
            }
        }
        out
    }

    fn pool(&self, p: &StoragePool) -> drv::Pool {
        drv::Pool {
            uid: p.metadata.uid.to_string(),
            cluster_uid: self.cluster.to_string(),
            source: p.spec.source.clone(),
        }
    }

    /// Brings the node's storage in line with `a`, and tells whether the open volumes or their
    /// sizes changed. Errors end the session; failures of one pool or volume are reported and the
    /// others go on.
    pub async fn reconcile(
        &mut self,
        client: &mut ControlClient<Channel>,
        a: &Assigned,
    ) -> Result<bool, AgentError> {
        let mut mine = BTreeMap::new();
        for p in &a.pools {
            let r = self.pool_step(p, a).await;
            if !r.released {
                mine.insert(p.metadata.uid, (self.pool(p), p.spec.driver));
            }
            report(&mut self.pools_reported, p.metadata.uid, r, |r| {
                client.report_pool(r)
            })
            .await?;
        }

        let opened = match self.crypt.opened().await {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(error = %e, "cannot list the open volumes");
                return Ok(false);
            }
        };
        let pool_of = |v: &Volume| v.status.pool.as_ref().and_then(|r| mine.get(&r.uid));
        // In use by an instance on this node that lists it: the only mappings that stay open.
        let keep: BTreeSet<String> = a
            .volumes
            .iter()
            .filter(|v| {
                pool_of(v).is_some()
                    && v.metadata.delete_time.is_none()
                    && v.status.phase != VolumePhase::Deleting
                    && v.status.attached_to.is_some_and(|i| {
                        a.instances.get(&i).is_some_and(|(scope, names)| {
                            *scope == v.metadata.scope && names.contains(&v.metadata.name)
                        })
                    })
            })
            .map(|v| mapping(v.metadata.uid))
            .collect();
        // Closed first: no longer used, or left open by an agent that stopped. One that does not
        // close (busy) keeps its device attached, so that its deletion fails and is retried.
        let mut open = BTreeMap::new();
        let mut busy = BTreeSet::new();
        for (name, size) in opened {
            if keep.contains(&name) {
                open.insert(name, size);
                continue;
            }
            match self.crypt.close(&name).await {
                Ok(()) => tracing::info!(mapping = %name, "volume closed"),
                Err(e) => {
                    tracing::warn!(mapping = %name, error = %e, "cannot close a volume");
                    busy.insert(name);
                }
            }
        }

        let mut in_use = BTreeMap::new();
        for v in &a.volumes {
            let Some((pool, kind)) = pool_of(v) else {
                continue;
            };
            let name = mapping(v.metadata.uid);
            let use_ = keep.contains(&name).then(|| open.get(&name).copied());
            let Some(mut r) = self.volume_step(client, v, pool, *kind, use_).await else {
                continue;
            };
            if use_.is_some() && r.open {
                in_use.insert(v.metadata.uid, r.size_bytes);
            }
            // Still open: the controller does not give it to another instance yet.
            r.open |= busy.contains(&name);
            report(&mut self.volumes_reported, v.metadata.uid, r, |r| {
                client.report_volume(r)
            })
            .await?;
        }
        let changed = self.open != in_use;
        self.open = in_use;
        Ok(changed)
    }

    async fn pool_step(&self, p: &StoragePool, a: &Assigned) -> PoolReport {
        let mut report = PoolReport {
            name: p.metadata.name.to_string(),
            uid: p.metadata.uid.to_string(),
            ..Default::default()
        };
        let uid = p.metadata.uid;
        let pool = Some(self.pool(p));
        let kind = p.spec.driver;
        if p.metadata.delete_time.is_some() {
            if a.volumes.iter().any(|v| on_pool(v, uid)) {
                report.message = "waits for its volumes to be deleted".into();
                return report;
            }
            match self
                .drivers
                .get(kind)
                .release_pool(drv::ReleasePoolRequest { pool })
                .await
            {
                Ok(_) => report.released = true,
                Err(s) => report.message = sanitize(s.message()),
            }
            return report;
        }
        let r = async {
            self.drivers
                .get(kind)
                .claim_pool(drv::ClaimPoolRequest { pool: pool.clone() })
                .await?;
            let info = self
                .drivers
                .get(kind)
                .get_pool(drv::GetPoolRequest { pool: pool.clone() })
                .await?;
            let found = self
                .drivers
                .get(kind)
                .list_volumes(drv::ListVolumesRequest { pool })
                .await?
                .volumes;
            Ok::<_, tonic::Status>((info, found))
        }
        .await;
        match r {
            Ok((info, found)) => {
                let caps = info.capabilities.unwrap_or_default();
                report.ready = true;
                report.capacity_bytes = info.capacity_bytes;
                report.allocation_unit_bytes = info.allocation_unit_bytes;
                report.snapshots = caps.snapshots;
                report.checksums = caps.checksums;
                // Never deleted: the operator looks at them.
                let known = |f: &drv::VolumeInfo| {
                    Uuid::parse_str(&f.uid).is_ok_and(|u| {
                        a.volumes
                            .iter()
                            .any(|v| v.metadata.uid == u && on_pool(v, uid))
                    })
                };
                let unknown: Vec<_> = found.iter().filter(|f| !known(f)).collect();
                for f in &unknown {
                    tracing::warn!(pool = %p.metadata.name, volume = %f.uid, "unknown volume in a pool: left as it is");
                }
                if !unknown.is_empty() {
                    report.message = format!(
                        "{} volume(s) on the storage that the platform does not know, left as they are",
                        unknown.len()
                    );
                }
            }
            Err(s) => report.message = sanitize(s.message()),
        }
        report
    }

    /// What to report on `v`, or `None` if there is nothing to do yet. `use_` is set while an
    /// instance on this node uses it, with the size of its open mapping if there is one.
    async fn volume_step(
        &mut self,
        client: &mut ControlClient<Channel>,
        v: &Volume,
        pool: &drv::Pool,
        kind: StorageDriver,
        use_: Option<Option<u64>>,
    ) -> Option<VolumeReport> {
        let Scope::Project { org, project } = &v.metadata.scope else {
            return None;
        };
        let mut report = VolumeReport {
            org: org.to_string(),
            project: project.to_string(),
            name: v.metadata.name.to_string(),
            uid: v.metadata.uid.to_string(),
            ..Default::default()
        };
        let r = match v.status.phase {
            VolumePhase::Deleting => self.delete(v, pool, kind, &mut report).await,
            VolumePhase::Placed | VolumePhase::Ready if v.status.granted_bytes > 0 => {
                self.make(client, v, pool, kind, use_, &mut report).await
            }
            _ => return None,
        };
        if let Err(e) = r {
            tracing::warn!(volume = %v.metadata.uid, error = %e, "volume step failed");
            report.message = sanitize(&e);
        }
        Some(report)
    }

    /// Its mapping was closed before.
    async fn delete(
        &self,
        v: &Volume,
        pool: &drv::Pool,
        kind: StorageDriver,
        report: &mut VolumeReport,
    ) -> Result<(), String> {
        let (pool, uid) = (Some(pool.clone()), v.metadata.uid.to_string());
        self.drivers
            .get(kind)
            .detach_volume(drv::DetachVolumeRequest {
                pool: pool.clone(),
                uid: uid.clone(),
            })
            .await
            .map_err(msg)?;
        self.drivers
            .get(kind)
            .delete_volume(drv::DeleteVolumeRequest { pool, uid })
            .await
            .map_err(msg)?;
        report.deleted = true;
        Ok(())
    }

    /// Creates and grows the device; opens it while in use, formatting it the first time.
    async fn make(
        &mut self,
        client: &mut ControlClient<Channel>,
        v: &Volume,
        pool: &drv::Pool,
        kind: StorageDriver,
        use_: Option<Option<u64>>,
        report: &mut VolumeReport,
    ) -> Result<(), String> {
        let (pool, uid) = (Some(pool.clone()), v.metadata.uid);
        let want = v.status.granted_bytes.saturating_add(LUKS_HEADER_BYTES);
        let mut size = self
            .drivers
            .get(kind)
            .create_volume(drv::CreateVolumeRequest {
                pool: pool.clone(),
                uid: uid.to_string(),
                size_bytes: want,
            })
            .await
            .map_err(msg)?
            .size_bytes;
        if size < want {
            size = self
                .drivers
                .get(kind)
                .grow_volume(drv::GrowVolumeRequest {
                    pool: pool.clone(),
                    uid: uid.to_string(),
                    size_bytes: want,
                })
                .await
                .map_err(msg)?
                .size_bytes;
        }
        let usable = size.saturating_sub(LUKS_HEADER_BYTES);
        report.created = true;
        report.size_bytes = usable;
        report.formatted = v.status.formatted;

        let Some(open) = use_ else {
            // Its mapping was closed before.
            self.drivers
                .get(kind)
                .detach_volume(drv::DetachVolumeRequest {
                    pool,
                    uid: uid.to_string(),
                })
                .await
                .map_err(msg)?;
            return Ok(());
        };
        let name = mapping(uid);
        if let Some(open) = open {
            // Open, so formatted; the instance sees the mapping's size until it follows.
            report.formatted = true;
            report.open = true;
            report.size_bytes = open.min(usable);
            if open < usable {
                let key = self.key(client, v).await?;
                self.crypt.resize(&name, &key).await?;
                report.size_bytes = usable;
            }
            return Ok(());
        }
        let attached = self
            .drivers
            .get(kind)
            .attach_volume(drv::AttachVolumeRequest {
                pool,
                uid: uid.to_string(),
            })
            .await
            .map_err(msg)?;
        // Kinds that a newer driver may answer with are refused.
        let dev = match attached.device {
            Some(drv::attach_volume_response::Device::Block(b)) if b.path.starts_with('/') => {
                PathBuf::from(b.path)
            }
            _ => return Err("the driver answered with an unknown kind of device".into()),
        };
        match self.crypt.header(&dev).await? {
            crypt::Header::Blank if v.status.formatted => {
                return Err(
                    "the encryption header is gone: the volume is not formatted again".into(),
                );
            }
            crypt::Header::Blank => {
                let key = self.key(client, v).await?;
                self.crypt.format(&dev, &key).await?;
                tracing::info!(volume = %uid, "volume formatted");
                report.formatted = true;
                self.crypt.open(&dev, &name, &key).await?;
            }
            crypt::Header::Luks => {
                report.formatted = true;
                let key = self.key(client, v).await?;
                self.crypt.open(&dev, &name, &key).await?;
            }
            crypt::Header::Other => {
                return Err(
                    "unknown data where the encryption header goes: the volume is not formatted"
                        .into(),
                );
            }
        }
        report.open = true;
        tracing::info!(volume = %uid, "volume opened");
        Ok(())
    }

    /// The volume's key, unless it was refused a short while ago.
    async fn key(
        &mut self,
        client: &mut ControlClient<Channel>,
        v: &Volume,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let uid = v.metadata.uid;
        if let Some((until, _)) = self.refused.get(&uid)
            && Instant::now() < *until
        {
            return Err("the key was refused: waiting before asking again".into());
        }
        let Scope::Project { org, project } = &v.metadata.scope else {
            return Err("not a project's volume".into());
        };
        let r = client
            .get_volume_key(VolumeKeyRequest {
                org: org.to_string(),
                project: project.to_string(),
                name: v.metadata.name.to_string(),
                uid: uid.to_string(),
            })
            .await;
        match r {
            Ok(r) => {
                self.refused.remove(&uid);
                let key = Zeroizing::new(r.into_inner().key);
                if key.len() != 32 {
                    return Err("the controller answered with a key of the wrong size".into());
                }
                Ok(key)
            }
            Err(s) => {
                let wait = self
                    .refused
                    .get(&uid)
                    .map_or(KEY_WAIT, |(_, w)| (*w * 2).min(MAX_KEY_WAIT));
                self.refused.insert(uid, (Instant::now() + wait, wait));
                Err(format!("key refused: {}", s.message()))
            }
        }
    }
}

fn msg(s: tonic::Status) -> String {
    s.message().to_owned()
}

fn on_pool(v: &Volume, pool: Uuid) -> bool {
    v.status.pool.as_ref().is_some_and(|r| r.uid == pool)
}

/// Sends `r` unless it was the last one sent for `uid`. A report that the controller refused
/// concerns that object only: the others go on.
async fn report<R: PartialEq + Clone, F>(
    sent: &mut HashMap<Uuid, R>,
    uid: Uuid,
    r: R,
    send: impl FnOnce(R) -> F,
) -> Result<(), AgentError>
where
    F: std::future::Future<Output = Result<tonic::Response<ReportResponse>, tonic::Status>>,
{
    use tonic::Code;
    if sent.get(&uid) == Some(&r) {
        return Ok(());
    }
    match send(r.clone()).await {
        Ok(_) => {
            sent.insert(uid, r);
            Ok(())
        }
        Err(s)
            if matches!(
                s.code(),
                Code::InvalidArgument
                    | Code::PermissionDenied
                    | Code::NotFound
                    | Code::FailedPrecondition
            ) =>
        {
            tracing::warn!(%uid, status = %s, "report rejected");
            Ok(())
        }
        Err(s) => Err(s.into()),
    }
}
