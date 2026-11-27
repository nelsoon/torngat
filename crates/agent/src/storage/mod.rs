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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use tonic::transport::Channel;
use torngat_api::Scope;
use torngat_api::storage::{LUKS_HEADER_BYTES, StoragePool, Volume, VolumePhase};
use torngat_proto::storage::v1 as drv;
use torngat_proto::v1::control_client::ControlClient;
use torngat_proto::v1::{PoolReport, VolumeKeyRequest, VolumeReport};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use crypt::{Crypt, Cryptsetup, FakeCrypt, mapping};
pub use driver::{AnyDriver, Driver, NoDriver};
pub use files::FileDriver;

use crate::{AgentError, sanitize};

/// Wait after a refused key, doubled up to [`MAX_KEY_WAIT`].
const KEY_WAIT: Duration = Duration::from_secs(5);
const MAX_KEY_WAIT: Duration = Duration::from_secs(300);

/// What the controller assigned: decoded, or nothing at all.
#[derive(Debug, Default, Clone)]
pub struct Assigned {
    pub pools: Vec<StoragePool>,
    pub volumes: Vec<Volume>,
    /// Instances on this node.
    pub instances: BTreeSet<Uuid>,
}

impl Assigned {
    /// `None` if the controller could not read storage, or an entry does not decode (a newer
    /// controller): then storage is left alone.
    pub fn decode(
        pools: &[Vec<u8>],
        volumes: &[Vec<u8>],
        unavailable: bool,
        instances: BTreeSet<Uuid>,
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
    driver: D,
    crypt: C,
    cluster: Uuid,
    /// Volumes whose key was refused: when to ask again, and the next wait.
    refused: HashMap<Uuid, (Instant, Duration)>,
    pools_reported: HashMap<Uuid, PoolReport>,
    volumes_reported: HashMap<Uuid, VolumeReport>,
}

impl<D: Driver, C: Crypt> Storage<D, C> {
    /// `cluster` marks the pools as this cluster's: see [`cluster_uid`](crate::cluster_uid).
    pub fn new(driver: D, crypt: C, cluster: Uuid) -> Self {
        Self {
            driver,
            crypt,
            cluster,
            refused: HashMap::new(),
            pools_reported: HashMap::new(),
            volumes_reported: HashMap::new(),
        }
    }

    pub fn driver(&self) -> &D {
        &self.driver
    }

    pub fn crypt(&self) -> &C {
        &self.crypt
    }

    /// Reports are repeated in a new session: the controller may have missed them.
    pub fn new_session(&mut self) {
        self.pools_reported.clear();
        self.volumes_reported.clear();
    }

    fn pool(&self, p: &StoragePool) -> drv::Pool {
        drv::Pool {
            uid: p.metadata.uid.to_string(),
            cluster_uid: self.cluster.to_string(),
            source: p.spec.source.clone(),
        }
    }

    /// Brings the node's storage in line with `a`. Errors end the session; failures of one pool
    /// or volume are reported and the others go on.
    pub async fn reconcile(
        &mut self,
        client: &mut ControlClient<Channel>,
        a: &Assigned,
    ) -> Result<(), AgentError> {
        let mut mine = BTreeMap::new();
        for p in &a.pools {
            let report = self.pool_step(p, a).await;
            if !report.released {
                mine.insert(p.metadata.uid, self.pool(p));
            }
            self.report_pool(client, p.metadata.uid, report).await?;
        }

        let opened = match self.crypt.opened().await {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(error = %e, "cannot list the open volumes");
                return Ok(());
            }
        };
        // Mappings that stay open: those in use, also when their step fails.
        let mut keep = BTreeSet::new();
        for v in &a.volumes {
            let Some(pool) = v.status.pool.as_ref().and_then(|r| mine.get(&r.uid)) else {
                continue;
            };
            let in_use = v.metadata.delete_time.is_none()
                && v.status.phase != VolumePhase::Deleting
                && v.status
                    .attached_to
                    .is_some_and(|i| a.instances.contains(&i));
            if in_use {
                keep.insert(mapping(v.metadata.uid));
            }
            let Some(report) = self.volume_step(client, v, pool, in_use, &opened).await else {
                continue;
            };
            self.report_volume(client, v.metadata.uid, report).await?;
        }

        // Left open by an agent that stopped, or by a step that failed.
        for name in opened.keys().filter(|n| !keep.contains(*n)) {
            match self.crypt.close(name).await {
                Ok(()) => tracing::info!(mapping = %name, "volume closed"),
                Err(e) => tracing::warn!(mapping = %name, error = %e, "cannot close a volume"),
            }
        }
        Ok(())
    }

    async fn pool_step(&self, p: &StoragePool, a: &Assigned) -> PoolReport {
        let mut report = PoolReport {
            name: p.metadata.name.to_string(),
            uid: p.metadata.uid.to_string(),
            ..Default::default()
        };
        let pool = Some(self.pool(p));
        if p.metadata.delete_time.is_some() {
            let uid = p.metadata.uid;
            if a.volumes
                .iter()
                .any(|v| v.status.pool.as_ref().is_some_and(|r| r.uid == uid))
            {
                report.message = "waits for its volumes to be deleted".into();
                return report;
            }
            match self
                .driver
                .release_pool(drv::ReleasePoolRequest { pool })
                .await
            {
                Ok(_) => report.released = true,
                Err(s) => report.message = sanitize(s.message()),
            }
            return report;
        }
        let r = async {
            self.driver
                .claim_pool(drv::ClaimPoolRequest { pool: pool.clone() })
                .await?;
            let info = self
                .driver
                .get_pool(drv::GetPoolRequest { pool: pool.clone() })
                .await?;
            let found = self
                .driver
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
                let known: BTreeSet<String> = a
                    .volumes
                    .iter()
                    .filter(|v| {
                        v.status
                            .pool
                            .as_ref()
                            .is_some_and(|r| r.uid == p.metadata.uid)
                    })
                    .map(|v| v.metadata.uid.to_string())
                    .collect();
                let unknown: Vec<_> = found.iter().filter(|f| !known.contains(&f.uid)).collect();
                if !unknown.is_empty() {
                    for f in &unknown {
                        tracing::warn!(pool = %p.metadata.name, volume = %f.uid, "unknown volume in a pool: left as it is");
                    }
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

    /// What to report on `v`, or `None` if there is nothing to do yet.
    async fn volume_step(
        &mut self,
        client: &mut ControlClient<Channel>,
        v: &Volume,
        pool: &drv::Pool,
        in_use: bool,
        opened: &BTreeMap<String, u64>,
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
            VolumePhase::Deleting => self.delete(v, pool, opened, &mut report).await,
            VolumePhase::Placed | VolumePhase::Ready if v.status.granted_bytes > 0 => {
                self.make(client, v, pool, in_use, opened, &mut report)
                    .await
            }
            _ => return None,
        };
        if let Err(e) = r {
            tracing::warn!(volume = %v.metadata.uid, error = %e, "volume step failed");
            report.message = sanitize(&e);
        }
        Some(report)
    }

    async fn delete(
        &self,
        v: &Volume,
        pool: &drv::Pool,
        opened: &BTreeMap<String, u64>,
        report: &mut VolumeReport,
    ) -> Result<(), String> {
        let name = mapping(v.metadata.uid);
        if opened.contains_key(&name) {
            self.crypt.close(&name).await?;
        }
        let (p, uid) = (Some(pool.clone()), v.metadata.uid.to_string());
        let st = |s: tonic::Status| s.message().to_owned();
        self.driver
            .detach_volume(drv::DetachVolumeRequest {
                pool: p.clone(),
                uid: uid.clone(),
            })
            .await
            .map_err(st)?;
        self.driver
            .delete_volume(drv::DeleteVolumeRequest { pool: p, uid })
            .await
            .map_err(st)?;
        report.deleted = true;
        Ok(())
    }

    /// Creates and grows the device; opens it if in use, formatting it the first time.
    async fn make(
        &mut self,
        client: &mut ControlClient<Channel>,
        v: &Volume,
        pool: &drv::Pool,
        in_use: bool,
        opened: &BTreeMap<String, u64>,
        report: &mut VolumeReport,
    ) -> Result<(), String> {
        let uid = v.metadata.uid;
        let p = Some(pool.clone());
        let st = |s: tonic::Status| s.message().to_owned();
        let want = v.status.granted_bytes.saturating_add(LUKS_HEADER_BYTES);
        let mut size = self
            .driver
            .create_volume(drv::CreateVolumeRequest {
                pool: p.clone(),
                uid: uid.to_string(),
                size_bytes: want,
            })
            .await
            .map_err(st)?
            .size_bytes;
        if size < want {
            size = self
                .driver
                .grow_volume(drv::GrowVolumeRequest {
                    pool: p.clone(),
                    uid: uid.to_string(),
                    size_bytes: want,
                })
                .await
                .map_err(st)?
                .size_bytes;
        }
        report.created = true;
        report.size_bytes = size.saturating_sub(LUKS_HEADER_BYTES);
        report.formatted = v.status.formatted;

        let name = mapping(uid);
        if !in_use {
            if opened.contains_key(&name) {
                self.crypt.close(&name).await?;
            }
            self.driver
                .detach_volume(drv::DetachVolumeRequest {
                    pool: p,
                    uid: uid.to_string(),
                })
                .await
                .map_err(st)?;
            return Ok(());
        }

        let attached = self
            .driver
            .attach_volume(drv::AttachVolumeRequest {
                pool: p,
                uid: uid.to_string(),
            })
            .await
            .map_err(st)?;
        // Kinds that a newer driver may answer with are refused.
        let dev = match attached.device {
            Some(drv::attach_volume_response::Device::Block(b)) if b.path.starts_with('/') => {
                PathBuf::from(b.path)
            }
            _ => return Err("the driver answered with an unknown kind of device".into()),
        };
        if let Some(&open) = opened.get(&name) {
            if open < report.size_bytes {
                let key = self.key(client, v).await?;
                self.crypt.resize(&name, &key).await?;
            }
            return Ok(());
        }
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

    async fn report_pool(
        &mut self,
        client: &mut ControlClient<Channel>,
        uid: Uuid,
        r: PoolReport,
    ) -> Result<(), AgentError> {
        if self.pools_reported.get(&uid) == Some(&r) {
            return Ok(());
        }
        match client.report_pool(r.clone()).await {
            Ok(_) => {
                self.pools_reported.insert(uid, r);
                Ok(())
            }
            Err(s) => rejected(s, uid),
        }
    }

    async fn report_volume(
        &mut self,
        client: &mut ControlClient<Channel>,
        uid: Uuid,
        r: VolumeReport,
    ) -> Result<(), AgentError> {
        if self.volumes_reported.get(&uid) == Some(&r) {
            return Ok(());
        }
        match client.report_volume(r.clone()).await {
            Ok(_) => {
                self.volumes_reported.insert(uid, r);
                Ok(())
            }
            Err(s) => rejected(s, uid),
        }
    }
}

/// A report that the controller refused concerns that object only: the others go on.
fn rejected(s: tonic::Status, uid: Uuid) -> Result<(), AgentError> {
    use tonic::Code;
    match s.code() {
        Code::InvalidArgument
        | Code::PermissionDenied
        | Code::NotFound
        | Code::FailedPrecondition => {
            tracing::warn!(%uid, status = %s, "report rejected");
            Ok(())
        }
        _ => Err(s.into()),
    }
}
