//! Workload runtimes: QEMU ([`crate::qemu`]) and a fake one for tests.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use torngat_api::compute::{Instance, Runtime as RuntimeKind};
use uuid::Uuid;

/// A disk for an instance: one of its volumes, open on this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disk {
    pub volume: Uuid,
    /// The decrypted device.
    pub path: PathBuf,
    /// The instance boots from it.
    pub boot: bool,
    /// Its size in bytes, as the node last saw it.
    pub size: u64,
}

/// Runs instances on this node. Instances are identified by `metadata.uid`.
pub trait Runtime: Send + Sync + 'static {
    /// Which hypervisor this runtime uses (reported to the controller).
    fn kind(&self) -> Option<RuntimeKind>;
    /// Starts the instance with `disks` (its volumes, in order) if it is not running. Idempotent.
    fn start(
        &self,
        inst: &Instance,
        disks: &[Disk],
    ) -> impl Future<Output = Result<(), String>> + Send;
    /// Gives a running instance any of `disks` it does not have yet, and the new size of those
    /// that grew. Idempotent.
    fn attach(&self, uid: Uuid, disks: &[Disk]) -> impl Future<Output = Result<(), String>> + Send;
    /// Stops the instance if it is running. Idempotent.
    fn stop(&self, uid: Uuid) -> impl Future<Output = Result<(), String>> + Send;
    /// Uids of instances currently running.
    fn running(&self) -> impl Future<Output = Vec<Uuid>> + Send;
    /// The last [`running`](Self::running) could not tell about some instance: ask again soon.
    fn unsettled(&self) -> bool {
        false
    }
}

/// In-memory runtime for tests: the running instances and the disks each started with.
/// Instances named `fail-*` fail to start.
#[derive(Debug, Clone, Default)]
pub struct FakeRuntime(Arc<Mutex<BTreeMap<Uuid, Vec<Disk>>>>);

impl FakeRuntime {
    /// The disks a running instance started with.
    pub fn disks(&self, uid: Uuid) -> Option<Vec<Disk>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&uid)
            .cloned()
    }
}

impl Runtime for FakeRuntime {
    fn kind(&self) -> Option<RuntimeKind> {
        None
    }

    async fn start(&self, inst: &Instance, disks: &[Disk]) -> Result<(), String> {
        if inst.metadata.name.as_str().starts_with("fail-") {
            return Err("simulated start failure".into());
        }
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(inst.metadata.uid)
            .or_insert_with(|| disks.to_vec());
        Ok(())
    }

    async fn attach(&self, uid: Uuid, disks: &[Disk]) -> Result<(), String> {
        let mut m = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let have = m.get_mut(&uid).ok_or("not running")?;
        for d in disks {
            match have.iter_mut().find(|h| h.volume == d.volume) {
                Some(h) => h.size = h.size.max(d.size),
                None => have.push(d.clone()),
            }
        }
        Ok(())
    }

    async fn stop(&self, uid: Uuid) -> Result<(), String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&uid);
        Ok(())
    }

    async fn running(&self) -> Vec<Uuid> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .copied()
            .collect()
    }
}
