//! Workload runtimes. M0 ships a fake runtime for tests; QEMU comes next.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};

use torngat_api::compute::{Instance, Runtime as RuntimeKind};
use uuid::Uuid;

/// Runs instances on this node. Instances are identified by `metadata.uid`.
pub trait Runtime: Send + Sync + 'static {
    /// Which hypervisor this runtime uses (reported to the controller).
    fn kind(&self) -> Option<RuntimeKind>;
    /// Starts the instance if it is not running. Idempotent.
    fn start(&self, inst: &Instance) -> impl Future<Output = Result<(), String>> + Send;
    /// Stops the instance if it is running. Idempotent.
    fn stop(&self, uid: Uuid) -> impl Future<Output = Result<(), String>> + Send;
    /// Uids of instances currently running.
    fn running(&self) -> impl Future<Output = Vec<Uuid>> + Send;
}

/// In-memory runtime for tests. Instances named `fail-*` fail to start.
#[derive(Debug, Clone, Default)]
pub struct FakeRuntime(Arc<Mutex<BTreeMap<Uuid, String>>>);

impl Runtime for FakeRuntime {
    fn kind(&self) -> Option<RuntimeKind> {
        None
    }

    async fn start(&self, inst: &Instance) -> Result<(), String> {
        if inst.metadata.name.as_str().starts_with("fail-") {
            return Err("simulated start failure".into());
        }
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(inst.metadata.uid, inst.metadata.name.to_string());
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
