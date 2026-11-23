//! Completes long-running operations from observed state.
//!
//! An instance carries `status.pending_operation` until it first reaches its desired power state
//! (or fails). Each pass completes the operation record (creating it if the API server has not
//! written it yet), then clears the link. Both steps are idempotent, so a crash or store error at
//! any point is repaired by the next pass.

use torngat_api::compute::{Instance, InstancePhase, PowerState};
use torngat_api::operation::{Operation, OperationError};
use torngat_store::{Precondition, StoreError};

use crate::scheduler::{ScheduleError, list_all};
use crate::{Controller, keys};

/// What the pending operation's outcome is, if it is finished.
fn outcome(i: &Instance) -> Option<Option<OperationError>> {
    let s = &i.status;
    match (i.spec.power_state, s.phase, &s.node) {
        (_, InstancePhase::Failed, _) => Some(Some(OperationError {
            code: "INTERNAL".into(),
            message: s
                .message
                .clone()
                .unwrap_or_else(|| "instance failed".into()),
        })),
        (PowerState::Running, InstancePhase::Running, Some(_))
        | (PowerState::Stopped, InstancePhase::Stopped, _)
        | (PowerState::Stopped, _, None) => Some(None),
        _ => None,
    }
}

/// Writes the operation as done (creating it if missing). Idempotent.
pub(crate) async fn finish(ctl: &Controller, op: Operation) -> Result<(), ScheduleError> {
    let key = keys::operation(op.id)?;
    for _ in 0..8 {
        let cur = ctl.store.get(&key).await?;
        let pre = match &cur {
            Some(v) => {
                let existing: Operation = serde_json::from_slice(&v.value)?;
                if existing.done {
                    return Ok(());
                }
                Precondition::Revision(v.revision)
            }
            None => Precondition::Absent,
        };
        match ctl
            .store
            .put(key.clone(), serde_json::to_vec(&op)?, pre)
            .await
        {
            Ok(_) => return Ok(()),
            Err(StoreError::PreconditionFailed { .. }) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(()) // contended: the next pass retries
}

/// One pass. Returns the number of operations completed.
pub async fn complete_operations_once(ctl: &Controller) -> Result<usize, ScheduleError> {
    let mut n = 0;
    for (key, v) in list_all(&ctl.store, &keys::all_instances()?).await? {
        let Ok(mut inst) = serde_json::from_slice::<Instance>(&v.value) else {
            continue;
        };
        let Some(op_id) = inst.status.pending_operation else {
            continue;
        };
        let Some(error) = outcome(&inst) else {
            continue;
        };
        let target = format!(
            "{}/instances/{}",
            inst.metadata.scope.segments().join("/"),
            inst.metadata.name
        );
        finish(
            ctl,
            Operation {
                id: op_id,
                target,
                done: true,
                error,
            },
        )
        .await?;
        // Clear the link only after the operation is durably done.
        inst.status.pending_operation = None;
        inst.metadata.etag = None;
        match ctl
            .store
            .put(
                key,
                serde_json::to_vec(&inst)?,
                Precondition::Revision(v.revision),
            )
            .await
        {
            Ok(_) => n += 1,
            Err(StoreError::PreconditionFailed { .. }) => {} // next pass
            Err(e) => return Err(e.into()),
        }
    }
    Ok(n)
}
