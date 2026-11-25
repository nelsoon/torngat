//! Encrypted backup of the cluster (`/v1/platform/backup`). Platform admin only.

use std::pin::Pin;
use std::sync::Arc;

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use tokio::sync::Semaphore;

use crate::{ApiError, AppState};

type Made = Result<Option<Vec<u8>>, String>;
type Make = dyn Fn() -> Pin<Box<dyn Future<Output = Made> + Send>> + Send + Sync;

/// Makes backups, encrypted for the recovery code; `None` if there is no code.
#[derive(Clone)]
pub struct Backup {
    make: Arc<Make>,
    /// The whole store is in memory meanwhile: one at a time.
    one: Arc<Semaphore>,
}

impl std::fmt::Debug for Backup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Backup")
    }
}

impl Backup {
    pub fn new<F>(make: impl Fn() -> F + Send + Sync + 'static) -> Self
    where
        F: Future<Output = Made> + Send + 'static,
    {
        Self {
            make: Arc::new(move || Box::pin(make())),
            one: Arc::new(Semaphore::new(1)),
        }
    }
}

pub async fn get_backup(State(st): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let one = st
        .backup
        .one
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Aborted("a backup is being made; retry".into()))?;
    let making = (st.backup.make)();
    // A client that goes away does not stop it: it counts until it is done.
    let made = tokio::spawn(async move {
        let _one = one;
        making.await
    })
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?
    .map_err(ApiError::Internal)?;
    let backup = made.ok_or_else(|| {
        ApiError::FailedPrecondition(
            "there is no recovery code: run `torngatd new-recovery-code`".into(),
        )
    })?;
    let headers = [
        (header::CONTENT_TYPE, "application/octet-stream"),
        (header::CACHE_CONTROL, "no-store"),
    ];
    Ok((headers, backup))
}
