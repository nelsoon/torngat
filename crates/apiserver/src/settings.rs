//! Platform settings (`/v1/platform/settings/...`). Platform admin only.

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use torngat_api::settings::TpmSettings;
use torngat_pki::TpmPolicy;
use torngat_store::{Key, Precondition};

use crate::handlers::body;
use crate::{ApiError, AppState};

fn tpm_key() -> Result<Key, ApiError> {
    // Must match the controller's `keys::tpm_policy`.
    Key::new("platform", ["settings", "tpm"]).map_err(|e| ApiError::Internal(e.to_string()))
}

pub async fn get_tpm(State(st): State<AppState>) -> Result<Json<TpmSettings>, ApiError> {
    // A missing record means the secure default (required).
    let policy = match st.store.get(&tpm_key()?).await? {
        Some(v) => serde_json::from_slice(&v.value)?,
        None => TpmPolicy::default(),
    };
    Ok(Json(TpmSettings {
        required: policy.required,
    }))
}

pub async fn put_tpm(
    State(st): State<AppState>,
    b: Result<Json<TpmSettings>, JsonRejection>,
) -> Result<Json<TpmSettings>, ApiError> {
    let req = body(b)?;
    let policy = TpmPolicy {
        required: req.required,
    };
    st.store
        .put(tpm_key()?, serde_json::to_vec(&policy)?, Precondition::None)
        .await?;
    tracing::info!(required = req.required, "TPM policy changed");
    Ok(Json(req))
}
