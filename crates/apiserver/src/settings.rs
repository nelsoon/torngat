//! Platform settings (`/v1/platform/settings/...`). Platform admin only.

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use torngat_api::settings::{ImageSettings, TpmSettings};
use torngat_pki::{TPM_POLICY_KEY, TpmPolicy};
use torngat_store::{Key, Precondition};

use crate::handlers::body;
use crate::{ApiError, AppState};

fn tpm_key() -> Result<Key, ApiError> {
    Key::new(TPM_POLICY_KEY.0, TPM_POLICY_KEY.1).map_err(|e| ApiError::Internal(e.to_string()))
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
    if req.required {
        tracing::info!("TPM policy changed: TPM required");
    } else {
        tracing::warn!("TPM requirement disabled: file-key nodes may join");
    }
    Ok(Json(req))
}

fn images_key() -> Result<Key, ApiError> {
    Key::new("platform", ["settings", "images"]).map_err(|e| ApiError::Internal(e.to_string()))
}

pub async fn get_images(State(st): State<AppState>) -> Result<Json<ImageSettings>, ApiError> {
    Ok(Json(match st.store.get(&images_key()?).await? {
        Some(v) => serde_json::from_slice(&v.value)?,
        None => ImageSettings::default(),
    }))
}

pub async fn put_images(
    State(st): State<AppState>,
    b: Result<Json<ImageSettings>, JsonRejection>,
) -> Result<Json<ImageSettings>, ApiError> {
    let req = body(b)?;
    req.validate().map_err(ApiError::InvalidArgument)?;
    st.store
        .put(images_key()?, serde_json::to_vec(&req)?, Precondition::None)
        .await?;
    tracing::info!(
        max_image_gib = req.max_image_gib,
        platform_private_sources = req.platform_private_sources,
        "image settings changed"
    );
    Ok(Json(req))
}
