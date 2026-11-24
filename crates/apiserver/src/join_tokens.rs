//! Join token administration (`/v1/platform/joinTokens`). Platform admin only.

use axum::Json;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use torngat_api::join::{CreateJoinTokenRequest, JoinTokenInfo};
use torngat_pki::{JoinToken, JoinTokenRecord};
use torngat_store::{Key, Precondition, Prefix, StoreError};

use crate::handlers::{ListQuery, ListResponse, body, query};
use crate::{ApiError, AppState};

fn key(id: &str) -> Result<Key, ApiError> {
    // Same layout as the controller's `keys::join_token`.
    Key::new("platform", ["jointokens", id]).map_err(|e| ApiError::Internal(e.to_string()))
}

fn info(r: JoinTokenRecord, token: Option<String>) -> JoinTokenInfo {
    JoinTokenInfo {
        name: r.id,
        node: r.node,
        description: r.description,
        create_time: r.create_time,
        expire_time: r.expire_time,
        token,
    }
}

fn not_found(id: &str) -> ApiError {
    ApiError::NotFound(format!("platform/joinTokens/{id}"))
}

pub async fn create_join_token(
    State(st): State<AppState>,
    b: Result<Json<CreateJoinTokenRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let req = body(b)?;
    req.validate().map_err(ApiError::InvalidArgument)?;
    let token = JoinToken::generate().map_err(|e| ApiError::Internal(e.to_string()))?;
    let rec = token.record(req.node.clone(), req.ttl(), req.description.clone());
    st.store
        .put(
            key(token.id())?,
            serde_json::to_vec(&rec)?,
            Precondition::Absent,
        )
        .await?;
    tracing::info!(id = %rec.id, node = ?rec.node, "join token created");
    let text = token.encode(&st.ca_hash);
    // The secret appears in this response only: never cache it.
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(info(rec, Some(text))),
    ))
}

pub async fn list_join_tokens(
    State(st): State<AppState>,
    q: Result<Query<ListQuery>, QueryRejection>,
) -> Result<Json<ListResponse<JoinTokenInfo>>, ApiError> {
    let q = query(q)?;
    let size = q.page_size.unwrap_or(100).clamp(1, 1000);
    let after = match q.page_token.as_deref() {
        Some(t) if torngat_pki::token::valid_id(t) => Some(key(t)?),
        Some(_) => return Err(ApiError::InvalidArgument("invalid page_token".into())),
        None => None,
    };
    let prefix =
        Prefix::new("platform", ["jointokens"]).map_err(|e| ApiError::Internal(e.to_string()))?;
    let rows = st.store.list(&prefix, after.as_ref(), size).await?;
    let full = rows.len() == size;
    let next_page_token = full
        .then(|| {
            rows.last()
                .map(|(k, _)| k.as_str().rsplit('/').next().unwrap_or_default().to_owned())
        })
        .flatten();
    let items = rows
        .into_iter()
        .filter_map(
            |(k, v)| match serde_json::from_slice::<JoinTokenRecord>(&v.value) {
                Ok(r) => Some(info(r, None)),
                // Possibly written by a newer version: skip it rather than fail the whole list.
                Err(e) => {
                    tracing::warn!(key = %k, error = %e, "skipping undecodable join token record");
                    None
                }
            },
        )
        .collect();
    Ok(Json(ListResponse {
        items,
        next_page_token,
    }))
}

pub async fn get_join_token(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<JoinTokenInfo>, ApiError> {
    if !torngat_pki::token::valid_id(&id) {
        return Err(not_found(&id));
    }
    let v = st
        .store
        .get(&key(&id)?)
        .await?
        .ok_or_else(|| not_found(&id))?;
    Ok(Json(info(serde_json::from_slice(&v.value)?, None)))
}

pub async fn delete_join_token(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !torngat_pki::token::valid_id(&id) {
        return Err(not_found(&id));
    }
    let k = key(&id)?;
    let v = st.store.get(&k).await?.ok_or_else(|| not_found(&id))?;
    st.store
        .delete(k, Precondition::Revision(v.revision))
        .await
        .map_err(|e| match e {
            StoreError::PreconditionFailed { current: None } => not_found(&id),
            e => e.into(),
        })?;
    tracing::info!(%id, "join token revoked");
    Ok(Json(serde_json::json!({})))
}
