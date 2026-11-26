//! Torngat API server.
//!
//! REST/JSON following Google's API Improvement Proposals (AIP): resource-oriented paths, standard
//! methods, etags for concurrency (AIP-154), long-running operations (AIP-151), `request_id` for
//! idempotent creates (AIP-155), AIP-193 errors.
//!
//! Security rules enforced here (see docs/SECURITY-NOTES.md):
//! - every request is authenticated before routing;
//! - server-set fields in request bodies are ignored;
//! - all user input is validated at this boundary (names in paths, specs, labels, sizes).
//!
//! M0 serves plain HTTP on loopback only; TLS comes with the internal CA.

#![forbid(unsafe_code)]

pub mod auth;
mod backup;
mod crud;
mod error;
mod handlers;
mod join_tokens;
mod settings;
mod storage;

use std::net::SocketAddr;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::get;
use torngat_store::Store;

pub use auth::AdminToken;
pub use backup::Backup;
pub use error::ApiError;

/// Largest accepted request body.
pub const MAX_BODY: usize = 256 * 1024;

#[derive(Clone, Debug)]
pub struct AppState {
    pub store: Store,
    pub token: AdminToken,
    /// Pin of the cluster CA, embedded in the join tokens this server hands out.
    pub ca_hash: torngat_pki::CaHash,
    pub backup: Backup,
}

async fn not_found() -> ApiError {
    ApiError::NotFound("resource".into())
}

/// Builds the HTTP router.
pub fn router(state: AppState) -> Router {
    use handlers::*;
    Router::new()
        .route(
            "/v1/orgs/{org}/projects/{project}/instances",
            get(list_instances).post(create_instance),
        )
        .route(
            "/v1/orgs/{org}/projects/{project}/instances/{instance}",
            get(get_instance)
                .patch(update_instance)
                .delete(delete_instance),
        )
        .route("/v1/operations/{id}", get(get_operation))
        .route("/v1/platform/nodes", get(list_nodes))
        .route("/v1/platform/nodes/{node}", get(get_node))
        .route(
            "/v1/platform/joinTokens",
            get(join_tokens::list_join_tokens).post(join_tokens::create_join_token),
        )
        .route(
            "/v1/platform/joinTokens/{id}",
            get(join_tokens::get_join_token).delete(join_tokens::delete_join_token),
        )
        .route(
            "/v1/platform/settings/tpm",
            get(settings::get_tpm).put(settings::put_tpm),
        )
        .route("/v1/platform/backup", get(backup::get_backup))
        .route(
            "/v1/platform/storagePools",
            get(storage::list_pools).post(storage::create_pool),
        )
        .route(
            "/v1/platform/storagePools/{pool}",
            get(storage::get_pool)
                .patch(storage::update_pool)
                .delete(storage::delete_pool),
        )
        .route(
            "/v1/platform/volumeTypes",
            get(storage::list_types).post(storage::create_type),
        )
        .route(
            "/v1/platform/volumeTypes/{type}",
            get(storage::get_type)
                .patch(storage::update_type)
                .delete(storage::delete_type),
        )
        .route(
            "/v1/orgs/{org}/projects/{project}/volumes",
            get(storage::list_volumes).post(storage::create_volume),
        )
        .route(
            "/v1/orgs/{org}/projects/{project}/volumes/{volume}",
            get(storage::get_volume)
                .patch(storage::update_volume)
                .delete(storage::delete_volume),
        )
        // Unknown paths go through authentication too, so they cannot be used to probe the API.
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_admin,
        ))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("refusing to listen on non-loopback address {0} without TLS")]
    NotLoopback(SocketAddr),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Serves the API until the process ends. Plain HTTP is only allowed on loopback, because the
/// bearer token would otherwise cross the network in clear text.
pub async fn serve(addr: SocketAddr, state: AppState) -> Result<(), ServeError> {
    if !addr.ip().is_loopback() {
        return Err(ServeError::NotLoopback(addr));
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router(state)).await?;
    Ok(())
}
