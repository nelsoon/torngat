//! Errors in the AIP-193 shape: `{"error": {"code", "status", "message"}}`.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use torngat_store::StoreError;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("authentication required")]
    Unauthenticated,
    #[error("{0} not found")]
    NotFound(String),
    #[error("{0} already exists")]
    AlreadyExists(String),
    #[error("{0}")]
    Aborted(String),
    #[error("{0}")]
    FailedPrecondition(String),
    #[error("service unavailable, retry")]
    Unavailable,
    /// Details are logged, never returned to the client.
    #[error("internal error")]
    Internal(String),
}

impl ApiError {
    fn parts(&self) -> (StatusCode, &'static str) {
        match self {
            ApiError::InvalidArgument(_) => (StatusCode::BAD_REQUEST, "INVALID_ARGUMENT"),
            ApiError::Unauthenticated => (StatusCode::UNAUTHORIZED, "UNAUTHENTICATED"),
            ApiError::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            ApiError::AlreadyExists(_) => (StatusCode::CONFLICT, "ALREADY_EXISTS"),
            ApiError::Aborted(_) => (StatusCode::CONFLICT, "ABORTED"),
            ApiError::FailedPrecondition(_) => (StatusCode::BAD_REQUEST, "FAILED_PRECONDITION"),
            ApiError::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "UNAVAILABLE"),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL"),
        }
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotLeader { .. } | StoreError::Closed => ApiError::Unavailable,
            StoreError::ValueTooLarge => ApiError::InvalidArgument("object too large".into()),
            StoreError::PreconditionFailed { .. } => {
                ApiError::Aborted("the object changed; re-read it and retry".into())
            }
            other => ApiError::Internal(other.to_string()),
        }
    }
}

impl From<torngat_api::compute::InstanceError> for ApiError {
    fn from(e: torngat_api::compute::InstanceError) -> Self {
        match e {
            torngat_api::compute::InstanceError::DisksWhileRunning => {
                ApiError::FailedPrecondition(e.to_string())
            }
            e => ApiError::InvalidArgument(e.to_string()),
        }
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::Internal(format!("encoding: {e}"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let ApiError::Internal(detail) = &self {
            tracing::error!(%detail, "internal error");
        }
        let (code, status) = self.parts();
        let body = json!({"error": {"code": code.as_u16(), "status": status, "message": self.to_string()}});
        (code, Json(body)).into_response()
    }
}
