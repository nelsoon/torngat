//! Long-running operations (AIP-151).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Returned by mutating calls that do not complete synchronously. Clients poll or watch it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    pub id: Uuid,
    /// Full resource path the operation acts on.
    pub target: String,
    pub done: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<OperationError>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationError {
    pub code: String,
    pub message: String,
}
