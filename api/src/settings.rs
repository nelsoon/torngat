//! Platform settings (`/v1/platform/settings/...`).

use serde::{Deserialize, Serialize};

/// Body of `GET` and `PUT /v1/platform/settings/tpm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TpmSettings {
    /// Only attested TPM-held node keys may join.
    pub required: bool,
}
