//! Platform settings (`/v1/platform/settings/...`).

use serde::{Deserialize, Serialize};

/// Body of `GET` and `PUT /v1/platform/settings/tpm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TpmSettings {
    /// Only attested TPM-held node keys may join.
    pub required: bool,
}

/// Default of [`ImageSettings::max_image_gib`].
pub const DEFAULT_MAX_IMAGE_GIB: u64 = 64;

fn default_max_image_gib() -> u64 {
    DEFAULT_MAX_IMAGE_GIB
}

/// Body of `GET` and `PUT /v1/platform/settings/images`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSettings {
    /// Largest download, and largest disk, of an image.
    #[serde(default = "default_max_image_gib")]
    pub max_image_gib: u64,
    /// Platform images may come from private and shared (CGNAT) addresses: a mirror on the
    /// operator's network. Project images never do.
    #[serde(default)]
    pub platform_private_sources: bool,
}

impl Default for ImageSettings {
    fn default() -> Self {
        Self {
            max_image_gib: DEFAULT_MAX_IMAGE_GIB,
            platform_private_sources: false,
        }
    }
}

impl ImageSettings {
    pub fn validate(&self) -> Result<(), String> {
        if (1..=crate::storage::MAX_VOLUME_GIB).contains(&self.max_image_gib) {
            Ok(())
        } else {
            Err(format!(
                "max_image_gib must be between 1 and {}",
                crate::storage::MAX_VOLUME_GIB
            ))
        }
    }

    pub fn max_image_bytes(&self) -> u64 {
        self.max_image_gib.saturating_mul(crate::storage::GIB)
    }
}
