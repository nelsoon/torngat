//! Generated gRPC code for the internal control protocol (`proto/control.proto`).

#![allow(
    missing_debug_implementations,
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used
)]

/// Version tag of the JSON payloads carried in the protocol.
pub const API_VERSION: &str = "v1alpha1";

pub mod v1 {
    tonic::include_proto!("torngat.control.v1");

    impl std::fmt::Debug for VolumeKeyResponse {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("VolumeKeyResponse(<redacted>)")
        }
    }
}

/// Contract with storage drivers (`proto/storage.proto`).
pub mod storage {
    pub mod v1 {
        tonic::include_proto!("torngat.storage.v1");
    }
}
