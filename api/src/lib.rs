//! Torngat resource model.
//!
//! Every API object follows the same shape: [`Object<S, St>`] = metadata + `spec` (desired state,
//! written by users) + `status` (observed state, written by the platform). Conventions follow
//! Google's API Improvement Proposals (AIP, <https://google.aip.dev>): hierarchical resource names,
//! etags for optimistic concurrency, long-running [`Operation`]s, and `request_id` for idempotent
//! creates.
//!
//! This crate is licensed Apache-2.0 so SDKs, the Terraform provider and third-party integrations
//! can depend on it freely.

#![forbid(unsafe_code)]

pub mod compute;
pub mod join;
pub mod meta;
pub mod name;
pub mod network;
pub mod node;
pub mod operation;
pub mod scheduling;
pub mod settings;

pub use meta::{Etag, Object, ObjectMeta};
pub use name::{Name, NameError, Scope};
pub use operation::Operation;
