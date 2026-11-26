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
pub mod storage;

pub use meta::{Etag, Object, ObjectMeta};

/// Characters refused in text that people read: control characters, and those that are invisible or
/// change the direction of what follows, so that a message cannot pass for another.
pub fn is_hidden(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' | '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{180E}' | '\u{3164}' | '\u{E0000}'..='\u{E007F}')
}
pub use name::{Name, NameError, Scope};
pub use operation::Operation;
