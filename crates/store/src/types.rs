//! Commands replicated through Raft and their results.

use std::fmt;
use std::io::Cursor;

use serde::{Deserialize, Serialize};

use crate::key::Key;

/// Maximum size of a stored value. Objects are small (specs and durable status); anything larger
/// belongs in object storage.
pub const MAX_VALUE_LEN: usize = 1024 * 1024;

/// Condition a write must satisfy to be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Precondition {
    /// Always apply.
    None,
    /// Apply only if the key does not exist (create).
    Absent,
    /// Apply only if the key exists and was last written at this revision (compare-and-swap).
    Revision(u64),
}

/// A state machine command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    Put {
        key: Key,
        value: Vec<u8>,
        precondition: Precondition,
    },
    Delete {
        key: Key,
        precondition: Precondition,
    },
}

impl Command {
    pub fn key(&self) -> &Key {
        match self {
            Command::Put { key, .. } | Command::Delete { key, .. } => key,
        }
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print values: they may hold sensitive data.
        match self {
            Command::Put {
                key,
                value,
                precondition,
            } => write!(f, "put {key} ({} bytes, {precondition:?})", value.len()),
            Command::Delete { key, precondition } => write!(f, "delete {key} ({precondition:?})"),
        }
    }
}

/// Result of applying a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// The command was applied at `revision` (the log index of its entry).
    Applied { revision: u64 },
    /// The precondition did not hold; `current` is the key's revision, if it exists.
    PreconditionFailed { current: Option<u64> },
    /// Not a command (blank or membership entry).
    None,
}

/// A stored value and the revision of the write that stored it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Versioned {
    pub revision: u64,
    pub value: Vec<u8>,
}

/// Raft node address (filled in when the network layer exists).
pub type Node = openraft::BasicNode;
pub type NodeId = u64;
pub type SnapshotData = Cursor<Vec<u8>>;

openraft::declare_raft_types!(
    /// Type configuration of the control-plane store.
    pub TypeConfig:
        D = Command,
        R = Response,
        NodeId = NodeId,
        Node = Node,
);

pub type Raft = openraft::Raft<TypeConfig, crate::sm::StateMachine>;
