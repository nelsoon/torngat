//! Where this node's private key lives: a file, or the TPM.

use std::path::Path;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use torngat_agent::NodeKey;

use crate::{Res, replace_private};

pub use torngat_agent::DEFAULT_TPM_TCTI as DEFAULT_TCTI;

/// Recorded in `node.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyConfig {
    /// `identity/node.key`, PKCS#8 PEM (lower assurance).
    #[default]
    File,
    /// `identity/node.tpmkey`: a blob only this TPM can load.
    Tpm { tcti: String },
}

impl std::fmt::Display for KeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyConfig::File => f.write_str("file"),
            KeyConfig::Tpm { tcti } => write!(f, "TPM ({tcti})"),
        }
    }
}

/// Where to keep the node key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TpmMode {
    /// Use the TPM if there is one.
    Auto,
    /// Require a TPM.
    On,
    /// Keep the key in a file.
    Off,
}

#[cfg(feature = "tpm")]
fn tpm_available(tcti: &str) -> bool {
    torngat_agent::tpm::available(tcti)
}

#[cfg(not(feature = "tpm"))]
fn tpm_available(_tcti: &str) -> bool {
    false
}

pub fn choose(mode: TpmMode, tcti: &str) -> Res<KeyConfig> {
    match mode {
        TpmMode::Off => Ok(KeyConfig::File),
        TpmMode::Auto if !tpm_available(tcti) => Ok(KeyConfig::File),
        TpmMode::Auto | TpmMode::On => {
            if !cfg!(feature = "tpm") {
                return Err("this torngatd was built without TPM support".into());
            }
            if !tpm_available(tcti) {
                return Err(format!("no TPM answers at {tcti}").into());
            }
            Ok(KeyConfig::Tpm {
                tcti: tcti.to_owned(),
            })
        }
    }
}

/// Loads the key in `ident`, or creates and saves it first; says whether it already existed.
/// Saving before joining lets a join whose answer was lost simply be re-run with the same key.
pub fn create_or_resume(ident: &Path, cfg: &KeyConfig) -> Res<(NodeKey, bool)> {
    match cfg {
        KeyConfig::File => {
            let path = ident.join("node.key");
            // An unreadable key (e.g. a crash while writing it) cannot have joined: replace it.
            let existing = std::fs::read_to_string(&path)
                .ok()
                .filter(|pem| torngat_pki::ca::parse_node_key(pem).is_ok());
            Ok(match existing {
                Some(pem) => (NodeKey::File(pem.into_bytes()), true),
                None => {
                    let pem = torngat_pki::ca::node_key()?.serialize_pem();
                    replace_private(&path, pem.as_bytes())?;
                    (NodeKey::File(pem.into_bytes()), false)
                }
            })
        }
        #[cfg(feature = "tpm")]
        KeyConfig::Tpm { tcti } => {
            use torngat_agent::tpm::TpmKey;
            let path = ident.join("node.tpmkey");
            // Only a missing or damaged blob means "no key yet"; a TPM error is reported, so a
            // transient failure never replaces a key that may already be enrolled.
            match std::fs::read(&path) {
                Ok(b) => match TpmKey::load(tcti, &b) {
                    Ok(k) => return Ok((NodeKey::Tpm(k), true)),
                    Err(torngat_agent::tpm::TpmError::BadBlob) => {}
                    Err(e) => return Err(format!("{}: {e}", path.display()).into()),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("{}: {e}", path.display()).into()),
            }
            let (k, blob) = TpmKey::create(tcti)?;
            replace_private(&path, &blob)?;
            Ok((NodeKey::Tpm(k), false))
        }
        #[cfg(not(feature = "tpm"))]
        KeyConfig::Tpm { .. } => Err("this torngatd was built without TPM support".into()),
    }
}

/// Loads the key for `run`.
pub fn load(ident: &Path, cfg: &KeyConfig) -> Res<NodeKey> {
    let read = |p: &Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    match cfg {
        KeyConfig::File => Ok(NodeKey::File(read(&ident.join("node.key"))?)),
        #[cfg(feature = "tpm")]
        KeyConfig::Tpm { tcti } => Ok(NodeKey::Tpm(torngat_agent::tpm::TpmKey::load(
            tcti,
            &read(&ident.join("node.tpmkey"))?,
        )?)),
        #[cfg(not(feature = "tpm"))]
        KeyConfig::Tpm { .. } => Err("this torngatd was built without TPM support".into()),
    }
}

/// SHA-256 of the TPM's endorsement key, to pin on a join token.
pub fn ek_pin(tcti: &str) -> Res<String> {
    #[cfg(feature = "tpm")]
    return Ok(torngat_attest::ek_pin(
        &torngat_agent::tpm::ek_certificate(tcti)?,
    )?);
    #[cfg(not(feature = "tpm"))]
    {
        let _ = tcti;
        Err("this torngatd was built without TPM support".into())
    }
}
