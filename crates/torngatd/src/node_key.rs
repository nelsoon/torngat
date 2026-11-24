//! Where this node's private key lives: a file, or the TPM.

use std::path::Path;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::{Res, replace_private};

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

/// `--tpm` for join.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TpmMode {
    /// Use the TPM if there is one.
    Auto,
    /// Require a TPM.
    On,
    /// Keep the key in a file.
    Off,
}

pub const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";

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

/// A key ready to sign a CSR.
pub enum LocalKey {
    File(String),
    #[cfg(feature = "tpm")]
    Tpm(torngat_agent::tpm::TpmKey),
}

impl LocalKey {
    pub fn csr(&self) -> Res<Vec<u8>> {
        match self {
            LocalKey::File(pem) => Ok(torngat_pki::ca::node_csr(
                &torngat_pki::ca::parse_node_key(pem)?,
            )?),
            #[cfg(feature = "tpm")]
            LocalKey::Tpm(k) => Ok(k.csr()?),
        }
    }

    pub fn storage(&self) -> torngat_pki::KeyStorage {
        match self {
            LocalKey::File(_) => torngat_pki::KeyStorage::File,
            #[cfg(feature = "tpm")]
            LocalKey::Tpm(_) => torngat_pki::KeyStorage::Tpm,
        }
    }
}

/// Loads the key in `ident`, or creates and saves it first. Saving before joining lets a join
/// whose answer was lost simply be re-run with the same key.
pub fn create_or_resume(ident: &Path, cfg: &KeyConfig) -> Res<LocalKey> {
    match cfg {
        KeyConfig::File => {
            let path = ident.join("node.key");
            // An unreadable key (e.g. a crash while writing it) cannot have joined: replace it.
            let existing = std::fs::read_to_string(&path)
                .ok()
                .filter(|pem| torngat_pki::ca::parse_node_key(pem).is_ok());
            Ok(LocalKey::File(match existing {
                Some(pem) => {
                    println!("Resuming with the existing key in {}.", path.display());
                    pem
                }
                None => {
                    let pem = torngat_pki::ca::node_key()?.serialize_pem();
                    replace_private(&path, pem.as_bytes())?;
                    pem
                }
            }))
        }
        #[cfg(feature = "tpm")]
        KeyConfig::Tpm { tcti } => {
            use torngat_agent::tpm::TpmKey;
            let path = ident.join("node.tpmkey");
            if let Some(k) = std::fs::read(&path)
                .ok()
                .and_then(|b| TpmKey::load(tcti, &b).ok())
            {
                println!("Resuming with the existing TPM key in {}.", path.display());
                return Ok(LocalKey::Tpm(k));
            }
            let (k, blob) = TpmKey::create(tcti)?;
            replace_private(&path, &blob)?;
            Ok(LocalKey::Tpm(k))
        }
        #[cfg(not(feature = "tpm"))]
        KeyConfig::Tpm { .. } => Err("this torngatd was built without TPM support".into()),
    }
}

/// Loads the key for `run`.
pub fn load(ident: &Path, cfg: &KeyConfig) -> Res<torngat_agent::NodeKey> {
    let read = |p: &Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    match cfg {
        KeyConfig::File => Ok(torngat_agent::NodeKey::File(read(&ident.join("node.key"))?)),
        #[cfg(feature = "tpm")]
        KeyConfig::Tpm { tcti } => Ok(torngat_agent::NodeKey::Tpm(
            torngat_agent::tpm::TpmKey::load(tcti, &read(&ident.join("node.tpmkey"))?)?,
        )),
        #[cfg(not(feature = "tpm"))]
        KeyConfig::Tpm { .. } => Err("this torngatd was built without TPM support".into()),
    }
}

/// SHA-256 of the TPM's endorsement key, to pin on a join token.
#[cfg(feature = "tpm")]
pub fn ek_pin(tcti: &str) -> Res<String> {
    Ok(torngat_attest::ek_pin(
        &torngat_agent::tpm::ek_certificate(tcti)?,
    )?)
}

#[cfg(not(feature = "tpm"))]
pub fn ek_pin(_tcti: &str) -> Res<String> {
    Err("this torngatd was built without TPM support".into())
}
