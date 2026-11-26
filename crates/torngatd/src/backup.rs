//! Backup and restore of the cluster: its CA, platform key and store.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use torngat_api::Name;
use torngat_controller::keys;
use torngat_controller::volume_keys::PlatformKeyRecord;
use torngat_keys::{PlatformKey, Recovery, RecoveryCode};
use torngat_pki::{Ca, TpmPolicy};
use torngat_store::{Key, Precondition, Store};
use zeroize::Zeroizing;

use crate::{
    NodeConfig, Res, Role, data_root, fresh_controller, node_key, open_store, platform_key_path,
    private_dir, read_line, read_tpm_roots, set_up_controller, write_private,
};

/// A new field needs a default, so that older backups still open.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Contents {
    #[serde(with = "time::serde::rfc3339")]
    create_time: OffsetDateTime,
    /// Name of the controller.
    name: Name,
    ca_pem: String,
    ca_key: Zeroizing<String>,
    platform_key: Zeroizing<String>,
    tpm_roots: Vec<String>,
    store: Vec<(Key, Vec<u8>)>,
}

/// Makes encrypted backups while the controller runs.
pub struct Backups {
    pub store: Store,
    pub platform_key: Arc<PlatformKey>,
    pub data: PathBuf,
    pub name: Name,
}

impl Backups {
    pub async fn make(&self) -> Res<Option<Vec<u8>>> {
        let Some(rec) = self.store.get(&keys::recovery()?).await? else {
            return Ok(None);
        };
        let recovery: Recovery = serde_json::from_slice(&rec.value)?;
        let pki = self.data.join("pki");
        let text =
            |p: PathBuf| std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()));
        let contents = Contents {
            create_time: OffsetDateTime::now_utc(),
            name: self.name.clone(),
            ca_pem: text(pki.join("ca.pem"))?,
            ca_key: Zeroizing::new(text(pki.join("ca.key"))?),
            platform_key: self.platform_key.encode(),
            tpm_roots: read_tpm_roots(&pki.join("tpm-roots"))?
                .into_iter()
                .map(String::from_utf8)
                .collect::<Result<_, _>>()?,
            store: self
                .store
                .export()
                .await?
                .into_iter()
                .map(|(k, v)| (k, v.value))
                .collect(),
        };
        tracing::info!(recovery_code = recovery.id(), "making a backup");
        Ok(Some(
            recovery.seal(&self.platform_key, &encode(&contents)?)?,
        ))
    }
}

fn encode(contents: &Contents) -> Res<Zeroizing<Vec<u8>>> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    // A buffer that grows would leave copies of the keys in memory.
    let mut size = Count(0);
    rmp_serde::encode::write_named(&mut size, contents)?;
    let mut out = Zeroizing::new(Vec::with_capacity(size.0));
    rmp_serde::encode::write_named(&mut *out, contents)?;
    Ok(out)
}

/// Makes a new recovery code, for backups made from now on.
pub async fn new_code(store: &Store, platform_key: &PlatformKey) -> Res<RecoveryCode> {
    let code = RecoveryCode::generate()?;
    store
        .put(
            keys::recovery()?,
            serde_json::to_vec(&code.register(platform_key)?)?,
            Precondition::None,
        )
        .await?;
    Ok(code)
}

pub fn print_code(code: &RecoveryCode) -> Res<()> {
    println!(
        "Recovery code, shown only now. Store it away from the cluster, and not with its backups:"
    );
    println!("\n    {}\n", *code.encode()?);
    println!(
        "With a backup it restores the cluster, and gives whoever has both full control of it."
    );
    Ok(())
}

/// Opens a backup and shows what it is.
fn open(file: &Path, code: &RecoveryCode) -> Res<Contents> {
    let sealed = std::fs::read(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let plain = code.open(sealed)?;
    Ok(rmp_serde::from_slice(&plain)?)
}

/// Sets this machine up as the controller that the backup was made on.
pub async fn restore(data: PathBuf, file: PathBuf, tpm_device: String) -> Res<()> {
    fresh_controller(&data)?;
    eprint!("Recovery code: ");
    let b = open(&file, &RecoveryCode::parse(&read_line()?)?)?;
    let ca = Ca::from_pem(&b.ca_pem, &b.ca_key)?;
    let platform_key = PlatformKey::decode(&b.platform_key)?;
    let find = |key: Key| b.store.iter().find(|(k, _)| *k == key).map(|(_, v)| v);
    // The key that the store needs, before anything is written.
    let record = find(keys::platform_key()?).ok_or("the backup has no platform key record")?;
    let record: PlatformKeyRecord = serde_json::from_slice(record)?;
    if record.id != platform_key.id() {
        return Err("the backup's platform key is not its cluster's".into());
    }
    let policy = match find(keys::tpm_policy()?) {
        Some(v) => serde_json::from_slice(v)?,
        None => TpmPolicy::default(),
    };
    let key_cfg = node_key::for_controller(policy.required, &tpm_device)?;
    for pem in &b.tpm_roots {
        torngat_pki::pem_certs(pem.as_bytes())?;
    }
    eprint!(
        "Restore controller {} as of {} (UTC)? Changes made since then are lost. \
         The old controller must be off for good. Type yes: ",
        b.name,
        b.create_time
            .replace_nanosecond(0)?
            .format(&time::format_description::well_known::Rfc3339)?,
    );
    if read_line()?.trim() != "yes" {
        return Err("not restored".into());
    }

    data_root(&data)?;
    private_dir(&data.join("keys"))?;
    let path = platform_key_path(&data);
    platform_key.save(&path)?;
    PlatformKey::sync(&path)?;
    let roots: Vec<_> = b.tpm_roots.into_iter().map(String::into_bytes).collect();
    let identity = set_up_controller(&data, &ca, &b.name, &key_cfg, &roots)?;

    let store = open_store(&data).await?;
    let filled = async {
        // A token that was used after the backup must not work again.
        let tokens = keys::join_tokens()?;
        let me = keys::node_identity(&b.name)?;
        for (k, v) in b.store {
            if k != me && !k.has_prefix(&tokens) {
                store.put(k, v, Precondition::Absent).await?;
            }
        }
        // This machine's own key replaces the old controller's.
        torngat_controller::identity::enroll(&store, &b.name, &identity).await?;
        Res::Ok(())
    }
    .await;
    store.shutdown().await?;
    filled?;

    let cfg = NodeConfig {
        role: Role::Controller,
        name: b.name.clone(),
        controller: None,
        key: key_cfg,
    };
    write_private(&data.join("node.json"), &serde_json::to_vec_pretty(&cfg)?)?;
    println!(
        "Restored controller {}. New admin token: {}",
        b.name,
        data.join("admin-token").display()
    );
    println!("The other nodes connect again if this machine has the old controller's address.");
    Ok(())
}
