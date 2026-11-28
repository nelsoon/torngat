//! `torngatd`: the Torngat node daemon.
//!
//! - `init`: create a new cluster on this node (CA, controller, first node, admin token, first
//!   join token).
//! - `join`: enroll this node into an existing cluster with a join token.
//! - `run`: run whatever this node was set up as (controller node: store, API server, controller,
//!   join endpoint and agent; other nodes: agent only).
//! - `restore`: set this machine up from a backup of the controller.
//! - `new-recovery-code`: make the code that opens later backups.
//! - `tpm-pin`: print this machine's TPM endorsement key pin, to pre-register it on a join token.
//!
//! State directory layout. The root is 0711 (others may traverse, not list: the unprivileged QEMU
//! user must reach `instances/`); everything secret is in 0700 directories as 0600 files:
//! ```text
//! node.json           role, node name, controller address (written last: marks setup done)
//! identity/           ca.pem, node.pem (chain), and node.key or node.tpmkey (TPM-wrapped blob)
//! pki/                ca.pem, ca.key, controller.pem (chain), controller.key, tpm-roots/*.pem
//!                     (vendor CAs trusted for TPM endorsement certificates) — controller only
//! keys/               platform.key, which every volume depends on — controller only
//! admin-token         bootstrap admin token for the API — controller only
//! store/              replicated store — controller only
//! instances/          workload runtime state
//! ```

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use torngat_agent::storage::Cryptsetup;
use torngat_api::Name;
use torngat_pki::{Ca, JoinToken, TpmPolicy};

mod backup;
mod node_key;
use node_key::{DEFAULT_TCTI, KeyConfig, TpmMode};

/// Default ports: control (mTLS, agents) and join (server-only TLS, enrollment).
const CONTROL_PORT: u16 = 7443;
const JOIN_PORT: u16 = 7444;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new cluster with this node as its controller.
    Init {
        #[arg(long, default_value = "/var/lib/torngat")]
        data: PathBuf,
        /// Node name, unique in the cluster.
        #[arg(long)]
        name: String,
        /// Whether nodes must hold their key in an attested TPM.
        #[arg(long, value_enum, default_value_t = TpmRequirement::Required)]
        tpm: TpmRequirement,
        /// TPM to use for this node's key.
        #[arg(long, default_value = DEFAULT_TCTI)]
        tpm_device: String,
        /// CA certificate(s) (PEM) trusted to issue TPM endorsement certificates; repeatable.
        /// Without any, TPM joins need a token pinned to the TPM (`tpm-pin`).
        #[arg(long)]
        tpm_ca: Vec<PathBuf>,
        /// Set the node up although the host's root file system is not sealed to its TPM, so that a
        /// stolen disk gives everything on it away (see `torngat-seal-root`).
        #[arg(long)]
        allow_unsealed_root: bool,
    },
    /// Enroll this node into an existing cluster.
    Join {
        #[arg(long, default_value = "/var/lib/torngat")]
        data: PathBuf,
        /// Controller host (name or IP address).
        #[arg(long)]
        controller: String,
        /// File holding the join token (keeps it out of the process list and shell history).
        #[arg(long)]
        token_file: PathBuf,
        /// Node name, unique in the cluster.
        #[arg(long)]
        name: String,
        #[arg(long, default_value_t = JOIN_PORT)]
        join_port: u16,
        #[arg(long, default_value_t = CONTROL_PORT)]
        control_port: u16,
        /// Where to keep the node key.
        #[arg(long, value_enum, default_value_t = TpmMode::On)]
        tpm: TpmMode,
        #[arg(long, default_value = DEFAULT_TCTI)]
        tpm_device: String,
        /// Set the node up although the host's root file system is not sealed to its TPM, so that a
        /// stolen disk gives everything on it away (see `torngat-seal-root`).
        #[arg(long)]
        allow_unsealed_root: bool,
    },
    /// Make a new recovery code, for backups made from now on (stop torngatd first).
    NewRecoveryCode {
        #[arg(long, default_value = "/var/lib/torngat")]
        data: PathBuf,
    },
    /// Set this machine up as the controller that a backup was made on. Asks for the recovery code.
    Restore {
        #[arg(long, default_value = "/var/lib/torngat")]
        data: PathBuf,
        #[arg(long)]
        backup: PathBuf,
        #[arg(long, default_value = DEFAULT_TCTI)]
        tpm_device: String,
        /// Set the node up although the host's root file system is not sealed to its TPM, so that a
        /// stolen disk gives everything on it away (see `torngat-seal-root`).
        #[arg(long)]
        allow_unsealed_root: bool,
    },
    /// Print this machine's TPM endorsement key pin (for `ek_sha256` on a join token).
    TpmPin {
        #[arg(long, default_value = DEFAULT_TCTI)]
        tpm_device: String,
    },
    /// Run this node.
    Run {
        #[arg(long, default_value = "/var/lib/torngat")]
        data: PathBuf,
        /// API server address (plain HTTP: loopback only until the API gets TLS).
        #[arg(long, default_value = "127.0.0.1:8080")]
        api: SocketAddr,
        /// Control endpoint for agents (controller node only).
        #[arg(long, default_value_t = SocketAddr::from(([0, 0, 0, 0], CONTROL_PORT)))]
        control: SocketAddr,
        /// Join endpoint for new nodes (controller node only).
        #[arg(long, default_value_t = SocketAddr::from(([0, 0, 0, 0], JOIN_PORT)))]
        join: SocketAddr,
        /// Tests only: every pool is a directory under DIR, volumes are files in it attached as
        /// loop devices, whatever the pool's driver. Nothing keeps the file system from filling up.
        #[arg(long, value_name = "DIR")]
        fake_storage: Option<PathBuf>,
        /// Room for volumes in each pool of --fake-storage.
        #[arg(long, default_value_t = 64, requires = "fake_storage")]
        fake_storage_gib: u64,
    },
}

type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum TpmRequirement {
    /// Only attested TPM-held node keys may join.
    Required,
    /// File keys are allowed too (lower assurance).
    Optional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    Controller,
    Agent,
}

/// `node.json`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeConfig {
    role: Role,
    name: Name,
    /// `host:port` of the control endpoint (agent nodes).
    controller: Option<String>,
    #[serde(default)]
    key: KeyConfig,
}

fn private_dir(p: &Path) -> Res<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(p)?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// The state root: traversable by the QEMU user, not listable.
fn data_root(p: &Path) -> Res<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o711)
        .create(p)?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o711))?;
    Ok(())
}

/// Writes a new 0600 file; never overwrites.
fn write_private(path: &Path, data: &[u8]) -> Res<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

fn node_name(raw: &str) -> Res<Name> {
    Name::new(raw).map_err(|e| format!("invalid node name {raw:?}: {e}").into())
}

/// Refuses to set up over an existing state directory.
fn fresh(data: &Path) -> Res<()> {
    if data.join("node.json").exists() {
        return Err(format!(
            "{} already holds a node; remove it to start over",
            data.display()
        )
        .into());
    }
    Ok(())
}

/// Also refuses what an interrupted setup left.
fn fresh_controller(data: &Path) -> Res<()> {
    fresh(data)?;
    if CONTROLLER_STATE.iter().any(|d| data.join(d).exists()) {
        return Err(format!(
            "{} holds a partial setup; remove it to start over",
            data.display()
        )
        .into());
    }
    Ok(())
}

/// `host` is a name, an IPv4 address or an IPv6 address (bare or in brackets), without a port.
fn host_port(host: &str, port: u16) -> Res<String> {
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
    if let Some(v6) = bare {
        v6.parse::<std::net::Ipv6Addr>()
            .map_err(|_| format!("invalid IPv6 address {host:?}"))?;
        return Ok(format!("{host}:{port}"));
    }
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        return Ok(format!("[{host}]:{port}"));
    }
    if host.is_empty() || host.contains(':') || host.contains('/') {
        return Err(format!(
            "--controller takes a host name or address without a port (got {host:?}); \
             use --join-port / --control-port for ports"
        )
        .into());
    }
    Ok(format!("{host}:{port}"))
}

/// Writes a 0600 file, replacing any previous one atomically (temp file + rename).
pub(crate) fn replace_private(path: &Path, data: &[u8]) -> Res<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    write_private(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

async fn open_store(data: &Path) -> Res<torngat_store::Store> {
    private_dir(&data.join("store"))?;
    let store = torngat_store::Store::open(
        data.join("store"),
        1,
        torngat_store::default_config(),
        torngat_store::nonet::NoNetwork,
    )
    .await?;
    if !store.raft().is_initialized().await? {
        store
            .initialize(BTreeMap::from([(1, torngat_store::Node::default())]))
            .await?;
    }
    store
        .raft()
        .wait(Some(Duration::from_secs(30)))
        .current_leader(1, "single node leader")
        .await?;
    Ok(store)
}

fn platform_key_path(data: &Path) -> PathBuf {
    data.join("keys/platform.key")
}

/// Creates it if the cluster never had one.
async fn load_platform_key(
    store: &torngat_store::Store,
    data: &Path,
) -> Res<torngat_keys::PlatformKey> {
    private_dir(&data.join("keys"))?;
    Ok(torngat_controller::volume_keys::load_platform_key(store, &platform_key_path(data)).await?)
}

/// Directories of a controller, besides the `node.json` that marks it complete.
const CONTROLLER_STATE: [&str; 4] = ["pki", "store", "identity", "keys"];

/// Writes the CA, the controller's certificate, the TPM roots, this node's identity and an admin
/// token. The operator is the trust root, so this node is enrolled without attestation.
fn set_up_controller(
    data: &Path,
    ca: &Ca,
    name: &Name,
    key_cfg: &KeyConfig,
    roots: &[Vec<u8>],
) -> Res<torngat_pki::NodeIdentity> {
    let pki = data.join("pki");
    let ident = data.join("identity");
    private_dir(&pki)?;
    private_dir(&ident)?;
    let tpm_roots = pki.join("tpm-roots");
    private_dir(&tpm_roots)?;
    for (i, pem) in roots.iter().enumerate() {
        write_private(&tpm_roots.join(format!("{i}.pem")), pem)?;
    }
    ca.save(&pki)?;
    let ctl = ca.issue_controller()?;
    write_private(&pki.join("controller.pem"), ctl.chain_pem.as_bytes())?;
    write_private(
        &pki.join("controller.key"),
        ctl.key_pem.as_deref().unwrap_or_default().as_bytes(),
    )?;
    let (key, _) = node_key::create_or_resume(&ident, key_cfg)?;
    let me = ca.sign_node_csr(&key.csr()?, name)?;
    let mut identity = me.identity(key.storage())?;
    // Close our TPM session first: some TPM transports take one client at a time.
    drop(key);
    if let KeyConfig::Tpm { tcti } = key_cfg {
        identity.ek_sha256 = node_key::ek_pin(tcti).ok();
    }
    write_private(&ident.join("ca.pem"), ca.cert_pem().as_bytes())?;
    write_private(&ident.join("node.pem"), me.chain_pem.as_bytes())?;
    let admin = torngat_pki::random_secret()?;
    write_private(&data.join("admin-token"), admin.as_bytes())?;
    Ok(identity)
}

/// Refuses to put secrets on a root file system that does not protect them.
fn check_root_sealed(allow_unsealed: bool) -> Res<()> {
    use torngat_agent::inventory::{DiskProtection, disk_protection};
    let why = match disk_protection() {
        DiskProtection::NoMarker => return Ok(()),
        DiskProtection::Provisional => {
            "is not sealed to this machine's TPM yet: run torngat-seal-root first"
        }
        DiskProtection::Unprotected => {
            "has its key on the boot partition, as this machine has no TPM: anyone with the disk can read it"
        }
    };
    if allow_unsealed {
        eprintln!("WARNING: the root file system {why}");
        return Ok(());
    }
    Err(format!("the root file system {why} (--allow-unsealed-root accepts that)").into())
}

async fn init(
    data: PathBuf,
    name: String,
    tpm: TpmRequirement,
    tpm_device: String,
    tpm_ca: Vec<PathBuf>,
) -> Res<()> {
    let name = node_name(&name)?;
    fresh_controller(&data)?;
    let required = tpm == TpmRequirement::Required;
    let key_cfg = node_key::for_controller(required, &tpm_device)?;
    // Vendor roots for TPM endorsement certificates: check them before writing anything.
    let mut roots = Vec::new();
    for f in &tpm_ca {
        let pem = std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?;
        torngat_pki::pem_certs(&pem)
            .map_err(|_| format!("{}: expected PEM certificates", f.display()))?;
        roots.push(pem);
    }

    data_root(&data)?;
    let ca = Ca::generate()?;
    let my_identity = set_up_controller(&data, &ca, &name, &key_cfg, &roots)?;

    let store = open_store(&data).await?;
    let setup = async {
        let platform_key = load_platform_key(&store, &data).await?;
        let code = backup::new_code(&store, &platform_key).await?;
        store
            .put(
                torngat_controller::keys::tpm_policy()?,
                serde_json::to_vec(&TpmPolicy { required })?,
                torngat_store::Precondition::Absent,
            )
            .await?;
        torngat_controller::identity::enroll(&store, &name, &my_identity).await?;
        let token = JoinToken::generate()?;
        let rec = token.record(
            None,
            torngat_pki::token::DEFAULT_TTL,
            "created by init".into(),
        );
        let key = torngat_controller::keys::join_token(token.id())?;
        store
            .put(
                key,
                serde_json::to_vec(&rec)?,
                torngat_store::Precondition::Absent,
            )
            .await?;
        Res::Ok((token, code))
    }
    .await;
    store.shutdown().await?;
    let (token, code) = setup?;

    let cfg = NodeConfig {
        role: Role::Controller,
        name: name.clone(),
        controller: None,
        key: key_cfg.clone(),
    };
    write_private(&data.join("node.json"), &serde_json::to_vec_pretty(&cfg)?)?;
    let join_token = data.join("join-token");
    write_private(&join_token, token.encode(&ca.hash()).as_bytes())?;

    println!("Cluster created; this node is {name}.");
    println!("  CA:          {}", ca.hash());
    println!("  Node key:    {key_cfg}");
    println!(
        "  TPM policy:  {}",
        if required {
            "required (only attested TPM keys may join)"
        } else {
            "optional (file keys allowed)"
        }
    );
    if required && roots.is_empty() {
        println!(
            "  No TPM vendor roots (--tpm-ca): joins need a token pinned to the TPM (ek_sha256, see `torngatd tpm-pin`)."
        );
    }
    println!(
        "  Admin token: {} (bootstrap only; keep it secret)",
        data.join("admin-token").display()
    );
    println!(
        "  Join token:  {} (single use, expires in 24 h)",
        join_token.display()
    );
    println!(
        "Start this node with: torngatd run --data {}",
        data.display()
    );
    println!(
        "Add a node: copy the join token to it, then run\n  torngatd join --controller <this host> --token-file <file>"
    );
    println!("More join tokens: POST /v1/platform/joinTokens on the API (admin token as Bearer).");
    println!();
    backup::print_code(&code)?;
    Ok(())
}

fn read_line() -> Res<zeroize::Zeroizing<String>> {
    let mut s = zeroize::Zeroizing::new(String::with_capacity(256));
    std::io::stdin().read_line(&mut s)?;
    Ok(s)
}

async fn new_recovery_code(data: PathBuf) -> Res<()> {
    let cfg: NodeConfig = serde_json::from_slice(&std::fs::read(data.join("node.json"))?)?;
    if cfg.role != Role::Controller {
        return Err("this node is not a controller".into());
    }
    let store = open_store(&data)
        .await
        .map_err(|e| format!("cannot open the store, is torngatd running? ({e})"))?;
    let made = async {
        let platform_key = load_platform_key(&store, &data).await?;
        backup::new_code(&store, &platform_key).await
    }
    .await;
    store.shutdown().await?;
    backup::print_code(&made?)?;
    println!("Backups made before still need the old code.");
    Ok(())
}

async fn join(
    data: PathBuf,
    controller: String,
    token_file: PathBuf,
    name: String,
    (join_port, control_port): (u16, u16),
    (tpm, tpm_device): (TpmMode, String),
) -> Res<()> {
    let name = node_name(&name)?;
    fresh(&data)?;
    let token = std::fs::read_to_string(&token_file)?;
    let join_addr = host_port(&controller, join_port)?;
    let control_addr = host_port(&controller, control_port)?;
    let key_cfg = node_key::choose(tpm, &tpm_device)?;
    data_root(&data)?;
    let ident = data.join("identity");
    private_dir(&ident)?;
    let (key, resume) = node_key::create_or_resume(&ident, &key_cfg)?;
    if resume {
        println!(
            "Resuming with the existing {key_cfg} key in {}.",
            ident.display()
        );
    }
    let enrolled = torngat_agent::join::join(&join_addr, token.trim(), &name, &key, resume).await?;
    replace_private(&ident.join("ca.pem"), enrolled.ca_pem.as_bytes())?;
    replace_private(&ident.join("node.pem"), enrolled.cert_chain_pem.as_bytes())?;
    let cfg = NodeConfig {
        role: Role::Agent,
        name: name.clone(),
        controller: Some(control_addr),
        key: key_cfg.clone(),
    };
    write_private(&data.join("node.json"), &serde_json::to_vec_pretty(&cfg)?)?;
    println!(
        "Joined as {name} ({key_cfg} key). The token is used up; you can delete {}.",
        token_file.display()
    );
    println!(
        "Start this node with: torngatd run --data {}",
        data.display()
    );
    Ok(())
}

/// The files of `pki/tpm-roots/*.pem`.
fn read_tpm_roots(dir: &Path) -> Res<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(format!("{}: {e}", dir.display()).into()),
    };
    for entry in entries {
        let p = entry?.path();
        if p.extension().is_some_and(|x| x == "pem") {
            out.push(std::fs::read(&p)?);
        }
    }
    Ok(out)
}

/// Every certificate in them.
fn tpm_anchors(dir: &Path) -> Res<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for pem in read_tpm_roots(dir)? {
        out.extend(torngat_pki::pem_certs(&pem).map_err(|e| format!("{}: {e}", dir.display()))?);
    }
    Ok(out)
}

/// The storage drivers: LVM (ZFS later), or `--fake-storage` for every pool.
fn storage_drivers(fake: Option<PathBuf>, gib: u64) -> torngat_agent::storage::Builtin {
    use torngat_agent::storage::{Builtin, FileDriver};
    Builtin::new(fake.map(|dir| {
        tracing::warn!(dir = %dir.display(), "fake storage: for tests only");
        FileDriver::new(dir, gib.saturating_mul(1 << 30), true)
    }))
}

async fn run(
    data: PathBuf,
    api: SocketAddr,
    control: SocketAddr,
    join_addr: SocketAddr,
    driver: torngat_agent::storage::Builtin,
) -> Res<()> {
    let cfg: NodeConfig = serde_json::from_slice(
        &std::fs::read(data.join("node.json"))
            .map_err(|e| format!("{}: {e} (run init or join first)", data.display()))?,
    )?;
    let ident = data.join("identity");
    // Re-assert permissions in case an older version or an operator loosened/tightened them.
    data_root(&data)?;
    private_dir(&ident)?;
    let read = |p: PathBuf| std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()));

    let runtime = torngat_agent::qemu::QemuRuntime::new(Default::default());
    let controller_url = match (&cfg.role, &cfg.controller) {
        // The local agent dials the control endpoint where it listens (loopback if on all).
        (Role::Controller, _) if control.ip().is_unspecified() => {
            let lo = if control.is_ipv6() {
                "[::1]"
            } else {
                "127.0.0.1"
            };
            format!("https://{lo}:{}", control.port())
        }
        (Role::Controller, _) => format!("https://{control}"),
        (Role::Agent, Some(c)) => format!("https://{c}"),
        (Role::Agent, None) => return Err("node.json: missing controller address".into()),
    };
    let agent_cfg = torngat_agent::AgentConfig {
        controller_url,
        controller_name: torngat_pki::CONTROLLER_NAME.into(),
        ca_pem: read(ident.join("ca.pem"))?,
        cert_pem: read(ident.join("node.pem"))?,
        key: node_key::load(&ident, &cfg.key)?,
    };

    if cfg.role == Role::Agent {
        tracing::info!(node = %cfg.name, "torngatd running (agent)");
        tokio::select! {
            () = torngat_agent::run(agent_cfg, runtime, driver, Cryptsetup) => {
                return Err("agent stopped".into());
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                return Ok(());
            }
        }
    }

    let pki = data.join("pki");
    private_dir(&pki)?;
    let ca = Arc::new(Ca::load(&pki)?);
    let anchors = tpm_anchors(&pki.join("tpm-roots"))?;
    let token = std::fs::read_to_string(data.join("admin-token"))?;
    let token = torngat_apiserver::AdminToken::new(token.trim())?;
    let store = open_store(&data).await?;

    let platform_key = Arc::new(load_platform_key(&store, &data).await?);
    // Image uploads, until their node has them.
    let uploads_dir = data.join("uploads");
    private_dir(&uploads_dir)?;
    let uploads = torngat_uploads::Uploads::new(uploads_dir);
    let ctl = torngat_controller::Controller::new(store.clone(), platform_key.clone())
        .with_uploads(uploads.clone());
    let backups = Arc::new(backup::Backups {
        store: store.clone(),
        platform_key,
        data: data.clone(),
        name: cfg.name.clone(),
    });
    let tls = torngat_controller::TlsConfig {
        cert_pem: read(pki.join("controller.pem"))?,
        key_pem: read(pki.join("controller.key"))?,
        client_ca_pem: ca.cert_pem().as_bytes().to_vec(),
    };
    let control_l = tokio::net::TcpListener::bind(control).await?;
    let join_l = tokio::net::TcpListener::bind(join_addr).await?;
    let controller = tokio::spawn(torngat_controller::serve(
        ctl.clone(),
        control_l,
        tls.clone(),
    ));
    let joiner = tokio::spawn(torngat_controller::serve_join(
        torngat_controller::JoinService::new(store.clone(), ca.clone(), anchors),
        join_l,
        tls.cert_pem.clone(),
        tls.key_pem.clone(),
    ));
    let scheduler = tokio::spawn(ctl.run_scheduler(Duration::from_millis(500)));
    let agent = tokio::spawn(torngat_agent::run(agent_cfg, runtime, driver, Cryptsetup));
    let state = torngat_apiserver::AppState {
        uploads: Some(uploads),
        store: store.clone(),
        token,
        ca_hash: ca.hash(),
        backup: torngat_apiserver::Backup::new(move || {
            let backups = backups.clone();
            async move {
                // The whole store is read and encrypted: not on the threads that serve.
                let rt = tokio::runtime::Handle::current();
                tokio::task::spawn_blocking(move || rt.block_on(backups.make()))
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|e| e.to_string())
            }
        }),
    };
    tracing::info!(node = %cfg.name, %api, %control, join = %join_addr, "torngatd running (controller)");
    // Any component stopping is fatal: never keep running half-alive.
    let result: Res<()> = tokio::select! {
        r = torngat_apiserver::serve(api, state) => r.map_err(Into::into),
        r = controller => Err(format!("controller stopped: {r:?}").into()),
        r = joiner => Err(format!("join endpoint stopped: {r:?}").into()),
        r = scheduler => Err(format!("scheduler stopped: {r:?}").into()),
        r = agent => Err(format!("agent stopped: {r:?}").into()),
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            Ok(())
        }
    };
    if let Err(e) = &result {
        tracing::error!(error = %e, "torngatd stopping");
    }
    store.shutdown().await?;
    result
}

fn main() -> std::process::ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match rt.block_on(main_async()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn main_async() -> Res<()> {
    // Logs go to stderr; stdout carries command output (e.g. `tpm-pin`).
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "info,openraft=warn,raft_log=warn,openraft_log_wal=warn,chunked_wal=warn,fjall=warn,lsm_tree=warn,tss_esapi=warn".into()
            }),
        )
        .init();
    match Cli::parse().cmd {
        Cmd::Init {
            data,
            name,
            tpm,
            tpm_device,
            tpm_ca,
            allow_unsealed_root,
        } => {
            check_root_sealed(allow_unsealed_root)?;
            init(data, name, tpm, tpm_device, tpm_ca).await
        }
        Cmd::NewRecoveryCode { data } => new_recovery_code(data).await,
        Cmd::Restore {
            data,
            backup,
            tpm_device,
            allow_unsealed_root,
        } => {
            check_root_sealed(allow_unsealed_root)?;
            backup::restore(data, backup, tpm_device).await
        }
        Cmd::TpmPin { tpm_device } => {
            println!("{}", node_key::ek_pin(&tpm_device)?);
            Ok(())
        }
        Cmd::Join {
            data,
            controller,
            token_file,
            name,
            join_port,
            control_port,
            tpm,
            tpm_device,
            allow_unsealed_root,
        } => {
            check_root_sealed(allow_unsealed_root)?;
            join(
                data,
                controller,
                token_file,
                name,
                (join_port, control_port),
                (tpm, tpm_device),
            )
            .await
        }
        Cmd::Run {
            data,
            api,
            control,
            join,
            fake_storage,
            fake_storage_gib,
        } => {
            let driver = storage_drivers(fake_storage, fake_storage_gib);
            run(data, api, control, join, driver).await
        }
    }
}
