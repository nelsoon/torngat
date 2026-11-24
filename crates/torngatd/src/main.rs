//! `torngatd`: the Torngat node daemon.
//!
//! - `init`: create a new cluster on this node (CA, controller, first node, admin token, first
//!   join token).
//! - `join`: enroll this node into an existing cluster with a join token.
//! - `run`: run whatever this node was set up as (controller node: store, API server, controller,
//!   join endpoint and agent; other nodes: agent only).
//!
//! State directory layout (all 0700/0600):
//! ```text
//! node.json           role, node name, controller address (written last: marks setup done)
//! identity/           ca.pem, node.pem (chain), node.key — this node's agent credentials
//! pki/                ca.pem, ca.key, controller.pem (chain), controller.key — controller only
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
use torngat_api::Name;
use torngat_pki::{Ca, JoinToken, KeyStorage};

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
        /// Node name (default: the host name).
        #[arg(long)]
        name: Option<String>,
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
        /// Node name (default: the host name).
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value_t = JOIN_PORT)]
        join_port: u16,
        #[arg(long, default_value_t = CONTROL_PORT)]
        control_port: u16,
    },
    /// Run this node.
    Run {
        #[arg(long, default_value = "/var/lib/torngat")]
        data: PathBuf,
        /// Unprivileged user QEMU runs as. Required when running as root.
        #[arg(long)]
        qemu_user: Option<String>,
        /// API server address (plain HTTP: loopback only until the API gets TLS).
        #[arg(long, default_value = "127.0.0.1:8080")]
        api: SocketAddr,
        /// Control endpoint for agents (controller node only).
        #[arg(long, default_value_t = SocketAddr::from(([0, 0, 0, 0], CONTROL_PORT)))]
        control: SocketAddr,
        /// Join endpoint for new nodes (controller node only).
        #[arg(long, default_value_t = SocketAddr::from(([0, 0, 0, 0], JOIN_PORT)))]
        join: SocketAddr,
    },
}

type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

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

fn node_name(arg: Option<String>) -> Res<Name> {
    let raw = match arg {
        Some(n) => n,
        None => {
            let h = std::fs::read_to_string("/proc/sys/kernel/hostname")?;
            h.trim()
                .split('.')
                .next()
                .unwrap_or_default()
                .to_lowercase()
        }
    };
    Name::new(&raw).map_err(|e| format!("invalid node name {raw:?} (use --name): {e}").into())
}

/// Refuses to set up over an existing state directory.
fn fresh(data: &Path) -> Res<()> {
    if data.join("node.json").exists() || data.join("identity").exists() {
        return Err(format!(
            "{} already holds a node; remove it to start over",
            data.display()
        )
        .into());
    }
    Ok(())
}

fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}") // IPv6 literal
    } else {
        format!("{host}:{port}")
    }
}

async fn open_store(data: &Path) -> Res<torngat_store::Store> {
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

async fn init(data: PathBuf, name: Option<String>) -> Res<()> {
    let name = node_name(name)?;
    fresh(&data)?;
    if data.join("pki").exists() || data.join("store").exists() {
        return Err(format!(
            "{} holds a partial setup; remove it to start over",
            data.display()
        )
        .into());
    }
    private_dir(&data)?;
    let pki = data.join("pki");
    let ident = data.join("identity");
    private_dir(&pki)?;
    private_dir(&ident)?;

    let ca = Ca::generate()?;
    ca.save(&pki)?;
    let ctl = ca.issue_controller()?;
    write_private(&pki.join("controller.pem"), ctl.chain_pem.as_bytes())?;
    write_private(
        &pki.join("controller.key"),
        ctl.key_pem.as_deref().unwrap_or_default().as_bytes(),
    )?;
    let me = ca.issue_node(&name)?;
    write_private(&ident.join("ca.pem"), ca.cert_pem().as_bytes())?;
    write_private(&ident.join("node.pem"), me.chain_pem.as_bytes())?;
    write_private(
        &ident.join("node.key"),
        me.key_pem.as_deref().unwrap_or_default().as_bytes(),
    )?;
    let admin = torngat_pki::random_secret()?;
    write_private(&data.join("admin-token"), admin.as_bytes())?;

    let store = open_store(&data).await?;
    let setup = async {
        torngat_controller::identity::enroll(&store, &name, &me.identity(KeyStorage::File)?)
            .await?;
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
        Res::Ok(token)
    }
    .await;
    store.shutdown().await?;
    let token = setup?;

    let cfg = NodeConfig {
        role: Role::Controller,
        name: name.clone(),
        controller: None,
    };
    write_private(&data.join("node.json"), &serde_json::to_vec_pretty(&cfg)?)?;
    let join_token = data.join("join-token");
    write_private(&join_token, token.encode(&ca.hash()).as_bytes())?;

    println!("Cluster created; this node is {name}.");
    println!("  CA:          {}", ca.hash());
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
    Ok(())
}

async fn join(
    data: PathBuf,
    controller: String,
    token_file: PathBuf,
    name: Option<String>,
    (join_port, control_port): (u16, u16),
) -> Res<()> {
    let name = node_name(name)?;
    fresh(&data)?;
    let token = std::fs::read_to_string(&token_file)?;
    let enrolled =
        torngat_agent::join::join(&host_port(&controller, join_port), token.trim(), &name).await?;
    private_dir(&data)?;
    let ident = data.join("identity");
    private_dir(&ident)?;
    write_private(&ident.join("ca.pem"), enrolled.ca_pem.as_bytes())?;
    write_private(&ident.join("node.pem"), enrolled.cert_chain_pem.as_bytes())?;
    write_private(&ident.join("node.key"), enrolled.key_pem.as_bytes())?;
    let cfg = NodeConfig {
        role: Role::Agent,
        name: name.clone(),
        controller: Some(host_port(&controller, control_port)),
    };
    write_private(&data.join("node.json"), &serde_json::to_vec_pretty(&cfg)?)?;
    println!(
        "Joined as {name}. The token is used up; you can delete {}.",
        token_file.display()
    );
    println!(
        "Start this node with: torngatd run --data {}",
        data.display()
    );
    Ok(())
}

async fn run(
    data: PathBuf,
    qemu_user: Option<String>,
    api: SocketAddr,
    control: SocketAddr,
    join_addr: SocketAddr,
) -> Res<()> {
    let cfg: NodeConfig = serde_json::from_slice(
        &std::fs::read(data.join("node.json"))
            .map_err(|e| format!("{}: {e} (run init or join first)", data.display()))?,
    )?;
    let ident = data.join("identity");
    let read = |p: PathBuf| std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()));

    let runtime = torngat_agent::qemu::QemuRuntime::new(torngat_agent::qemu::QemuConfig {
        state_dir: data.join("instances"),
        run_as: qemu_user,
        ..Default::default()
    })?;
    let controller_url = match (&cfg.role, &cfg.controller) {
        (Role::Controller, _) => format!("https://127.0.0.1:{}", control.port()),
        (Role::Agent, Some(c)) => format!("https://{c}"),
        (Role::Agent, None) => return Err("node.json: missing controller address".into()),
    };
    let agent_cfg = torngat_agent::AgentConfig {
        controller_url,
        controller_name: torngat_pki::CONTROLLER_NAME.into(),
        ca_pem: read(ident.join("ca.pem"))?,
        cert_pem: read(ident.join("node.pem"))?,
        key_pem: read(ident.join("node.key"))?,
    };

    if cfg.role == Role::Agent {
        tracing::info!(node = %cfg.name, "torngatd running (agent)");
        tokio::select! {
            () = torngat_agent::run(agent_cfg, runtime) => return Err("agent stopped".into()),
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                return Ok(());
            }
        }
    }

    let pki = data.join("pki");
    let ca = Arc::new(Ca::load(&pki)?);
    let token = std::fs::read_to_string(data.join("admin-token"))?;
    let token = torngat_apiserver::AdminToken::new(token.trim())?;
    let store = open_store(&data).await?;

    let ctl = torngat_controller::Controller::new(store.clone());
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
        torngat_controller::JoinService::new(store.clone(), ca.clone()),
        join_l,
        tls.cert_pem.clone(),
        tls.key_pem.clone(),
    ));
    let scheduler = tokio::spawn(ctl.run_scheduler(Duration::from_millis(500)));
    let agent = tokio::spawn(torngat_agent::run(agent_cfg, runtime));
    let state = torngat_apiserver::AppState {
        store: store.clone(),
        token,
        ca_hash: ca.hash(),
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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "info,openraft=warn,raft_log=warn,openraft_log_wal=warn,chunked_wal=warn,fjall=warn,lsm_tree=warn".into()
            }),
        )
        .init();
    match Cli::parse().cmd {
        Cmd::Init { data, name } => init(data, name).await,
        Cmd::Join {
            data,
            controller,
            token_file,
            name,
            join_port,
            control_port,
        } => {
            join(
                data,
                controller,
                token_file,
                name,
                (join_port, control_port),
            )
            .await
        }
        Cmd::Run {
            data,
            qemu_user,
            api,
            control,
            join,
        } => run(data, qemu_user, api, control, join).await,
    }
}
