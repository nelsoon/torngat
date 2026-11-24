//! `torngatd`: M0 development entry points.
//!
//! - `dev-certs`: throwaway CA, controller and node certificates for a lab.
//! - `dev-single`: one node running store, API server, controller and agent (QEMU runtime).
//!
//! These are scaffolding until `init` / `join` (internal CA, join tokens, TPM keys) exist.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write a throwaway CA plus controller and node certificates into DIR.
    DevCerts {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        node: String,
    },
    /// Run a single-node cluster (store, API, controller, agent) in this process.
    DevSingle {
        #[arg(long, default_value = "/var/lib/torngat")]
        data: PathBuf,
        #[arg(long)]
        certs: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8080")]
        api: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:7443")]
        control: SocketAddr,
        /// File containing the bootstrap admin token (at least 32 characters).
        #[arg(long)]
        token_file: PathBuf,
        /// Unprivileged user QEMU runs as. Required when running as root.
        #[arg(long)]
        qemu_user: Option<String>,
    },
}

type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn write_private(path: &Path, data: &[u8]) -> Res<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    // `mode` only applies on creation: also fix permissions of a file that already existed.
    use std::os::unix::fs::PermissionsExt;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(data)?;
    Ok(())
}

fn dev_certs(out: &Path, node: &str) -> Res<()> {
    // Same rule the controller applies to the certificate's node name.
    torngat_api::Name::new(node).map_err(|e| format!("invalid node name: {e}"))?;
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(out)?;
        std::fs::set_permissions(out, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut p = CertificateParams::new(Vec::<String>::new())?;
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(p, KeyPair::generate()?)?;
    write_private(&out.join("ca.pem"), ca.pem().as_bytes())?;
    for (file, san) in [
        ("controller", "controller.torngat".to_owned()),
        ("node", format!("{node}.node.torngat")),
    ] {
        let key = KeyPair::generate()?;
        let cert = CertificateParams::new(vec![san])?.signed_by(&key, &ca)?;
        write_private(&out.join(format!("{file}.pem")), cert.pem().as_bytes())?;
        write_private(
            &out.join(format!("{file}.key")),
            key.serialize_pem().as_bytes(),
        )?;
    }
    println!(
        "wrote ca.pem, controller.{{pem,key}}, node.{{pem,key}} to {}",
        out.display()
    );
    Ok(())
}

async fn dev_single(
    data: PathBuf,
    certs: PathBuf,
    api: SocketAddr,
    control: SocketAddr,
    token_file: PathBuf,
    qemu_user: Option<String>,
) -> Res<()> {
    let read = |f: &str| std::fs::read(certs.join(f));
    let token = std::fs::read_to_string(&token_file)?;
    let token = torngat_apiserver::AdminToken::new(token.trim())?;

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

    let ctl = torngat_controller::Controller::new(store.clone());
    let listener = tokio::net::TcpListener::bind(control).await?;
    let tls = torngat_controller::TlsConfig {
        cert_pem: read("controller.pem")?,
        key_pem: read("controller.key")?,
        client_ca_pem: read("ca.pem")?,
    };
    let controller = tokio::spawn(torngat_controller::serve(ctl.clone(), listener, tls));
    let scheduler = tokio::spawn(ctl.run_scheduler(Duration::from_millis(500)));

    let runtime = torngat_agent::qemu::QemuRuntime::new(torngat_agent::qemu::QemuConfig {
        state_dir: data.join("instances"),
        run_as: qemu_user,
        ..Default::default()
    })?;
    let agent = torngat_agent::AgentConfig {
        controller_url: format!("https://{control}"),
        controller_name: "controller.torngat".into(),
        ca_pem: read("ca.pem")?,
        cert_pem: read("node.pem")?,
        key_pem: read("node.key")?,
    };
    let agent = tokio::spawn(torngat_agent::run(agent, runtime));

    let state = torngat_apiserver::AppState {
        store: store.clone(),
        token,
    };
    tracing::info!(%api, %control, "torngatd dev-single running");
    // Any component stopping is fatal: never keep running half-alive.
    let result: Res<()> = tokio::select! {
        r = torngat_apiserver::serve(api, state) => r.map_err(Into::into),
        r = controller => Err(format!("controller stopped: {r:?}").into()),
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

#[tokio::main]
async fn main() -> Res<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "info,openraft=warn,raft_log=warn,openraft_log_wal=warn".into()
            }),
        )
        .init();
    match Cli::parse().cmd {
        Cmd::DevCerts { out, node } => dev_certs(&out, &node),
        Cmd::DevSingle {
            data,
            certs,
            api,
            control,
            token_file,
            qemu_user,
        } => dev_single(data, certs, api, control, token_file, qemu_user).await,
    }
}
