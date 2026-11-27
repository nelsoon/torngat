//! QEMU/KVM runtime: one transient systemd unit per instance, `torngat-vm-<uid>.service`.
//!
//! - Each unit runs under a user of its own (`DynamicUser`), allocated by systemd when it starts:
//!   two instances never share a user, and none is root. Its only extra group is `kvm`.
//! - The unit is sandboxed (no capabilities, no network, `/dev/kvm` as its only device, a read-only
//!   system) and limited (memory, tasks, no core dumps: guest memory is the tenant's).
//! - Units outlive the agent: restarting or updating `torngatd` does not touch them. The agent finds
//!   its instances again by listing the units.
//! - State: `/var/lib/torngat-vm/<uid>/` (console log, kept after the instance stops) and
//!   `/run/torngat-vm/<uid>/` (QMP socket, gone with the unit); both 0700 and owned by the
//!   instance's user. QEMU's own messages go to the journal.
//! - QEMU arguments are built only from validated, bounded fields (uid, vcpus, memory), never from
//!   tenant strings; QEMU runs with its seccomp sandbox and without default devices or user
//!   config.
//! - Disks: QEMU cannot open any device but `/dev/kvm`. It starts paused; the agent opens the
//!   instance's decrypted volumes and hands QEMU the open files over QMP (`add-fd`), adds them as
//!   virtio disks (the boot disk first in the boot order), then lets the guest run. An instance
//!   whose start was interrupted (still paused, e.g. the agent restarted) is stopped and started
//!   again.

use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::json;
use torngat_api::compute::{Capability, Instance, MAX_DISKS, Runtime as RuntimeKind};
use uuid::Uuid;

use crate::qmp::Qmp;
use crate::runtime::{Disk, Runtime};

pub const UNIT_PREFIX: &str = "torngat-vm-";
const STATE_ROOT: &str = "/var/lib/torngat-vm";
const RUNTIME_ROOT: &str = "/run/torngat-vm";
/// The agent's own: `<uid>` once that instance's guest was let run.
const STARTED_ROOT: &str = "/run/torngat-vm-started";
const SLICE: &str = "torngat-vms.slice";

/// Bound on every QMP exchange.
const QMP_TIMEOUT: Duration = Duration::from_secs(5);
/// Time allowed for QEMU to come up and answer on QMP.
const START_TIMEOUT: Duration = Duration::from_secs(15);
/// Time systemd gives QEMU after SIGTERM before it kills it.
const KILL_AFTER: Duration = Duration::from_secs(10);

/// Capabilities this runtime can provide today.
const SUPPORTED: &[Capability] = &[Capability::LiveMigratable];

const MIB: u64 = 1 << 20;

const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const JOURNALCTL: &str = "/usr/bin/journalctl";

#[derive(Debug, Clone)]
pub struct QemuConfig {
    pub qemu: String,
    /// Time allowed for a guest to power off before it is stopped.
    pub stop_timeout: Duration,
}

impl Default for QemuConfig {
    fn default() -> Self {
        Self {
            qemu: "/usr/bin/qemu-system-x86_64".into(),
            stop_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QemuRuntime {
    cfg: QemuConfig,
}

/// The instance's unit.
pub fn unit(uid: Uuid) -> String {
    format!("{UNIT_PREFIX}{uid}.service")
}

/// The instance's console log, on the host.
pub fn console_log(uid: Uuid) -> String {
    format!("{STATE_ROOT}/{uid}/console.log")
}

fn qmp_socket(uid: Uuid) -> String {
    format!("{RUNTIME_ROOT}/{uid}/qmp.sock")
}

fn started(uid: Uuid) -> PathBuf {
    Path::new(STARTED_ROOT).join(uid.to_string())
}

/// QEMU's names for a volume's disk: block node (at most 31 characters), device, and the serial
/// number the guest sees (at most 20: `/dev/disk/by-id/virtio-<serial>`).
fn disk_names(volume: Uuid) -> (String, String, String) {
    let hex = volume.simple().to_string();
    (
        format!("v{}", &hex[..30]),
        format!("disk-{volume}"),
        hex[..20].to_owned(),
    )
}

/// Hands `disks` to the paused QEMU behind `q`, then lets the guest run.
fn attach_and_run(q: &mut Qmp, disks: &[Disk]) -> std::io::Result<()> {
    if disks.len() > DISK_PORTS {
        return Err(std::io::Error::other("too many disks"));
    }
    for (i, d) in disks.iter().enumerate() {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(rustix::fs::OFlags::DIRECT.bits() as i32)
            .open(&d.path)?;
        if !file.metadata()?.file_type().is_block_device() {
            return Err(std::io::Error::other("a disk is not a block device"));
        }
        q.execute_with_fd("add-fd", Some(json!({ "fdset-id": i })), file.as_fd())?;
        let (node, id, serial) = disk_names(d.volume);
        q.execute(
            "blockdev-add",
            Some(json!({
                "driver": "raw",
                "node-name": node,
                "file": {
                    "driver": "host_device",
                    "filename": format!("/dev/fdset/{i}"),
                    "cache": { "direct": true },
                },
            })),
        )?;
        let mut dev = json!({
            "driver": "virtio-blk-pci",
            "bus": disk_port(i),
            "drive": node,
            "id": id,
            "serial": serial,
        });
        if d.boot {
            dev["bootindex"] = json!(0);
        }
        q.execute("device_add", Some(dev))?;
    }
    q.execute("cont", None)?;
    Ok(())
}

/// The unit's settings. Pure function of validated fields, for testing.
pub fn properties(inst: &Instance) -> Vec<String> {
    let uid = inst.metadata.uid;
    let guest = inst.spec.memory_mib.saturating_mul(MIB);
    // QEMU itself: page tables, device emulation, buffers.
    let memory = guest.saturating_add(256 * MIB).saturating_add(guest / 16);
    let tasks = 64 + 4 * u64::from(inst.spec.vcpus);
    vec![
        format!("Description=Torngat instance {uid}"),
        "DynamicUser=yes".into(),
        "SupplementaryGroups=kvm".into(),
        format!("StateDirectory=torngat-vm/{uid}"),
        "StateDirectoryMode=0700".into(),
        format!("RuntimeDirectory=torngat-vm/{uid}"),
        "RuntimeDirectoryMode=0700".into(),
        "UMask=0077".into(),
        // Resources.
        format!("MemoryMax={memory}"),
        "MemorySwapMax=0".into(),
        format!("TasksMax={tasks}"),
        "LimitCORE=0".into(),
        // Devices: a /dev of its own (null, zero, random, ..., no shared /dev/shm) and /dev/kvm.
        "PrivateDevices=yes".into(),
        "BindPaths=/dev/kvm".into(),
        "DevicePolicy=closed".into(),
        "DeviceAllow=/dev/kvm rw".into(),
        "PrivateIPC=yes".into(),
        // Network: none for now; networks will hand QEMU its interfaces.
        "PrivateNetwork=yes".into(),
        "IPAddressDeny=any".into(),
        "RestrictAddressFamilies=AF_UNIX".into(),
        // Privileges.
        "CapabilityBoundingSet=".into(),
        "AmbientCapabilities=".into(),
        "NoNewPrivileges=yes".into(),
        "RestrictNamespaces=yes".into(),
        "RestrictRealtime=yes".into(),
        "LockPersonality=yes".into(),
        // KVM only: QEMU never generates code.
        "MemoryDenyWriteExecute=yes".into(),
        "SystemCallArchitectures=native".into(),
        "KeyringMode=private".into(),
        // What it sees of the host.
        "ProtectSystem=strict".into(),
        "ProtectHome=yes".into(),
        "PrivateTmp=yes".into(),
        "ProtectProc=invisible".into(),
        "ProcSubset=pid".into(),
        "ProtectKernelTunables=yes".into(),
        "ProtectKernelModules=yes".into(),
        "ProtectKernelLogs=yes".into(),
        "ProtectControlGroups=yes".into(),
        "ProtectClock=yes".into(),
        "ProtectHostname=yes".into(),
        // The system's buses: nothing to ask systemd or others for.
        "InaccessiblePaths=-/run/dbus -/run/systemd/private -/run/systemd/io.systemd.ManagedOOM"
            .into(),
        // The agent decides about restarts.
        "Restart=no".into(),
        format!("TimeoutStopSec={}", KILL_AFTER.as_secs()),
    ]
}

/// Disk slots: one per disk an instance can have (its data disks and boot disk), so that disks can
/// be added to a running guest.
const DISK_PORTS: usize = MAX_DISKS + 1;

/// The PCIe port of the `i`th disk slot.
fn disk_port(i: usize) -> String {
    format!("disk{i}")
}

/// QEMU command line for an instance. Pure function of validated fields, for testing.
pub fn args(inst: &Instance) -> Vec<String> {
    let uid = inst.metadata.uid;
    let mut args: Vec<String> = vec![
        "-name".into(),
        format!("guest={uid},debug-threads=on"),
        "-uuid".into(),
        uid.hyphenated().to_string(),
        "-machine".into(),
        "q35,accel=kvm".into(),
        "-cpu".into(),
        "host".into(),
        "-smp".into(),
        inst.spec.vcpus.to_string(),
        "-m".into(),
        format!("{}M", inst.spec.memory_mib),
        "-nodefaults".into(),
        "-no-user-config".into(),
        "-display".into(),
        "none".into(),
        "-chardev".into(),
        format!("file,id=console,path={},append=on", console_log(uid)),
        "-serial".into(),
        "chardev:console".into(),
        "-qmp".into(),
        format!("unix:{},server=on,wait=off", qmp_socket(uid)),
        // Paused until the agent has given it its disks.
        "-S".into(),
        "-boot".into(),
        "strict=on".into(),
        "-sandbox".into(),
        "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny".into(),
    ];
    for i in 0..DISK_PORTS {
        args.push("-device".into());
        args.push(format!(
            "pcie-root-port,id={},chassis={}",
            disk_port(i),
            i + 1
        ));
    }
    args
}

/// Effective uid of this process, from /proc (no unsafe code).
fn effective_uid() -> std::io::Result<u32> {
    let s = std::fs::read_to_string("/proc/self/status")?;
    s.lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| std::io::Error::other("cannot read effective uid"))
}

/// Unit states in which QEMU may still run.
fn running_state(s: &str) -> bool {
    matches!(s, "active" | "activating" | "reloading" | "deactivating")
}

impl QemuRuntime {
    pub fn new(cfg: QemuConfig) -> Self {
        Self { cfg }
    }

    async fn output(&self, cmd: &str, args: &[&str]) -> Result<String, String> {
        let out = tokio::process::Command::new(cmd)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .await
            .map_err(|e| format!("{cmd}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "{cmd} {}: {}",
                args.first().copied().unwrap_or_default(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    async fn show(&self, uid: Uuid, property: &str) -> Result<String, String> {
        let p = format!("--property={property}");
        let out = self
            .output(SYSTEMCTL, &["show", &p, "--value", &unit(uid)])
            .await?;
        Ok(out.trim().to_owned())
    }

    async fn is_running(&self, uid: Uuid) -> Result<bool, String> {
        Ok(running_state(&self.show(uid, "ActiveState").await?))
    }

    /// Runs `f` on a QMP session with the instance's QEMU, within `timeout`.
    ///
    /// The socket's directory belongs to the instance's user: a QEMU taken over by its guest could
    /// put another instance's socket there. Nothing is sent unless the other end is this unit's
    /// main process.
    async fn qmp<T: Send + 'static>(
        &self,
        uid: Uuid,
        timeout: Duration,
        f: impl FnOnce(&mut Qmp) -> std::io::Result<T> + Send + 'static,
    ) -> std::io::Result<T> {
        let main: i32 = self
            .show(uid, "MainPID")
            .await
            .map_err(std::io::Error::other)?
            .parse()
            .map_err(|_| std::io::Error::other("no main process"))?;
        let sock = qmp_socket(uid);
        let session = tokio::task::spawn_blocking(move || {
            let mut q = Qmp::connect(Path::new(&sock), main, QMP_TIMEOUT)?;
            f(&mut q)
        });
        tokio::time::timeout(timeout, session)
            .await
            .map_err(|_| std::io::Error::other("qmp timed out"))?
            .map_err(std::io::Error::other)?
    }

    /// QEMU's run state (e.g. `prelaunch` before the guest was let run, `running`).
    async fn status(&self, uid: Uuid) -> std::io::Result<String> {
        self.qmp(uid, QMP_TIMEOUT, |q| {
            let r = q.execute("query-status", None)?;
            Ok(r.get("status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned())
        })
        .await
    }

    async fn wait_gone(&self, uid: Uuid, timeout: Duration) -> Result<bool, String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if !self.is_running(uid).await? {
                return Ok(true);
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// The last lines QEMU wrote, from the journal.
    async fn log_tail(&self, uid: Uuid) -> String {
        let out = self
            .output(
                JOURNALCTL,
                &[
                    "--unit",
                    &unit(uid),
                    "--lines=5",
                    "--output=cat",
                    "--no-pager",
                ],
            )
            .await
            .unwrap_or_default();
        out.lines().collect::<Vec<_>>().join(" | ")
    }

    /// Stops the unit: systemd sends SIGTERM, then SIGKILL after [`KILL_AFTER`].
    async fn stop_unit(&self, uid: Uuid) -> Result<(), String> {
        self.output(SYSTEMCTL, &["stop", &unit(uid)])
            .await
            .map(|_| ())
    }
}

impl Runtime for QemuRuntime {
    fn kind(&self) -> Option<RuntimeKind> {
        Some(RuntimeKind::Qemu)
    }

    async fn start(&self, inst: &Instance, disks: &[Disk]) -> Result<(), String> {
        let uid = inst.metadata.uid;
        if let Some(c) = inst
            .spec
            .capabilities
            .iter()
            .find(|c| !SUPPORTED.contains(c))
        {
            return Err(format!("capability {c:?} is not available on this node"));
        }
        // Defense in depth: the controller validated the spec, but this process spends real
        // resources on it.
        inst.spec.validate().map_err(|e| e.to_string())?;
        if effective_uid().map_err(|e| e.to_string())? != 0 {
            return Err("instances need the agent to run as root".into());
        }
        if self.is_running(uid).await? {
            return Ok(());
        }
        // A unit that failed before is kept until this.
        let _ = self.output(SYSTEMCTL, &["reset-failed", &unit(uid)]).await;
        let _ = std::fs::remove_file(started(uid));
        let mut run: Vec<String> = vec![
            format!("--unit={}", unit(uid)),
            format!("--slice={SLICE}"),
            "--collect".into(),
            "--quiet".into(),
            "--service-type=exec".into(),
        ];
        run.extend(
            properties(inst)
                .into_iter()
                .map(|p| format!("--property={p}")),
        );
        run.push("--".into());
        run.push(self.cfg.qemu.clone());
        run.extend(args(inst));
        let run: Vec<&str> = run.iter().map(String::as_str).collect();
        self.output(SYSTEMD_RUN, &run).await?;

        // QEMU answers on QMP (it can still exit after starting, e.g. when memory or KVM
        // initialisation fails), then gets its disks and runs the guest.
        let deadline = tokio::time::Instant::now() + START_TIMEOUT;
        let mut failure = None;
        while tokio::time::Instant::now() < deadline {
            if self.status(uid).await.is_ok() {
                let disks = disks.to_vec();
                match self
                    .qmp(uid, START_TIMEOUT, move |q| attach_and_run(q, &disks))
                    .await
                {
                    Ok(()) => {
                        std::fs::create_dir_all(STARTED_ROOT)
                            .and_then(|()| std::fs::write(started(uid), b""))
                            .map_err(|e| format!("{STARTED_ROOT}: {e}"))?;
                        return Ok(());
                    }
                    Err(e) => {
                        failure = Some(e.to_string());
                        break;
                    }
                }
            }
            // The cleanup below also runs when systemctl fails.
            if !matches!(self.is_running(uid).await, Ok(true)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // Do not leave a half-started VM behind.
        let _ = self.stop_unit(uid).await;
        Err(match failure {
            Some(e) => format!("cannot give the instance its disks: {e}"),
            None => format!("qemu failed to start: {}", self.log_tail(uid).await),
        })
    }

    async fn stop(&self, uid: Uuid) -> Result<(), String> {
        if !self.is_running(uid).await? {
            return Ok(());
        }
        // Ask the guest, then systemd (which waits until it is stopped).
        let _ = self
            .qmp(uid, QMP_TIMEOUT, |q| q.execute("system_powerdown", None))
            .await;
        if self.wait_gone(uid, self.cfg.stop_timeout).await? {
            return Ok(());
        }
        match self.stop_unit(uid).await {
            // It may have gone meanwhile.
            Err(e) if self.is_running(uid).await? => Err(e),
            _ => Ok(()),
        }
    }

    async fn running(&self) -> Vec<Uuid> {
        let pattern = format!("{UNIT_PREFIX}*.service");
        let out = self
            .output(
                SYSTEMCTL,
                &[
                    "list-units",
                    "--all",
                    "--type=service",
                    "--plain",
                    "--no-legend",
                    "--no-pager",
                    &pattern,
                ],
            )
            .await;
        let out = match out {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(error = %e, "cannot list instance units");
                return vec![];
            }
        };
        let units = parse_units(&out);
        let mut running = Vec::with_capacity(units.len());
        for uid in units {
            if started(uid).exists() {
                running.push(uid);
                continue;
            }
            match self.status(uid).await.as_deref() {
                // Its start was interrupted: it never ran, so it is started again.
                Ok("prelaunch") => {
                    tracing::warn!(%uid, "instance left paused before it ran: stopping it");
                    if let Err(e) = self.stop_unit(uid).await {
                        tracing::warn!(%uid, error = %e, "cannot stop it");
                        running.push(uid);
                    }
                }
                Ok(_) => {
                    let _ = std::fs::create_dir_all(STARTED_ROOT)
                        .and_then(|()| std::fs::write(started(uid), b""));
                    running.push(uid);
                }
                // Not answering (yet): looked at again next time.
                Err(_) => running.push(uid),
            }
        }
        // Markers of instances that are gone.
        if let Ok(dir) = std::fs::read_dir(STARTED_ROOT) {
            for e in dir.flatten() {
                let gone = e
                    .file_name()
                    .to_str()
                    .and_then(|n| Uuid::parse_str(n).ok())
                    .is_none_or(|u| !running.contains(&u));
                if gone {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        running
    }
}

/// Uids of the running instances in `systemctl list-units --plain --no-legend` output
/// (UNIT LOAD ACTIVE SUB DESCRIPTION).
fn parse_units(out: &str) -> Vec<Uuid> {
    out.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let name = f.next()?;
            let active = f.nth(1)?;
            let uid = name.strip_prefix(UNIT_PREFIX)?.strip_suffix(".service")?;
            if !running_state(active) {
                return None;
            }
            Uuid::parse_str(uid).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::collections::BTreeSet;
    use torngat_api::compute::{InstanceSpec, PowerState};
    use torngat_api::{Name, Object, ObjectMeta, Scope};

    fn inst(name: &str, vcpus: u32, mem: u64, caps: &[Capability]) -> Instance {
        Object {
            metadata: ObjectMeta {
                name: Name::new(name).unwrap(),
                scope: Scope::Project {
                    org: Name::new("acme").unwrap(),
                    project: Name::new("web").unwrap(),
                },
                uid: Uuid::now_v7(),
                cell: None,
                labels: Default::default(),
                generation: 1,
                etag: None,
                create_time: None,
                update_time: None,
                delete_time: None,
            },
            spec: InstanceSpec {
                vcpus,
                memory_mib: mem,
                capabilities: caps.iter().copied().collect::<BTreeSet<_>>(),
                power_state: PowerState::Running,
                claims: vec![],
                boot_disk: None,
                disks: vec![],
            },
            status: Default::default(),
        }
    }

    #[test]
    fn args_use_only_validated_fields_and_sandbox() {
        let i = inst("vm-1", 2, 512, &[]);
        let a = args(&i);
        assert!(a.windows(2).any(|w| w[0] == "-smp" && w[1] == "2"));
        assert!(a.windows(2).any(|w| w[0] == "-m" && w[1] == "512M"));
        assert!(a.iter().any(|x| x.starts_with("on,obsolete=deny")));
        assert!(a.contains(&"-nodefaults".to_string()));
        // The user-chosen instance name never reaches the command line.
        assert!(!a.iter().any(|x| x.contains("vm-1")));
        assert!(!properties(&i).iter().any(|x| x.contains("vm-1")));
    }

    #[test]
    fn units_are_confined_and_limited() {
        let i = inst("vm-1", 2, 1024, &[]);
        let p = properties(&i);
        for want in [
            "DynamicUser=yes",
            "LimitCORE=0",
            "DevicePolicy=closed",
            "DeviceAllow=/dev/kvm rw",
            "PrivateNetwork=yes",
            "CapabilityBoundingSet=",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "Restart=no",
        ] {
            assert!(p.iter().any(|x| x == want), "missing {want}");
        }
        let gib = 1024 * MIB;
        let mem = format!("MemoryMax={}", gib + 256 * MIB + gib / 16);
        assert!(p.contains(&mem), "{p:?}");
        assert!(p.contains(&"TasksMax=72".to_string()));
        assert!(p.contains(&format!("StateDirectory=torngat-vm/{}", i.metadata.uid)));
    }

    #[test]
    fn units_are_found_again() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let out = format!(
            "torngat-vm-{a}.service loaded active running Torngat instance {a}\n\
             torngat-vm-{b}.service loaded failed failed Torngat instance {b}\n\
             torngat-vm-x.service loaded active running other\n\
             torngatd.service loaded active running Torngat node daemon\n"
        );
        assert_eq!(parse_units(&out), vec![a]);
    }

    #[tokio::test]
    async fn refuses_unsupported_capabilities() {
        let r = QemuRuntime::new(QemuConfig::default());
        let e = r
            .start(&inst("vm-gpu", 1, 128, &[Capability::Gpu]), &[])
            .await
            .unwrap_err();
        assert!(e.contains("not available"), "{e}");
    }
}
