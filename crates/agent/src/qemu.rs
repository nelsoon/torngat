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
//!   again: the agent asks each instance it finds once whether its guest ran.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{Seek, SeekFrom};
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::net::UnixStream;

use serde_json::json;
use torngat_api::compute::{Capability, Instance, MAX_DISKS, Runtime as RuntimeKind};
use uuid::Uuid;

use crate::qmp::Qmp;
use crate::runtime::{Disk, Runtime};

pub const UNIT_PREFIX: &str = "torngat-vm-";
const STATE_ROOT: &str = "/var/lib/torngat-vm";
const RUNTIME_ROOT: &str = "/run/torngat-vm";
pub(crate) const SLICE: &str = "torngat-vms.slice";

/// Bound on every QMP exchange.
const QMP_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound on a QMP session with a running QEMU (several commands).
const QMP_SESSION: Duration = Duration::from_secs(10);
/// First wait before asking a QEMU that failed again, doubled up to [`MAX_RETRY_WAIT`].
const RETRY_WAIT: Duration = Duration::from_secs(10);
const MAX_RETRY_WAIT: Duration = Duration::from_secs(300);
/// Time allowed for QEMU to come up and answer on QMP.
const START_TIMEOUT: Duration = Duration::from_secs(15);
/// Time systemd gives QEMU after SIGTERM before it kills it.
const KILL_AFTER: Duration = Duration::from_secs(10);

/// Capabilities this runtime can provide today.
const SUPPORTED: &[Capability] = &[Capability::LiveMigratable];

const MIB: u64 = 1 << 20;

pub(crate) const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
pub(crate) const SYSTEMCTL: &str = "/usr/bin/systemctl";
const JOURNALCTL: &str = "/usr/bin/journalctl";

#[derive(Debug, Clone)]
pub struct QemuConfig {
    pub qemu: String,
    /// UEFI firmware (OVMF), read-only, and the template of each instance's UEFI variables.
    pub firmware: String,
    pub firmware_vars: String,
    /// Time allowed for a guest to power off before it is stopped.
    pub stop_timeout: Duration,
}

impl Default for QemuConfig {
    fn default() -> Self {
        Self {
            qemu: "/usr/bin/qemu-system-x86_64".into(),
            firmware: "/usr/share/OVMF/OVMF_CODE_4M.fd".into(),
            firmware_vars: "/usr/share/OVMF/OVMF_VARS_4M.fd".into(),
            stop_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QemuRuntime {
    cfg: QemuConfig,
    /// Instances whose guest this agent saw running (not paused before it ran).
    started: Arc<Mutex<HashSet<Uuid>>>,
    /// The last [`Runtime::running`] could not tell about some instance.
    unsettled: Arc<AtomicBool>,
    /// The disks each running instance has, with the size QEMU has for them.
    given: Arc<Mutex<HashMap<Uuid, BTreeMap<Uuid, u64>>>>,
    /// Instances whose QEMU failed to answer: when to ask again, the wait, the failure. A QEMU may
    /// be its guest's; one that fails or stalls must not hold back the other instances.
    failing: Arc<Mutex<HashMap<Uuid, Failing>>>,
}

/// When to ask a failing QEMU again, the wait, and its failure.
type Failing = (Instant, Duration, String);

/// The instance's unit.
pub fn unit(uid: Uuid) -> String {
    format!("{UNIT_PREFIX}{uid}.service")
}

/// The instance's UEFI variables (boot entries), kept across its restarts.
fn uefi_vars(uid: Uuid) -> String {
    format!("{STATE_ROOT}/{uid}/uefi-vars.fd")
}

/// The instance's console log, on the host.
pub fn console_log(uid: Uuid) -> String {
    format!("{STATE_ROOT}/{uid}/console.log")
}

fn qmp_socket(uid: Uuid) -> String {
    format!("{RUNTIME_ROOT}/{uid}/qmp.sock")
}

/// QEMU's names for a volume's disk: block node (at most 31 characters), device, and the serial
/// number the guest sees (at most 20: `/dev/disk/by-id/virtio-<serial>`).
fn disk_names(volume: Uuid) -> (String, String, String) {
    let hex = volume.simple().to_string();
    // The end of a uid is its random part.
    (
        format!("v{}", &hex[2..]),
        format!("disk-{volume}"),
        hex[12..].to_owned(),
    )
}

fn other(m: &str) -> std::io::Error {
    std::io::Error::other(m.to_owned())
}

/// Opens `d` for QEMU: read-write, bypassing the host's page cache.
fn open_disk(d: &Disk) -> std::io::Result<std::fs::File> {
    // Checked before opening it too: O_DIRECT fails on some other kinds of files.
    let block = |m: std::fs::Metadata| m.file_type().is_block_device();
    if !block(std::fs::metadata(&d.path)?) {
        return Err(other("a disk is not a block device"));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(rustix::fs::OFlags::DIRECT.bits() as i32)
        .open(&d.path)?;
    if !block(file.metadata()?) {
        return Err(other("a disk is not a block device"));
    }
    Ok(file)
}

/// Adds `d` as a virtio disk on PCIe port `port`, its file passed in fd set `port`. Undone if it
/// fails, so that it can be tried again.
fn add_disk(q: &mut Qmp, port: usize, d: &Disk, file: &std::fs::File) -> std::io::Result<()> {
    let (node, id, serial) = disk_names(d.volume);
    // A set left by an earlier attempt could hold another volume's file.
    let _ = q.execute("remove-fd", Some(json!({ "fdset-id": port })));
    q.execute_with_fd("add-fd", Some(json!({ "fdset-id": port })), file.as_fd())?;
    let added = q.execute(
        "blockdev-add",
        Some(json!({
            "driver": "raw",
            "node-name": node,
            "file": {
                "driver": "host_device",
                "filename": format!("/dev/fdset/{port}"),
                "cache": { "direct": true },
            },
        })),
    );
    let mut dev = json!({
        "driver": "virtio-blk-pci",
        "bus": disk_port(port),
        "drive": node,
        "id": id,
        "serial": serial,
    });
    if d.boot {
        dev["bootindex"] = json!(0);
    }
    let r = added.and_then(|_| q.execute("device_add", Some(dev)));
    if r.is_err() {
        let _ = q.execute("blockdev-del", Some(json!({ "node-name": node })));
        let _ = q.execute("remove-fd", Some(json!({ "fdset-id": port })));
    }
    r.map(|_| ())
}

/// Hands `disks` to the paused QEMU behind `q`, then lets the guest run. Returns the size QEMU
/// has for each.
fn attach_and_run(q: &mut Qmp, disks: &[Disk]) -> std::io::Result<BTreeMap<Uuid, u64>> {
    if disks.len() > DISK_PORTS {
        return Err(other("too many disks"));
    }
    for (i, d) in disks.iter().enumerate() {
        add_disk(q, i, d, &open_disk(d)?)?;
    }
    let sizes = disk_sizes(q, disks)?;
    q.execute("cont", None)?;
    Ok(sizes)
}

/// The size QEMU has for each of `disks` it has.
fn disk_sizes(q: &mut Qmp, disks: &[Disk]) -> std::io::Result<BTreeMap<Uuid, u64>> {
    let sizes = sizes(q)?;
    Ok(disks
        .iter()
        .filter_map(|d| Some((d.volume, *sizes.get(&disk_names(d.volume).0)?)))
        .collect())
}

/// What QEMU says it has: the disk ports in use, and the volumes it has as disks. QEMU may be its
/// guest's: this only tells the agent where to try, every step is checked by QEMU itself.
fn plugged(q: &mut Qmp) -> std::io::Result<(BTreeSet<usize>, BTreeSet<Uuid>)> {
    let pci = q.execute("query-pci", None)?;
    let (mut ports, mut volumes) = (BTreeSet::new(), BTreeSet::new());
    let buses = list(Some(&pci));
    for dev in buses.iter().flat_map(devices) {
        let Some(port) = qdev_id(dev)
            .and_then(|i| i.strip_prefix("disk"))
            .and_then(|n| n.parse::<usize>().ok())
        else {
            continue;
        };
        for inner in dev.get("pci_bridge").map(devices).unwrap_or_default() {
            ports.insert(port);
            if let Some(v) = qdev_id(inner)
                .and_then(|i| i.strip_prefix("disk-"))
                .and_then(|u| Uuid::parse_str(u).ok())
            {
                volumes.insert(v);
            }
        }
    }
    Ok((ports, volumes))
}

fn list(v: Option<&serde_json::Value>) -> &[serde_json::Value] {
    v.and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn devices(bus: &serde_json::Value) -> &[serde_json::Value] {
    list(bus.get("devices"))
}

fn qdev_id(dev: &serde_json::Value) -> Option<&str> {
    dev.get("qdev_id").and_then(serde_json::Value::as_str)
}

/// The size QEMU gives each of our disks, by block node.
fn sizes(q: &mut Qmp) -> std::io::Result<HashMap<String, u64>> {
    let nodes = q.execute("query-named-block-nodes", Some(json!({ "flat": true })))?;
    Ok(list(Some(&nodes))
        .iter()
        .filter_map(|n| {
            let name = n.get("node-name")?.as_str()?;
            let size = n.pointer("/image/virtual-size")?.as_u64()?;
            Some((name.to_owned(), size))
        })
        .collect())
}

/// A failure to update a running instance's disks, and whether it was QEMU's (then QEMU is not
/// asked again for a while) or the node's.
struct Failure {
    error: std::io::Error,
    qemu: bool,
}

/// Gives the running guest behind `q` those of `disks` it does not have, on free ports, then
/// grows those whose device grew. One disk that fails does not hold back the others. Returns, for
/// each disk, the size it is known to have (QEMU's, or the node's when the device is no larger
/// than what QEMU has), and the first failure.
fn update_disks(
    q: &mut Qmp,
    disks: &[Disk],
) -> std::io::Result<(BTreeMap<Uuid, u64>, Option<Failure>)> {
    let (mut used, have) = plugged(q)?;
    let sizes = sizes(q)?;
    let mut known = BTreeMap::new();
    let mut failure: Option<Failure> = None;
    // The first failure is told; it is QEMU's if any was.
    let mut fail = |error, qemu: bool| match &mut failure {
        Some(f) => f.qemu |= qemu,
        None => failure = Some(Failure { error, qemu }),
    };
    for d in disks.iter().filter(|d| !have.contains(&d.volume)) {
        // The ports in use are what QEMU says.
        let Some(port) = (0..DISK_PORTS).find(|p| !used.contains(p)) else {
            fail(other("no free disk slot"), true);
            break;
        };
        let file = match open_disk(d) {
            Ok(f) => f,
            Err(e) => {
                fail(e, false);
                continue;
            }
        };
        match add_disk(q, port, d, &file) {
            Ok(()) => {
                used.insert(port);
            }
            Err(e) => fail(e, true),
        }
    }
    for d in disks.iter().filter(|d| have.contains(&d.volume)) {
        let (node, _, _) = disk_names(d.volume);
        let Some(&had) = sizes.get(&node) else {
            fail(other("QEMU does not say how large a disk is"), true);
            continue;
        };
        if had >= d.size {
            continue;
        }
        let actual = match std::fs::File::open(&d.path).and_then(|mut f| f.seek(SeekFrom::End(0))) {
            Ok(a) => a,
            Err(e) => {
                fail(e, false);
                continue;
            }
        };
        if actual <= had {
            // The device is not larger yet: nothing to give until the node reports more.
            known.insert(d.volume, d.size);
            continue;
        }
        if let Err(e) = q.execute(
            "block_resize",
            Some(json!({ "node-name": node, "size": actual })),
        ) {
            fail(e, true);
        }
    }
    match disk_sizes(q, disks) {
        Ok(sizes) => {
            for (v, size) in sizes {
                let k = known.entry(v).or_default();
                *k = (*k).max(size);
            }
        }
        Err(e) => fail(e, true),
    }
    Ok((known, failure))
}

/// The unit's settings. Pure function of validated fields and the configuration, for testing.
pub fn properties(inst: &Instance, cfg: &QemuConfig) -> Vec<String> {
    let uid = inst.metadata.uid;
    let guest = inst.spec.memory_mib.saturating_mul(MIB);
    // QEMU itself: page tables, device emulation, buffers.
    let memory = guest.saturating_add(256 * MIB).saturating_add(guest / 16);
    let tasks = 64 + 4 * u64::from(inst.spec.vcpus);
    let mut p = vec![
        format!("Description=Torngat instance {uid}"),
        "DynamicUser=yes".into(),
        "SupplementaryGroups=kvm".into(),
        format!("StateDirectory=torngat-vm/{uid}"),
        "StateDirectoryMode=0700".into(),
        format!("RuntimeDirectory=torngat-vm/{uid}"),
        "RuntimeDirectoryMode=0700".into(),
        "UMask=0077".into(),
        // Its UEFI variables, made from the template at its first start, by its own user (the agent
        // writes nothing in the instance's directories). Copied, then renamed: an interrupted copy
        // is not taken for the file. `$$` is systemd's escape for `$`.
        format!(
            "ExecStartPre=/bin/sh -c 'test -e \"$$1\" || {{ cp --no-preserve=mode \"$$0\" \"$$1.tmp\" && mv \"$$1.tmp\" \"$$1\"; }}' {} {}",
            cfg.firmware_vars,
            uefi_vars(uid)
        ),
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
    ];
    p.extend(confined());
    p.extend([
        // The agent decides about restarts.
        "Restart=no".into(),
        format!("TimeoutStopSec={}", KILL_AFTER.as_secs()),
    ]);
    p
}

/// What a unit that runs untrusted input is allowed, for QEMU and qemu-img: no network, no
/// privileges, and little of the host.
pub(crate) fn confined() -> Vec<String> {
    vec![
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
    ]
}

/// Disk slots: one per disk an instance can have (its data disks and boot disk), so that disks can
/// be added to a running guest.
const DISK_PORTS: usize = MAX_DISKS + 1;

/// The PCIe port of the `i`th disk slot.
fn disk_port(i: usize) -> String {
    format!("disk{i}")
}

/// QEMU command line for an instance. Pure function of validated fields and the configuration,
/// for testing.
pub fn args(inst: &Instance, cfg: &QemuConfig) -> Vec<String> {
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
        // UEFI only.
        "-drive".into(),
        format!(
            "if=pflash,format=raw,unit=0,readonly=on,file={}",
            cfg.firmware
        ),
        "-drive".into(),
        format!("if=pflash,format=raw,unit=1,file={}", uefi_vars(uid)),
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
        Self {
            cfg,
            started: Arc::default(),
            unsettled: Arc::default(),
            given: Arc::default(),
            failing: Arc::default(),
        }
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

    fn started_set(&self) -> std::sync::MutexGuard<'_, HashSet<Uuid>> {
        self.started.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn failing_map(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, Failing>> {
        self.failing.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The last failure, if QEMU is not to be asked again yet.
    fn held_off(&self, uid: Uuid) -> Result<(), String> {
        match self.failing_map().get(&uid) {
            Some((until, _, e)) if Instant::now() < *until => Err(e.clone()),
            _ => Ok(()),
        }
    }

    /// Records that QEMU failed: it is asked again after a wait that doubles each time.
    fn failed(&self, uid: Uuid, e: String) -> String {
        let mut m = self.failing_map();
        let now = Instant::now();
        // Doubled while it keeps failing; from the start again after a long quiet time.
        let wait = match m.get(&uid) {
            Some((until, w, _)) if now < *until + MAX_RETRY_WAIT => (*w * 2).min(MAX_RETRY_WAIT),
            _ => RETRY_WAIT,
        };
        m.insert(uid, (now + wait, wait, e.clone()));
        e
    }

    fn given_map(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, BTreeMap<Uuid, u64>>> {
        self.given.lock().unwrap_or_else(PoisonError::into_inner)
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
        let stream = tokio::time::timeout(QMP_TIMEOUT, UnixStream::connect(qmp_socket(uid)))
            .await
            .map_err(|_| std::io::Error::other("qmp: cannot connect"))??
            .into_std()?;
        let session = tokio::task::spawn_blocking(move || {
            let mut q = Qmp::new(stream, main, QMP_TIMEOUT, timeout)?;
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
        for f in [&self.cfg.firmware, &self.cfg.firmware_vars] {
            if !Path::new(f).is_file() {
                return Err(format!("the UEFI firmware {f} is missing (package ovmf)"));
            }
        }
        // A unit that failed before is kept until this.
        let _ = self.output(SYSTEMCTL, &["reset-failed", &unit(uid)]).await;
        self.started_set().remove(&uid);
        self.given_map().remove(&uid);
        self.failing_map().remove(&uid);
        let mut run: Vec<String> = vec![
            format!("--unit={}", unit(uid)),
            format!("--slice={SLICE}"),
            "--collect".into(),
            "--quiet".into(),
            "--service-type=exec".into(),
        ];
        run.extend(
            properties(inst, &self.cfg)
                .into_iter()
                .map(|p| format!("--property={p}")),
        );
        run.push("--".into());
        run.push(self.cfg.qemu.clone());
        run.extend(args(inst, &self.cfg));
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
                    Ok(sizes) => {
                        self.started_set().insert(uid);
                        self.given_map().insert(uid, sizes);
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

    async fn attach(&self, uid: Uuid, disks: &[Disk]) -> Result<(), String> {
        // Nothing new since they were given (unknown after the agent restarted: QEMU is asked).
        let known = self.given_map().get(&uid).is_some_and(|had| {
            disks
                .iter()
                .all(|d| had.get(&d.volume).is_some_and(|s| *s >= d.size))
        });
        if known {
            self.failing_map().remove(&uid);
            return Ok(());
        }
        self.held_off(uid)?;
        let list = disks.to_vec();
        let r = self
            .qmp(uid, QMP_SESSION, move |q| update_disks(q, &list))
            .await;
        let failure = match r {
            Ok((sizes, failure)) => {
                self.given_map().entry(uid).or_default().extend(sizes);
                failure
            }
            Err(error) => Some(Failure { error, qemu: true }),
        };
        match failure {
            None => {
                self.failing_map().remove(&uid);
                Ok(())
            }
            // QEMU is asked again only after a while; the node's own failures are retried as usual.
            Some(f) if f.qemu => Err(self.failed(uid, f.error.to_string())),
            Some(f) => Err(f.error.to_string()),
        }
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
        self.started_set().retain(|u| units.contains(u));
        self.given_map().retain(|u, _| units.contains(u));
        self.failing_map().retain(|u, _| units.contains(u));
        let mut running = Vec::with_capacity(units.len());
        let mut unsettled = false;
        for uid in units {
            if self.started_set().contains(&uid) {
                running.push(uid);
                continue;
            }
            // QEMU did not answer a short while ago: not asked again yet.
            if self.held_off(uid).is_err() {
                unsettled = true;
                running.push(uid);
                continue;
            }
            let status = self.status(uid).await;
            match &status {
                Ok(_) => {
                    self.failing_map().remove(&uid);
                }
                Err(e) => {
                    self.failed(uid, e.to_string());
                }
            }
            match status.as_deref() {
                // Its start was interrupted: it never ran, so it is started again.
                Ok("prelaunch") => {
                    tracing::warn!(%uid, "instance left paused before it ran: stopping it");
                    if let Err(e) = self.stop_unit(uid).await {
                        tracing::warn!(%uid, error = %e, "cannot stop it");
                        running.push(uid);
                    }
                }
                Ok(_) => {
                    self.started_set().insert(uid);
                    running.push(uid);
                }
                // Not answering (yet): looked at again soon.
                Err(_) => {
                    unsettled = true;
                    running.push(uid);
                }
            }
        }
        self.unsettled.store(unsettled, Ordering::Relaxed);
        running
    }

    fn unsettled(&self) -> bool {
        self.unsettled.load(Ordering::Relaxed)
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
        let a = args(&i, &QemuConfig::default());
        assert!(a.windows(2).any(|w| w[0] == "-smp" && w[1] == "2"));
        assert!(a.windows(2).any(|w| w[0] == "-m" && w[1] == "512M"));
        assert!(a.iter().any(|x| x.starts_with("on,obsolete=deny")));
        assert!(a.contains(&"-nodefaults".to_string()));
        // The user-chosen instance name never reaches the command line.
        assert!(!a.iter().any(|x| x.contains("vm-1")));
        assert!(
            !properties(&i, &QemuConfig::default())
                .iter()
                .any(|x| x.contains("vm-1"))
        );
    }

    #[test]
    fn units_are_confined_and_limited() {
        let i = inst("vm-1", 2, 1024, &[]);
        let p = properties(&i, &QemuConfig::default());
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
    fn disk_names_fit_qemu() {
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let (node, id, serial) = disk_names(a);
        assert!(node.len() <= 31 && node.starts_with('v'));
        assert_eq!(serial.len(), 20);
        assert_eq!(id, format!("disk-{a}"));
        // Made in the same millisecond, still told apart.
        assert_ne!(disk_names(b).2, serial);
        assert_ne!(disk_names(b).0, node);
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
