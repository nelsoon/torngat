//! QEMU/KVM runtime.
//!
//! Each instance is a detached QEMU process (own session via `setsid -f`), so workloads survive
//! agent restarts. QEMU's own `-daemonize` is not used: it is incompatible with the strict
//! seccomp sandbox (`elevateprivileges=deny`) on current QEMU. Next step: one transient systemd
//! unit per instance (cgroup limits, journald, supervision, per-instance users).
//!
//! State lives in `<state_dir>/<uid>/` (mode 0700, owned by the QEMU user): pidfile, QMP socket,
//! console and QEMU logs. `<state_dir>` itself is 0711 (traversable, not listable). The agent finds
//! its instances again by reading the pidfiles and checking `/proc/<pid>/cmdline`, which guards
//! against PID reuse.
//!
//! Security:
//! - arguments are built only from validated, bounded fields (uid, vcpus, memory), never from
//!   tenant strings;
//! - QEMU runs with its seccomp sandbox (`-sandbox on,...`), no default devices, no user config;
//! - when the agent runs as root, QEMU is started through `setpriv` as an unprivileged user and
//!   never runs as root; starting as root without such a user is refused.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use torngat_api::compute::{Capability, Instance, Runtime as RuntimeKind};
use uuid::Uuid;

use crate::Runtime;

#[derive(Debug, Clone)]
pub struct QemuConfig {
    pub qemu: PathBuf,
    /// `setsid` from util-linux, used to detach QEMU into its own session.
    pub setsid: PathBuf,
    /// `setpriv` from util-linux, used to drop to `run_as` before QEMU starts.
    pub setpriv: PathBuf,
    /// `kill`, used as a last resort on a verified QEMU pid.
    pub kill: PathBuf,
    pub state_dir: PathBuf,
    /// Unprivileged user QEMU runs as. Required when the agent runs as root.
    pub run_as: Option<String>,
    /// Time allowed for a guest to power off before it is forced.
    pub stop_timeout: Duration,
}

impl Default for QemuConfig {
    fn default() -> Self {
        Self {
            qemu: PathBuf::from("/usr/bin/qemu-system-x86_64"),
            setsid: PathBuf::from("/usr/bin/setsid"),
            setpriv: PathBuf::from("/usr/bin/setpriv"),
            kill: PathBuf::from("/usr/bin/kill"),
            state_dir: PathBuf::from("/var/lib/torngat/instances"),
            run_as: None,
            stop_timeout: Duration::from_secs(10),
        }
    }
}

/// A resolved unprivileged account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Account {
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone)]
pub struct QemuRuntime {
    cfg: QemuConfig,
    account: Option<Account>,
}

/// Maximum length of a UNIX socket path, including the terminating NUL (Linux `sun_path`).
const MAX_UNIX_PATH: usize = 108;
/// Bound on every QMP exchange.
const QMP_TIMEOUT: Duration = Duration::from_secs(5);
/// Time allowed for QEMU to come up and answer on QMP.
const START_TIMEOUT: Duration = Duration::from_secs(15);

/// Capabilities this runtime can provide today.
const SUPPORTED: &[Capability] = &[Capability::LiveMigratable];

fn invalid(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg)
}

/// Effective uid of this process, from /proc (no unsafe code).
fn effective_uid() -> std::io::Result<u32> {
    let s = std::fs::read_to_string("/proc/self/status")?;
    s.lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| invalid("cannot read effective uid".into()))
}

/// Looks up a user in /etc/passwd. Refuses root and malformed names.
fn lookup_account(user: &str) -> std::io::Result<Account> {
    if user.is_empty()
        || !user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(invalid(format!("invalid user name {user:?}")));
    }
    let passwd = std::fs::read_to_string("/etc/passwd")?;
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 4 && f[0] == user {
            let (uid, gid) = (f[2].parse(), f[3].parse());
            if let (Ok(uid), Ok(gid)) = (uid, gid) {
                if uid == 0 || gid == 0 {
                    return Err(invalid(format!("user {user} is privileged")));
                }
                return Ok(Account { uid, gid });
            }
        }
    }
    Err(invalid(format!("user {user} not found")))
}

impl QemuRuntime {
    pub fn new(cfg: QemuConfig) -> std::io::Result<Self> {
        // `<state_dir>/<uuid>/qmp.sock` must fit in a UNIX socket path (108 bytes incl. NUL).
        let suffix = "/".len() + 36 + "/qmp.sock".len();
        if cfg.state_dir.as_os_str().len() + suffix >= MAX_UNIX_PATH {
            return Err(invalid(format!(
                "state dir {} is too long for QEMU control sockets (max {} bytes)",
                cfg.state_dir.display(),
                MAX_UNIX_PATH - 1 - suffix
            )));
        }
        // Paths end up inside QEMU option strings, where ',' is a separator.
        let path = cfg
            .state_dir
            .to_str()
            .ok_or_else(|| invalid("state dir is not UTF-8".into()))?;
        if path.contains(',') {
            return Err(invalid("state dir must not contain ','".into()));
        }
        let account = match (&cfg.run_as, effective_uid()?) {
            (Some(u), 0) => Some(lookup_account(u)?),
            (None, 0) => {
                return Err(invalid(
                    "refusing to run QEMU as root: configure an unprivileged QEMU user".into(),
                ));
            }
            // Not root: QEMU simply runs as this (unprivileged) user.
            (_, _) => None,
        };
        make_dir(&cfg.state_dir, 0o711, None)?;
        Ok(Self { cfg, account })
    }

    fn dir(&self, uid: Uuid) -> PathBuf {
        self.cfg.state_dir.join(uid.hyphenated().to_string())
    }

    /// QEMU command line for an instance. Pure function of validated fields, for testing.
    pub fn args(&self, inst: &Instance) -> Vec<String> {
        let uid = inst.metadata.uid;
        let dir = self.dir(uid);
        let p = |f: &str| dir.join(f).display().to_string();
        vec![
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
            format!("file,id=console,path={},append=on", p("console.log")),
            "-serial".into(),
            "chardev:console".into(),
            "-qmp".into(),
            format!("unix:{},server=on,wait=off", p("qmp.sock")),
            "-pidfile".into(),
            p("qemu.pid"),
            "-sandbox".into(),
            "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny".into(),
        ]
    }

    fn pid(&self, uid: Uuid) -> Option<u32> {
        let pid: u32 = std::fs::read_to_string(self.dir(uid).join("qemu.pid"))
            .ok()?
            .trim()
            .parse()
            .ok()?;
        // Only trust the pid if that process is our QEMU for this uid.
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        let needle = format!("guest={uid},");
        let ours = cmdline
            .split(|b| *b == 0)
            .any(|arg| arg.starts_with(needle.as_bytes()));
        ours.then_some(pid)
    }

    /// Runs one QMP command (one of our constants, never user input) with a timeout.
    async fn qmp(&self, uid: Uuid, command: &'static str) -> std::io::Result<()> {
        let sock = self.dir(uid).join("qmp.sock");
        tokio::time::timeout(QMP_TIMEOUT, async move {
            let s = UnixStream::connect(sock).await?;
            let (r, mut w) = s.into_split();
            let mut lines = BufReader::new(r).lines();
            let _greeting = lines.next_line().await?;
            w.write_all(b"{\"execute\":\"qmp_capabilities\"}\n").await?;
            let _ = lines.next_line().await?;
            w.write_all(format!("{{\"execute\":\"{command}\"}}\n").as_bytes())
                .await?;
            let reply = lines.next_line().await?.unwrap_or_default();
            if reply.contains("\"error\"") {
                return Err(std::io::Error::other(format!("qmp {command} failed")));
            }
            Ok(())
        })
        .await
        .map_err(|_| std::io::Error::other("qmp timed out"))?
    }

    async fn wait_gone(&self, uid: Uuid, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if self.pid(uid).is_none() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        self.pid(uid).is_none()
    }

    /// Sends a signal to the verified QEMU pid of `uid`.
    async fn signal(&self, uid: Uuid, sig: &'static str) {
        if let Some(pid) = self.pid(uid) {
            let _ = tokio::process::Command::new(&self.cfg.kill)
                .args([sig, &pid.to_string()])
                .status()
                .await;
        }
    }

    fn log_tail(&self, uid: Uuid) -> String {
        let s = std::fs::read_to_string(self.dir(uid).join("qemu.log")).unwrap_or_default();
        let mut lines: Vec<&str> = s.lines().rev().take(5).collect();
        lines.reverse();
        lines.join(" | ")
    }
}

/// Creates `p` with `mode` (and owner, if given), fixing them if it already exists.
fn make_dir(p: &Path, mode: u32, owner: Option<Account>) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(p)?;
    if let Some(a) = owner {
        std::os::unix::fs::chown(p, Some(a.uid), Some(a.gid))?;
    }
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
}

impl Runtime for QemuRuntime {
    fn kind(&self) -> Option<RuntimeKind> {
        Some(RuntimeKind::Qemu)
    }

    async fn start(&self, inst: &Instance) -> Result<(), String> {
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
        if self.pid(uid).is_some() {
            return Ok(());
        }
        let dir = self.dir(uid);
        make_dir(&dir, 0o700, self.account).map_err(|e| format!("state dir: {e}"))?;
        let _ = std::fs::remove_file(dir.join("qemu.pid"));
        let _ = std::fs::remove_file(dir.join("qmp.sock"));
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("qemu.log"))
            .map_err(|e| format!("log: {e}"))?;
        if let Some(a) = self.account {
            std::os::unix::fs::chown(dir.join("qemu.log"), Some(a.uid), Some(a.gid))
                .map_err(|e| format!("log: {e}"))?;
        }
        let log2 = log.try_clone().map_err(|e| format!("log: {e}"))?;

        let mut cmd = tokio::process::Command::new(&self.cfg.setsid);
        cmd.arg("-f");
        if let Some(a) = self.account {
            // Drop to the QEMU user before exec: QEMU never runs as root.
            cmd.arg(&self.cfg.setpriv).args([
                format!("--reuid={}", a.uid),
                format!("--regid={}", a.gid),
                "--clear-groups".into(),
                "--inh-caps=-all".into(),
                "--bounding-set=-all".into(),
                "--no-new-privs".into(),
                "--".into(),
            ]);
        }
        let status = cmd
            .arg(&self.cfg.qemu)
            .args(self.args(inst))
            .stdin(std::process::Stdio::null())
            .stdout(log)
            .stderr(log2)
            .status()
            .await
            .map_err(|e| format!("cannot run qemu: {e}"))?;
        if !status.success() {
            return Err("cannot detach qemu".into());
        }

        // Running = the process is ours and answers on QMP (it can still die after writing its
        // pidfile, e.g. when memory or KVM initialisation fails).
        let deadline = tokio::time::Instant::now() + START_TIMEOUT;
        while tokio::time::Instant::now() < deadline {
            if self.pid(uid).is_some() && self.qmp(uid, "query-status").await.is_ok() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // Do not leave a half-started VM behind.
        self.signal(uid, "-KILL").await;
        Err(format!("qemu failed to start: {}", self.log_tail(uid)))
    }

    async fn stop(&self, uid: Uuid) -> Result<(), String> {
        if self.pid(uid).is_none() {
            return Ok(());
        }
        // Ask the guest, then QEMU, then the kernel.
        let _ = self.qmp(uid, "system_powerdown").await;
        if !self.wait_gone(uid, self.cfg.stop_timeout).await {
            let _ = self.qmp(uid, "quit").await;
            if !self.wait_gone(uid, Duration::from_secs(5)).await {
                self.signal(uid, "-TERM").await;
                if !self.wait_gone(uid, Duration::from_secs(5)).await {
                    self.signal(uid, "-KILL").await;
                    if !self.wait_gone(uid, Duration::from_secs(5)).await {
                        return Err("qemu did not stop".into());
                    }
                }
            }
        }
        // Keep the logs for debugging; drop the rest.
        let dir = self.dir(uid);
        let _ = std::fs::remove_file(dir.join("qmp.sock"));
        let _ = std::fs::remove_file(dir.join("qemu.pid"));
        Ok(())
    }

    async fn running(&self) -> Vec<Uuid> {
        let Ok(rd) = std::fs::read_dir(&self.cfg.state_dir) else {
            return vec![];
        };
        rd.flatten()
            .filter_map(|e| Uuid::parse_str(&e.file_name().to_string_lossy()).ok())
            .filter(|u| self.pid(*u).is_some())
            .collect()
    }
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
            },
            status: Default::default(),
        }
    }

    fn rt(dir: &Path) -> QemuRuntime {
        QemuRuntime::new(QemuConfig {
            state_dir: dir.to_path_buf(),
            stop_timeout: Duration::from_secs(2),
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn args_use_only_validated_fields_and_sandbox() {
        let d = tempfile::tempdir().unwrap();
        let r = rt(d.path());
        let i = inst("vm-1", 2, 512, &[]);
        let a = r.args(&i);
        assert!(a.windows(2).any(|w| w[0] == "-smp" && w[1] == "2"));
        assert!(a.windows(2).any(|w| w[0] == "-m" && w[1] == "512M"));
        assert!(a.iter().any(|x| x.starts_with("on,obsolete=deny")));
        assert!(a.contains(&"-nodefaults".to_string()));
        // The user-chosen instance name never reaches the command line.
        assert!(!a.iter().any(|x| x.contains("vm-1")));
        let mode = std::fs::metadata(d.path()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(mode.permissions().mode() & 0o777, 0o711);
    }

    #[test]
    fn refuses_state_dir_too_long_for_sockets() {
        let long = PathBuf::from(format!("/tmp/{}", "x".repeat(80)));
        let e = QemuRuntime::new(QemuConfig {
            state_dir: long,
            ..Default::default()
        })
        .unwrap_err();
        assert!(e.to_string().contains("too long"), "{e}");
        assert!(QemuConfig::default().state_dir.as_os_str().len() < 60);
        let comma = QemuRuntime::new(QemuConfig {
            state_dir: PathBuf::from("/tmp/a,b"),
            ..Default::default()
        })
        .unwrap_err();
        assert!(comma.to_string().contains("','"), "{comma}");
    }

    #[test]
    fn account_lookup_refuses_root_and_bad_names() {
        assert!(lookup_account("root").is_err());
        assert!(lookup_account("a b").is_err());
        assert!(lookup_account("x,user=root").is_err());
        assert!(lookup_account("no-such-user-torngat").is_err());
    }

    #[tokio::test]
    async fn refuses_unsupported_capabilities() {
        let d = tempfile::tempdir().unwrap();
        let r = rt(d.path());
        let e = r
            .start(&inst("vm-gpu", 1, 128, &[Capability::Gpu]))
            .await
            .unwrap_err();
        assert!(e.contains("not available"), "{e}");
    }

    fn kvm_usable() -> bool {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok()
            && Path::new(&QemuConfig::default().qemu).exists()
    }

    /// Starts and stops a real (empty) VM when KVM and QEMU are available here.
    #[tokio::test]
    async fn real_qemu_start_stop_and_rediscovery() {
        if !kvm_usable() {
            eprintln!("skipping: no usable /dev/kvm or qemu");
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let r = rt(d.path());
        let i = inst("vm-real", 1, 128, &[]);
        r.start(&i).await.unwrap();
        // Idempotent, and visible to a fresh runtime (as after an agent restart).
        r.start(&i).await.unwrap();
        assert_eq!(rt(d.path()).running().await, vec![i.metadata.uid]);
        r.stop(i.metadata.uid).await.unwrap();
        assert!(r.running().await.is_empty());
        r.stop(i.metadata.uid).await.unwrap();
    }
}
