//! QEMU/KVM runtime.
//!
//! Each instance is a detached QEMU process (own session via `setsid -f`), so workloads survive
//! agent restarts. QEMU's own `-daemonize` is not used: it is incompatible with the strict
//! seccomp sandbox (`elevateprivileges=deny`) on current QEMU. Next step: one transient systemd
//! unit per instance (cgroup limits, journald, supervision). State lives in
//! `<state_dir>/<uid>/` (mode 0700): pidfile, QMP socket, serial console log. The agent finds its
//! instances again by reading the pidfiles and checking `/proc/<pid>/cmdline`, which guards
//! against PID reuse.
//!
//! Security:
//! - arguments are built only from validated, bounded fields (uid, vcpus, memory), never from
//!   user strings;
//! - QEMU runs with its seccomp sandbox (`-sandbox on,...`), no default devices, no user config,
//!   and drops to an unprivileged user when started as root (`-run-with user=`).

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
    pub state_dir: PathBuf,
    /// Unprivileged user QEMU switches to when the agent runs as root.
    pub run_as: Option<String>,
    /// Time allowed for a guest to power off before it is killed.
    pub stop_timeout: Duration,
}

impl Default for QemuConfig {
    fn default() -> Self {
        Self {
            qemu: PathBuf::from("/usr/bin/qemu-system-x86_64"),
            setsid: PathBuf::from("/usr/bin/setsid"),
            state_dir: PathBuf::from("/var/lib/torngat/instances"),
            run_as: None,
            stop_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QemuRuntime {
    cfg: QemuConfig,
}

/// Maximum length of a UNIX socket path, including the terminating NUL (Linux `sun_path`).
const MAX_UNIX_PATH: usize = 108;

/// Capabilities this runtime can provide today.
const SUPPORTED: &[Capability] = &[Capability::LiveMigratable];

impl QemuRuntime {
    pub fn new(cfg: QemuConfig) -> std::io::Result<Self> {
        // `<state_dir>/<uuid>/qmp.sock` must fit in a UNIX socket path (108 bytes incl. NUL).
        let suffix = "/".len() + 36 + "/qmp.sock".len();
        if cfg.state_dir.as_os_str().len() + suffix >= MAX_UNIX_PATH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "state dir {} is too long for QEMU control sockets (max {} bytes)",
                    cfg.state_dir.display(),
                    MAX_UNIX_PATH - 1 - suffix
                ),
            ));
        }
        create_private_dir(&cfg.state_dir)?;
        Ok(Self { cfg })
    }

    fn dir(&self, uid: Uuid) -> PathBuf {
        self.cfg.state_dir.join(uid.hyphenated().to_string())
    }

    /// QEMU command line for an instance. Pure function of validated fields, for testing.
    pub fn args(&self, inst: &Instance) -> Vec<String> {
        let uid = inst.metadata.uid;
        let dir = self.dir(uid);
        let p = |f: &str| dir.join(f).display().to_string();
        let mut a = vec![
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
            "-serial".into(),
            format!("file:{}", p("console.log")),
            "-qmp".into(),
            format!("unix:{},server=on,wait=off", p("qmp.sock")),
            "-pidfile".into(),
            p("qemu.pid"),
            "-sandbox".into(),
            "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny".into(),
        ];
        if let Some(user) = &self.cfg.run_as {
            a.push("-run-with".into());
            a.push(format!("user={user}"));
        }
        a
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

    async fn qmp(&self, uid: Uuid, command: &str) -> std::io::Result<()> {
        let s = UnixStream::connect(self.dir(uid).join("qmp.sock")).await?;
        let (r, mut w) = s.into_split();
        let mut lines = BufReader::new(r).lines();
        let _greeting = lines.next_line().await?;
        w.write_all(b"{\"execute\":\"qmp_capabilities\"}\n").await?;
        let _ = lines.next_line().await?;
        // `command` is one of our constants, never user input.
        w.write_all(format!("{{\"execute\":\"{command}\"}}\n").as_bytes())
            .await?;
        let _ = lines.next_line().await;
        Ok(())
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
}

fn create_private_dir(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(p)?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
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
        create_private_dir(&dir).map_err(|e| format!("state dir: {e}"))?;
        let _ = std::fs::remove_file(dir.join("qemu.pid"));
        let log = std::fs::File::create(dir.join("qemu.log")).map_err(|e| format!("log: {e}"))?;
        let log2 = log.try_clone().map_err(|e| format!("log: {e}"))?;
        let status = tokio::process::Command::new(&self.cfg.setsid)
            .arg("-f")
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
        // QEMU writes its pidfile early in startup; give it a moment, then report its own error.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            if self.pid(uid).is_some() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let err = std::fs::read_to_string(dir.join("qemu.log")).unwrap_or_default();
        let tail: String = err.lines().rev().take(5).collect::<Vec<_>>().join(" | ");
        Err(format!("qemu failed to start: {tail}"))
    }

    async fn stop(&self, uid: Uuid) -> Result<(), String> {
        if self.pid(uid).is_none() {
            return Ok(());
        }
        // Ask the guest politely, then insist.
        let _ = self.qmp(uid, "system_powerdown").await;
        if !self.wait_gone(uid, self.cfg.stop_timeout).await {
            let _ = self.qmp(uid, "quit").await;
            if !self.wait_gone(uid, Duration::from_secs(5)).await {
                return Err("qemu did not stop".into());
            }
        }
        // Keep the console log for debugging; drop the rest.
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
        assert_eq!(mode.permissions().mode() & 0o777, 0o700);
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
