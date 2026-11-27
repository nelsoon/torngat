//! Instances as systemd units, with real QEMU and KVM. Needs root, systemd, QEMU and /dev/kvm:
//!
//!   cargo test -p torngat-agent --test qemu_units --no-run    # then run the binary with sudo, --ignored

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::process::Command;

use torngat_agent::qemu::{self, QemuConfig, QemuRuntime, console_log, unit};
use torngat_agent::{Disk, Runtime};
use torngat_api::compute::{Instance, InstanceSpec, PowerState};
use torngat_api::{Name, Object, ObjectMeta, Scope};
use uuid::Uuid;

fn inst(name: &str) -> Instance {
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
            vcpus: 1,
            memory_mib: 128,
            capabilities: BTreeSet::new(),
            power_state: PowerState::Running,
            claims: vec![],
            boot_disk: None,
            disks: vec![],
        },
        status: Default::default(),
    }
}

fn show(uid: Uuid, property: &str) -> String {
    let out = Command::new("systemctl")
        .args([
            "show",
            &format!("--property={property}"),
            "--value",
            &unit(uid),
        ])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// A field of `/proc/<pid>/status`.
fn status(pid: &str, field: &str) -> String {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    s.lines()
        .find_map(|l| l.strip_prefix(&format!("{field}:")))
        .unwrap()
        .trim()
        .to_owned()
}

fn ns(pid: &str, kind: &str) -> std::path::PathBuf {
    std::fs::read_link(format!("/proc/{pid}/ns/{kind}")).unwrap()
}

fn rt() -> QemuRuntime {
    QemuRuntime::new(QemuConfig {
        stop_timeout: std::time::Duration::from_secs(2),
        ..Default::default()
    })
}

#[tokio::test]
#[ignore = "needs root, systemd, QEMU and /dev/kvm"]
async fn instances_are_units_of_their_own() {
    let r = rt();
    let (a, b) = (inst("a"), inst("b"));
    let (ua, ub) = (a.metadata.uid, b.metadata.uid);
    r.start(&a, &[]).await.unwrap();
    r.start(&b, &[]).await.unwrap();
    // Idempotent.
    r.start(&a, &[]).await.unwrap();

    let mut users = BTreeSet::new();
    for u in [ua, ub] {
        assert_eq!(show(u, "ActiveState"), "active");
        let pid = show(u, "MainPID");
        let ids = status(&pid, "Uid");
        let uid: u32 = ids.split_whitespace().next().unwrap().parse().unwrap();
        assert!(uid != 0, "runs as root");
        // Real, effective, saved and file system uid are all the same.
        assert!(
            ids.split_whitespace().all(|x| x == uid.to_string()),
            "{ids}"
        );
        users.insert(uid);
        assert_eq!(status(&pid, "NoNewPrivs"), "1");
        assert_eq!(status(&pid, "CapEff"), "0000000000000000");
        assert_eq!(status(&pid, "CapBnd"), "0000000000000000");
        assert_ne!(ns(&pid, "net"), ns("1", "net"), "shares the host's network");
        assert_ne!(ns(&pid, "ipc"), ns("1", "ipc"), "shares the host's IPC");
        assert_ne!(ns(&pid, "mnt"), ns("1", "mnt"), "sees the host's /dev");
        assert!(std::path::Path::new(&console_log(u)).exists());
        assert_eq!(show(u, "LimitCORE"), "0");
        assert_eq!(show(u, "DynamicUser"), "yes");
    }
    assert_eq!(users.len(), 2, "two instances share a user");

    // Found again by a new agent.
    let found: BTreeSet<_> = rt().running().await.into_iter().collect();
    assert!(found.contains(&ua) && found.contains(&ub), "{found:?}");

    // A QEMU taken over by its guest puts B's control socket in its own directory: stopping A
    // must not reach B.
    let sock = format!("/run/torngat-vm/{ua}/qmp.sock");
    std::fs::remove_file(&sock).unwrap();
    std::os::unix::fs::symlink(format!("/run/torngat-vm/{ub}/qmp.sock"), &sock).unwrap();
    let b_pid = show(ub, "MainPID");
    r.stop(ua).await.unwrap();
    assert_eq!(show(ub, "ActiveState"), "active");
    assert_eq!(show(ub, "MainPID"), b_pid);

    // Stopped: the unit is gone, the console log stays; it starts again.
    r.stop(ua).await.unwrap();
    assert!(!r.running().await.contains(&ua));
    assert_eq!(show(ua, "LoadState"), "not-found");
    assert!(std::path::Path::new(&console_log(ua)).exists());
    r.start(&a, &[]).await.unwrap();
    assert!(r.running().await.contains(&ua));

    for u in [ua, ub] {
        r.stop(u).await.unwrap();
        r.stop(u).await.unwrap();
    }
    assert!(!r.running().await.iter().any(|u| *u == ua || *u == ub));
}

/// A boot sector that writes `TORNGAT-BOOT-OK` to the first serial port and halts.
fn boot_sector() -> Vec<u8> {
    let mut b = vec![
        0x31, 0xc0, // xor ax, ax
        0x8e, 0xd8, // mov ds, ax
        0xfc, // cld
        0xbe, 0x17, 0x7c, // mov si, 0x7c17 (the text)
        0xba, 0xf8, 0x03, // mov dx, 0x3f8
        0xac, // lodsb
        0x84, 0xc0, // test al, al
        0x74, 0x03, // jz +3
        0xee, // out dx, al
        0xeb, 0xf8, // jmp lodsb
        0xfa, // cli
        0xf4, // hlt
        0xeb, 0xfd, // jmp hlt
    ];
    b.extend_from_slice(b"TORNGAT-BOOT-OK\r\n\0");
    b.resize(510, 0);
    b.extend_from_slice(&[0x55, 0xaa]);
    b
}

/// A loop device over a new 1 MiB file that starts with `head`.
struct Loop(String);

impl Loop {
    fn new(dir: &std::path::Path, name: &str, head: &[u8]) -> Self {
        let f = dir.join(name);
        let mut data = head.to_vec();
        data.resize(1 << 20, 0);
        std::fs::write(&f, data).unwrap();
        let out = Command::new("losetup")
            .args(["--find", "--show"])
            .arg(&f)
            .output()
            .unwrap();
        assert!(out.status.success());
        Self(String::from_utf8(out.stdout).unwrap().trim().to_owned())
    }

    fn disk(&self, boot: bool) -> Disk {
        Disk {
            volume: Uuid::now_v7(),
            path: self.0.clone().into(),
            boot,
        }
    }
}

impl Drop for Loop {
    fn drop(&mut self) {
        let _ = Command::new("losetup").args(["-d", &self.0]).status();
    }
}

async fn console_has(uid: Uuid, text: &str) -> bool {
    for _ in 0..100 {
        if std::fs::read_to_string(console_log(uid)).is_ok_and(|s| s.contains(text)) {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    false
}

#[tokio::test]
#[ignore = "needs root, systemd, QEMU and /dev/kvm"]
async fn instances_boot_from_their_disks() {
    let dir = tempfile::Builder::new()
        .prefix("torngat-disks")
        .tempdir_in("/var/tmp")
        .unwrap();
    let boot = Loop::new(dir.path(), "boot", &boot_sector());
    let data = Loop::new(dir.path(), "data", &[]);
    let r = rt();

    // Given its disks open, as files: it cannot open devices itself.
    let a = inst("a");
    let ua = a.metadata.uid;
    r.start(&a, &[boot.disk(true), data.disk(false)])
        .await
        .unwrap();
    assert!(console_has(ua, "TORNGAT-BOOT-OK").await, "did not boot");
    let pid = show(ua, "MainPID");
    let open: BTreeSet<_> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .filter_map(|e| std::fs::read_link(e.unwrap().path()).ok())
        .collect();
    for d in [&boot.0, &data.0] {
        assert!(
            open.contains(std::path::Path::new(d)),
            "{d} not open: {open:?}"
        );
    }

    // An agent that restarts finds it again, also without its own record of it.
    std::fs::remove_file(format!("/run/torngat-vm-started/{ua}")).unwrap();
    assert!(rt().running().await.contains(&ua));
    assert_eq!(show(ua, "MainPID"), pid);

    // A disk that cannot be given: it does not start, and nothing is left.
    let b = inst("b");
    let ub = b.metadata.uid;
    let bad = Disk {
        volume: Uuid::now_v7(),
        path: dir.path().join("boot"),
        boot: true,
    };
    let e = r.start(&b, &[bad]).await.unwrap_err();
    assert!(e.contains("not a block device"), "{e}");
    assert!(!r.running().await.contains(&ub));

    // Left paused before its guest ran (the agent stopped while starting it): stopped, so that
    // it is started again.
    let c = inst("c");
    let uc = c.metadata.uid;
    let mut run = vec![
        format!("--unit={}", unit(uc)),
        "--slice=torngat-vms.slice".into(),
        "--collect".into(),
        "--quiet".into(),
        "--service-type=exec".into(),
    ];
    run.extend(
        qemu::properties(&c)
            .into_iter()
            .map(|p| format!("--property={p}")),
    );
    run.push("--".into());
    run.push(QemuConfig::default().qemu);
    run.extend(qemu::args(&c));
    assert!(
        Command::new("systemd-run")
            .args(&run)
            .status()
            .unwrap()
            .success()
    );
    let mut found = true;
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        found = rt().running().await.contains(&uc);
        if !found {
            break;
        }
    }
    assert!(!found, "a paused instance is taken as running");
    assert_eq!(show(uc, "LoadState"), "not-found");

    r.stop(ua).await.unwrap();
    assert!(!r.running().await.contains(&ua));
    assert!(!std::path::Path::new(&format!("/run/torngat-vm-started/{ua}")).exists());
}
