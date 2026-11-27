//! Instances as systemd units, with real QEMU and KVM. Needs root, systemd, QEMU and /dev/kvm:
//!
//!   cargo test -p torngat-agent --test qemu_units --no-run    # then run the binary with sudo, --ignored

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::process::Command;

use torngat_agent::Runtime;
use torngat_agent::qemu::{QemuConfig, QemuRuntime, console_log, unit};
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
    r.start(&a).await.unwrap();
    r.start(&b).await.unwrap();
    // Idempotent.
    r.start(&a).await.unwrap();

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
    r.start(&a).await.unwrap();
    assert!(r.running().await.contains(&ua));

    for u in [ua, ub] {
        r.stop(u).await.unwrap();
        r.stop(u).await.unwrap();
    }
    assert!(!r.running().await.iter().any(|u| *u == ua || *u == ub));
}
