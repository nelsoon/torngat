//! Volumes on loop devices with the real `cryptsetup`, and the udev rule that keeps the host from
//! probing what is in them. Needs root, cryptsetup, e2fsprogs and udev; changes nothing that stays:
//!
//!   cargo test -p torngat-agent --test luks --no-run    # then run the binary with sudo, --ignored

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

use torngat_agent::storage::crypt::Header;
use torngat_agent::storage::{Crypt, Cryptsetup, Driver, FileDriver, mapping};
use torngat_proto::storage::v1::attach_volume_response::Device;
use torngat_proto::storage::v1::*;
use uuid::Uuid;

const MIB: u64 = 1 << 20;
const RULE: &str = "59-torngat-volumes.rules";

fn run(cmd: &str, args: &[&str]) -> String {
    let out = Command::new(cmd).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{cmd} {}: {}",
        args.first().copied().unwrap_or_default(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Installs the image's rule for this test only (`/run` is not kept), and removes it after.
struct UdevRule(PathBuf);

impl UdevRule {
    fn install() -> Self {
        let src = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../image/mkosi.extra/usr/lib/udev/rules.d")
            .join(RULE);
        let dst = PathBuf::from("/run/udev/rules.d").join(RULE);
        std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
        std::fs::copy(src, &dst).unwrap();
        run("udevadm", &["control", "--reload"]);
        Self(dst)
    }
}

impl Drop for UdevRule {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = Command::new("udevadm")
            .args(["control", "--reload"])
            .status();
    }
}

/// Whether udev made a by-label link for `label`, after an ext4 file system with that label was
/// made in the open mapping `name`.
fn labelled(name: &str, label: &str) -> bool {
    run(
        "mkfs.ext4",
        &["-q", "-F", "-L", label, &format!("/dev/mapper/{name}")],
    );
    run(
        "udevadm",
        &["trigger", "--settle", &format!("/dev/mapper/{name}")],
    );
    Path::new("/dev/disk/by-label").join(label).exists()
}

fn pool() -> Option<Pool> {
    Some(Pool {
        uid: Uuid::now_v7().to_string(),
        cluster_uid: Uuid::now_v7().to_string(),
        source: "data".into(),
    })
}

async fn attach(d: &FileDriver, pool: &Option<Pool>, uid: Uuid) -> PathBuf {
    let r = d
        .attach_volume(AttachVolumeRequest {
            pool: pool.clone(),
            uid: uid.to_string(),
        })
        .await
        .unwrap();
    let Some(Device::Block(b)) = r.device else {
        panic!("no block device")
    };
    PathBuf::from(b.path)
}

#[tokio::test]
#[ignore = "needs root, cryptsetup, e2fsprogs and udev"]
async fn volumes_on_loop_devices() {
    let _rule = UdevRule::install();
    let root = tempfile::TempDir::new_in("/var/tmp").unwrap();
    std::fs::create_dir(root.path().join("data")).unwrap();
    let d = FileDriver::new(root.path(), 1 << 30, true);
    let c = Cryptsetup;
    let pool = pool();
    d.claim_pool(ClaimPoolRequest { pool: pool.clone() })
        .await
        .unwrap();
    let uid = Uuid::now_v7();
    let name = mapping(uid);
    let size = d
        .create_volume(CreateVolumeRequest {
            pool: pool.clone(),
            uid: uid.to_string(),
            size_bytes: 64 * MIB,
        })
        .await
        .unwrap()
        .size_bytes;
    assert_eq!(size, 64 * MIB);
    let dev = attach(&d, &pool, uid).await;
    assert!(
        dev.to_string_lossy().starts_with("/dev/loop"),
        "{}",
        dev.display()
    );
    // The driver answers with the same device while attached.
    assert_eq!(attach(&d, &pool, uid).await, dev);

    assert_eq!(c.header(&dev).await.unwrap(), Header::Blank);
    let key = [7u8; 32];
    c.format(&dev, &key).await.unwrap();
    assert_eq!(c.header(&dev).await.unwrap(), Header::Luks);
    c.open(&dev, &name, &key).await.unwrap();
    assert_eq!(c.opened().await.unwrap().get(&name), Some(&(48 * MIB)));

    // What the tenant writes is not probed; the same with another name is (the rule is what
    // stops it).
    assert!(!labelled(&name, "tgtenant"));
    let props = run(
        "udevadm",
        &["info", "--query=property", &format!("/dev/mapper/{name}")],
    );
    assert!(!props.contains("ID_FS_TYPE="), "{props}");

    // Grown while open.
    d.grow_volume(GrowVolumeRequest {
        pool: pool.clone(),
        uid: uid.to_string(),
        size_bytes: 128 * MIB,
    })
    .await
    .unwrap();
    c.resize(&name, &key).await.unwrap();
    assert_eq!(c.opened().await.unwrap().get(&name), Some(&(112 * MIB)));

    c.close(&name).await.unwrap();
    assert!(!c.opened().await.unwrap().contains_key(&name));
    assert!(c.open(&dev, &name, &[8u8; 32]).await.is_err());

    // The control: a mapping with another name is probed and linked.
    let control = format!("tgtest-{}", Uuid::now_v7().simple());
    c.open(&dev, &control, &key).await.unwrap();
    let linked = labelled(&control, "tgcontrol");
    c.close(&control).await.unwrap();
    assert!(
        linked,
        "udev did not link the control mapping: the test proves nothing"
    );

    // Something else in the header area is never formatted over.
    let other = Uuid::now_v7();
    d.create_volume(CreateVolumeRequest {
        pool: pool.clone(),
        uid: other.to_string(),
        size_bytes: 64 * MIB,
    })
    .await
    .unwrap();
    let odev = attach(&d, &pool, other).await;
    run(
        "dd",
        &[
            "if=/dev/urandom",
            &format!("of={}", odev.display()),
            "bs=4096",
            "count=1",
            "seek=100",
            "conv=fsync",
        ],
    );
    assert_eq!(c.header(&odev).await.unwrap(), Header::Other);
    // Not a block device: refused.
    let file = root.path().join("data").join(format!("{other}.img"));
    assert!(c.header(&file).await.is_err());

    for u in [uid, other] {
        let r = DeleteVolumeRequest {
            pool: pool.clone(),
            uid: u.to_string(),
        };
        // Attached volumes are not deleted.
        assert!(d.delete_volume(r.clone()).await.is_err());
        d.detach_volume(DetachVolumeRequest {
            pool: pool.clone(),
            uid: u.to_string(),
        })
        .await
        .unwrap();
        d.delete_volume(r).await.unwrap();
    }
    assert!(
        run("losetup", &["--list", "--noheadings"])
            .lines()
            .all(|l| !l.contains(&*root.path().to_string_lossy()))
    );
    d.release_pool(ReleasePoolRequest { pool }).await.unwrap();
}
