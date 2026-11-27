//! The LVM driver on a volume group made on a loop device. Needs root and lvm2; removes what it made:
//!
//!   cargo test -p torngat-agent --test lvm --no-run    # then run the binary with sudo, --ignored

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Seek, SeekFrom};
use std::process::Command;

use tonic::Code;
use torngat_agent::storage::crypt::Header;
use torngat_agent::storage::{Crypt, Cryptsetup, Driver, LvmDriver};
use torngat_proto::storage::v1::attach_volume_response::Device;
use torngat_proto::storage::v1::*;
use uuid::Uuid;

const MIB: u64 = 1 << 20;

fn run(cmd: &str, args: &[&str]) -> String {
    let out = Command::new(cmd).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{cmd}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// A volume group on a loop device, removed when dropped.
struct Group {
    name: String,
    dev: String,
    _file: tempfile::NamedTempFile,
}

impl Group {
    fn new() -> Self {
        let file = tempfile::NamedTempFile::new_in("/var/tmp").unwrap();
        file.as_file().set_len(512 * MIB).unwrap();
        let path = file.path().to_str().unwrap().to_owned();
        let dev = run("losetup", &["--find", "--show", &path]);
        let name = format!("tgtest{}", &Uuid::now_v7().simple().to_string()[24..]);
        run("lvm", &["vgcreate", "--yes", &name, &dev]);
        Self {
            name,
            dev,
            _file: file,
        }
    }
    fn lv(&self, args: &[&str]) {
        let mut a = vec!["lvcreate", "--yes", "--activate=y"];
        a.extend(args);
        a.push(&self.name);
        run("lvm", &a);
    }
    fn tags(&self, what: &str) -> String {
        let (cmd, field) = if what.contains('/') {
            ("lvs", "lv_tags")
        } else {
            ("vgs", "vg_tags")
        };
        run("lvm", &[cmd, "--noheadings", "-o", field, what])
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        let _ = Command::new("lvm")
            .args(["vgremove", "--yes", "--force", &self.name])
            .status();
        let _ = Command::new("lvm")
            .args(["pvremove", "--yes", &self.dev])
            .status();
        let _ = Command::new("losetup")
            .args(["--detach", &self.dev])
            .status();
    }
}

fn pool(g: &Group, cluster: Uuid, uid: Uuid) -> Option<Pool> {
    Some(Pool {
        uid: uid.to_string(),
        cluster_uid: cluster.to_string(),
        source: g.name.clone(),
    })
}

fn zeros_at(dev: &str, offset: u64, len: u64) -> bool {
    let mut f = std::fs::File::open(dev).unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf = vec![0u8; len as usize];
    f.read_exact(&mut buf).unwrap();
    buf.iter().all(|&b| b == 0)
}

fn junk(dev: &str, mib: u64) {
    run(
        "dd",
        &[
            "if=/dev/urandom",
            &format!("of={dev}"),
            "bs=1M",
            &format!("count={mib}"),
            "conv=fsync",
            "status=none",
        ],
    );
}

async fn attach(d: &LvmDriver, p: &Option<Pool>, uid: Uuid) -> String {
    let r = d
        .attach_volume(AttachVolumeRequest {
            pool: p.clone(),
            uid: uid.to_string(),
        })
        .await
        .unwrap();
    let Some(Device::Block(b)) = r.device else {
        panic!("no block device")
    };
    b.path
}

#[tokio::test]
#[ignore = "needs root and lvm2"]
async fn volumes_in_a_volume_group() {
    let g = Group::new();
    let d = LvmDriver;
    let (cluster, uid) = (Uuid::now_v7(), Uuid::now_v7());
    let p = pool(&g, cluster, uid);
    let code = |s: tonic::Status| s.code();

    // Someone else's volume, and old data where ours will go.
    g.lv(&["--size", "64m", "--name", "other"]);
    g.lv(&["--size", "200m", "--name", "old"]);
    junk(&format!("/dev/{}/old", g.name), 200);
    run("lvm", &["lvremove", "--yes", &format!("{}/old", g.name)]);

    // Unmarked: only claiming works; another cluster's mark is refused.
    let err = d.get_pool(GetPoolRequest { pool: p.clone() }).await;
    assert_eq!(err.map_err(code).unwrap_err(), Code::FailedPrecondition);
    d.claim_pool(ClaimPoolRequest { pool: p.clone() })
        .await
        .unwrap();
    d.claim_pool(ClaimPoolRequest { pool: p.clone() })
        .await
        .unwrap();
    assert_eq!(g.tags(&g.name), format!("torngat:{cluster}:{uid}"));
    let other = pool(&g, Uuid::now_v7(), Uuid::now_v7());
    let err = d.claim_pool(ClaimPoolRequest { pool: other }).await;
    assert_eq!(err.map_err(code).unwrap_err(), Code::FailedPrecondition);
    let missing = Some(Pool {
        source: "tgnosuchgroup".into(),
        ..p.clone().unwrap()
    });
    let err = d.claim_pool(ClaimPoolRequest { pool: missing }).await;
    assert_eq!(err.map_err(code).unwrap_err(), Code::NotFound);

    // What others use is not counted.
    let info = d
        .get_pool(GetPoolRequest { pool: p.clone() })
        .await
        .unwrap();
    assert_eq!(info.allocation_unit_bytes, 4 * MIB);
    assert!(info.capacity_bytes <= 512 * MIB - 64 * MIB, "{info:?}");
    assert!(info.capacity_bytes >= 400 * MIB, "{info:?}");

    // Created over old data: the first and last 16 MiB are zeros; left inactive.
    let v = Uuid::now_v7();
    let create = |uid: Uuid, size: u64| CreateVolumeRequest {
        pool: p.clone(),
        uid: uid.to_string(),
        size_bytes: size,
    };
    let size = d
        .create_volume(create(v, 63 * MIB))
        .await
        .unwrap()
        .size_bytes;
    assert_eq!(size, 64 * MIB);
    let at = format!("{}/torngat-{v}", g.name);
    assert!(!g.tags(&at).contains("zeroing"));
    assert_eq!(
        d.create_volume(create(v, 200 * MIB))
            .await
            .unwrap()
            .size_bytes,
        64 * MIB
    );
    let dev = attach(&d, &p, v).await;
    assert!(dev.starts_with("/dev/mapper/"), "{dev}");
    assert!(zeros_at(&dev, 0, 16 * MIB) && zeros_at(&dev, 48 * MIB, 16 * MIB));
    assert_eq!(
        Cryptsetup.header(dev.as_ref()).await.unwrap(),
        Header::Blank
    );

    // A creation cut short is finished.
    let w = Uuid::now_v7();
    let mark = format!("torngat:{cluster}:{uid}");
    g.lv(&[
        "--size",
        "32m",
        "--name",
        &format!("torngat-{w}"),
        "--addtag",
        &mark,
        "--addtag",
        "torngat-zeroing",
    ]);
    junk(&format!("/dev/{}/torngat-{w}", g.name), 32);
    let err = d
        .attach_volume(AttachVolumeRequest {
            pool: p.clone(),
            uid: w.to_string(),
        })
        .await;
    assert_eq!(err.map_err(code).unwrap_err(), Code::FailedPrecondition);
    d.create_volume(create(w, 32 * MIB)).await.unwrap();
    let wdev = attach(&d, &p, w).await;
    assert!(zeros_at(&wdev, 0, 16 * MIB) && zeros_at(&wdev, 16 * MIB, 16 * MIB));

    // Only this pool's volumes are listed.
    let list = d
        .list_volumes(ListVolumesRequest { pool: p.clone() })
        .await
        .unwrap();
    let mut found: Vec<_> = list.volumes.iter().map(|x| x.uid.clone()).collect();
    found.sort();
    let mut want = vec![v.to_string(), w.to_string()];
    want.sort();
    assert_eq!(found, want);
    assert!(list.volumes.iter().all(|x| x.attached));

    // Grown while attached.
    let grown = d
        .grow_volume(GrowVolumeRequest {
            pool: p.clone(),
            uid: v.to_string(),
            size_bytes: 128 * MIB,
        })
        .await
        .unwrap();
    assert_eq!(grown.size_bytes, 128 * MIB);
    let err = d.create_volume(create(Uuid::now_v7(), 2048 * MIB)).await;
    assert_eq!(err.map_err(code).unwrap_err(), Code::ResourceExhausted);

    // Open: neither detached nor deleted.
    let held = std::fs::File::open(&dev).unwrap();
    let del = |uid: Uuid| DeleteVolumeRequest {
        pool: p.clone(),
        uid: uid.to_string(),
    };
    let err = d.delete_volume(del(v)).await;
    assert_eq!(err.map_err(code).unwrap_err(), Code::FailedPrecondition);
    let det = |uid: Uuid| DetachVolumeRequest {
        pool: p.clone(),
        uid: uid.to_string(),
    };
    assert!(d.detach_volume(det(v)).await.is_err());
    drop(held);

    // A volume with our name but not our mark is never touched.
    let stranger = Uuid::now_v7();
    g.lv(&["--size", "8m", "--name", &format!("torngat-{stranger}")]);
    let err = d.delete_volume(del(stranger)).await;
    assert_eq!(err.map_err(code).unwrap_err(), Code::FailedPrecondition);

    // The pool keeps its mark while it holds volumes.
    let err = d.release_pool(ReleasePoolRequest { pool: p.clone() }).await;
    assert_eq!(err.map_err(code).unwrap_err(), Code::FailedPrecondition);
    for u in [v, w] {
        d.detach_volume(det(u)).await.unwrap();
        d.delete_volume(del(u)).await.unwrap();
        d.delete_volume(del(u)).await.unwrap();
        d.detach_volume(det(u)).await.unwrap();
    }
    let left = run("lvm", &["lvs", "--noheadings", "-o", "lv_name", &g.name]);
    let mut left: Vec<_> = left.split_whitespace().collect();
    left.sort();
    let stranger_name = format!("torngat-{stranger}");
    let mut expect = vec!["other", stranger_name.as_str()];
    expect.sort();
    assert_eq!(left, expect);
    d.release_pool(ReleasePoolRequest { pool: p.clone() })
        .await
        .unwrap();
    d.release_pool(ReleasePoolRequest { pool: p })
        .await
        .unwrap();
    assert_eq!(g.tags(&g.name), "");
}
