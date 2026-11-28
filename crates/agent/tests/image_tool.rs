//! qemu-img in its sandbox, on real block devices (loop devices). Needs root, systemd and qemu-img:
//!
//! ```sh
//! sudo env PATH=/usr/sbin:/usr/bin:/sbin:/bin <test binary> --ignored --test-threads=1
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

use torngat_agent::import::{ImageTool, QemuImg};
use torngat_api::image::ImageFormat;
use uuid::Uuid;

const MIB: u64 = 1 << 20;

fn run(cmd: &str, args: &[&str]) -> String {
    let out = Command::new(cmd).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{cmd} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// A loop device over a file of `size` bytes, detached when dropped.
/// The file is kept for as long as the device.
struct Loop(PathBuf, #[allow(dead_code)] tempfile::NamedTempFile);

impl Loop {
    fn new(size: u64) -> Self {
        let f = tempfile::NamedTempFile::new().unwrap();
        f.as_file().set_len(size).unwrap();
        let dev = run("losetup", &["--find", "--show", f.path().to_str().unwrap()]);
        Loop(PathBuf::from(dev.trim()), f)
    }

    fn write(&self, data: &[u8]) {
        use std::io::Write;
        let mut d = std::fs::OpenOptions::new()
            .write(true)
            .open(&self.0)
            .unwrap();
        d.write_all(data).unwrap();
        d.sync_all().unwrap();
    }

    fn read(&self, len: usize) -> Vec<u8> {
        let mut v = std::fs::read(&self.0).unwrap();
        v.truncate(len);
        v
    }
}

impl Drop for Loop {
    fn drop(&mut self) {
        let _ = Command::new("losetup").args(["-d"]).arg(&self.0).status();
    }
}

/// A qcow2 file of `raw`, made by qemu-img outside the sandbox, with extra `create` options.
fn qcow2(dir: &Path, raw: &[u8], opts: &[&str]) -> Vec<u8> {
    let r = dir.join("disk.raw");
    let q = dir.join("disk.qcow2");
    std::fs::write(&r, raw).unwrap();
    let _ = std::fs::remove_file(&q);
    let mut args = vec!["convert", "-f", "raw", "-O", "qcow2"];
    args.extend_from_slice(opts);
    args.extend([r.to_str().unwrap(), q.to_str().unwrap()]);
    run("qemu-img", &args);
    std::fs::read(&q).unwrap()
}

#[tokio::test]
#[ignore = "needs root, systemd and qemu-img"]
async fn converts_in_its_sandbox() {
    let dir = tempfile::TempDir::new().unwrap();
    let tool = QemuImg::default();
    let task = Uuid::now_v7();
    let raw: Vec<u8> = (0..(8 * MIB) as u32).map(|i| (i % 253) as u8).collect();

    // qcow2: measured, then copied over a device that is not blank.
    let file = qcow2(dir.path(), &raw, &[]);
    let src = Loop::new(64 * MIB);
    src.write(&file);
    let len = file.len() as u64;
    assert_eq!(tool.qcow2_size(task, &src.0, len).await, Ok(8 * MIB));
    let dst = Loop::new(16 * MIB);
    dst.write(&vec![0xee; (16 * MIB) as usize]);
    tool.convert(task, &src.0, len, ImageFormat::Qcow2, &dst.0)
        .await
        .unwrap();
    assert_eq!(dst.read(raw.len()), raw);

    // Raw: only the first `len` bytes are read.
    let src = Loop::new(32 * MIB);
    src.write(&raw[..MIB as usize]);
    let dst = Loop::new(16 * MIB);
    dst.write(&vec![0xee; (16 * MIB) as usize]);
    tool.convert(task, &src.0, MIB, ImageFormat::Raw, &dst.0)
        .await
        .unwrap();
    let got = dst.read(2 * MIB as usize);
    assert_eq!(&got[..MIB as usize], &raw[..MIB as usize]);
    assert!(got[MIB as usize..].iter().all(|b| *b == 0xee));

    // A backing file, or a data file on another device: refused, never opened.
    let base = dir.path().join("base.raw");
    std::fs::write(&base, vec![0x5a; MIB as usize]).unwrap();
    let backed = dir.path().join("backed.qcow2");
    run(
        "qemu-img",
        &[
            "create",
            "-f",
            "qcow2",
            "-F",
            "raw",
            "-b",
            base.to_str().unwrap(),
            backed.to_str().unwrap(),
        ],
    );
    let datafile = dir.path().join("data.qcow2");
    let data = dir.path().join("secret.raw");
    std::fs::write(&data, vec![0x5a; MIB as usize]).unwrap();
    let opt = format!("data_file={}", data.display());
    run(
        "qemu-img",
        &[
            "create",
            "-f",
            "qcow2",
            "-o",
            &opt,
            datafile.to_str().unwrap(),
            "1M",
        ],
    );
    for bad in [backed, datafile] {
        let file = std::fs::read(&bad).unwrap();
        let src = Loop::new(16 * MIB);
        src.write(&file);
        let r = tool.qcow2_size(task, &src.0, file.len() as u64).await;
        assert!(r.is_err(), "{}: {r:?}", bad.display());
        // Converted anyway: nothing of the backing or data file comes through.
        let dst = Loop::new(4 * MIB);
        let _ = tool
            .convert(task, &src.0, file.len() as u64, ImageFormat::Qcow2, &dst.0)
            .await;
        assert!(!dst.read(MIB as usize).contains(&0x5a));
    }
}
