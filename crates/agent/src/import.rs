//! Image imports on the node.
//!
//! Each image assigned here goes through steps, each in a task of its own (off the session loop),
//! whose result is reported to the controller:
//! 1. the length of the download;
//! 2. once the staging volume is open: the download into it, checked against the image's checksum,
//!    then its format (by its first bytes) and the size of its disk;
//! 3. once the image's volume is open: the copy of the disk into it.
//!
//! A step that was interrupted (the agent stopped, the session ended) starts over. qemu-img reads
//! what tenants sent: it runs in a sandbox (see [`QemuImg`]).

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tonic::transport::Channel;
use torngat_api::Scope;
use torngat_api::image::{Checksum, Image, ImageFormat};
use torngat_api::settings::ImageSettings;
use torngat_proto::v1::ImageReport;
use torngat_proto::v1::control_client::ControlClient;
use uuid::Uuid;

use crate::fetch::{Fetcher, Limits, Reach};
use crate::sanitize;

/// How often a step that goes on is reported, so that the controller knows the import moves on.
const PROGRESS_EVERY: Duration = Duration::from_secs(60);
/// The start of a qcow2 file.
const QCOW2_MAGIC: &[u8; 4] = b"QFI\xfb";

/// Downloads, reads and converts disk images.
pub trait ImageTool: Clone + Send + Sync + 'static {
    /// The length of the file at `url`.
    fn length(
        &self,
        url: &str,
        reach: Reach,
        max: u64,
    ) -> impl Future<Output = Result<u64, String>> + Send;

    /// Writes the file at `url` to `out`: `length` bytes that match `checksum`.
    fn download(
        &self,
        url: &str,
        reach: Reach,
        max: u64,
        length: u64,
        checksum: &Checksum,
        out: &mut tokio::fs::File,
    ) -> impl Future<Output = Result<(), String>> + Send;

    /// The size of the disk in the qcow2 image held by the first `len` bytes of `src`. Refuses one
    /// with a backing file or a data file.
    fn qcow2_size(
        &self,
        task: Uuid,
        src: &Path,
        len: u64,
    ) -> impl Future<Output = Result<u64, String>> + Send;

    /// Writes the disk in the image (`format`) held by the first `len` bytes of `src` onto `dst`.
    fn convert(
        &self,
        task: Uuid,
        src: &Path,
        len: u64,
        format: ImageFormat,
        dst: &Path,
    ) -> impl Future<Output = Result<(), String>> + Send;

    /// Stops what runs for `task`, if anything.
    fn stop(&self, task: Uuid) -> impl Future<Output = ()> + Send;
}

/// What a step found.
#[derive(Debug)]
enum Done {
    Length(u64),
    Info(ImageFormat, u64),
    Converted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Length,
    Download,
    Convert,
}

impl Step {
    fn doing(self) -> &'static str {
        match self {
            Step::Length => "asking for its length",
            Step::Download => "downloading",
            Step::Convert => "copying it into its volume",
        }
    }
}

#[derive(Debug)]
struct Task {
    step: Step,
    handle: JoinHandle<Result<Done, String>>,
    reported: Instant,
}

/// Where an image's volumes are open: path and size.
pub type Opened = Option<(PathBuf, u64)>;

#[derive(Debug)]
pub struct Importer<T> {
    tool: T,
    tasks: HashMap<Uuid, Task>,
    /// Steps whose result was reported, until the controller's answer comes: not started again
    /// meanwhile (unless the answer takes long: the report may have been lost).
    reported: HashMap<Uuid, (Step, Instant)>,
    /// Told when a task ends.
    done: Arc<Notify>,
}

fn report_of(image: &Image) -> ImageReport {
    let (org, project) = match &image.metadata.scope {
        Scope::Project { org, project } => (org.to_string(), project.to_string()),
        _ => (String::new(), String::new()),
    };
    ImageReport {
        org,
        project,
        name: image.metadata.name.to_string(),
        uid: image.metadata.uid.to_string(),
        ..Default::default()
    }
}

impl<T: ImageTool> Importer<T> {
    pub fn new(tool: T) -> Self {
        Self {
            tool,
            tasks: HashMap::new(),
            reported: HashMap::new(),
            done: Arc::new(Notify::new()),
        }
    }

    /// Wakes the session loop when a step ends.
    pub fn notifier(&self) -> Arc<Notify> {
        self.done.clone()
    }

    /// Stops every step: the session ended, and what it found could not be reported.
    pub async fn stop_all(&mut self) {
        self.reported.clear();
        for (uid, t) in self.tasks.drain() {
            t.handle.abort();
            self.tool.stop(uid).await;
        }
    }

    /// Starts, follows and reports the steps of `images`, and stops those of other images.
    /// `opened(image, staging)` tells where its staging volume (or its image volume) is open.
    pub async fn reconcile(
        &mut self,
        client: &mut ControlClient<Channel>,
        images: &[Image],
        settings: &ImageSettings,
        opened: impl Fn(&Image, bool) -> Opened,
    ) -> Result<(), tonic::Status> {
        let gone: Vec<Uuid> = self
            .tasks
            .keys()
            .filter(|u| !images.iter().any(|i| i.metadata.uid == **u))
            .copied()
            .collect();
        self.reported
            .retain(|u, _| images.iter().any(|i| i.metadata.uid == *u));
        for uid in gone {
            if let Some(t) = self.tasks.remove(&uid) {
                t.handle.abort();
                self.tool.stop(uid).await;
            }
        }

        for image in images {
            let uid = image.metadata.uid;
            let staging = opened(image, true);
            let target = opened(image, false);
            let want = if image.status.download_bytes.is_none() {
                Some(Step::Length)
            } else if image.status.format.is_none() {
                staging.is_some().then_some(Step::Download)
            } else {
                (staging.is_some() && target.is_some()).then_some(Step::Convert)
            };
            match self.reported.get(&uid) {
                Some((step, at)) if Some(*step) == want && at.elapsed() < PROGRESS_EVERY => {
                    continue;
                }
                _ => {
                    self.reported.remove(&uid);
                }
            }
            if let Some(t) = self.tasks.get_mut(&uid) {
                if Some(t.step) != want {
                    // The controller moved on, or a volume closed.
                    t.handle.abort();
                    self.tasks.remove(&uid);
                    self.tool.stop(uid).await;
                } else if !t.handle.is_finished() {
                    if t.reported.elapsed() >= PROGRESS_EVERY {
                        t.reported = Instant::now();
                        let mut r = report_of(image);
                        r.message = t.step.doing().into();
                        send(client, r).await?;
                    }
                    continue;
                } else if let Some(t) = self.tasks.remove(&uid) {
                    let result = t.handle.await.unwrap_or_else(|e| Err(e.to_string()));
                    let mut r = report_of(image);
                    match result {
                        Ok(Done::Length(n)) => r.download_bytes = n,
                        Ok(Done::Info(f, size)) => {
                            r.format = match f {
                                ImageFormat::Raw => "raw",
                                ImageFormat::Qcow2 => "qcow2",
                            }
                            .into();
                            r.size_bytes = size;
                        }
                        Ok(Done::Converted) => r.done = true,
                        Err(e) => {
                            tracing::warn!(image = %uid, error = %e, "image import failed");
                            r.failed = true;
                            r.message = sanitize(&e);
                            if r.message.is_empty() {
                                r.message = "failed".into();
                            }
                        }
                    }
                    send(client, r).await?;
                    // The next step starts once the controller answered with the new state.
                    self.reported.insert(uid, (t.step, Instant::now()));
                    continue;
                }
            }
            let Some(step) = want else { continue };
            let job = Job {
                tool: self.tool.clone(),
                uid,
                url: image.spec.source.url.clone(),
                checksum: image.spec.source.checksum.clone(),
                length: image.status.download_bytes.unwrap_or(0),
                format: image.status.format,
                size: image.status.size_bytes,
                reach: if image.metadata.scope == Scope::Platform
                    && settings.platform_private_sources
                {
                    Reach::Private
                } else {
                    Reach::Public
                },
                max: settings.max_image_bytes(),
                staging,
                target,
            };
            let done = self.done.clone();
            let handle = tokio::spawn(async move {
                let r = job.run(step).await;
                done.notify_one();
                r
            });
            tracing::info!(image = %uid, step = step.doing(), "image import step started");
            self.tasks.insert(
                uid,
                Task {
                    step,
                    handle,
                    reported: Instant::now(),
                },
            );
        }
        Ok(())
    }
}

/// Sends a report. A refusal is logged, not an error: the controller's state decides what comes next.
async fn send(client: &mut ControlClient<Channel>, r: ImageReport) -> Result<(), tonic::Status> {
    match client.report_image(r).await {
        Ok(_) => Ok(()),
        Err(s)
            if matches!(
                s.code(),
                tonic::Code::FailedPrecondition
                    | tonic::Code::InvalidArgument
                    | tonic::Code::PermissionDenied
            ) =>
        {
            tracing::warn!(error = %s.message(), "image report refused");
            Ok(())
        }
        Err(s) => Err(s),
    }
}

/// What a step needs, copied out of the image.
struct Job<T> {
    tool: T,
    uid: Uuid,
    url: String,
    checksum: Checksum,
    length: u64,
    format: Option<ImageFormat>,
    size: u64,
    reach: Reach,
    max: u64,
    staging: Opened,
    target: Opened,
}

impl<T: ImageTool> Job<T> {
    async fn run(self, step: Step) -> Result<Done, String> {
        match step {
            Step::Length => {
                let n = self.tool.length(&self.url, self.reach, self.max).await?;
                if n == 0 {
                    return Err("the file is empty".into());
                }
                Ok(Done::Length(n))
            }
            Step::Download => {
                let (path, room) = self.staging.clone().ok_or("no staging volume")?;
                if room < self.length {
                    return Err("the staging volume is too small".into());
                }
                let mut out = tokio::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .await
                    .map_err(|e| format!("cannot open the staging volume: {e}"))?;
                let (url, reach, max) = (&self.url, self.reach, self.max);
                self.tool
                    .download(url, reach, max, self.length, &self.checksum, &mut out)
                    .await?;
                out.sync_all()
                    .await
                    .map_err(|e| format!("cannot write the staging volume: {e}"))?;
                drop(out);
                let format = detect(&path, self.length).await?;
                let size = match format {
                    ImageFormat::Raw => self.length,
                    ImageFormat::Qcow2 => {
                        self.tool.qcow2_size(self.uid, &path, self.length).await?
                    }
                };
                if size == 0 || size > self.max {
                    return Err(format!(
                        "its disk is {size} bytes: more than the {} allowed",
                        self.max
                    ));
                }
                Ok(Done::Info(format, size))
            }
            Step::Convert => {
                let (src, _) = self.staging.clone().ok_or("no staging volume")?;
                let (dst, room) = self.target.clone().ok_or("no image volume")?;
                let format = self.format.ok_or("no format")?;
                if room < self.size {
                    return Err("the image's volume is too small".into());
                }
                self.tool
                    .convert(self.uid, &src, self.length, format, &dst)
                    .await?;
                Ok(Done::Converted)
            }
        }
    }
}

/// The format of the image in the first `len` bytes of `path`, from its first bytes.
async fn detect(path: &Path, len: u64) -> Result<ImageFormat, String> {
    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("cannot read the staging volume: {e}"))?;
    let mut magic = [0u8; 4];
    if len < magic.len() as u64 {
        return Ok(ImageFormat::Raw);
    }
    f.read_exact(&mut magic)
        .await
        .map_err(|e| format!("cannot read the staging volume: {e}"))?;
    Ok(if &magic == QCOW2_MAGIC {
        ImageFormat::Qcow2
    } else {
        ImageFormat::Raw
    })
}

/// The block device options for qemu-img: the first `len` bytes of `src` as an image of `format`.
/// A backing file is never opened.
pub fn source_options(src: &Path, len: u64, format: ImageFormat) -> String {
    let file = serde_json::json!({"driver": "host_device", "filename": src});
    let bounded = serde_json::json!({"driver": "raw", "size": len, "file": file});
    let opts = match format {
        ImageFormat::Raw => bounded,
        ImageFormat::Qcow2 => {
            serde_json::json!({"driver": "qcow2", "backing": null, "file": bounded})
        }
    };
    format!("json:{opts}")
}

/// Whether `qemu-img info` output describes a qcow2 image with no backing or data file, and its
/// disk size if so.
pub fn qcow2_info(out: &[u8]) -> Result<u64, String> {
    let v: serde_json::Value =
        serde_json::from_slice(out).map_err(|_| "qemu-img info: unexpected output".to_owned())?;
    if v.get("format").and_then(|f| f.as_str()) != Some("qcow2") {
        return Err("not a qcow2 image".into());
    }
    if v.get("backing-filename").is_some() || v.get("full-backing-filename").is_some() {
        return Err("the image has a backing file: refused".into());
    }
    if v.pointer("/format-specific/data/data-file").is_some() {
        return Err("the image has a data file: refused".into());
    }
    v.get("virtual-size")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "qemu-img info: no size".to_owned())
}

/// qemu-img in a transient unit: no network, no capabilities, nothing of the host's but the
/// two devices it works on (read-only for the source), and time and memory limits.
#[derive(Debug, Clone)]
pub struct QemuImg {
    /// `/usr/bin/qemu-img`.
    pub program: PathBuf,
    pub runtime_max: Duration,
}

impl Default for QemuImg {
    fn default() -> Self {
        Self {
            program: "/usr/bin/qemu-img".into(),
            runtime_max: Duration::from_secs(6 * 3600),
        }
    }
}

/// Longest output read from qemu-img.
const MAX_OUTPUT: u64 = 1 << 20;

fn unit(task: Uuid) -> String {
    format!("torngat-image-{task}")
}

impl QemuImg {
    /// The sandbox's properties, with `read` readable and `write` writable.
    pub fn properties(&self, read: &Path, write: Option<&Path>) -> Vec<String> {
        let mut p = vec![
            "Description=Torngat image tool".into(),
            "DynamicUser=yes".into(),
            // Device nodes are the disk group's; only those allowed below can be opened.
            "SupplementaryGroups=disk".into(),
            "PrivateDevices=yes".into(),
            "DevicePolicy=closed".into(),
            format!("BindReadOnlyPaths={}", read.display()),
            format!("DeviceAllow={} r", read.display()),
            "MemoryMax=2G".into(),
            "MemorySwapMax=0".into(),
            "TasksMax=64".into(),
            "LimitCORE=0".into(),
            format!("RuntimeMaxSec={}", self.runtime_max.as_secs()),
            "PrivateIPC=yes".into(),
            "PrivateNetwork=yes".into(),
            "IPAddressDeny=any".into(),
            "RestrictAddressFamilies=AF_UNIX".into(),
            "CapabilityBoundingSet=".into(),
            "AmbientCapabilities=".into(),
            "NoNewPrivileges=yes".into(),
            "RestrictNamespaces=yes".into(),
            "RestrictRealtime=yes".into(),
            "RestrictSUIDSGID=yes".into(),
            "LockPersonality=yes".into(),
            "MemoryDenyWriteExecute=yes".into(),
            "SystemCallArchitectures=native".into(),
            "SystemCallFilter=@system-service".into(),
            "KeyringMode=private".into(),
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
            "UMask=0077".into(),
            "InaccessiblePaths=-/run/dbus -/run/systemd/private -/run/systemd/io.systemd.ManagedOOM"
                .into(),
        ];
        if let Some(w) = write {
            p.push(format!("BindPaths={}", w.display()));
            p.push(format!("DeviceAllow={} rw", w.display()));
        }
        p
    }

    /// Runs qemu-img with `args` in the sandbox; returns its output.
    async fn run(
        &self,
        task: Uuid,
        read: &Path,
        write: Option<&Path>,
        args: &[String],
    ) -> Result<Vec<u8>, String> {
        // The device node itself, not the /dev/mapper link: that is what is bound and allowed.
        let node = |p: &Path| std::fs::canonicalize(p).map_err(|e| format!("{}: {e}", p.display()));
        let read = node(read)?;
        let write = write.map(node).transpose()?;
        // A unit left by an agent that stopped.
        self.stop(task).await;
        let mut cmd = tokio::process::Command::new("systemd-run");
        cmd.args([
            "--wait",
            "--pipe",
            "--collect",
            "--quiet",
            "--service-type=exec",
        ])
        .arg(format!("--unit={}", unit(task)));
        for p in self.properties(&read, write.as_deref()) {
            cmd.arg("-p").arg(p);
        }
        cmd.arg("--").arg(&self.program).args(args);
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| format!("systemd-run: {e}"))?;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let (o, e) = (child.stdout.take(), child.stderr.take());
        let read_out = async {
            if let Some(o) = o {
                let _ = o.take(MAX_OUTPUT).read_to_end(&mut out).await;
            }
        };
        let read_err = async {
            if let Some(e) = e {
                let _ = e.take(MAX_OUTPUT).read_to_end(&mut err).await;
            }
        };
        let (status, (), ()) = tokio::join!(child.wait(), read_out, read_err);
        let status = status.map_err(|e| format!("systemd-run: {e}"))?;
        if !status.success() {
            let text = String::from_utf8_lossy(&err);
            let last = text
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("");
            // qemu-img names the devices: tenants need not see host paths.
            let last = last.replace(&*read.to_string_lossy(), "the download");
            let last = match &write {
                Some(w) => last.replace(&*w.to_string_lossy(), "the image's volume"),
                None => last,
            };
            return Err(format!(
                "qemu-img failed: {}",
                last.chars().take(200).collect::<String>()
            ));
        }
        Ok(out)
    }
}

fn fetcher(reach: Reach, max: u64) -> Result<Fetcher, String> {
    let limits = Limits {
        max_bytes: max,
        ..Default::default()
    };
    Fetcher::new(reach, limits).map_err(|e| e.to_string())
}

impl ImageTool for QemuImg {
    async fn length(&self, url: &str, reach: Reach, max: u64) -> Result<u64, String> {
        fetcher(reach, max)?
            .length(url)
            .await
            .map_err(|e| e.to_string())
    }

    async fn download(
        &self,
        url: &str,
        reach: Reach,
        max: u64,
        length: u64,
        checksum: &Checksum,
        out: &mut tokio::fs::File,
    ) -> Result<(), String> {
        fetcher(reach, max)?
            .download(url, length, checksum, out)
            .await
            .map_err(|e| e.to_string())
    }

    async fn qcow2_size(&self, task: Uuid, src: &Path, len: u64) -> Result<u64, String> {
        let node = std::fs::canonicalize(src).map_err(|e| format!("{}: {e}", src.display()))?;
        let args = vec![
            "info".into(),
            "--output=json".into(),
            source_options(&node, len, ImageFormat::Qcow2),
        ];
        let out = self.run(task, &node, None, &args).await?;
        qcow2_info(&out)
    }

    async fn convert(
        &self,
        task: Uuid,
        src: &Path,
        len: u64,
        format: ImageFormat,
        dst: &Path,
    ) -> Result<(), String> {
        let canon =
            |p: &Path| std::fs::canonicalize(p).map_err(|e| format!("{}: {e}", p.display()));
        let (s, d) = (canon(src)?, canon(dst)?);
        let target = format!(
            "driver=raw,file.driver=host_device,file.filename={}",
            d.display()
        );
        let args = vec![
            "convert".into(),
            // The target exists; holes are written as zeros (the device is not blank).
            "-n".into(),
            "--target-image-opts".into(),
            source_options(&s, len, format),
            target,
        ];
        self.run(task, &s, Some(&d), &args).await.map(|_| ())
    }

    async fn stop(&self, task: Uuid) {
        let _ = tokio::process::Command::new("systemctl")
            .args(["stop", "--quiet"])
            .arg(format!("{}.service", unit(task)))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;
    }
}

/// For tests: files are served from memory, by URL (with no check of where it leads); raw images
/// are copied, qcow2 ones only measured (from their header).
#[derive(Debug, Clone, Default)]
pub struct FakeImageTool {
    pub files: Arc<std::sync::Mutex<HashMap<String, Vec<u8>>>>,
}

impl FakeImageTool {
    fn file(&self, url: &str) -> Result<Vec<u8>, String> {
        self.files
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(url)
            .cloned()
            .ok_or_else(|| "the server answered 404".to_owned())
    }
}

impl ImageTool for FakeImageTool {
    async fn length(&self, url: &str, _reach: Reach, max: u64) -> Result<u64, String> {
        let n = self.file(url)?.len() as u64;
        if n > max {
            return Err(format!("the file is larger than {max} bytes"));
        }
        Ok(n)
    }

    async fn download(
        &self,
        url: &str,
        _reach: Reach,
        _max: u64,
        length: u64,
        checksum: &Checksum,
        out: &mut tokio::fs::File,
    ) -> Result<(), String> {
        use tokio::io::AsyncWriteExt;
        let f = self.file(url)?;
        if f.len() as u64 != length {
            return Err("the length changed".into());
        }
        let want = match checksum {
            Checksum::Sha256(h) => h.clone(),
            Checksum::Sha512(_) => return Err("the fake tool checks sha256 only".into()),
        };
        if torngat_pki::hex_sha256(&f) != want {
            return Err("the checksum does not match".into());
        }
        out.write_all(&f).await.map_err(|e| e.to_string())
    }

    async fn qcow2_size(&self, _task: Uuid, src: &Path, _len: u64) -> Result<u64, String> {
        let mut f = tokio::fs::File::open(src)
            .await
            .map_err(|e| e.to_string())?;
        let mut header = [0u8; 32];
        f.read_exact(&mut header).await.map_err(|e| e.to_string())?;
        // The disk size is at bytes 24..32, big-endian.
        let mut size = [0u8; 8];
        size.copy_from_slice(&header[24..32]);
        Ok(u64::from_be_bytes(size))
    }

    async fn convert(
        &self,
        _task: Uuid,
        src: &Path,
        len: u64,
        format: ImageFormat,
        dst: &Path,
    ) -> Result<(), String> {
        if format != ImageFormat::Raw {
            return Err("the fake tool copies raw images only".into());
        }
        let mut from = tokio::fs::File::open(src)
            .await
            .map_err(|e| e.to_string())?;
        let mut to = tokio::fs::OpenOptions::new()
            .write(true)
            .open(dst)
            .await
            .map_err(|e| e.to_string())?;
        tokio::io::copy(&mut (&mut from).take(len), &mut to)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn stop(&self, _task: Uuid) {}
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn options() {
        let o = source_options(Path::new("/dev/dm-3"), 1000, ImageFormat::Qcow2);
        let v: serde_json::Value = serde_json::from_str(o.strip_prefix("json:").unwrap()).unwrap();
        assert_eq!(v["driver"], "qcow2");
        assert!(v["backing"].is_null() && v.get("backing").is_some());
        assert_eq!(v["file"]["driver"], "raw");
        assert_eq!(v["file"]["size"], 1000);
        assert_eq!(v["file"]["file"]["filename"], "/dev/dm-3");
        let o = source_options(Path::new("/dev/dm-3"), 7, ImageFormat::Raw);
        assert!(o.starts_with(r#"json:{"driver":"raw""#) || o.contains(r#""driver":"raw""#));
    }

    #[test]
    fn info() {
        let ok = br#"{"format":"qcow2","virtual-size":3221225472,"format-specific":{"type":"qcow2","data":{"compat":"1.1"}}}"#;
        assert_eq!(qcow2_info(ok), Ok(3221225472));
        for bad in [
            &br#"{"format":"qcow2","virtual-size":1,"backing-filename":"/etc/shadow"}"#[..],
            br#"{"format":"qcow2","virtual-size":1,"format-specific":{"data":{"data-file":"/dev/sda"}}}"#,
            br#"{"format":"raw","virtual-size":1}"#,
            br#"{"format":"qcow2"}"#,
            b"not json",
        ] {
            assert!(qcow2_info(bad).is_err());
        }
    }

    #[test]
    fn sandbox() {
        let p = QemuImg::default().properties(Path::new("/dev/dm-1"), Some(Path::new("/dev/dm-2")));
        for want in [
            "DynamicUser=yes",
            "PrivateDevices=yes",
            "DevicePolicy=closed",
            "PrivateNetwork=yes",
            "CapabilityBoundingSet=",
            "ProtectSystem=strict",
            "BindReadOnlyPaths=/dev/dm-1",
            "DeviceAllow=/dev/dm-1 r",
            "BindPaths=/dev/dm-2",
            "DeviceAllow=/dev/dm-2 rw",
        ] {
            assert!(p.iter().any(|x| x == want), "{want}");
        }
        let ro = QemuImg::default().properties(Path::new("/dev/dm-1"), None);
        assert!(
            !ro.iter()
                .any(|x| x.contains(" rw") || x.starts_with("BindPaths="))
        );
    }

    #[tokio::test]
    async fn formats_by_content() {
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("f");
        let mut q = QCOW2_MAGIC.to_vec();
        q.extend_from_slice(&[0; 100]);
        std::fs::write(&p, &q).unwrap();
        assert_eq!(detect(&p, 104).await, Ok(ImageFormat::Qcow2));
        std::fs::write(&p, b"QFI").unwrap();
        assert_eq!(detect(&p, 3).await, Ok(ImageFormat::Raw));
        std::fs::write(&p, [0u8; 512]).unwrap();
        assert_eq!(detect(&p, 512).await, Ok(ImageFormat::Raw));
    }
}
