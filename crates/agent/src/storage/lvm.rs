//! LVM driver: a pool is a volume group that the operator made; a volume is a thick logical volume
//! in it, `torngat-<uid>`.
//!
//! - The group is marked with the tag `torngat:<cluster>:<pool>`; volumes carry the same tag. Only
//!   logical volumes with this name and tag are ever changed, and the group is never created,
//!   changed otherwise or removed.
//! - A new volume carries the tag `torngat-zeroing` until its first and last 16 MiB are zeros: a
//!   creation cut short is finished, never answered as done.
//! - Deleting deactivates the volume first (which fails while anything has it open), overwrites its
//!   first 16 MiB (the encryption header), discards its blocks where the disks can, then removes it.
//! - Attached = active. Volumes are activated one by one; nothing is activated at boot.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;
use tonic::Status;
use torngat_api::storage::LUKS_HEADER_BYTES;
use torngat_proto::storage::v1::attach_volume_response::Device;
use torngat_proto::storage::v1::*;
use uuid::Uuid;

use super::driver::{Driver, pool_of, volume_uid, write_zeros};

const LVM: &str = "/usr/sbin/lvm";
const BLKDISCARD: &str = "/usr/sbin/blkdiscard";
const PREFIX: &str = "torngat-";
const ZEROING: &str = "torngat-zeroing";
const MARKS: &str = "torngat:";
/// LVM waits for locks and udev; a call that takes longer is stuck.
const TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Default)]
pub struct LvmDriver;

#[derive(Debug, Deserialize)]
struct Report<T> {
    report: Vec<BTreeMap<String, Vec<T>>>,
}

#[derive(Debug, Deserialize)]
struct Log {
    #[serde(default)]
    log: Vec<LogEntry>,
}

#[derive(Debug, Deserialize)]
struct LogEntry {
    log_type: String,
    log_message: String,
}

#[derive(Debug, Deserialize)]
struct Vg {
    vg_free: String,
    vg_extent_size: String,
    vg_tags: String,
}

#[derive(Debug, Deserialize)]
struct Lv {
    lv_name: String,
    lv_size: String,
    lv_tags: String,
    lv_active: String,
    lv_dm_path: String,
}

impl Lv {
    fn has(&self, tag: &str) -> bool {
        self.lv_tags.split(',').any(|t| t == tag)
    }
    fn size(&self) -> Result<u64, Status> {
        number(&self.lv_size)
    }
    fn active(&self) -> bool {
        !self.lv_active.is_empty()
    }
}

fn number(s: &str) -> Result<u64, Status> {
    s.trim()
        .parse()
        .map_err(|_| Status::internal(format!("lvm: unexpected size {s:?}")))
}

/// How a group is marked.
#[derive(Debug, PartialEq, Eq)]
enum Marked {
    Ours,
    Not,
    Other,
}

fn marked(v: &Vg, mark: &str) -> Marked {
    let mut marks = v.vg_tags.split(',').filter(|t| t.starts_with(MARKS));
    match marks.next() {
        None => Marked::Not,
        Some(t) if t == mark && marks.next().is_none() => Marked::Ours,
        Some(_) => Marked::Other,
    }
}

/// The group's name and this pool's mark.
fn target(pool: &Option<Pool>) -> Result<(String, String), Status> {
    let p = pool_of(pool)?;
    let ids = Uuid::parse_str(&p.cluster_uid).and_then(|c| Ok((c, Uuid::parse_str(&p.uid)?)));
    let Ok((cluster, uid)) = ids else {
        return Err(Status::invalid_argument("invalid pool uid"));
    };
    Ok((p.source.clone(), format!("{MARKS}{cluster}:{uid}")))
}

fn lv_name(uid: &str) -> Result<String, Status> {
    Ok(format!("{PREFIX}{}", volume_uid(uid)?))
}

/// Runs `lvm ARGS`: stdout, or the error from stderr or the report's log.
async fn lvm(args: &[&str]) -> Result<String, Status> {
    let run = tokio::process::Command::new(LVM)
        .args(args)
        // The errors are told apart by their English text.
        .env("LC_ALL", "C")
        // The TPM's descriptor is inherited (docs/SECURITY-NOTES.md); LVM would warn about it.
        .env("LVM_SUPPRESS_FD_WARNINGS", "1")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output();
    let what = format!("lvm {}", args.first().copied().unwrap_or_default());
    let out = tokio::time::timeout(TIMEOUT, run)
        .await
        .map_err(|_| Status::unavailable(format!("{what}: timed out")))?
        .map_err(|e| Status::internal(format!("{what}: {e}")))?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    let mut err = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    if let Ok(r) = serde_json::from_slice::<Log>(&out.stdout) {
        let logged: Vec<_> = r
            .log
            .into_iter()
            .filter(|l| l.log_type == "error")
            .map(|l| l.log_message)
            .collect();
        if !logged.is_empty() {
            err = logged.join("; ");
        }
    }
    let lower = err.to_lowercase();
    let msg = format!("{what}: {err}");
    Err(
        if lower.contains("insufficient free space") || lower.contains("insufficient suitable") {
            Status::resource_exhausted(msg)
        } else if lower.contains("not found") {
            Status::not_found(msg)
        } else if lower.contains("in use") || lower.contains("is open") {
            Status::failed_precondition(msg)
        } else {
            Status::internal(msg)
        },
    )
}

async fn report<T: serde::de::DeserializeOwned>(
    args: &[&str],
    kind: &str,
) -> Result<Vec<T>, Status> {
    let out = lvm(args).await?;
    let r: Report<T> = serde_json::from_str(&out)
        .map_err(|e| Status::internal(format!("lvm: unexpected report: {e}")))?;
    Ok(r.report
        .into_iter()
        .flat_map(|mut m| m.remove(kind).unwrap_or_default())
        .collect())
}

const JSON: [&str; 3] = ["--reportformat=json", "--units=b", "--nosuffix"];

async fn vg(name: &str) -> Result<Vg, Status> {
    let mut a = vec!["vgs"];
    a.extend(JSON);
    a.extend(["-o", "vg_free,vg_extent_size,vg_tags", name]);
    report::<Vg>(&a, "vg")
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| Status::not_found("no such volume group"))
}

/// Every logical volume of the group.
async fn lvs(vg: &str) -> Result<Vec<Lv>, Status> {
    let mut a = vec!["lvs"];
    a.extend(JSON);
    a.extend(["-o", "lv_name,lv_size,lv_tags,lv_active,lv_dm_path", vg]);
    report(&a, "lv").await
}

/// A group marked as the request's pool.
struct Group {
    name: String,
    mark: String,
    vg: Vg,
}

impl Group {
    /// The group, if it carries this pool's mark.
    async fn of(pool: &Option<Pool>) -> Result<Self, Status> {
        let (name, mark) = target(pool)?;
        let vg = vg(&name).await?;
        if marked(&vg, &mark) != Marked::Ours {
            return Err(Status::failed_precondition(
                "the volume group is not marked as this pool",
            ));
        }
        Ok(Self { name, mark, vg })
    }

    /// This pool's volumes.
    async fn volumes(&self) -> Result<Vec<Lv>, Status> {
        Ok(lvs(&self.name)
            .await?
            .into_iter()
            .filter(|l| l.has(&self.mark))
            .collect())
    }

    /// This pool's volume `uid`, if there is one. One with that name but not this pool's mark is
    /// refused.
    async fn volume(&self, uid: &str) -> Result<Option<Lv>, Status> {
        let name = lv_name(uid)?;
        let Some(lv) = lvs(&self.name)
            .await?
            .into_iter()
            .find(|l| l.lv_name == name)
        else {
            return Ok(None);
        };
        if !lv.has(&self.mark) {
            return Err(Status::failed_precondition(
                "a logical volume with this name is not this pool's",
            ));
        }
        Ok(Some(lv))
    }

    fn at(&self, lv: &Lv) -> String {
        format!("{}/{}", self.name, lv.lv_name)
    }

    /// Activates it; its device.
    async fn activate(&self, lv: &Lv) -> Result<String, Status> {
        if !lv.lv_dm_path.starts_with("/dev/") {
            return Err(Status::internal("lvm: no device path"));
        }
        lvm(&["lvchange", "--activate=y", &self.at(lv)]).await?;
        Ok(lv.lv_dm_path.clone())
    }

    /// Fails with `FAILED_PRECONDITION` while the volume is open.
    async fn deactivate(&self, lv: &Lv) -> Result<(), Status> {
        lvm(&["lvchange", "--activate=n", &self.at(lv)])
            .await
            .map(|_| ())
    }
}

/// Writes zeros over `ranges` (offset, length) of the block device `dev`.
async fn zero(dev: &str, ranges: &[(u64, u64)]) -> Result<(), Status> {
    use std::os::unix::fs::FileTypeExt;
    let io = |e: std::io::Error| Status::internal(format!("{dev}: {e}"));
    if !tokio::fs::metadata(dev)
        .await
        .map_err(io)?
        .file_type()
        .is_block_device()
    {
        return Err(Status::internal(format!("{dev} is not a block device")));
    }
    let mut f = tokio::fs::OpenOptions::new()
        .write(true)
        .open(dev)
        .await
        .map_err(io)?;
    for &(offset, len) in ranges {
        write_zeros(&mut f, offset, len).await.map_err(io)?;
    }
    Ok(())
}

impl Driver for LvmDriver {
    async fn claim_pool(&self, r: ClaimPoolRequest) -> Result<ClaimPoolResponse, Status> {
        let (name, mark) = target(&r.pool)?;
        match marked(&vg(&name).await?, &mark) {
            Marked::Ours => {}
            Marked::Other => {
                return Err(Status::failed_precondition(
                    "the volume group carries another mark",
                ));
            }
            Marked::Not => {
                lvm(&["vgchange", "--addtag", &mark, &name]).await?;
            }
        }
        Ok(ClaimPoolResponse {})
    }

    async fn release_pool(&self, r: ReleasePoolRequest) -> Result<ReleasePoolResponse, Status> {
        let (name, mark) = target(&r.pool)?;
        // A group that is not found may only be out of sight (its disk missing for a while), with
        // its mark and volumes: never taken as released.
        match marked(&vg(&name).await?, &mark) {
            Marked::Not => {}
            Marked::Other => {
                return Err(Status::failed_precondition(
                    "the volume group carries another mark",
                ));
            }
            Marked::Ours => {
                if lvs(&name).await?.iter().any(|l| l.has(&mark)) {
                    return Err(Status::failed_precondition("the pool holds volumes"));
                }
                lvm(&["vgchange", "--deltag", &mark, &name]).await?;
            }
        }
        Ok(ReleasePoolResponse {})
    }

    async fn get_pool(&self, r: GetPoolRequest) -> Result<GetPoolResponse, Status> {
        let g = Group::of(&r.pool).await?;
        // Free space and this pool's volumes: what others use (also hidden volumes) is not counted.
        let mut ours = 0u64;
        for l in g.volumes().await? {
            ours = ours.saturating_add(l.size()?);
        }
        Ok(GetPoolResponse {
            capacity_bytes: number(&g.vg.vg_free)?.saturating_add(ours),
            capabilities: Some(Capabilities::default()),
            allocation_unit_bytes: number(&g.vg.vg_extent_size)?,
        })
    }

    async fn list_volumes(&self, r: ListVolumesRequest) -> Result<ListVolumesResponse, Status> {
        let g = Group::of(&r.pool).await?;
        let mut volumes = Vec::new();
        for l in g.volumes().await? {
            let Some(uid) = l
                .lv_name
                .strip_prefix(PREFIX)
                .and_then(|u| Uuid::parse_str(u).ok())
            else {
                continue;
            };
            volumes.push(VolumeInfo {
                uid: uid.to_string(),
                size_bytes: l.size()?,
                attached: l.active(),
            });
        }
        Ok(ListVolumesResponse { volumes })
    }

    async fn create_volume(&self, r: CreateVolumeRequest) -> Result<CreateVolumeResponse, Status> {
        let g = Group::of(&r.pool).await?;
        let lv = match g.volume(&r.uid).await? {
            Some(lv) => lv,
            None => {
                let size = format!("{}b", r.size_bytes.max(2 * LUKS_HEADER_BYTES));
                lvm(&[
                    "lvcreate",
                    "--yes",
                    "--wipesignatures=n",
                    "--zero=n",
                    "--activate=n",
                    "--addtag",
                    &g.mark,
                    "--addtag",
                    ZEROING,
                    "--size",
                    &size,
                    "--name",
                    &lv_name(&r.uid)?,
                    &g.name,
                ])
                .await?;
                g.volume(&r.uid)
                    .await?
                    .ok_or_else(|| Status::internal("lvm: the new volume is not there"))?
            }
        };
        let size = lv.size()?;
        if lv.has(ZEROING) {
            let dev = g.activate(&lv).await?;
            let head = size.min(LUKS_HEADER_BYTES);
            let tail = size.saturating_sub(LUKS_HEADER_BYTES).max(head);
            zero(&dev, &[(0, head), (tail, size - tail)]).await?;
            lvm(&["lvchange", "--deltag", ZEROING, &g.at(&lv)]).await?;
            g.deactivate(&lv).await?;
        }
        Ok(CreateVolumeResponse { size_bytes: size })
    }

    async fn grow_volume(&self, r: GrowVolumeRequest) -> Result<GrowVolumeResponse, Status> {
        let g = Group::of(&r.pool).await?;
        let lv = g
            .volume(&r.uid)
            .await?
            .ok_or_else(|| Status::not_found("no such volume"))?;
        let have = lv.size()?;
        if r.size_bytes <= have {
            return Ok(GrowVolumeResponse { size_bytes: have });
        }
        let size = format!("{}b", r.size_bytes);
        lvm(&["lvextend", "--size", &size, &g.at(&lv)]).await?;
        let lv = g
            .volume(&r.uid)
            .await?
            .ok_or_else(|| Status::not_found("no such volume"))?;
        Ok(GrowVolumeResponse {
            size_bytes: lv.size()?,
        })
    }

    async fn delete_volume(&self, r: DeleteVolumeRequest) -> Result<DeleteVolumeResponse, Status> {
        let g = Group::of(&r.pool).await?;
        let Some(lv) = g.volume(&r.uid).await? else {
            return Ok(DeleteVolumeResponse {});
        };
        // Fails while anything has it open (LVM waits out udev's short looks), so that a volume in
        // use is never wiped.
        g.deactivate(&lv).await?;
        let dev = g.activate(&lv).await?;
        // The header first: what is left cannot be opened.
        zero(&dev, &[(0, lv.size()?.min(LUKS_HEADER_BYTES))]).await?;
        // Not every disk can discard.
        let discard = tokio::process::Command::new(BLKDISCARD)
            .arg(&dev)
            .kill_on_drop(true)
            .output();
        if !tokio::time::timeout(TIMEOUT, discard)
            .await
            .is_ok_and(|o| o.is_ok_and(|o| o.status.success()))
        {
            tracing::info!(device = %dev, "blocks not discarded");
        }
        // lvremove deactivates it first, and fails if it was opened meanwhile.
        lvm(&["lvremove", "--yes", &g.at(&lv)]).await?;
        Ok(DeleteVolumeResponse {})
    }

    async fn attach_volume(&self, r: AttachVolumeRequest) -> Result<AttachVolumeResponse, Status> {
        let g = Group::of(&r.pool).await?;
        let lv = g
            .volume(&r.uid)
            .await?
            .ok_or_else(|| Status::not_found("no such volume"))?;
        if lv.has(ZEROING) {
            return Err(Status::failed_precondition("the volume is not made yet"));
        }
        let path = g.activate(&lv).await?;
        Ok(AttachVolumeResponse {
            device: Some(Device::Block(BlockDevice { path })),
        })
    }

    async fn detach_volume(&self, r: DetachVolumeRequest) -> Result<DetachVolumeResponse, Status> {
        let g = Group::of(&r.pool).await?;
        if let Some(lv) = g.volume(&r.uid).await?
            && lv.active()
        {
            g.deactivate(&lv).await?;
        }
        Ok(DetachVolumeResponse {})
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn reports_marks_and_names() {
        let out = r#"{"report":[{"lv":[{"lv_name":"torngat-x","lv_size":"20971520","lv_tags":"torngat:a:b,torngat-zeroing","lv_active":"active","lv_dm_path":"/dev/mapper/vg-torngat--x"}]}],"log":[]}"#;
        let r: Report<Lv> = serde_json::from_str(out).unwrap();
        let lv = &r.report[0]["lv"][0];
        assert!(lv.has("torngat:a:b") && lv.has(ZEROING) && !lv.has("torngat"));
        assert_eq!(lv.size().unwrap(), 20 << 20);

        let vg = |tags: &str| Vg {
            vg_free: "0".into(),
            vg_extent_size: "4194304".into(),
            vg_tags: tags.into(),
        };
        assert_eq!(marked(&vg(""), "torngat:a:b"), Marked::Not);
        assert_eq!(marked(&vg("os,torngat:a:b"), "torngat:a:b"), Marked::Ours);
        assert_eq!(marked(&vg("torngat:a:c"), "torngat:a:b"), Marked::Other);
        assert_eq!(
            marked(&vg("torngat:a:b,torngat:a:c"), "torngat:a:b"),
            Marked::Other
        );

        let c = Uuid::now_v7();
        let p = Uuid::now_v7();
        let pool = |source: &str| {
            Some(Pool {
                uid: p.to_string(),
                cluster_uid: c.to_string(),
                source: source.into(),
            })
        };
        assert_eq!(
            target(&pool("data")).unwrap(),
            ("data".into(), format!("torngat:{c}:{p}"))
        );
        for bad in ["", "-x", "a/b", "../x", "A", "@tag"] {
            assert!(target(&pool(bad)).is_err(), "{bad}");
        }
        assert!(lv_name("../x").is_err());
    }
}
