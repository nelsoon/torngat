//! LVM driver: a pool is a volume group that the operator made; a volume is a thick logical volume
//! in it, `torngat-<uid>`.
//!
//! - The group is marked with the tag `torngat:<cluster>:<pool>`; volumes carry the same tag. Only
//!   logical volumes with this name and tag are ever changed, and the group is never created,
//!   changed otherwise or removed.
//! - A new volume carries the tag `torngat-zeroing` until its first and last 16 MiB are zeros: a
//!   creation cut short is finished, never answered as done.
//! - Deleting overwrites the first 16 MiB (the encryption header), discards the blocks where the
//!   disks can, then removes the volume.
//! - Attached = active. Volumes are activated one by one; nothing is activated at boot.

use std::collections::BTreeMap;

use serde::Deserialize;
use tonic::Status;
use torngat_api::storage::LUKS_HEADER_BYTES;
use torngat_proto::storage::v1::attach_volume_response::Device;
use torngat_proto::storage::v1::*;
use uuid::Uuid;

use super::driver::{Driver, write_zeros};

const LVM: &str = "/usr/sbin/lvm";
const BLKDISCARD: &str = "/usr/sbin/blkdiscard";
const PREFIX: &str = "torngat-";
const ZEROING: &str = "torngat-zeroing";
const MARKS: &str = "torngat:";

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
    vg_size: String,
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
    fn tags(&self) -> impl Iterator<Item = &str> {
        self.lv_tags.split(',').filter(|t| !t.is_empty())
    }
    fn has(&self, tag: &str) -> bool {
        self.tags().any(|t| t == tag)
    }
    fn size(&self) -> Result<u64, Status> {
        number(&self.lv_size)
    }
}

fn number(s: &str) -> Result<u64, Status> {
    s.trim()
        .parse()
        .map_err(|_| Status::internal(format!("lvm: unexpected size {s:?}")))
}

/// The group's name and this pool's mark.
fn target(pool: &Option<Pool>) -> Result<(String, String), Status> {
    let p = pool
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("no pool"))?;
    let ok = !p.source.is_empty()
        && p.source
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        && !p.source.starts_with(['-', '_']);
    let ids = Uuid::parse_str(&p.cluster_uid).and_then(|c| Ok((c, Uuid::parse_str(&p.uid)?)));
    let Ok((cluster, uid)) = ids else {
        return Err(Status::invalid_argument("invalid pool uid"));
    };
    if !ok {
        return Err(Status::invalid_argument("invalid pool source"));
    }
    Ok((p.source.clone(), format!("{MARKS}{cluster}:{uid}")))
}

fn lv_name(uid: &str) -> Result<String, Status> {
    let uid = Uuid::parse_str(uid).map_err(|_| Status::invalid_argument("invalid volume uid"))?;
    Ok(format!("{PREFIX}{uid}"))
}

/// Runs `lvm ARGS`; stdout, or the error with stderr.
async fn lvm(args: &[&str]) -> Result<String, Status> {
    let out = tokio::process::Command::new(LVM)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .map_err(|e| Status::internal(format!("lvm: {e}")))?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    // With --reportformat=json, errors are in the report's log.
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
    let msg = format!("lvm {}: {err}", args.first().copied().unwrap_or_default());
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

async fn vg(name: &str) -> Result<Vg, Status> {
    report::<Vg>(
        &[
            "vgs",
            "--reportformat=json",
            "--units=b",
            "--nosuffix",
            "-o",
            "vg_size,vg_extent_size,vg_tags",
            name,
        ],
        "vg",
    )
    .await?
    .into_iter()
    .next()
    .ok_or_else(|| Status::not_found("no such volume group"))
}

/// Every logical volume of the group.
async fn lvs(vg: &str) -> Result<Vec<Lv>, Status> {
    report(
        &[
            "lvs",
            "--reportformat=json",
            "--units=b",
            "--nosuffix",
            "-o",
            "lv_name,lv_size,lv_tags,lv_active,lv_dm_path",
            vg,
        ],
        "lv",
    )
    .await
}

/// Fails with `FAILED_PRECONDITION` while the volume is open.
async fn deactivate(at: &str) -> Result<(), Status> {
    match lvm(&["lvchange", "--activate=n", at]).await {
        Err(s) if s.code() == tonic::Code::Internal && s.message().contains("open") => Err(
            Status::failed_precondition(format!("the volume is in use: {}", s.message())),
        ),
        r => r.map(|_| ()),
    }
}

fn vg_marks(v: &Vg) -> impl Iterator<Item = &str> {
    v.vg_tags.split(',').filter(|t| t.starts_with(MARKS))
}

impl LvmDriver {
    /// The group, if it carries this pool's mark.
    async fn marked(&self, pool: &Option<Pool>) -> Result<(String, String), Status> {
        let (name, mark) = target(pool)?;
        if !vg_marks(&vg(&name).await?).any(|t| t == mark) {
            return Err(Status::failed_precondition(
                "the volume group is not marked as this pool",
            ));
        }
        Ok((name, mark))
    }

    /// This pool's volume `uid`, if there is one. One with that name but not this pool's mark is
    /// refused.
    async fn volume(&self, vg: &str, mark: &str, uid: &str) -> Result<Option<Lv>, Status> {
        let name = lv_name(uid)?;
        let Some(lv) = lvs(vg).await?.into_iter().find(|l| l.lv_name == name) else {
            return Ok(None);
        };
        if !lv.has(mark) {
            return Err(Status::failed_precondition(
                "a logical volume with this name is not this pool's",
            ));
        }
        Ok(Some(lv))
    }

    /// Activates it and returns its device (from a fresh report: the path appears with it).
    async fn activate(&self, vg: &str, name: &str) -> Result<String, Status> {
        lvm(&["lvchange", "--activate=y", &format!("{vg}/{name}")]).await?;
        let lv = lvs(vg)
            .await?
            .into_iter()
            .find(|l| l.lv_name == name)
            .ok_or_else(|| Status::not_found("no such volume"))?;
        if !lv.lv_dm_path.starts_with("/dev/") {
            return Err(Status::internal("lvm: no device path"));
        }
        Ok(lv.lv_dm_path)
    }

    /// Zeros the first and last 16 MiB, then drops the pending tag.
    async fn finish(&self, vg: &str, lv: &Lv) -> Result<(), Status> {
        let size = lv.size()?;
        let dev = self.activate(vg, &lv.lv_name).await?;
        let io = |e: std::io::Error| Status::internal(format!("{dev}: {e}"));
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&dev)
            .await
            .map_err(io)?;
        let head = size.min(LUKS_HEADER_BYTES);
        write_zeros(&mut f, 0, head).await.map_err(io)?;
        let tail = size.saturating_sub(LUKS_HEADER_BYTES).max(head);
        write_zeros(&mut f, tail, size - tail).await.map_err(io)?;
        drop(f);
        let at = format!("{vg}/{}", lv.lv_name);
        lvm(&["lvchange", "--deltag", ZEROING, &at]).await?;
        lvm(&["lvchange", "--activate=n", &at]).await?;
        Ok(())
    }
}

impl Driver for LvmDriver {
    async fn claim_pool(&self, r: ClaimPoolRequest) -> Result<ClaimPoolResponse, Status> {
        let (name, mark) = target(&r.pool)?;
        let v = vg(&name).await?;
        let marks: Vec<&str> = vg_marks(&v).collect();
        if marks.contains(&mark.as_str()) {
            return Ok(ClaimPoolResponse {});
        }
        if !marks.is_empty() {
            return Err(Status::failed_precondition(
                "the volume group carries another mark",
            ));
        }
        lvm(&["vgchange", "--addtag", &mark, &name]).await?;
        Ok(ClaimPoolResponse {})
    }

    async fn release_pool(&self, r: ReleasePoolRequest) -> Result<ReleasePoolResponse, Status> {
        let (name, mark) = target(&r.pool)?;
        let v = vg(&name).await?;
        let marks: Vec<&str> = vg_marks(&v).collect();
        if !marks.contains(&mark.as_str()) {
            if marks.is_empty() {
                return Ok(ReleasePoolResponse {});
            }
            return Err(Status::failed_precondition(
                "the volume group carries another mark",
            ));
        }
        if lvs(&name).await?.iter().any(|l| l.has(&mark)) {
            return Err(Status::failed_precondition("the pool holds volumes"));
        }
        lvm(&["vgchange", "--deltag", &mark, &name]).await?;
        Ok(ReleasePoolResponse {})
    }

    async fn get_pool(&self, r: GetPoolRequest) -> Result<GetPoolResponse, Status> {
        let (name, mark) = self.marked(&r.pool).await?;
        let v = vg(&name).await?;
        // What others use is not this pool's.
        let mut others = 0u64;
        for l in lvs(&name).await? {
            if !l.has(&mark) {
                others = others.saturating_add(l.size()?);
            }
        }
        Ok(GetPoolResponse {
            capacity_bytes: number(&v.vg_size)?.saturating_sub(others),
            capabilities: Some(Capabilities::default()),
            allocation_unit_bytes: number(&v.vg_extent_size)?,
        })
    }

    async fn list_volumes(&self, r: ListVolumesRequest) -> Result<ListVolumesResponse, Status> {
        let (name, mark) = self.marked(&r.pool).await?;
        let mut volumes = Vec::new();
        for l in lvs(&name).await? {
            let uid = l
                .lv_name
                .strip_prefix(PREFIX)
                .and_then(|u| Uuid::parse_str(u).ok());
            let (Some(uid), true) = (uid, l.has(&mark)) else {
                continue;
            };
            volumes.push(VolumeInfo {
                uid: uid.to_string(),
                size_bytes: l.size()?,
                attached: !l.lv_active.is_empty(),
            });
        }
        Ok(ListVolumesResponse { volumes })
    }

    async fn create_volume(&self, r: CreateVolumeRequest) -> Result<CreateVolumeResponse, Status> {
        let (vg, mark) = self.marked(&r.pool).await?;
        let lv = match self.volume(&vg, &mark, &r.uid).await? {
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
                    &mark,
                    "--addtag",
                    ZEROING,
                    "--size",
                    &size,
                    "--name",
                    &lv_name(&r.uid)?,
                    &vg,
                ])
                .await?;
                self.volume(&vg, &mark, &r.uid)
                    .await?
                    .ok_or_else(|| Status::internal("lvm: the new volume is not there"))?
            }
        };
        if lv.has(ZEROING) {
            self.finish(&vg, &lv).await?;
        }
        Ok(CreateVolumeResponse {
            size_bytes: lv.size()?,
        })
    }

    async fn grow_volume(&self, r: GrowVolumeRequest) -> Result<GrowVolumeResponse, Status> {
        let (vg, mark) = self.marked(&r.pool).await?;
        let lv = self
            .volume(&vg, &mark, &r.uid)
            .await?
            .ok_or_else(|| Status::not_found("no such volume"))?;
        let have = lv.size()?;
        if r.size_bytes <= have {
            return Ok(GrowVolumeResponse { size_bytes: have });
        }
        let at = format!("{vg}/{}", lv.lv_name);
        lvm(&["lvextend", "--size", &format!("{}b", r.size_bytes), &at]).await?;
        let lv = self
            .volume(&vg, &mark, &r.uid)
            .await?
            .ok_or_else(|| Status::not_found("no such volume"))?;
        Ok(GrowVolumeResponse {
            size_bytes: lv.size()?,
        })
    }

    async fn delete_volume(&self, r: DeleteVolumeRequest) -> Result<DeleteVolumeResponse, Status> {
        let (vg, mark) = self.marked(&r.pool).await?;
        let Some(lv) = self.volume(&vg, &mark, &r.uid).await? else {
            return Ok(DeleteVolumeResponse {});
        };
        // Deactivated first: that fails while anything has it open (LVM waits out udev's short
        // looks), so that an instance's volume is never wiped.
        let at = format!("{vg}/{}", lv.lv_name);
        deactivate(&at).await?;
        let dev = self.activate(&vg, &lv.lv_name).await?;
        // The header first: what is left cannot be opened.
        let io = |e: std::io::Error| Status::internal(format!("{dev}: {e}"));
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&dev)
            .await
            .map_err(io)?;
        write_zeros(&mut f, 0, lv.size()?.min(LUKS_HEADER_BYTES))
            .await
            .map_err(io)?;
        drop(f);
        // Not every disk can discard.
        let discard = tokio::process::Command::new(BLKDISCARD)
            .arg(&dev)
            .output()
            .await;
        if !discard.as_ref().is_ok_and(|o| o.status.success()) {
            tracing::info!(device = %dev, "blocks not discarded");
        }
        deactivate(&at).await?;
        lvm(&["lvremove", "--yes", &at]).await?;
        Ok(DeleteVolumeResponse {})
    }

    async fn attach_volume(&self, r: AttachVolumeRequest) -> Result<AttachVolumeResponse, Status> {
        let (vg, mark) = self.marked(&r.pool).await?;
        let lv = self
            .volume(&vg, &mark, &r.uid)
            .await?
            .ok_or_else(|| Status::not_found("no such volume"))?;
        if lv.has(ZEROING) {
            return Err(Status::failed_precondition("the volume is not made yet"));
        }
        let path = self.activate(&vg, &lv.lv_name).await?;
        Ok(AttachVolumeResponse {
            device: Some(Device::Block(BlockDevice { path })),
        })
    }

    async fn detach_volume(&self, r: DetachVolumeRequest) -> Result<DetachVolumeResponse, Status> {
        let (vg, mark) = self.marked(&r.pool).await?;
        let Some(lv) = self.volume(&vg, &mark, &r.uid).await? else {
            return Ok(DetachVolumeResponse {});
        };
        if !lv.lv_active.is_empty() {
            deactivate(&format!("{vg}/{}", lv.lv_name)).await?;
        }
        Ok(DetachVolumeResponse {})
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn reports_and_names() {
        let out = r#"{"report":[{"lv":[{"lv_name":"torngat-x","lv_size":"20971520","lv_tags":"torngat:a:b,torngat-zeroing","lv_active":"active","lv_dm_path":"/dev/mapper/vg-torngat--x"}]}],"log":[]}"#;
        let r: Report<Lv> = serde_json::from_str(out).unwrap();
        let lv = &r.report[0]["lv"][0];
        assert!(lv.has("torngat:a:b") && lv.has(ZEROING) && !lv.has("torngat"));
        assert_eq!(lv.size().unwrap(), 20 << 20);

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
        for bad in ["", "-x", "a/b", "../x", "A"] {
            assert!(target(&pool(bad)).is_err(), "{bad}");
        }
        assert!(lv_name("../x").is_err());
    }
}
