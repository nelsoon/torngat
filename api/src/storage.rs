//! Storage pools, volume types and volumes.
//!
//! Operators describe *pools* (storage on one node) and group them into *volume types*. Tenants
//! create *volumes* of a type and never see pools or drivers. Local volumes get their node at first
//! use by an instance, so that both land where there is room.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Name;
use crate::meta::Object;

const GIB: u64 = 1024 * 1024 * 1024;
/// Space at the start of a device for the LUKS2 header.
pub const LUKS_HEADER_BYTES: u64 = 16 * 1024 * 1024;

pub const MAX_VOLUME_GIB: u64 = 64 * 1024;
/// A pool's record lists its reservations and is written as a whole for each.
pub const MAX_VOLUMES_PER_POOL: usize = 1024;
pub const MAX_POOLS_PER_TYPE: usize = 1024;
pub const MAX_DESCRIPTION_LEN: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    #[error(
        "source must be 1 to 63 lowercase letters, digits, '-' and '_', starting with a letter or digit"
    )]
    Source,
    #[error("size_gib must be between 1 and {MAX_VOLUME_GIB}")]
    Size,
    #[error("a volume type needs 1 to {MAX_POOLS_PER_TYPE} pools")]
    Pools,
    #[error("description is longer than {MAX_DESCRIPTION_LEN} bytes or has control characters")]
    Description,
    #[error("a volume cannot get smaller than the space it was given")]
    Shrink,
    #[error("the type of a volume cannot change")]
    Type,
    #[error("not enough free space in the pool")]
    NoSpace,
    #[error("the volume has no space in the pool")]
    NotReserved,
    #[error("the pool holds too many volumes")]
    TooManyVolumes,
}

// ---------- pools ----------

pub type StoragePool = Object<StoragePoolSpec, StoragePoolStatus>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageDriver {
    /// Thick logical volumes in an LVM volume group.
    Lvm,
    /// Volumes in a ZFS pool.
    Zfs,
}

/// Storage on one node, made by the operator: the platform uses it but never creates or erases it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoragePoolSpec {
    pub node: Name,
    pub driver: StorageDriver,
    /// Name of the volume group or ZFS pool.
    pub source: String,
    /// No new volumes are placed here.
    #[serde(default)]
    pub unschedulable: bool,
}

impl StoragePoolSpec {
    pub fn validate(&self) -> Result<(), StorageError> {
        // The name ends up in command lines and device paths on the node.
        let ok = (1..=63).contains(&self.source.len())
            && self.source.as_bytes()[0].is_ascii_alphanumeric()
            && self
                .source
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if ok {
            Ok(())
        } else {
            Err(StorageError::Source)
        }
    }

    /// Whether both name the same storage.
    pub fn same_storage(&self, other: &Self) -> bool {
        (&self.node, self.driver, &self.source) == (&other.node, other.driver, &other.source)
    }
}

/// What a pool can do, reported by its driver and never inferred from its name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageCapabilities {
    #[serde(default)]
    pub snapshots: bool,
    #[serde(default)]
    pub checksums: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoragePoolStatus {
    /// The node may have marked the storage as this pool's. Set before it is asked to, and cleared
    /// after it removed the mark.
    #[serde(default)]
    pub claimed: bool,
    /// The node has found the storage and marked it.
    #[serde(default)]
    pub ready: bool,
    /// What volumes may use in total: without what the pool itself needs or others use.
    #[serde(default)]
    pub capacity_bytes: u64,
    /// Devices are multiples of this.
    #[serde(default)]
    pub allocation_unit_bytes: u64,
    #[serde(default)]
    pub capabilities: StorageCapabilities,
    /// Space promised to volumes, by uid: the size of their devices. Written with compare-and-swap,
    /// so the same space is never promised twice, after the volume names this pool in its status.
    /// Deleting a volume always writes this, even if there is nothing to release, so that a late
    /// reservation for it fails; the controller also releases those of volumes that are gone.
    #[serde(default)]
    pub reservations: BTreeMap<Uuid, u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl StoragePoolStatus {
    pub fn reserved_bytes(&self) -> u64 {
        self.reservations
            .values()
            .fold(0, |sum, b| sum.saturating_add(*b))
    }

    /// Reserves `bytes` for a volume that is being placed. Nothing changes on error.
    pub fn reserve(&mut self, volume: Uuid, bytes: u64) -> Result<(), StorageError> {
        if !self.reservations.contains_key(&volume)
            && self.reservations.len() >= MAX_VOLUMES_PER_POOL
        {
            return Err(StorageError::TooManyVolumes);
        }
        self.set(volume, bytes)
    }

    /// Reserves more for a volume that has a reservation. Nothing changes on error.
    pub fn grow(&mut self, volume: Uuid, bytes: u64) -> Result<(), StorageError> {
        match self.reservations.get(&volume) {
            None => Err(StorageError::NotReserved),
            Some(current) if *current >= bytes => Ok(()),
            Some(_) => self.set(volume, bytes),
        }
    }

    fn set(&mut self, volume: Uuid, bytes: u64) -> Result<(), StorageError> {
        let current = self.reservations.get(&volume).copied().unwrap_or_default();
        let others = self.reserved_bytes().saturating_sub(current);
        if others.saturating_add(bytes) > self.capacity_bytes {
            return Err(StorageError::NoSpace);
        }
        self.reservations.insert(volume, bytes);
        Ok(())
    }

    pub fn release(&mut self, volume: &Uuid) {
        self.reservations.remove(volume);
    }
}

// ---------- volume types ----------

pub type VolumeType = Object<VolumeTypeSpec>;

/// What tenants choose from. Its pools are the operator's business.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeTypeSpec {
    pub pools: BTreeSet<Name>,
    #[serde(default)]
    pub description: String,
}

impl VolumeTypeSpec {
    pub fn validate(&self) -> Result<(), StorageError> {
        if !(1..=MAX_POOLS_PER_TYPE).contains(&self.pools.len()) {
            return Err(StorageError::Pools);
        }
        if self.description.len() > MAX_DESCRIPTION_LEN
            || self.description.chars().any(crate::is_hidden)
        {
            return Err(StorageError::Description);
        }
        Ok(())
    }
}

// ---------- volumes ----------

pub type Volume = Object<VolumeSpec, VolumeStatus>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeSpec {
    pub volume_type: Name,
    pub size_gib: u64,
    /// Deleting the volume is refused while set.
    #[serde(default)]
    pub delete_protection: bool,
}

impl VolumeSpec {
    pub fn validate(&self) -> Result<(), StorageError> {
        if !(1..=MAX_VOLUME_GIB).contains(&self.size_gib) {
            return Err(StorageError::Size);
        }
        Ok(())
    }

    /// Whether a volume may change from `self` to `new`. A size that was not granted yet can be
    /// taken back.
    pub fn validate_update(&self, status: &VolumeStatus, new: &Self) -> Result<(), StorageError> {
        new.validate()?;
        if new.volume_type != self.volume_type {
            return Err(StorageError::Type);
        }
        if new.size_bytes() < status.granted_bytes {
            return Err(StorageError::Shrink);
        }
        Ok(())
    }

    /// Size that the instance sees.
    pub fn size_bytes(&self) -> u64 {
        self.size_gib.saturating_mul(GIB)
    }

    /// Size of the device: what is reserved and created.
    pub fn device_bytes(&self) -> u64 {
        self.size_bytes().saturating_add(LUKS_HEADER_BYTES)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumePhase {
    /// Not placed yet: waits for its first use.
    #[default]
    Pending,
    /// A pool was chosen; its space may not be reserved yet.
    Placing,
    /// Has space in a pool; not created on the node yet.
    Placed,
    Ready,
    Deleting,
    Failed,
}

/// A pool, and not one made later with the same name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolRef {
    pub name: Name,
    pub uid: Uuid,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeStatus {
    #[serde(default)]
    pub phase: VolumePhase,
    /// Operator's view; not for tenants. Once set, the volume is deleted by releasing it there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<PoolRef>,
    /// Size that the instance may have, the header not counted; the node grows the volume to at most
    /// this. Placement writes it before reserving, and clears it with the pool if there is no space.
    /// Growth reserves first: a size that is refused was never granted.
    #[serde(default)]
    pub granted_bytes: u64,
    /// Size that the instance sees. Smaller than the spec until a resize is done.
    #[serde(default)]
    pub size_bytes: u64,
    /// The node formatted the device (it reports it): it is never formatted again, whatever is
    /// found on it.
    #[serde(default)]
    pub formatted: bool,
    /// uid of the one instance that uses it, set with compare-and-swap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attached_to: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Name {
        Name::new(s).unwrap_or_else(|e| unreachable!("{e}"))
    }

    #[test]
    fn source_names() {
        let spec = |source: &str| StoragePoolSpec {
            node: name("n1"),
            driver: StorageDriver::Lvm,
            source: source.into(),
            unschedulable: false,
        };
        for ok in ["data", "vg_1", "0a", "a-b"] {
            assert_eq!(spec(ok).validate(), Ok(()), "{ok}");
        }
        let long = "a".repeat(64);
        for bad in [
            "", "-data", "_d", ".", "..", "a/b", "a b", "a@b", "Data", "é", &long,
        ] {
            assert_eq!(spec(bad).validate(), Err(StorageError::Source), "{bad}");
        }
    }

    #[test]
    fn reservations_never_exceed_capacity() {
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let mut s = StoragePoolStatus {
            capacity_bytes: 100,
            ..Default::default()
        };
        assert_eq!(s.reserve(a, 60), Ok(()));
        assert_eq!(s.reserve(b, 41), Err(StorageError::NoSpace));
        assert_eq!(s.reserve(b, u64::MAX), Err(StorageError::NoSpace));
        assert_eq!(s.reserve(b, 40), Ok(()));
        // Growing counts only the difference; a refused growth keeps the old reservation.
        assert_eq!(s.grow(a, 61), Err(StorageError::NoSpace));
        assert_eq!(s.reserved_bytes(), 100);
        s.release(&b);
        assert_eq!(s.grow(b, 1), Err(StorageError::NotReserved));
        assert_eq!(s.grow(a, 100), Ok(()));
        // Never less.
        assert_eq!(s.grow(a, 1), Ok(()));
        assert_eq!(s.reserved_bytes(), 100);
        s.release(&a);
        assert_eq!(s.reserved_bytes(), 0);
    }

    #[test]
    fn too_many_volumes() {
        let mut s = StoragePoolStatus {
            capacity_bytes: u64::MAX,
            ..Default::default()
        };
        for i in 0..MAX_VOLUMES_PER_POOL {
            assert_eq!(s.reserve(Uuid::from_u128(i as u128), 1), Ok(()));
        }
        assert_eq!(s.reserve(Uuid::max(), 1), Err(StorageError::TooManyVolumes));
        assert_eq!(s.reserve(Uuid::from_u128(0), 2), Ok(()));
    }

    #[test]
    fn volumes_only_grow() {
        let v = VolumeSpec {
            volume_type: name("fast"),
            size_gib: 10,
            delete_protection: false,
        };
        let with = |size_gib| VolumeSpec {
            size_gib,
            ..v.clone()
        };
        let placed = VolumeStatus {
            granted_bytes: v.size_bytes(),
            ..Default::default()
        };
        assert_eq!(v.validate_update(&placed, &with(11)), Ok(()));
        assert_eq!(v.validate_update(&placed, &with(10)), Ok(()));
        assert_eq!(
            v.validate_update(&placed, &with(9)),
            Err(StorageError::Shrink)
        );
        // Growth that was never granted can be taken back, as can anything before placement.
        assert_eq!(with(99).validate_update(&placed, &with(10)), Ok(()));
        let pending = VolumeStatus::default();
        assert_eq!(v.validate_update(&pending, &with(1)), Ok(()));
        assert_eq!(
            v.validate_update(&placed, &with(MAX_VOLUME_GIB + 1)),
            Err(StorageError::Size)
        );
        assert_eq!(v.device_bytes() - v.size_bytes(), LUKS_HEADER_BYTES);
        assert_eq!(with(0).validate(), Err(StorageError::Size));
        let other = VolumeSpec {
            volume_type: name("slow"),
            ..v.clone()
        };
        assert_eq!(v.validate_update(&placed, &other), Err(StorageError::Type));
    }
}
