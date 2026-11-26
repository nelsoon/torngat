//! Storage pools and volume types (operator API), and volumes (tenant API).

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use torngat_api::storage::{
    StorageError, StoragePool, StoragePoolSpec, Volume, VolumePhase, VolumeSpec, VolumeType,
    VolumeTypeSpec,
};
use torngat_api::{Name, Object, Scope};
use torngat_store::{Key, Precondition, StoreError};
use uuid::Uuid;

use crate::crud::{Input, Kind, Params, Update, any, invalid};
use crate::handlers::{
    DeleteQuery, ListQuery, ListResponse, body, decode, name, node_key, project_scope, query,
    store_key,
};
use crate::{ApiError, AppState};

type Body<T> = Result<Json<T>, JsonRejection>;

impl From<StorageError> for ApiError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::NoSpace | StorageError::NotReserved | StorageError::TooManyVolumes => {
                ApiError::FailedPrecondition(e.to_string())
            }
            e => invalid(e),
        }
    }
}

const POOLS: Kind = Kind {
    keyspace: "platform",
    segment: "storagepools",
    path: "storagePools",
};
const TYPES: Kind = Kind {
    keyspace: "platform",
    segment: "volumetypes",
    path: "volumeTypes",
};
const VOLUMES: Kind = Kind {
    keyspace: "storage",
    segment: "volumes",
    path: "volumes",
};

/// Refuses a reference to something that does not exist or is being deleted.
async fn require(st: &AppState, key: Key, what: &str, n: &Name) -> Result<(), ApiError> {
    let found: Option<Object<serde_json::Value, serde_json::Value>> =
        match st.store.get(&key).await? {
            Some(v) => Some(decode(v)?),
            None => None,
        };
    match found {
        Some(o) if o.metadata.delete_time.is_none() => Ok(()),
        _ => Err(invalid(format!("there is no {what} {n}"))),
    }
}

// ---------- pools ----------

#[derive(Debug, Deserialize)]
pub struct CreatePoolQuery {
    storage_pool_id: String,
}

pub async fn create_pool(
    State(st): State<AppState>,
    q: Params<CreatePoolQuery>,
    b: Body<Input<StoragePoolSpec>>,
) -> Result<Json<StoragePool>, ApiError> {
    let n = name("storage pool", &query(q)?.storage_pool_id)?;
    let input = body(b)?;
    input.spec.validate()?;
    let node = &input.spec.node;
    require(&st, node_key(node)?, "node", node).await?;
    // For a clear answer; the node itself refuses storage that another pool uses.
    let prefix = POOLS.prefix(&Scope::Platform)?;
    let spec = input.spec.clone();
    if any(&st, &prefix, |p: &StoragePool| p.spec.same_storage(&spec)).await? {
        return Err(ApiError::AlreadyExists("a pool with this storage".into()));
    }
    POOLS
        .create(&st, Scope::Platform, n, Uuid::now_v7(), input)
        .await
}

pub async fn get_pool(
    State(st): State<AppState>,
    Path(pool): Path<String>,
) -> Result<Json<StoragePool>, ApiError> {
    let n = name("storage pool", &pool)?;
    POOLS.get(&st, &Scope::Platform, &n).await
}

pub async fn list_pools(
    State(st): State<AppState>,
    q: Params<ListQuery>,
) -> Result<Json<ListResponse<StoragePool>>, ApiError> {
    let mut page: Json<ListResponse<StoragePool>> = POOLS.list(&st, &Scope::Platform, q).await?;
    // Long; reading one pool shows them.
    for p in &mut page.items {
        p.status.reservations.clear();
    }
    Ok(page)
}

pub async fn update_pool(
    State(st): State<AppState>,
    Path(pool): Path<String>,
    b: Body<Update<StoragePoolSpec>>,
) -> Result<Json<StoragePool>, ApiError> {
    let n = name("storage pool", &pool)?;
    let check = async |old: StoragePool, new: StoragePoolSpec| {
        if old.spec.same_storage(&new) {
            Ok(())
        } else {
            Err(ApiError::InvalidArgument(
                "node, driver and source cannot change".into(),
            ))
        }
    };
    POOLS
        .update(&st, &Scope::Platform, &n, body(b)?, check)
        .await
}

pub async fn delete_pool(
    State(st): State<AppState>,
    Path(pool): Path<String>,
    q: Params<DeleteQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let n = name("storage pool", &pool)?;
    let cur = POOLS
        .find_for_delete(&st, &Scope::Platform, &n, query(q)?)
        .await?;
    let rev = cur.revision;
    let p: StoragePool = decode(cur)?;
    // A reservation made after this read changes the revision, so the delete fails.
    if !p.status.reservations.is_empty() {
        return Err(ApiError::FailedPrecondition(format!(
            "{n} holds {} volumes",
            p.status.reservations.len()
        )));
    }
    let types = TYPES.prefix(&Scope::Platform)?;
    if any(&st, &types, |t: &VolumeType| t.spec.pools.contains(&n)).await? {
        return Err(ApiError::FailedPrecondition(format!(
            "{n} is in a volume type"
        )));
    }
    let uid = p.metadata.uid;
    let names = |v: &Volume| v.status.pool.as_ref().is_some_and(|r| r.uid == uid);
    if any(&st, &VOLUMES.all()?, names).await? {
        return Err(ApiError::FailedPrecondition(format!("{n} holds volumes")));
    }
    // The controller removes it, once its node removed its mark and nothing uses it: a type may
    // have been given it meanwhile.
    POOLS.delete_later(&st, &Scope::Platform, &n, rev, p).await
}

// ---------- volume types ----------

#[derive(Debug, Deserialize)]
pub struct CreateTypeQuery {
    volume_type_id: String,
}

/// `old` are pools that the type had already.
async fn check_type(
    st: &AppState,
    spec: &VolumeTypeSpec,
    old: &std::collections::BTreeSet<Name>,
) -> Result<(), ApiError> {
    spec.validate()?;
    for p in spec.pools.difference(old) {
        require(st, POOLS.key(&Scope::Platform, p)?, "storage pool", p).await?;
    }
    Ok(())
}

pub async fn create_type(
    State(st): State<AppState>,
    q: Params<CreateTypeQuery>,
    b: Body<Input<VolumeTypeSpec>>,
) -> Result<Json<VolumeType>, ApiError> {
    let n = name("volume type", &query(q)?.volume_type_id)?;
    let input = body(b)?;
    check_type(&st, &input.spec, &Default::default()).await?;
    TYPES
        .create(&st, Scope::Platform, n, Uuid::now_v7(), input)
        .await
}

pub async fn get_type(
    State(st): State<AppState>,
    Path(t): Path<String>,
) -> Result<Json<VolumeType>, ApiError> {
    let n = name("volume type", &t)?;
    TYPES.get(&st, &Scope::Platform, &n).await
}

pub async fn list_types(
    State(st): State<AppState>,
    q: Params<ListQuery>,
) -> Result<Json<ListResponse<VolumeType>>, ApiError> {
    TYPES.list(&st, &Scope::Platform, q).await
}

pub async fn update_type(
    State(st): State<AppState>,
    Path(t): Path<String>,
    b: Body<Update<VolumeTypeSpec>>,
) -> Result<Json<VolumeType>, ApiError> {
    let n = name("volume type", &t)?;
    let check =
        async |old: VolumeType, new: VolumeTypeSpec| check_type(&st, &new, &old.spec.pools).await;
    TYPES
        .update(&st, &Scope::Platform, &n, body(b)?, check)
        .await
}

pub async fn delete_type(
    State(st): State<AppState>,
    Path(t): Path<String>,
    q: Params<DeleteQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let n = name("volume type", &t)?;
    let cur = TYPES
        .find_for_delete(&st, &Scope::Platform, &n, query(q)?)
        .await?;
    // Looks at every volume: rare, and for operators only. A volume created meanwhile keeps the name
    // of a missing type and is not placed.
    if any(&st, &VOLUMES.all()?, |v: &Volume| v.spec.volume_type == n).await? {
        return Err(ApiError::FailedPrecondition(format!(
            "{n} is used by volumes"
        )));
    }
    TYPES.delete(&st, &Scope::Platform, &n, cur.revision).await
}

// ---------- volumes ----------

#[derive(Debug, Deserialize)]
pub struct CreateVolumeQuery {
    volume_id: String,
    request_id: Option<Uuid>,
}

/// What a request id was used for. Kept even if the create is refused: a retry tries again.
#[derive(Debug, Serialize, Deserialize)]
struct VolumeRequest {
    target: String,
    spec: VolumeSpec,
    labels: BTreeMap<String, String>,
    uid: Uuid,
    /// When the volume was created. If that one is gone, it was deleted since.
    #[serde(default, with = "time::serde::rfc3339::option")]
    created: Option<OffsetDateTime>,
}

/// Claims a request id (AIP-155), or returns the record of an earlier attempt. The first attempt
/// fixes the uid, so every attempt creates or finds the same volume. Also returns the revision.
async fn claim(
    st: &AppState,
    key: &Key,
    rec: VolumeRequest,
) -> Result<(VolumeRequest, u64), ApiError> {
    match st
        .store
        .put(key.clone(), serde_json::to_vec(&rec)?, Precondition::Absent)
        .await
    {
        Ok(rev) => Ok((rec, rev)),
        Err(StoreError::PreconditionFailed { .. }) => {
            let (old, rev) = request_record(st, key).await?;
            if old.target != rec.target || old.spec != rec.spec || old.labels != rec.labels {
                return Err(invalid(
                    "request_id was already used for a different request",
                ));
            }
            Ok((old, rev))
        }
        Err(e) => Err(e.into()),
    }
}

async fn request_record(st: &AppState, key: &Key) -> Result<(VolumeRequest, u64), ApiError> {
    let v = st.store.get(key).await?.ok_or(ApiError::Unavailable)?;
    Ok((serde_json::from_slice(&v.value)?, v.revision))
}

/// The volume of this name, if it has this uid.
async fn find_by_uid(
    st: &AppState,
    scope: &Scope,
    n: &Name,
    uid: Uuid,
) -> Result<Option<Volume>, ApiError> {
    let Some(v) = st.store.get(&VOLUMES.key(scope, n)?).await? else {
        return Ok(None);
    };
    let v: Volume = decode(v)?;
    Ok((v.metadata.uid == uid).then_some(v))
}

pub async fn create_volume(
    State(st): State<AppState>,
    Path((org, project)): Path<(String, String)>,
    q: Params<CreateVolumeQuery>,
    b: Body<Input<VolumeSpec>>,
) -> Result<Json<Volume>, ApiError> {
    let scope = project_scope(&org, &project)?;
    let q = query(q)?;
    let n = name("volume", &q.volume_id)?;
    let input = body(b)?;
    input.spec.validate()?;
    let t = &input.spec.volume_type;
    require(&st, TYPES.key(&Scope::Platform, t)?, "volume type", t).await?;
    let Some(rid) = q.request_id else {
        return VOLUMES.create(&st, scope, n, Uuid::now_v7(), input).await;
    };

    // Namespaced by scope, so tenants cannot observe each other's request ids.
    let rid = rid.hyphenated().to_string();
    let mut segs = vec!["volumerequests"];
    segs.extend(scope.segments());
    segs.push(&rid);
    let key = store_key("ops", &segs)?;
    let target = VOLUMES.full_name(&scope, &n);
    let rec = VolumeRequest {
        target: target.clone(),
        spec: input.spec.clone(),
        labels: input.labels.clone(),
        uid: Uuid::now_v7(),
        created: None,
    };
    let (mut rec, rev) = claim(&st, &key, rec).await?;
    let (volume, mine) = match find_by_uid(&st, &scope, &n, rec.uid).await? {
        Some(v) => (v, false),
        None if rec.created.is_some() => return Err(ApiError::NotFound(target)),
        None => match VOLUMES
            .create(&st, scope.clone(), n.clone(), rec.uid, input)
            .await
        {
            Ok(Json(v)) => (v, true),
            // Perhaps by another attempt.
            Err(ApiError::AlreadyExists(e)) => match find_by_uid(&st, &scope, &n, rec.uid).await? {
                Some(v) => (v, false),
                None => return Err(ApiError::AlreadyExists(e)),
            },
            Err(e) => return Err(e),
        },
    };
    if rec.created.is_none() {
        // Before the client knows that the volume exists, and can delete it: later attempts must not
        // bring it back.
        rec.created = volume.metadata.create_time;
        match st
            .store
            .put(
                key.clone(),
                serde_json::to_vec(&rec)?,
                Precondition::Revision(rev),
            )
            .await
        {
            Ok(_) => return Ok(Json(volume)),
            Err(StoreError::PreconditionFailed { .. }) => rec = request_record(&st, &key).await?.0,
            Err(e) => return Err(e.into()),
        }
    }
    if rec.created == volume.metadata.create_time {
        return Ok(Json(volume));
    }
    // Another attempt's volume was deleted while this one was about to create it: undo.
    if mine {
        undo(&st, &scope, &n, rec.uid).await?;
    }
    Err(ApiError::NotFound(target))
}

/// Deletes the volume of this uid, even if it changed meanwhile (such as being placed).
async fn undo(st: &AppState, scope: &Scope, n: &Name, uid: Uuid) -> Result<(), ApiError> {
    for _ in 0..8 {
        let Some(cur) = st.store.get(&VOLUMES.key(scope, n)?).await? else {
            return Ok(());
        };
        let rev = cur.revision;
        let mut v: Volume = decode(cur)?;
        if v.metadata.uid != uid {
            return Ok(());
        }
        let done = if v.status.pool.is_some() {
            v.status.phase = VolumePhase::Deleting;
            VOLUMES.delete_later(st, scope, n, rev, v).await
        } else {
            VOLUMES.delete(st, scope, n, rev).await
        };
        match done {
            Ok(_) | Err(ApiError::NotFound(_)) => return Ok(()),
            Err(ApiError::Aborted(_)) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(ApiError::Aborted("the volume changed; retry".into()))
}

pub async fn get_volume(
    State(st): State<AppState>,
    Path((org, project, volume)): Path<(String, String, String)>,
) -> Result<Json<Volume>, ApiError> {
    let n = name("volume", &volume)?;
    VOLUMES.get(&st, &project_scope(&org, &project)?, &n).await
}

pub async fn list_volumes(
    State(st): State<AppState>,
    Path((org, project)): Path<(String, String)>,
    q: Params<ListQuery>,
) -> Result<Json<ListResponse<Volume>>, ApiError> {
    VOLUMES.list(&st, &project_scope(&org, &project)?, q).await
}

pub async fn update_volume(
    State(st): State<AppState>,
    Path((org, project, volume)): Path<(String, String, String)>,
    b: Body<Update<VolumeSpec>>,
) -> Result<Json<Volume>, ApiError> {
    let n = name("volume", &volume)?;
    let check =
        async |old: Volume, new: VolumeSpec| Ok(old.spec.validate_update(&old.status, &new)?);
    VOLUMES
        .update(&st, &project_scope(&org, &project)?, &n, body(b)?, check)
        .await
}

pub async fn delete_volume(
    State(st): State<AppState>,
    Path((org, project, volume)): Path<(String, String, String)>,
    q: Params<DeleteQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scope = project_scope(&org, &project)?;
    let n = name("volume", &volume)?;
    let cur = VOLUMES.find_for_delete(&st, &scope, &n, query(q)?).await?;
    let rev = cur.revision;
    let mut v: Volume = decode(cur)?;
    if v.spec.delete_protection {
        return Err(ApiError::FailedPrecondition(format!(
            "{n} is protected from deletion"
        )));
    }
    if v.status.attached_to.is_some() {
        return Err(ApiError::FailedPrecondition(format!(
            "{n} is used by an instance"
        )));
    }
    if v.status.pool.is_some() {
        // Its blocks, then its reservation, are released first.
        v.status.phase = VolumePhase::Deleting;
        return VOLUMES.delete_later(&st, &scope, &n, rev, v).await;
    }
    // A pool chosen after this read changes the revision, so the delete fails.
    VOLUMES.delete(&st, &scope, &n, rev).await
}
