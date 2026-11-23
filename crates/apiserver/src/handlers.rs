//! Request handlers.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use torngat_api::compute::{Instance, InstanceSpec, InstanceStatus};
use torngat_api::meta::Cell;
use torngat_api::node::Node;
use torngat_api::operation::Operation;
use torngat_api::{Etag, Name, Object, ObjectMeta, Scope};
use torngat_store::{Key, Precondition, Prefix, StoreError, Versioned};
use uuid::Uuid;

use crate::{ApiError, AppState};

const DEFAULT_PAGE: usize = 100;
const MAX_PAGE: usize = 1000;

fn name(kind: &str, s: &str) -> Result<Name, ApiError> {
    Name::new(s).map_err(|e| ApiError::InvalidArgument(format!("invalid {kind} name: {e}")))
}

fn body<T>(b: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    b.map(|Json(t)| t)
        .map_err(|e| ApiError::InvalidArgument(format!("invalid request body: {}", e.body_text())))
}

fn query<T>(q: Result<Query<T>, QueryRejection>) -> Result<T, ApiError> {
    q.map(|Query(t)| t)
        .map_err(|e| ApiError::InvalidArgument(format!("invalid query: {}", e.body_text())))
}

fn store_key(keyspace: &str, segs: &[&str]) -> Result<Key, ApiError> {
    Key::new(keyspace, segs.iter().copied()).map_err(|e| ApiError::Internal(e.to_string()))
}

fn instance_key(scope: &Scope, n: &Name) -> Result<Key, ApiError> {
    let mut segs = scope.segments();
    segs.extend(["instances", n.as_str()]);
    store_key("compute", &segs)
}

fn instances_prefix(scope: &Scope) -> Result<Prefix, ApiError> {
    let mut segs = scope.segments();
    segs.push("instances");
    Prefix::new("compute", segs).map_err(|e| ApiError::Internal(e.to_string()))
}

/// Etags are the store revision, opaque to clients.
fn etag(rev: u64) -> Etag {
    Etag(format!("\"{rev}\""))
}

fn parse_etag(e: &Etag) -> Result<u64, ApiError> {
    let bad = || ApiError::InvalidArgument("malformed etag".into());
    let inner =
        e.0.strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or_else(bad)?;
    if inner.is_empty() || !inner.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    inner.parse().map_err(|_| bad())
}

fn decode<S, St>(v: Versioned) -> Result<Object<S, St>, ApiError>
where
    S: serde::de::DeserializeOwned,
    St: serde::de::DeserializeOwned + Default,
{
    let mut o: Object<S, St> = serde_json::from_slice(&v.value)?;
    o.metadata.etag = Some(etag(v.revision));
    Ok(o)
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

// ---------- instances ----------

/// Client-writable part of an instance: everything else is server-set and ignored if sent.
#[derive(Debug, Deserialize)]
pub struct InstanceInput {
    #[serde(default)]
    labels: BTreeMap<String, String>,
    spec: InstanceSpec,
}

#[derive(Debug, Deserialize)]
pub struct CreateQuery {
    instance_id: String,
    request_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RequestRecord {
    target: String,
    operation: Uuid,
}

fn project_scope(org: &str, project: &str) -> Result<Scope, ApiError> {
    Ok(Scope::Project {
        org: name("organization", org)?,
        project: name("project", project)?,
    })
}

fn resource_path(scope: &Scope, kind: &str, n: &Name) -> String {
    format!("{}/{kind}/{n}", scope.segments().join("/"))
}

pub async fn create_instance(
    State(st): State<AppState>,
    Path((org, project)): Path<(String, String)>,
    q: Result<Query<CreateQuery>, QueryRejection>,
    b: Result<Json<InstanceInput>, JsonRejection>,
) -> Result<Json<Operation>, ApiError> {
    let scope = project_scope(&org, &project)?;
    let q = query(q)?;
    let input = body(b)?;
    let n = name("instance", &q.instance_id)?;
    input
        .spec
        .validate()
        .map_err(|e| ApiError::InvalidArgument(e.to_string()))?;
    let target = resource_path(&scope, "instances", &n);

    let op = Operation {
        id: Uuid::now_v7(),
        target: target.clone(),
        done: false,
        error: None,
    };

    // Idempotency (AIP-155): claim the request_id *before* creating anything, so concurrent or
    // crashed-and-retried duplicates always converge on the same operation.
    let mut claimed: Option<Key> = None;
    if let Some(rid) = q.request_id {
        // Namespaced by scope, so tenants cannot observe each other's request ids.
        let rid = rid.hyphenated().to_string();
        let mut segs = vec!["requests"];
        segs.extend(scope.segments());
        segs.push(&rid);
        let k = store_key("ops", &segs)?;
        let rec = RequestRecord {
            target: target.clone(),
            operation: op.id,
        };
        match st
            .store
            .put(k.clone(), serde_json::to_vec(&rec)?, Precondition::Absent)
            .await
        {
            Ok(_) => claimed = Some(k),
            Err(StoreError::PreconditionFailed { .. }) => {
                return replay(&st, &k, &target).await.map(Json);
            }
            Err(e) => return Err(e.into()),
        }
    }

    let metadata = ObjectMeta {
        name: n.clone(),
        scope: scope.clone(),
        uid: Uuid::now_v7(),
        cell: Some(Cell::default_cell()),
        labels: input.labels,
        generation: 1,
        etag: None,
        create_time: Some(now()),
        update_time: Some(now()),
        delete_time: None,
    };
    let created = async {
        metadata
            .validate()
            .map_err(|e| ApiError::InvalidArgument(e.to_string()))?;
        let obj: Instance = Object {
            metadata,
            spec: input.spec,
            status: InstanceStatus::default(),
        };
        st.store
            .put(
                instance_key(&scope, &n)?,
                serde_json::to_vec(&obj)?,
                Precondition::Absent,
            )
            .await
            .map_err(|e| match e {
                StoreError::PreconditionFailed { .. } => ApiError::AlreadyExists(target.clone()),
                e => e.into(),
            })
    }
    .await;
    if let Err(e) = created {
        // Only a definite rejection releases the claim; on an unknown outcome (store error) the
        // claim stays so a retry replays instead of creating twice.
        if let (Some(k), ApiError::AlreadyExists(_) | ApiError::InvalidArgument(_)) = (&claimed, &e)
        {
            if let Err(release) = st.store.delete(k.clone(), Precondition::None).await {
                tracing::warn!(error = %release, "could not release request_id claim");
            }
        }
        return Err(e);
    }
    put_op_if_absent(&st, &op).await?;
    Ok(Json(op))
}

/// Writes `op` unless it already exists.
async fn put_op_if_absent(st: &AppState, op: &Operation) -> Result<(), ApiError> {
    let k = store_key("ops", &["operations", &op.id.hyphenated().to_string()])?;
    match st
        .store
        .put(k, serde_json::to_vec(op)?, Precondition::Absent)
        .await
    {
        Ok(_) | Err(StoreError::PreconditionFailed { .. }) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Answers a create whose request_id was already claimed.
async fn replay(st: &AppState, k: &Key, target: &str) -> Result<Operation, ApiError> {
    let v = st.store.get(k).await?.ok_or(ApiError::Unavailable)?; // released concurrently: let the client retry
    let rec: RequestRecord = serde_json::from_slice(&v.value)?;
    if rec.target != target {
        return Err(ApiError::InvalidArgument(
            "request_id was already used for a different request".into(),
        ));
    }
    match get_op(st, rec.operation).await {
        Ok(op) => Ok(op),
        Err(ApiError::NotFound(_)) => {
            // The first attempt claimed the id but has not (or never will) finish. If the
            // resource exists, complete the bookkeeping; otherwise the first attempt is still in
            // flight or failed with an unknown outcome: ask the client to retry.
            let exists = target_exists(st, target).await?;
            if !exists {
                return Err(ApiError::Unavailable);
            }
            let op = Operation {
                id: rec.operation,
                target: target.to_owned(),
                done: false,
                error: None,
            };
            put_op_if_absent(st, &op).await?;
            get_op(st, rec.operation).await
        }
        Err(e) => Err(e),
    }
}

async fn target_exists(st: &AppState, target: &str) -> Result<bool, ApiError> {
    // `target` was built by `resource_path` from validated names.
    let segs: Vec<&str> = target.split('/').collect();
    let k = store_key("compute", &segs)?;
    Ok(st.store.get(&k).await?.is_some())
}

pub async fn get_instance(
    State(st): State<AppState>,
    Path((org, project, instance)): Path<(String, String, String)>,
) -> Result<Json<Instance>, ApiError> {
    let scope = project_scope(&org, &project)?;
    let n = name("instance", &instance)?;
    let v = st
        .store
        .get(&instance_key(&scope, &n)?)
        .await?
        .ok_or_else(|| ApiError::NotFound(resource_path(&scope, "instances", &n)))?;
    decode(v).map(Json)
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    page_size: Option<usize>,
    page_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListResponse<T> {
    items: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_page_token: Option<String>,
}

pub async fn list_instances(
    State(st): State<AppState>,
    Path((org, project)): Path<(String, String)>,
    q: Result<Query<ListQuery>, QueryRejection>,
) -> Result<Json<ListResponse<Instance>>, ApiError> {
    let scope = project_scope(&org, &project)?;
    let q = query(q)?;
    let size = q.page_size.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    // The page token is the last returned name; it is validated like any name.
    let after = q
        .page_token
        .as_deref()
        .map(|t| name("page_token", t).and_then(|n| instance_key(&scope, &n)))
        .transpose()?;
    let rows = st
        .store
        .list(&instances_prefix(&scope)?, after.as_ref(), size)
        .await?;
    let next = (rows.len() == size)
        .then(|| {
            rows.last()
                .map(|(k, _)| k.as_str().rsplit('/').next().unwrap_or_default().to_owned())
        })
        .flatten();
    let items = rows
        .into_iter()
        .map(|(_, v)| decode(v))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(ListResponse {
        items,
        next_page_token: next,
    }))
}

/// Client-writable fields for update. `etag`, if given, must match (AIP-154).
#[derive(Debug, Deserialize)]
pub struct InstanceUpdate {
    etag: Option<Etag>,
    labels: Option<BTreeMap<String, String>>,
    spec: Option<InstanceSpec>,
}

pub async fn update_instance(
    State(st): State<AppState>,
    Path((org, project, instance)): Path<(String, String, String)>,
    b: Result<Json<InstanceUpdate>, JsonRejection>,
) -> Result<Json<Instance>, ApiError> {
    let scope = project_scope(&org, &project)?;
    let n = name("instance", &instance)?;
    let upd = body(b)?;
    let key = instance_key(&scope, &n)?;
    let cur = st
        .store
        .get(&key)
        .await?
        .ok_or_else(|| ApiError::NotFound(resource_path(&scope, "instances", &n)))?;
    let rev = cur.revision;
    if let Some(e) = &upd.etag
        && parse_etag(e)? != rev
    {
        return Err(ApiError::Aborted("etag mismatch; re-read and retry".into()));
    }
    let mut obj: Instance = decode(cur)?;
    if let Some(labels) = upd.labels {
        obj.metadata.labels = labels;
    }
    if let Some(spec) = upd.spec {
        spec.validate()
            .map_err(|e| ApiError::InvalidArgument(e.to_string()))?;
        if spec != obj.spec {
            obj.spec = spec;
            obj.metadata.generation += 1;
        }
    }
    obj.metadata
        .validate()
        .map_err(|e| ApiError::InvalidArgument(e.to_string()))?;
    obj.metadata.update_time = Some(now());
    obj.metadata.etag = None;
    // Compare-and-swap on the revision we read: concurrent writers cannot be lost.
    let new_rev = st
        .store
        .put(key, serde_json::to_vec(&obj)?, Precondition::Revision(rev))
        .await?;
    obj.metadata.etag = Some(etag(new_rev));
    Ok(Json(obj))
}

#[derive(Debug, Deserialize)]
pub struct DeleteQuery {
    etag: Option<String>,
}

pub async fn delete_instance(
    State(st): State<AppState>,
    Path((org, project, instance)): Path<(String, String, String)>,
    q: Result<Query<DeleteQuery>, QueryRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scope = project_scope(&org, &project)?;
    let n = name("instance", &instance)?;
    let q = query(q)?;
    let key = instance_key(&scope, &n)?;
    let pre = match q.etag {
        Some(e) => Precondition::Revision(parse_etag(&Etag(e))?),
        None => match st.store.get(&key).await? {
            Some(v) => Precondition::Revision(v.revision),
            None => return Err(ApiError::NotFound(resource_path(&scope, "instances", &n))),
        },
    };
    st.store.delete(key, pre).await.map_err(|e| match e {
        StoreError::PreconditionFailed { current: None } => {
            ApiError::NotFound(resource_path(&scope, "instances", &n))
        }
        e => e.into(),
    })?;
    Ok(Json(serde_json::json!({})))
}

// ---------- operations ----------

async fn get_op(st: &AppState, id: Uuid) -> Result<Operation, ApiError> {
    let k = store_key("ops", &["operations", &id.hyphenated().to_string()])?;
    let v = st
        .store
        .get(&k)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("operations/{id}")))?;
    Ok(serde_json::from_slice(&v.value)?)
}

pub async fn get_operation(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Operation>, ApiError> {
    let id = Uuid::parse_str(&id)
        .map_err(|_| ApiError::InvalidArgument("invalid operation id".into()))?;
    get_op(&st, id).await.map(Json)
}

// ---------- nodes (operator API, read-only in M0: agents register through the controller) ----------

fn node_key(n: &Name) -> Result<Key, ApiError> {
    store_key("platform", &["nodes", n.as_str()])
}

pub async fn get_node(
    State(st): State<AppState>,
    Path(node): Path<String>,
) -> Result<Json<Node>, ApiError> {
    let n = name("node", &node)?;
    let v = st
        .store
        .get(&node_key(&n)?)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("platform/nodes/{n}")))?;
    decode(v).map(Json)
}

pub async fn list_nodes(
    State(st): State<AppState>,
    q: Result<Query<ListQuery>, QueryRejection>,
) -> Result<Json<ListResponse<Node>>, ApiError> {
    let q = query(q)?;
    let size = q.page_size.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let after = q
        .page_token
        .as_deref()
        .map(|t| name("page_token", t).and_then(|n| node_key(&n)))
        .transpose()?;
    let prefix =
        Prefix::new("platform", ["nodes"]).map_err(|e| ApiError::Internal(e.to_string()))?;
    let rows = st.store.list(&prefix, after.as_ref(), size).await?;
    let next = (rows.len() == size)
        .then(|| {
            rows.last()
                .map(|(k, _)| k.as_str().rsplit('/').next().unwrap_or_default().to_owned())
        })
        .flatten();
    let items = rows
        .into_iter()
        .map(|(_, v)| decode(v))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(ListResponse {
        items,
        next_page_token: next,
    }))
}
