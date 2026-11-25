//! Creating, reading, changing and deleting objects of any kind.

use std::collections::BTreeMap;
use std::future::Future;

use axum::Json;
use axum::extract::Query;
use axum::extract::rejection::QueryRejection;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use torngat_api::meta::Cell;
use torngat_api::{Etag, Name, Object, ObjectMeta, Scope};
use torngat_store::{Key, Precondition, Prefix, StoreError, Versioned};
use uuid::Uuid;

use crate::handlers::{
    DeleteQuery, ListQuery, ListResponse, decode, etag, list, now, parse_etag, query,
    resource_path, store_key,
};
use crate::{ApiError, AppState};

const CAS_RETRIES: usize = 8;
/// Objects can be large; a scan holds one page at a time.
const SCAN_PAGE: usize = 100;

pub(crate) type Params<T> = Result<Query<T>, QueryRejection>;

pub(crate) fn invalid(e: impl std::fmt::Display) -> ApiError {
    ApiError::InvalidArgument(e.to_string())
}

/// Refuses fields that this version does not know, in requests only: stored objects may have been
/// written by a newer one. Top level only;
/// types must serialize every field they know, and have no aliases.
fn known_only<S: DeserializeOwned + Serialize>(v: serde_json::Value) -> Result<S, String> {
    let s = S::deserialize(&v).map_err(|e| e.to_string())?;
    let known = serde_json::to_value(&s).map_err(|e| e.to_string())?;
    let fields = v.as_object().ok_or("expected an object")?;
    match fields.keys().find(|k| known.get(k.as_str()).is_none()) {
        Some(k) => Err(format!("unknown field {k:?}")),
        None => Ok(s),
    }
}

fn strict<'de, D: Deserializer<'de>, S: DeserializeOwned + Serialize>(d: D) -> Result<S, D::Error> {
    known_only(serde_json::Value::deserialize(d)?).map_err(serde::de::Error::custom)
}

fn strict_option<'de, D: Deserializer<'de>, S: DeserializeOwned + Serialize>(
    d: D,
) -> Result<Option<S>, D::Error> {
    Option::<serde_json::Value>::deserialize(d)?
        .map(known_only)
        .transpose()
        .map_err(serde::de::Error::custom)
}

/// Client-writable part of a new object: everything else is server-set and ignored if sent.
#[derive(Debug, Deserialize)]
#[serde(bound(deserialize = "S: DeserializeOwned + Serialize"))]
pub struct Input<S> {
    #[serde(default)]
    pub(crate) labels: BTreeMap<String, String>,
    #[serde(deserialize_with = "strict")]
    pub(crate) spec: S,
}

/// Client-writable fields for update. `etag`, if given, must match (AIP-154).
#[derive(Debug, Deserialize)]
#[serde(bound(deserialize = "S: DeserializeOwned + Serialize"))]
pub struct Update<S> {
    etag: Option<Etag>,
    labels: Option<BTreeMap<String, String>>,
    #[serde(default, deserialize_with = "strict_option")]
    spec: Option<S>,
}

/// Where a kind of object lives.
pub(crate) struct Kind {
    pub(crate) keyspace: &'static str,
    /// Segment in store keys.
    pub(crate) segment: &'static str,
    /// Segment in resource paths.
    pub(crate) path: &'static str,
}

impl Kind {
    fn segments<'a>(&self, scope: &'a Scope) -> Vec<&'a str> {
        // The platform keyspace holds platform objects only.
        match scope {
            Scope::Platform => vec![self.segment],
            s => {
                let mut segs = s.segments();
                segs.push(self.segment);
                segs
            }
        }
    }

    pub(crate) fn key(&self, scope: &Scope, n: &Name) -> Result<Key, ApiError> {
        let mut segs = self.segments(scope);
        segs.push(n.as_str());
        store_key(self.keyspace, &segs)
    }

    pub(crate) fn prefix(&self, scope: &Scope) -> Result<Prefix, ApiError> {
        Prefix::new(self.keyspace, self.segments(scope))
            .map_err(|e| ApiError::Internal(e.to_string()))
    }

    /// Every project's objects of every kind in the keyspace.
    pub(crate) fn all(&self) -> Result<Prefix, ApiError> {
        Prefix::new(self.keyspace, ["orgs"]).map_err(|e| ApiError::Internal(e.to_string()))
    }

    pub(crate) fn full_name(&self, scope: &Scope, n: &Name) -> String {
        resource_path(scope, self.path, n)
    }

    pub(crate) async fn find(
        &self,
        st: &AppState,
        scope: &Scope,
        n: &Name,
    ) -> Result<Versioned, ApiError> {
        st.store
            .get(&self.key(scope, n)?)
            .await?
            .ok_or_else(|| ApiError::NotFound(self.full_name(scope, n)))
    }

    pub(crate) async fn get<S, So>(
        &self,
        st: &AppState,
        scope: &Scope,
        n: &Name,
    ) -> Result<Json<Object<S, So>>, ApiError>
    where
        S: DeserializeOwned,
        So: DeserializeOwned + Default,
    {
        decode(self.find(st, scope, n).await?).map(Json)
    }

    pub(crate) async fn list<S, So>(
        &self,
        st: &AppState,
        scope: &Scope,
        q: Params<ListQuery>,
    ) -> Result<Json<ListResponse<Object<S, So>>>, ApiError>
    where
        S: DeserializeOwned,
        So: DeserializeOwned + Default,
    {
        list(st, query(q)?, &self.prefix(scope)?, |n| self.key(scope, n)).await
    }

    pub(crate) async fn create<S, So>(
        &self,
        st: &AppState,
        scope: Scope,
        n: Name,
        uid: Uuid,
        input: Input<S>,
    ) -> Result<Json<Object<S, So>>, ApiError>
    where
        S: Serialize,
        So: Serialize + Default,
    {
        let key = self.key(&scope, &n)?;
        let full_name = self.full_name(&scope, &n);
        let mut obj = Object {
            metadata: ObjectMeta {
                name: n,
                scope,
                uid,
                cell: Some(Cell::default_cell()),
                labels: input.labels,
                generation: 1,
                etag: None,
                create_time: Some(now()),
                update_time: Some(now()),
                delete_time: None,
            },
            spec: input.spec,
            status: So::default(),
        };
        obj.metadata.validate().map_err(invalid)?;
        let rev = st
            .store
            .put(key, serde_json::to_vec(&obj)?, Precondition::Absent)
            .await
            .map_err(|e| match e {
                StoreError::PreconditionFailed { .. } => ApiError::AlreadyExists(full_name),
                e => e.into(),
            })?;
        obj.metadata.etag = Some(etag(rev));
        Ok(Json(obj))
    }

    /// `check` sees the object and its new spec. Without an etag, a change of the status by the
    /// platform in between is not an error.
    pub(crate) async fn update<S, So, F>(
        &self,
        st: &AppState,
        scope: &Scope,
        n: &Name,
        upd: Update<S>,
        check: impl Fn(Object<S, So>, S) -> F,
    ) -> Result<Json<Object<S, So>>, ApiError>
    where
        S: Serialize + DeserializeOwned + PartialEq + Clone,
        So: Serialize + DeserializeOwned + Default + PartialEq + Clone,
        F: Future<Output = Result<(), ApiError>>,
    {
        let key = self.key(scope, n)?;
        let mut first: Option<(S, BTreeMap<String, String>)> = None;
        let mut attempts = if upd.etag.is_some() { 1 } else { CAS_RETRIES };
        loop {
            attempts -= 1;
            let cur = self.find(st, scope, n).await?;
            check_etag(upd.etag.as_ref(), &cur)?;
            let rev = cur.revision;
            let old: Object<S, So> = decode(cur)?;
            let seen = first.get_or_insert_with(|| (old.spec.clone(), old.metadata.labels.clone()));
            if (&seen.0, &seen.1) != (&old.spec, &old.metadata.labels) {
                return Err(ApiError::Aborted("the object changed; retry".into()));
            }
            if old.metadata.delete_time.is_some() {
                return Err(ApiError::FailedPrecondition("being deleted".into()));
            }
            let mut new = old.clone();
            if let Some(labels) = &upd.labels {
                new.metadata.labels.clone_from(labels);
                new.metadata.validate().map_err(invalid)?;
            }
            if let Some(spec) = &upd.spec
                && *spec != old.spec
            {
                check(old.clone(), spec.clone()).await?;
                new.spec = spec.clone();
                new.metadata.generation += 1;
            }
            if new == old {
                return Ok(Json(old));
            }
            new.metadata.update_time = Some(now());
            new.metadata.etag = None;
            // Compare-and-swap on the revision we read: concurrent writers cannot be lost.
            let put = st
                .store
                .put(
                    key.clone(),
                    serde_json::to_vec(&new)?,
                    Precondition::Revision(rev),
                )
                .await;
            match put {
                Ok(rev) => {
                    new.metadata.etag = Some(etag(rev));
                    return Ok(Json(new));
                }
                Err(StoreError::PreconditionFailed { .. }) if attempts > 0 => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// The object to delete, if it is still what the client saw.
    pub(crate) async fn find_for_delete(
        &self,
        st: &AppState,
        scope: &Scope,
        n: &Name,
        q: DeleteQuery,
    ) -> Result<Versioned, ApiError> {
        let cur = self.find(st, scope, n).await?;
        check_etag(q.etag.map(Etag).as_ref(), &cur)?;
        Ok(cur)
    }

    /// Marks an object for deletion by the platform.
    pub(crate) async fn delete_later<S, So>(
        &self,
        st: &AppState,
        scope: &Scope,
        n: &Name,
        revision: u64,
        mut obj: Object<S, So>,
    ) -> Result<Json<serde_json::Value>, ApiError>
    where
        S: Serialize,
        So: Serialize,
    {
        if obj.metadata.delete_time.is_none() {
            obj.metadata.delete_time = Some(now());
            obj.metadata.etag = None;
            st.store
                .put(
                    self.key(scope, n)?,
                    serde_json::to_vec(&obj)?,
                    Precondition::Revision(revision),
                )
                .await?;
        }
        Ok(Json(serde_json::json!({})))
    }

    /// Deletes the object unless it changed since `revision`.
    pub(crate) async fn delete(
        &self,
        st: &AppState,
        scope: &Scope,
        n: &Name,
        revision: u64,
    ) -> Result<Json<serde_json::Value>, ApiError> {
        st.store
            .delete(self.key(scope, n)?, Precondition::Revision(revision))
            .await
            .map_err(|e| match e {
                StoreError::PreconditionFailed { current: None } => {
                    ApiError::NotFound(self.full_name(scope, n))
                }
                e => e.into(),
            })?;
        Ok(Json(serde_json::json!({})))
    }
}

fn check_etag(sent: Option<&Etag>, cur: &Versioned) -> Result<(), ApiError> {
    if let Some(e) = sent
        && parse_etag(e)? != cur.revision
    {
        return Err(ApiError::Aborted("etag mismatch; re-read and retry".into()));
    }
    Ok(())
}

/// Whether any object under `prefix` satisfies `f`.
pub(crate) async fn any<S, So>(
    st: &AppState,
    prefix: &Prefix,
    f: impl Fn(&Object<S, So>) -> bool,
) -> Result<bool, ApiError>
where
    S: DeserializeOwned,
    So: DeserializeOwned + Default,
{
    let mut after = None;
    loop {
        let rows = st.store.list(prefix, after.as_ref(), SCAN_PAGE).await?;
        let full = rows.len() == SCAN_PAGE;
        after = rows.last().map(|(k, _)| k.clone());
        for (_, v) in rows {
            if f(&decode(v)?) {
                return Ok(true);
            }
        }
        if !full {
            return Ok(false);
        }
    }
}
