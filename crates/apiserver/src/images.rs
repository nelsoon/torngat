//! Images: of the platform (operator API) and of a project (tenant API).

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use serde::Deserialize;
use torngat_api::Scope;
use torngat_api::image::{Image, ImageError, ImagePhase, ImageSpec, image_volume, staging_volume};
use torngat_api::storage::Volume;
use uuid::Uuid;

use crate::crud::{Input, Kind, Params, Update, any, invalid};
use crate::handlers::{
    DeleteQuery, ListQuery, ListResponse, body, decode, name, project_scope, query,
};
use crate::{ApiError, AppState};

type Body<T> = Result<Json<T>, JsonRejection>;

pub(crate) const IMAGES: Kind = Kind {
    keyspace: "images",
    segment: "images",
    path: "images",
};

impl From<ImageError> for ApiError {
    fn from(e: ImageError) -> Self {
        invalid(e)
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateImageQuery {
    image_id: String,
}

async fn create(
    st: &AppState,
    scope: Scope,
    q: Params<CreateImageQuery>,
    b: Body<Input<ImageSpec>>,
) -> Result<Json<Image>, ApiError> {
    let n = name("image", &query(q)?.image_id)?;
    let input = body(b)?;
    input.spec.validate()?;
    image_volume(&n)?;
    staging_volume(&n)?;
    crate::storage::require_type(st, &input.spec.volume_type).await?;
    IMAGES.create(st, scope, n, Uuid::now_v7(), input).await
}

async fn get(st: &AppState, scope: Scope, image: &str) -> Result<Json<Image>, ApiError> {
    IMAGES.get(st, &scope, &name("image", image)?).await
}

async fn list(
    st: &AppState,
    scope: Scope,
    q: Params<ListQuery>,
) -> Result<Json<ListResponse<Image>>, ApiError> {
    IMAGES.list(st, &scope, q).await
}

async fn update(
    st: &AppState,
    scope: Scope,
    image: &str,
    b: Body<Update<ImageSpec>>,
) -> Result<Json<Image>, ApiError> {
    let n = name("image", image)?;
    let check = async |old: Image, new: ImageSpec| Ok(old.spec.validate_update(&new)?);
    IMAGES.update(st, &scope, &n, body(b)?, check).await
}

async fn delete(
    st: &AppState,
    scope: Scope,
    image: &str,
    q: Params<DeleteQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let n = name("image", image)?;
    let cur = IMAGES.find_for_delete(st, &scope, &n, query(q)?).await?;
    let rev = cur.revision;
    let mut i: Image = decode(cur)?;
    let uid = i.metadata.uid;
    // A boot disk of an instance, not yet filled.
    let filling = |v: &Volume| {
        v.status.fill.is_some_and(|f| f.image == uid)
            && !v.status.filled
            && v.status.owner.is_some()
            && v.metadata.delete_time.is_none()
    };
    if any(st, &crate::storage::VOLUMES.all()?, filling).await? {
        return Err(ApiError::FailedPrecondition(format!(
            "{n} is being copied to a boot disk: try again later"
        )));
    }
    // The controller makes volumes only once it gave the image a node; giving it one changes the
    // revision, so the delete fails.
    if i.status.node.is_none() {
        return IMAGES.delete(st, &scope, &n, rev).await;
    }
    // Its volumes first.
    i.status.phase = ImagePhase::Deleting;
    IMAGES.delete_later(st, &scope, &n, rev, i).await
}

// ---------- platform ----------

pub async fn create_platform_image(
    State(st): State<AppState>,
    q: Params<CreateImageQuery>,
    b: Body<Input<ImageSpec>>,
) -> Result<Json<Image>, ApiError> {
    create(&st, Scope::Platform, q, b).await
}

pub async fn get_platform_image(
    State(st): State<AppState>,
    Path(image): Path<String>,
) -> Result<Json<Image>, ApiError> {
    get(&st, Scope::Platform, &image).await
}

pub async fn list_platform_images(
    State(st): State<AppState>,
    q: Params<ListQuery>,
) -> Result<Json<ListResponse<Image>>, ApiError> {
    list(&st, Scope::Platform, q).await
}

pub async fn update_platform_image(
    State(st): State<AppState>,
    Path(image): Path<String>,
    b: Body<Update<ImageSpec>>,
) -> Result<Json<Image>, ApiError> {
    update(&st, Scope::Platform, &image, b).await
}

pub async fn delete_platform_image(
    State(st): State<AppState>,
    Path(image): Path<String>,
    q: Params<DeleteQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    delete(&st, Scope::Platform, &image, q).await
}

// ---------- project ----------

pub async fn create_image(
    State(st): State<AppState>,
    Path((org, project)): Path<(String, String)>,
    q: Params<CreateImageQuery>,
    b: Body<Input<ImageSpec>>,
) -> Result<Json<Image>, ApiError> {
    create(&st, project_scope(&org, &project)?, q, b).await
}

pub async fn get_image(
    State(st): State<AppState>,
    Path((org, project, image)): Path<(String, String, String)>,
) -> Result<Json<Image>, ApiError> {
    get(&st, project_scope(&org, &project)?, &image).await
}

pub async fn list_images(
    State(st): State<AppState>,
    Path((org, project)): Path<(String, String)>,
    q: Params<ListQuery>,
) -> Result<Json<ListResponse<Image>>, ApiError> {
    list(&st, project_scope(&org, &project)?, q).await
}

pub async fn update_image(
    State(st): State<AppState>,
    Path((org, project, image)): Path<(String, String, String)>,
    b: Body<Update<ImageSpec>>,
) -> Result<Json<Image>, ApiError> {
    update(&st, project_scope(&org, &project)?, &image, b).await
}

pub async fn delete_image(
    State(st): State<AppState>,
    Path((org, project, image)): Path<(String, String, String)>,
    q: Params<DeleteQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    delete(&st, project_scope(&org, &project)?, &image, q).await
}

// ---------- uploads ----------

impl From<torngat_uploads::UploadError> for ApiError {
    fn from(e: torngat_uploads::UploadError) -> Self {
        use torngat_uploads::UploadError as U;
        match e {
            U::Io(e) => ApiError::Internal(e.to_string()),
            U::Finished | U::NotFinished => ApiError::FailedPrecondition(e.to_string()),
            e => invalid(e),
        }
    }
}

/// The image, if it takes an upload now.
async fn uploading(st: &AppState, scope: &Scope, image: &str) -> Result<(Image, u64), ApiError> {
    let n = name("image", image)?;
    let cur = IMAGES.find(st, scope, &n).await?;
    let rev = cur.revision;
    let i: Image = decode(cur)?;
    if i.spec.source.url.is_some() {
        return Err(ApiError::FailedPrecondition(format!(
            "{n} is downloaded from its URL"
        )));
    }
    if i.metadata.delete_time.is_some()
        || i.status.uploaded
        || i.status.phase != ImagePhase::Pending
    {
        return Err(ApiError::FailedPrecondition(format!(
            "{n} takes no upload now"
        )));
    }
    Ok((i, rev))
}

fn store_of(st: &AppState) -> Result<&torngat_uploads::Uploads, ApiError> {
    st.uploads
        .as_ref()
        .ok_or_else(|| ApiError::FailedPrecondition("uploads are not enabled".into()))
}

async fn put(
    st: &AppState,
    scope: Scope,
    image: &str,
    part: u32,
    body: axum::body::Body,
) -> Result<Json<serde_json::Value>, ApiError> {
    use futures_util::TryStreamExt;
    let uploads = store_of(st)?;
    let (i, _) = uploading(st, &scope, image).await?;
    let stream = body.into_data_stream().map_err(std::io::Error::other);
    let bytes = uploads
        .put_part(
            i.metadata.uid,
            part,
            tokio_util::io::StreamReader::new(stream),
        )
        .await?;
    Ok(Json(serde_json::json!({"part": part, "bytes": bytes})))
}

async fn received(
    st: &AppState,
    scope: Scope,
    image: &str,
) -> Result<Json<serde_json::Value>, ApiError> {
    let uploads = store_of(st)?;
    let n = name("image", image)?;
    let i: Image = IMAGES.get(st, &scope, &n).await?.0;
    let parts: Vec<_> = uploads
        .parts(i.metadata.uid)
        .await?
        .into_iter()
        .map(|(part, bytes)| serde_json::json!({"part": part, "bytes": bytes}))
        .collect();
    Ok(Json(
        serde_json::json!({"parts": parts, "uploaded": i.status.uploaded}),
    ))
}

async fn finish(st: &AppState, scope: Scope, image: &str) -> Result<Json<Image>, ApiError> {
    let uploads = store_of(st)?;
    let (i, _) = uploading(st, &scope, image).await?;
    let settings = crate::settings::image_settings(st).await?;
    let len = uploads
        .finish(
            i.metadata.uid,
            &i.spec.source.checksum,
            settings.max_image_bytes(),
        )
        .await?;
    // Server-set: the controller gives it a node now.
    let n = i.metadata.name.clone();
    let uid = i.metadata.uid;
    for _ in 0..8 {
        let cur = IMAGES.find(st, &scope, &n).await?;
        let rev = cur.revision;
        let mut img: Image = decode(cur)?;
        if img.metadata.uid != uid || img.metadata.delete_time.is_some() {
            return Err(ApiError::NotFound(IMAGES.full_name(&scope, &n)));
        }
        img.status.uploaded = true;
        img.status.download_bytes = Some(len);
        img.status.message = None;
        img.metadata.etag = None;
        match st
            .store
            .put(
                IMAGES.key(&scope, &n)?,
                serde_json::to_vec(&img)?,
                torngat_store::Precondition::Revision(rev),
            )
            .await
        {
            Ok(rev) => {
                img.metadata.etag = Some(crate::handlers::etag(rev));
                return Ok(Json(img));
            }
            Err(torngat_store::StoreError::PreconditionFailed { .. }) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(ApiError::Aborted("the image changed; retry".into()))
}

pub async fn put_platform_part(
    State(st): State<AppState>,
    Path((image, part)): Path<(String, u32)>,
    body: axum::body::Body,
) -> Result<Json<serde_json::Value>, ApiError> {
    put(&st, Scope::Platform, &image, part, body).await
}

pub async fn get_platform_upload(
    State(st): State<AppState>,
    Path(image): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    received(&st, Scope::Platform, &image).await
}

pub async fn finish_platform_upload(
    State(st): State<AppState>,
    Path(image): Path<String>,
) -> Result<Json<Image>, ApiError> {
    finish(&st, Scope::Platform, &image).await
}

pub async fn put_part(
    State(st): State<AppState>,
    Path((org, project, image, part)): Path<(String, String, String, u32)>,
    body: axum::body::Body,
) -> Result<Json<serde_json::Value>, ApiError> {
    put(&st, project_scope(&org, &project)?, &image, part, body).await
}

pub async fn get_upload(
    State(st): State<AppState>,
    Path((org, project, image)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    received(&st, project_scope(&org, &project)?, &image).await
}

pub async fn finish_upload(
    State(st): State<AppState>,
    Path((org, project, image)): Path<(String, String, String)>,
) -> Result<Json<Image>, ApiError> {
    finish(&st, project_scope(&org, &project)?, &image).await
}
