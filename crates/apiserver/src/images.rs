//! Images: of the platform (operator API) and of a project (tenant API).

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use serde::Deserialize;
use torngat_api::Scope;
use torngat_api::image::{Image, ImageError, ImagePhase, ImageSpec, image_volume, staging_volume};
use uuid::Uuid;

use crate::crud::{Input, Kind, Params, Update, invalid};
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
