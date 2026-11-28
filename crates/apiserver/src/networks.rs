//! Host networks and provider networks (operator API), and networks of projects (tenant API).

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use serde::Deserialize;
use torngat_api::network::{
    HostNetwork, HostNetworkSpec, Network, NetworkError, NetworkSpec, ProviderNetwork,
    ProviderNetworkSpec,
};
use torngat_api::{Name, Scope};
use uuid::Uuid;

use crate::crud::{Input, Kind, Params, Update, any, invalid};
use crate::handlers::{
    DeleteQuery, ListQuery, ListResponse, body, decode, name, node_key, project_scope, query,
};
use crate::{ApiError, AppState};

type Body<T> = Result<Json<T>, JsonRejection>;

const HOST_NETWORKS: Kind = Kind {
    keyspace: "platform",
    segment: "hostnetworks",
    path: "hostNetworks",
};
const PROVIDER_NETWORKS: Kind = Kind {
    keyspace: "platform",
    segment: "providernetworks",
    path: "providerNetworks",
};
pub(crate) const NETWORKS: Kind = Kind {
    keyspace: "network",
    segment: "networks",
    path: "networks",
};

impl From<NetworkError> for ApiError {
    fn from(e: NetworkError) -> Self {
        invalid(e)
    }
}

async fn exists<S: serde::de::DeserializeOwned, St: serde::de::DeserializeOwned + Default>(
    st: &AppState,
    kind: &Kind,
    scope: &Scope,
    n: &Name,
) -> Result<Option<torngat_api::Object<S, St>>, ApiError> {
    match st.store.get(&kind.key(scope, n)?).await? {
        Some(v) => {
            let o: torngat_api::Object<S, St> = decode(v)?;
            Ok(o.metadata.delete_time.is_none().then_some(o))
        }
        None => Ok(None),
    }
}

// ---------- host networks ----------

#[derive(Debug, Deserialize)]
pub struct CreateHostNetworkQuery {
    host_network_id: String,
}

pub async fn create_host_network(
    State(st): State<AppState>,
    q: Params<CreateHostNetworkQuery>,
    b: Body<Input<HostNetworkSpec>>,
) -> Result<Json<HostNetwork>, ApiError> {
    let n = name("host network", &query(q)?.host_network_id)?;
    let input = body(b)?;
    input.spec.validate()?;
    let node = &input.spec.node;
    if st.store.get(&node_key(node)?).await?.is_none() {
        return Err(invalid(format!("there is no node {node}")));
    }
    let spec = input.spec.clone();
    let same = |h: &HostNetwork| {
        h.spec.node == spec.node && h.spec.uplink == spec.uplink && h.spec.vlan == spec.vlan
    };
    if any(&st, &HOST_NETWORKS.prefix(&Scope::Platform)?, same).await? {
        return Err(ApiError::AlreadyExists(
            "a host network on this uplink and VLAN".into(),
        ));
    }
    HOST_NETWORKS
        .create(&st, Scope::Platform, n, Uuid::now_v7(), input)
        .await
}

pub async fn get_host_network(
    State(st): State<AppState>,
    Path(h): Path<String>,
) -> Result<Json<HostNetwork>, ApiError> {
    HOST_NETWORKS
        .get(&st, &Scope::Platform, &name("host network", &h)?)
        .await
}

pub async fn list_host_networks(
    State(st): State<AppState>,
    q: Params<ListQuery>,
) -> Result<Json<ListResponse<HostNetwork>>, ApiError> {
    HOST_NETWORKS.list(&st, &Scope::Platform, q).await
}

pub async fn update_host_network(
    State(st): State<AppState>,
    Path(h): Path<String>,
    b: Body<Update<HostNetworkSpec>>,
) -> Result<Json<HostNetwork>, ApiError> {
    let n = name("host network", &h)?;
    let check = async |old: HostNetwork, new: HostNetworkSpec| {
        new.validate()?;
        if (&old.spec.node, &old.spec.uplink, old.spec.vlan) != (&new.node, &new.uplink, new.vlan) {
            return Err(invalid("node, uplink and vlan cannot change"));
        }
        Ok(())
    };
    HOST_NETWORKS
        .update(&st, &Scope::Platform, &n, body(b)?, check)
        .await
}

pub async fn delete_host_network(
    State(st): State<AppState>,
    Path(h): Path<String>,
    q: Params<DeleteQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let n = name("host network", &h)?;
    let cur = HOST_NETWORKS
        .find_for_delete(&st, &Scope::Platform, &n, query(q)?)
        .await?;
    HOST_NETWORKS
        .delete(&st, &Scope::Platform, &n, cur.revision)
        .await
}

// ---------- provider networks ----------

#[derive(Debug, Deserialize)]
pub struct CreateProviderNetworkQuery {
    provider_network_id: String,
}

pub async fn create_provider_network(
    State(st): State<AppState>,
    q: Params<CreateProviderNetworkQuery>,
    b: Body<Input<ProviderNetworkSpec>>,
) -> Result<Json<ProviderNetwork>, ApiError> {
    let n = name("provider network", &query(q)?.provider_network_id)?;
    let input = body(b)?;
    input.spec.validate()?;
    PROVIDER_NETWORKS
        .create(&st, Scope::Platform, n, Uuid::now_v7(), input)
        .await
}

pub async fn get_provider_network(
    State(st): State<AppState>,
    Path(p): Path<String>,
) -> Result<Json<ProviderNetwork>, ApiError> {
    PROVIDER_NETWORKS
        .get(&st, &Scope::Platform, &name("provider network", &p)?)
        .await
}

pub async fn list_provider_networks(
    State(st): State<AppState>,
    q: Params<ListQuery>,
) -> Result<Json<ListResponse<ProviderNetwork>>, ApiError> {
    PROVIDER_NETWORKS.list(&st, &Scope::Platform, q).await
}

pub async fn update_provider_network(
    State(st): State<AppState>,
    Path(p): Path<String>,
    b: Body<Update<ProviderNetworkSpec>>,
) -> Result<Json<ProviderNetwork>, ApiError> {
    let n = name("provider network", &p)?;
    // Who may use it changes; where it is and its addresses do not.
    let check = async |old: ProviderNetwork, new: ProviderNetworkSpec| {
        new.validate()?;
        if (&old.spec.physnet, old.spec.vlan, &old.spec.pool) != (&new.physnet, new.vlan, &new.pool)
        {
            return Err(invalid("physnet, vlan and pool cannot change"));
        }
        Ok(())
    };
    PROVIDER_NETWORKS
        .update(&st, &Scope::Platform, &n, body(b)?, check)
        .await
}

pub async fn delete_provider_network(
    State(st): State<AppState>,
    Path(p): Path<String>,
    q: Params<DeleteQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let n = name("provider network", &p)?;
    let cur = PROVIDER_NETWORKS
        .find_for_delete(&st, &Scope::Platform, &n, query(q)?)
        .await?;
    let rev = cur.revision;
    let pn: ProviderNetwork = decode(cur)?;
    // An allocation made after this read changes the revision, so the delete fails.
    if !pn.status.allocations.is_empty() {
        return Err(ApiError::FailedPrecondition(format!(
            "{n} has {} addresses in use",
            pn.status.allocations.len()
        )));
    }
    let names =
        |net: &Network| matches!(&net.spec, NetworkSpec::Provider { network } if *network == n);
    if any(&st, &NETWORKS.all()?, names).await? {
        return Err(ApiError::FailedPrecondition(format!(
            "{n} is used by networks of projects"
        )));
    }
    PROVIDER_NETWORKS
        .delete(&st, &Scope::Platform, &n, rev)
        .await
}

// ---------- networks of projects ----------

#[derive(Debug, Deserialize)]
pub struct CreateNetworkQuery {
    network_id: String,
}

pub async fn create_network(
    State(st): State<AppState>,
    Path((org, project)): Path<(String, String)>,
    q: Params<CreateNetworkQuery>,
    b: Body<Input<NetworkSpec>>,
) -> Result<Json<Network>, ApiError> {
    let scope = project_scope(&org, &project)?;
    let n = name("network", &query(q)?.network_id)?;
    let input = body(b)?;
    input.spec.validate()?;
    if let NetworkSpec::Provider { network } = &input.spec {
        let pn: Option<ProviderNetwork> =
            exists(&st, &PROVIDER_NETWORKS, &Scope::Platform, network).await?;
        if !pn.is_some_and(|p| p.spec.tenants) {
            return Err(invalid(format!(
                "there is no provider network {network} open to projects"
            )));
        }
    }
    NETWORKS.create(&st, scope, n, Uuid::now_v7(), input).await
}

pub async fn get_network(
    State(st): State<AppState>,
    Path((org, project, net)): Path<(String, String, String)>,
) -> Result<Json<Network>, ApiError> {
    NETWORKS
        .get(
            &st,
            &project_scope(&org, &project)?,
            &name("network", &net)?,
        )
        .await
}

pub async fn list_networks(
    State(st): State<AppState>,
    Path((org, project)): Path<(String, String)>,
    q: Params<ListQuery>,
) -> Result<Json<ListResponse<Network>>, ApiError> {
    NETWORKS.list(&st, &project_scope(&org, &project)?, q).await
}

pub async fn update_network(
    State(st): State<AppState>,
    Path((org, project, net)): Path<(String, String, String)>,
    b: Body<Update<NetworkSpec>>,
) -> Result<Json<Network>, ApiError> {
    let n = name("network", &net)?;
    let check = async |old: Network, new: NetworkSpec| Ok(old.spec.validate_update(&new)?);
    NETWORKS
        .update(&st, &project_scope(&org, &project)?, &n, body(b)?, check)
        .await
}

pub async fn delete_network(
    State(st): State<AppState>,
    Path((org, project, net)): Path<(String, String, String)>,
    q: Params<DeleteQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scope = project_scope(&org, &project)?;
    let n = name("network", &net)?;
    let cur = NETWORKS.find_for_delete(&st, &scope, &n, query(q)?).await?;
    let rev = cur.revision;
    let net: Network = decode(cur)?;
    // An instance made after this read that lists it waits for it (its interface is not given
    // an address).
    let lists =
        |i: &torngat_api::compute::Instance| i.spec.interfaces.iter().any(|f| f.network == n);
    let used = !net.status.allocations.is_empty()
        || any(&st, &crate::handlers::instances_prefix(&scope)?, lists).await?;
    if used {
        return Err(ApiError::FailedPrecondition(format!(
            "{n} is used by instances"
        )));
    }
    NETWORKS.delete(&st, &scope, &n, rev).await
}
