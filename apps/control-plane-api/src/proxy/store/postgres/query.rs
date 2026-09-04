use postgres::GenericClient;

use super::super::McpProxy;
use super::super::shared::{StoreProxy, StoredRevision, configuration_error, revision_key};
use super::rows::{store_proxy_from_row, stored_revision_from_row};
use crate::proxy::{McpProxyRevision, ProxyError, ProxyId, ProxyRevisionId};

pub(crate) fn query_proxy_for_update(
    client: &mut impl GenericClient,
    proxy_id: &ProxyId,
) -> Result<Option<StoreProxy>, ProxyError> {
    client
        .query_opt(
            "SELECT proxy_id, workspace_id, namespace_id, display_name, slug, description, owner,
                    lifecycle_state, redaction_status, active_revision_id, draft_revision_id,
                    created_at_micros
             FROM mcp_proxies
             WHERE proxy_id = $1
             FOR UPDATE",
            &[proxy_id.as_uuid()],
        )
        .map_err(|_| configuration_error())?
        .map(store_proxy_from_row)
        .transpose()
}

pub(crate) fn query_revision_row(
    client: &mut impl GenericClient,
    proxy_id: &ProxyId,
    revision_id: &ProxyRevisionId,
) -> Result<Option<StoredRevision>, ProxyError> {
    client
        .query_opt(
            "SELECT proxy_id, revision_id, spec_json, config_hash, lifecycle_state, redaction_status,
                    created_by, created_at, is_published
             FROM mcp_proxy_revisions
             WHERE proxy_id = $1 AND revision_id = $2",
            &[proxy_id.as_uuid(), revision_id.as_uuid()],
        )
        .map_err(|_| configuration_error())?
        .map(stored_revision_from_row)
        .transpose()
}

pub(crate) fn load_proxy(
    client: &mut impl GenericClient,
    proxy_id: &str,
    override_revision_id: Option<&str>,
) -> Result<McpProxy, ProxyError> {
    let proxy_uuid = uuid::Uuid::parse_str(proxy_id).map_err(|_| configuration_error())?;
    let proxy = client
        .query_one(
            "SELECT proxy_id, workspace_id, namespace_id, display_name, slug, description, owner,
                    lifecycle_state, redaction_status, active_revision_id, draft_revision_id,
                    created_at_micros
             FROM mcp_proxies
             WHERE proxy_id = $1",
            &[&proxy_uuid],
        )
        .map_err(|_| ProxyError::proxy_not_found())?;
    let proxy = store_proxy_from_row(proxy)?;
    let override_revision = override_revision_id
        .map(ProxyRevisionId::new)
        .transpose()
        .map_err(|_| configuration_error())?;
    let draft = if let Some(revision_id) = override_revision.as_ref() {
        query_revision_row(client, &proxy.proxy_id, revision_id)?
    } else {
        None
    };
    Ok(proxy.to_proxy(&load_revision_map(client, &proxy)?, draft.as_ref()))
}

pub(crate) fn load_revision(
    client: &mut impl GenericClient,
    proxy_id: &str,
    revision_id: &str,
) -> Result<McpProxyRevision, ProxyError> {
    let proxy_id = ProxyId::new(proxy_id).map_err(|_| configuration_error())?;
    let revision_id = ProxyRevisionId::new(revision_id).map_err(|_| configuration_error())?;
    query_revision_row(client, &proxy_id, &revision_id)?
        .map(|stored| stored.revision)
        .ok_or_else(ProxyError::revision_not_found)
}

fn load_revision_map(
    client: &mut impl GenericClient,
    proxy: &StoreProxy,
) -> Result<std::collections::HashMap<String, StoredRevision>, ProxyError> {
    let rows = client
        .query(
            "SELECT proxy_id, revision_id, spec_json, config_hash, lifecycle_state, redaction_status,
                    created_by, created_at, is_published
             FROM mcp_proxy_revisions
             WHERE proxy_id = $1",
            &[proxy.proxy_id.as_uuid()],
        )
        .map_err(|_| configuration_error())?;
    let mut revisions = std::collections::HashMap::new();
    for row in rows {
        let stored = stored_revision_from_row(row)?;
        revisions.insert(
            revision_key(&proxy.proxy_id, &stored.revision.revision_id),
            stored,
        );
    }
    Ok(revisions)
}

pub(crate) fn map_identity_error(_error: postgres::Error) -> ProxyError {
    ProxyError::identity_conflict()
}
