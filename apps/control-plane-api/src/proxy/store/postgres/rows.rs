use postgres::Row;

use crate::ExactScope;
use crate::proxy::{
    McpProxyRevision, ProxyError, ProxyId, ProxyLifecycleState, ProxyRedactionStatus,
    ProxyRevisionId,
};

use super::super::shared::{StoreProxy, StoredRevision, configuration_error, parse_spec_json};

pub(super) fn store_proxy_from_row(row: Row) -> Result<StoreProxy, ProxyError> {
    Ok(StoreProxy {
        proxy_id: ProxyId::new(row.get::<_, uuid::Uuid>(0).hyphenated().to_string())
            .map_err(|_| configuration_error())?,
        scope: ExactScope {
            workspace_id: row.get(1),
            namespace_id: row.get(2),
        },
        display_name: row.get(3),
        slug: row.get(4),
        description: row.get(5),
        owner: row.get(6),
        lifecycle_state: text_to_state(row.get::<_, String>(7).as_str())?,
        redaction_status: text_to_redaction(row.get::<_, String>(8).as_str())?,
        active_revision_id: row
            .get::<_, Option<uuid::Uuid>>(9)
            .map(|value| ProxyRevisionId::new(value.hyphenated().to_string()))
            .transpose()
            .map_err(|_| configuration_error())?,
        draft_revision_id: row
            .get::<_, Option<uuid::Uuid>>(10)
            .map(|value| ProxyRevisionId::new(value.hyphenated().to_string()))
            .transpose()
            .map_err(|_| configuration_error())?,
        created_at_micros: u128::try_from(row.get::<_, i64>(11))
            .map_err(|_| configuration_error())?,
    })
}

pub(super) fn stored_revision_from_row(row: Row) -> Result<StoredRevision, ProxyError> {
    let spec_json: String = row.get(2);
    let spec = parse_spec_json(&spec_json)?;
    let mut revision = McpProxyRevision::new(
        ProxyId::new(row.get::<_, uuid::Uuid>(0).hyphenated().to_string())
            .map_err(|_| configuration_error())?,
        ProxyRevisionId::new(row.get::<_, uuid::Uuid>(1).hyphenated().to_string())
            .map_err(|_| configuration_error())?,
        spec,
        row.get::<_, String>(3),
        text_to_state(row.get::<_, String>(4).as_str())?,
    )?;
    revision.redaction_status = text_to_redaction(row.get::<_, String>(5).as_str())?;
    revision.created_by = row.get(6);
    revision.created_at = row.get(7);
    Ok(StoredRevision {
        revision,
        published: row.get(8),
    })
}

pub(super) fn state_to_text(state: ProxyLifecycleState) -> &'static str {
    match state {
        ProxyLifecycleState::Draft => "draft",
        ProxyLifecycleState::Validating => "validating",
        ProxyLifecycleState::AwaitingApproval => "awaiting_approval",
        ProxyLifecycleState::Provisioning => "provisioning",
        ProxyLifecycleState::Ready => "ready",
        ProxyLifecycleState::Degraded => "degraded",
        ProxyLifecycleState::Paused => "paused",
        ProxyLifecycleState::Failed => "failed",
        ProxyLifecycleState::Retiring => "retiring",
        ProxyLifecycleState::Retired => "retired",
    }
}

pub(super) fn text_to_state(value: &str) -> Result<ProxyLifecycleState, ProxyError> {
    match value {
        "draft" => Ok(ProxyLifecycleState::Draft),
        "validating" => Ok(ProxyLifecycleState::Validating),
        "awaiting_approval" => Ok(ProxyLifecycleState::AwaitingApproval),
        "provisioning" => Ok(ProxyLifecycleState::Provisioning),
        "ready" => Ok(ProxyLifecycleState::Ready),
        "degraded" => Ok(ProxyLifecycleState::Degraded),
        "paused" => Ok(ProxyLifecycleState::Paused),
        "failed" => Ok(ProxyLifecycleState::Failed),
        "retiring" => Ok(ProxyLifecycleState::Retiring),
        "retired" => Ok(ProxyLifecycleState::Retired),
        _ => Err(configuration_error()),
    }
}

pub(super) fn redaction_to_text(status: ProxyRedactionStatus) -> &'static str {
    match status {
        ProxyRedactionStatus::Redacted => "redacted",
        ProxyRedactionStatus::PartiallyRedacted => "partially_redacted",
    }
}

pub(super) fn text_to_redaction(value: &str) -> Result<ProxyRedactionStatus, ProxyError> {
    match value {
        "redacted" => Ok(ProxyRedactionStatus::Redacted),
        "partially_redacted" => Ok(ProxyRedactionStatus::PartiallyRedacted),
        _ => Err(configuration_error()),
    }
}
