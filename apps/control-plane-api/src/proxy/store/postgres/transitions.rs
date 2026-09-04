use postgres::GenericClient;

use super::super::shared::configuration_error;
use super::rows;
use crate::ExactScope;
use crate::proxy::{ProxyError, ProxyId, ProxyLifecycleState, ProxyRevisionId};

// This adapter mirrors the lifecycle transition SQL columns and keeps the query explicit.
#[allow(clippy::too_many_arguments)]
pub(super) fn insert_lifecycle_transition(
    client: &mut impl GenericClient,
    operation: &str,
    scope: &ExactScope,
    proxy_id: &ProxyId,
    revision_id: Option<&ProxyRevisionId>,
    prior_state: Option<ProxyLifecycleState>,
    next_state: ProxyLifecycleState,
    actor_id: Option<&str>,
    reason_code: &str,
    status: &str,
    occurred_at_micros: u128,
    request_id: Option<&str>,
) -> Result<(), ProxyError> {
    let revision_uuid = revision_id.map(|value| value.as_uuid());
    let prior_state = prior_state.map(rows::state_to_text);
    let next_state = rows::state_to_text(next_state);
    let occurred_at_micros =
        i64::try_from(occurred_at_micros).map_err(|_| configuration_error())?;
    let request_id = request_id
        .map(uuid::Uuid::parse_str)
        .transpose()
        .map_err(|_| configuration_error())?;
    client
        .execute(
            "INSERT INTO mcp_proxy_lifecycle_transitions
             (transition_id, request_id, operation, workspace_id, namespace_id, proxy_id, revision_id,
              prior_state, next_state, actor_id, reason_code, status, occurred_at_micros)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
            &[
                &uuid::Uuid::now_v7(),
                &request_id,
                &operation,
                &scope.workspace_id,
                &scope.namespace_id,
                proxy_id.as_uuid(),
                &revision_uuid,
                &prior_state,
                &next_state,
                &actor_id,
                &reason_code,
                &status,
                &occurred_at_micros,
            ],
        )
        .map_err(|_| configuration_error())?;
    Ok(())
}
