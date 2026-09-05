use apex_durability::PostgresClientOps as GenericClient;

use super::super::shared::{IdempotencyRecord, check_idempotency_record, configuration_error};
use crate::ExactScope;
use crate::proxy::ProxyError;

pub(super) fn query_idempotency(
    client: &mut impl GenericClient,
    request_id: &str,
    operation: &'static str,
    expected_hash: &str,
    expected_scope: &ExactScope,
) -> Result<Option<IdempotencyRecord>, ProxyError> {
    let request_uuid =
        uuid::Uuid::parse_str(request_id).map_err(|_| ProxyError::invalid_request_id())?;
    let Some(row) = client
        .query_opt(
            "SELECT payload_hash, workspace_id, namespace_id, proxy_id, revision_id
             FROM mcp_proxy_idempotency
             WHERE request_id = $1 AND operation = $2
             FOR UPDATE",
            &[&request_uuid, &operation],
        )
        .map_err(|_| configuration_error())?
    else {
        return Ok(None);
    };
    let record = IdempotencyRecord {
        request_id: request_id.to_owned(),
        operation,
        payload_hash: row.get(0),
        scope: ExactScope {
            workspace_id: row.get(1),
            namespace_id: row.get(2),
        },
        proxy_id: row.get::<_, uuid::Uuid>(3).hyphenated().to_string(),
        revision_id: row
            .get::<_, Option<uuid::Uuid>>(4)
            .map(|value| value.hyphenated().to_string()),
    };
    check_idempotency_record(&record, expected_hash, expected_scope)?;
    Ok(Some(record))
}

pub(super) fn insert_idempotency(
    client: &mut impl GenericClient,
    record: IdempotencyRecord,
) -> Result<(), ProxyError> {
    let request_uuid =
        uuid::Uuid::parse_str(&record.request_id).map_err(|_| ProxyError::invalid_request_id())?;
    let revision_uuid = record
        .revision_id
        .as_deref()
        .map(uuid::Uuid::parse_str)
        .transpose()
        .map_err(|_| configuration_error())?;
    let proxy_uuid = uuid::Uuid::parse_str(&record.proxy_id).map_err(|_| configuration_error())?;
    client
        .execute(
            "INSERT INTO mcp_proxy_idempotency
             (request_id, operation, payload_hash, workspace_id, namespace_id, proxy_id, revision_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &request_uuid,
                &record.operation,
                &record.payload_hash,
                &record.scope.workspace_id,
                &record.scope.namespace_id,
                &proxy_uuid,
                &revision_uuid,
            ],
        )
        .map_err(|_| configuration_error())?;
    Ok(())
}
