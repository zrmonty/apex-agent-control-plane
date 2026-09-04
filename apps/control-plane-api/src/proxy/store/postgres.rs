mod connection;
use apex_durability::PostgresClientOps;
mod idempotency;
mod lifecycle;
mod operation_journal;
mod operations;
mod rows;
mod transitions;

use super::shared::{
    CREATE_OPERATION, IdempotencyRecord, PUBLISH_OPERATION, RETIRE_OPERATION,
    UPDATE_DRAFT_OPERATION, build_revision, configuration_error, create_payload_hash,
    encode_cursor, ensure_scope_match, parse_cursor, publish_payload_hash, retire_payload_hash,
    spec_json, update_payload_hash, validate_create, validate_publish, validate_request_id,
    validate_retire, validate_scope, validate_update,
};
use super::{
    CreateProxy, CreateProxyResult, ListProxies, ListProxiesPage, ListProxyActivity,
    ListProxyActivityPage, McpProxy, ProxyLifecycleStore, ProxyRevisionStore, ProxyStore,
    PublishRevision, RetireProxy, RollbackProxy, RotateProxyCredentials, TransitionProxyLifecycle,
    UpdateProxyDraft,
};
use crate::ExactScope;
use crate::proxy::{
    McpProxyRevision, ProxyError, ProxyId, ProxyLifecycleState, ProxyRedactionStatus,
    ProxyRevisionId,
};
use connection::ProxyConnection;
use idempotency::{insert_idempotency, query_idempotency};
use rows::{redaction_to_text, state_to_text, store_proxy_from_row};
use transitions::insert_lifecycle_transition;

const PROXY_SCHEMA_LOCK: i64 = 0x0A9E_1DE3_0000_0004_u64 as i64;

pub struct PostgresProxyStore {
    client: ProxyConnection,
}

impl ProxyLifecycleStore for PostgresProxyStore {
    fn transition(&self, input: TransitionProxyLifecycle) -> Result<McpProxy, ProxyError> {
        lifecycle::transition(self, input)
    }

    fn rotate_credentials(
        &self,
        input: RotateProxyCredentials,
    ) -> Result<McpProxyRevision, ProxyError> {
        lifecycle::rotate_credentials(self, input)
    }

    fn rollback(&self, input: RollbackProxy) -> Result<McpProxy, ProxyError> {
        lifecycle::rollback(self, input)
    }

    fn list_activity(&self, query: ListProxyActivity) -> Result<ListProxyActivityPage, ProxyError> {
        lifecycle::list_activity(self, query)
    }
}

impl PostgresProxyStore {
    pub fn connect(connection_string: &str) -> Result<Self, ProxyError> {
        let mut client = apex_durability::connect_postgres_for_worker(connection_string)
            .map_err(|_| configuration_error())?;
        apex_durability::apply_postgres_schema(
            &mut client,
            PROXY_SCHEMA_LOCK,
            include_str!("../../../../../deploy/postgres/mcp_proxies.sql"),
        )
        .map_err(|_| configuration_error())?;
        apex_durability::apply_postgres_schema(
            &mut client,
            PROXY_SCHEMA_LOCK,
            include_str!("../../../../../deploy/postgres/mcp_proxy_operations.sql"),
        )
        .map_err(|_| configuration_error())?;
        Ok(Self {
            client: ProxyConnection::new(client, connection_string)
                .map_err(|_| configuration_error())?,
        })
    }
}

impl ProxyStore for PostgresProxyStore {
    fn create_with_outcome(&self, input: CreateProxy) -> Result<CreateProxyResult, ProxyError> {
        let (display_name, description, owner) = validate_create(&input)?;
        let created_at_micros = validate_request_id(&input.request_id)?;
        let payload_hash = create_payload_hash(
            &input,
            &display_name,
            description.as_deref(),
            owner.as_deref(),
        );
        let mut client = self.client.lock().map_err(|_| configuration_error())?;
        let mut tx = client.transaction().map_err(|_| configuration_error())?;
        if let Some(record) = query_idempotency(
            &mut tx,
            &input.request_id,
            CREATE_OPERATION,
            &payload_hash,
            &input.scope,
        )? {
            tx.commit().map_err(|_| configuration_error())?;
            return Ok(CreateProxyResult {
                proxy: load_proxy(
                    &mut *client,
                    &record.proxy_id,
                    record.revision_id.as_deref(),
                )?,
                duplicate: true,
            });
        }
        let conflict = tx
            .query_opt(
                "SELECT 1 FROM mcp_proxies
                 WHERE proxy_id = $1
                    OR (workspace_id = $2 AND namespace_id = $3 AND slug = $4)
                 FOR UPDATE",
                &[
                    input.proxy_id.as_uuid(),
                    &input.scope.workspace_id,
                    &input.scope.namespace_id,
                    &input.slug,
                ],
            )
            .map_err(|_| configuration_error())?;
        if conflict.is_some() {
            if let Some(record) = query_idempotency(
                &mut tx,
                &input.request_id,
                CREATE_OPERATION,
                &payload_hash,
                &input.scope,
            )? {
                tx.commit().map_err(|_| configuration_error())?;
                return Ok(CreateProxyResult {
                    proxy: load_proxy(
                        &mut *client,
                        &record.proxy_id,
                        record.revision_id.as_deref(),
                    )?,
                    duplicate: true,
                });
            }
            return Err(ProxyError::identity_conflict());
        }
        tx.execute(
            "INSERT INTO mcp_proxies
             (proxy_id, workspace_id, namespace_id, display_name, slug, description, owner,
              lifecycle_state, redaction_status, active_revision_id, draft_revision_id,
              created_at_micros, desired_state)
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'draft', 'redacted', NULL, NULL, $8, 'draft')",
            &[
                input.proxy_id.as_uuid(),
                &input.scope.workspace_id,
                &input.scope.namespace_id,
                &display_name,
                &input.slug,
                &description,
                &owner,
                &i64::try_from(created_at_micros).map_err(|_| configuration_error())?,
            ],
        )
        .map_err(map_identity_error)?;
        insert_lifecycle_transition(
            &mut tx,
            CREATE_OPERATION,
            &input.scope,
            &input.proxy_id,
            None,
            None,
            ProxyLifecycleState::Draft,
            None,
            "proxy.created",
            "committed",
            created_at_micros,
            Some(input.request_id.as_str()),
        )?;
        insert_idempotency(
            &mut tx,
            IdempotencyRecord {
                request_id: input.request_id,
                operation: CREATE_OPERATION,
                payload_hash,
                proxy_id: input.proxy_id.to_string(),
                revision_id: None,
                scope: input.scope,
            },
        )?;
        tx.commit().map_err(|_| configuration_error())?;
        Ok(CreateProxyResult {
            proxy: load_proxy(&mut *client, &input.proxy_id.to_string(), None)?,
            duplicate: false,
        })
    }

    fn update_draft(&self, input: UpdateProxyDraft) -> Result<McpProxy, ProxyError> {
        let (actor_id, draft_json) = validate_update(&input)?;
        let created_at_micros = validate_request_id(&input.request_id)?;
        let payload_hash = update_payload_hash(&input, &actor_id, &draft_json);
        let mut client = self.client.lock().map_err(|_| configuration_error())?;
        let mut tx = client.transaction().map_err(|_| configuration_error())?;
        let proxy = query_proxy_for_update(&mut tx, &input.proxy_id)?
            .ok_or_else(ProxyError::proxy_not_found)?;
        if let Some(record) = query_idempotency(
            &mut tx,
            &input.request_id,
            UPDATE_DRAFT_OPERATION,
            &payload_hash,
            &input.scope,
        )? {
            tx.commit().map_err(|_| configuration_error())?;
            return load_proxy(
                &mut *client,
                &record.proxy_id,
                record.revision_id.as_deref(),
            );
        }
        ensure_scope_match(&proxy.scope, &input.scope)?;
        let prior_state = proxy.lifecycle_state;
        if proxy.draft_revision_id != input.expected_revision_id {
            return Err(ProxyError::revision_conflict());
        }
        let revision_id = ProxyRevisionId::new(&input.request_id).expect("validated request id");
        let revision = build_revision(
            input.proxy_id.clone(),
            revision_id.clone(),
            input.spec,
            actor_id,
            ProxyLifecycleState::Draft,
            ProxyRedactionStatus::Redacted,
            created_at_micros,
        )?;
        tx.execute(
            "INSERT INTO mcp_proxy_revisions
             (proxy_id, revision_id, spec_json, config_hash, lifecycle_state, redaction_status,
              created_by, created_at_micros, created_at, is_published)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, FALSE)",
            &[
                input.proxy_id.as_uuid(),
                revision_id.as_uuid(),
                &spec_json(&revision.spec),
                &revision.config_hash,
                &state_to_text(revision.lifecycle_state),
                &redaction_to_text(revision.redaction_status),
                &revision.created_by,
                &i64::try_from(created_at_micros).map_err(|_| configuration_error())?,
                &revision.created_at,
            ],
        )
        .map_err(|_| configuration_error())?;
        tx.execute(
            "UPDATE mcp_proxies SET draft_revision_id = $1 WHERE proxy_id = $2",
            &[revision_id.as_uuid(), input.proxy_id.as_uuid()],
        )
        .map_err(|_| configuration_error())?;
        insert_lifecycle_transition(
            &mut tx,
            UPDATE_DRAFT_OPERATION,
            &input.scope,
            &input.proxy_id,
            Some(&revision_id),
            Some(prior_state),
            ProxyLifecycleState::Draft,
            Some(&revision.created_by),
            "proxy.draft_updated",
            "committed",
            created_at_micros,
            Some(input.request_id.as_str()),
        )?;
        insert_idempotency(
            &mut tx,
            IdempotencyRecord {
                request_id: input.request_id,
                operation: UPDATE_DRAFT_OPERATION,
                payload_hash,
                proxy_id: input.proxy_id.to_string(),
                revision_id: Some(revision_id.to_string()),
                scope: input.scope,
            },
        )?;
        tx.commit().map_err(|_| configuration_error())?;
        load_proxy(
            &mut *client,
            &input.proxy_id.to_string(),
            Some(&revision_id.to_string()),
        )
    }

    fn publish_revision(&self, input: PublishRevision) -> Result<McpProxyRevision, ProxyError> {
        let actor_id = validate_publish(&input)?;
        let created_at_micros = validate_request_id(&input.request_id)?;
        let payload_hash = publish_payload_hash(&input, &actor_id);
        let mut client = self.client.lock().map_err(|_| configuration_error())?;
        let mut tx = client.transaction().map_err(|_| configuration_error())?;
        let proxy = query_proxy_for_update(&mut tx, &input.proxy_id)?
            .ok_or_else(ProxyError::proxy_not_found)?;
        if let Some(record) = query_idempotency(
            &mut tx,
            &input.request_id,
            PUBLISH_OPERATION,
            &payload_hash,
            &input.scope,
        )? {
            tx.commit().map_err(|_| configuration_error())?;
            return load_revision(
                &mut *client,
                &record.proxy_id,
                record
                    .revision_id
                    .as_deref()
                    .ok_or_else(configuration_error)?,
            );
        }
        ensure_scope_match(&proxy.scope, &input.scope)?;
        let prior_state = proxy.lifecycle_state;
        if proxy.active_revision_id != input.expected_revision_id {
            return Err(ProxyError::revision_conflict());
        }
        if proxy.lifecycle_state == ProxyLifecycleState::Retired {
            return Err(ProxyError::identity_conflict());
        }
        let draft = query_revision_row(&mut tx, &input.proxy_id, &input.draft_revision_id)?
            .ok_or_else(ProxyError::revision_not_found)?;
        if draft.published {
            return Err(ProxyError::immutable_revision());
        }
        let revision_id = ProxyRevisionId::new(&input.request_id).expect("validated request id");
        let revision = build_revision(
            input.proxy_id.clone(),
            revision_id.clone(),
            draft.revision.spec,
            actor_id,
            ProxyLifecycleState::Draft,
            ProxyRedactionStatus::Redacted,
            created_at_micros,
        )?;
        tx.execute(
            "INSERT INTO mcp_proxy_revisions
             (proxy_id, revision_id, spec_json, config_hash, lifecycle_state, redaction_status,
              created_by, created_at_micros, created_at, is_published)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE)",
            &[
                input.proxy_id.as_uuid(),
                revision_id.as_uuid(),
                &spec_json(&revision.spec),
                &revision.config_hash,
                &state_to_text(revision.lifecycle_state),
                &redaction_to_text(revision.redaction_status),
                &revision.created_by,
                &i64::try_from(created_at_micros).map_err(|_| configuration_error())?,
                &revision.created_at,
            ],
        )
        .map_err(|_| configuration_error())?;
        tx.execute(
            "UPDATE mcp_proxies SET active_revision_id = $1 WHERE proxy_id = $2",
            &[revision_id.as_uuid(), input.proxy_id.as_uuid()],
        )
        .map_err(|_| configuration_error())?;
        insert_lifecycle_transition(
            &mut tx,
            PUBLISH_OPERATION,
            &input.scope,
            &input.proxy_id,
            Some(&revision_id),
            Some(prior_state),
            ProxyLifecycleState::Draft,
            Some(&revision.created_by),
            "proxy.revision_published",
            "committed",
            created_at_micros,
            Some(input.request_id.as_str()),
        )?;
        insert_idempotency(
            &mut tx,
            IdempotencyRecord {
                request_id: input.request_id,
                operation: PUBLISH_OPERATION,
                payload_hash,
                proxy_id: input.proxy_id.to_string(),
                revision_id: Some(revision_id.to_string()),
                scope: input.scope,
            },
        )?;
        tx.commit().map_err(|_| configuration_error())?;
        load_revision(
            &mut *client,
            &input.proxy_id.to_string(),
            &revision_id.to_string(),
        )
    }

    fn get(&self, scope: ExactScope, proxy_id: ProxyId) -> Result<McpProxy, ProxyError> {
        validate_scope(&scope)?;
        let mut client = self.client.lock().map_err(|_| configuration_error())?;
        let proxy = load_proxy(&mut *client, &proxy_id.to_string(), None)?;
        ensure_scope_match(&proxy.scope, &scope)?;
        Ok(proxy)
    }

    fn list(&self, query: ListProxies) -> Result<ListProxiesPage, ProxyError> {
        validate_scope(&query.scope)?;
        let cursor = parse_cursor(&query.page_token)?;
        let mut client = self.client.lock().map_err(|_| configuration_error())?;
        let page_size = i64::try_from(query.page_size.max(1)).map_err(|_| configuration_error())?;
        let cursor_micros = cursor
            .as_ref()
            .map(|(micros, _)| i64::try_from(*micros).map_err(|_| configuration_error()))
            .transpose()?;
        let cursor_proxy = cursor
            .as_ref()
            .map(|(_, proxy_id)| proxy_id.as_str())
            .unwrap_or("");
        let rows = client
            .query(
                "SELECT proxy_id, workspace_id, namespace_id, display_name, slug, description, owner,
                        lifecycle_state, redaction_status, active_revision_id, draft_revision_id,
                        created_at_micros
                 FROM mcp_proxies
                 WHERE workspace_id = $1
                   AND namespace_id = $2
                   AND (
                        $3::bigint IS NULL
                        OR created_at_micros > $3
                        OR (created_at_micros = $3 AND proxy_id::text > $4)
                   )
                 ORDER BY created_at_micros ASC, proxy_id ASC
                 LIMIT $5",
                &[
                    &query.scope.workspace_id,
                    &query.scope.namespace_id,
                    &cursor_micros,
                    &cursor_proxy,
                    &(page_size + 1),
                ],
            )
            .map_err(|_| configuration_error())?;
        let mut proxies: Vec<_> = rows
            .into_iter()
            .map(store_proxy_from_row)
            .collect::<Result<_, _>>()?;
        let has_more = proxies.len() > query.page_size.max(1);
        proxies.truncate(query.page_size.max(1));
        let next_page_token = if has_more {
            let last = proxies.last().expect("proxy page");
            encode_cursor(last.created_at_micros, &last.proxy_id)
        } else {
            String::new()
        };
        Ok(ListProxiesPage {
            proxies: proxies
                .into_iter()
                .map(|proxy| proxy.to_summary())
                .collect(),
            next_page_token,
        })
    }
}

impl ProxyRevisionStore for PostgresProxyStore {
    fn get_revision(
        &self,
        scope: ExactScope,
        proxy_id: ProxyId,
        revision_id: ProxyRevisionId,
    ) -> Result<McpProxyRevision, ProxyError> {
        validate_scope(&scope)?;
        let mut client = self.client.lock().map_err(|_| configuration_error())?;
        let proxy = load_proxy(&mut *client, &proxy_id.to_string(), None)?;
        ensure_scope_match(&proxy.scope, &scope)?;
        load_revision(
            &mut *client,
            &proxy_id.to_string(),
            &revision_id.to_string(),
        )
    }

    fn retire(&self, input: RetireProxy) -> Result<McpProxy, ProxyError> {
        validate_retire(&input)?;
        let occurred_at_micros = validate_request_id(&input.request_id)?;
        let payload_hash = retire_payload_hash(&input);
        let mut client = self.client.lock().map_err(|_| configuration_error())?;
        let mut tx = client.transaction().map_err(|_| configuration_error())?;
        let proxy = query_proxy_for_update(&mut tx, &input.proxy_id)?
            .ok_or_else(ProxyError::proxy_not_found)?;
        if let Some(record) = query_idempotency(
            &mut tx,
            &input.request_id,
            RETIRE_OPERATION,
            &payload_hash,
            &input.scope,
        )? {
            tx.commit().map_err(|_| configuration_error())?;
            return load_proxy(
                &mut *client,
                &record.proxy_id,
                record.revision_id.as_deref(),
            );
        }
        ensure_scope_match(&proxy.scope, &input.scope)?;
        if proxy.active_revision_id != input.expected_revision_id {
            return Err(ProxyError::revision_conflict());
        }
        let prior_state = proxy.lifecycle_state;
        tx.execute(
            "UPDATE mcp_proxies
             SET lifecycle_state = 'retired', desired_state = 'retired', retired_at_micros = $2
             WHERE proxy_id = $1",
            &[
                input.proxy_id.as_uuid(),
                &i64::try_from(occurred_at_micros).map_err(|_| configuration_error())?,
            ],
        )
        .map_err(|_| configuration_error())?;
        insert_lifecycle_transition(
            &mut tx,
            RETIRE_OPERATION,
            &input.scope,
            &input.proxy_id,
            input.expected_revision_id.as_ref(),
            Some(prior_state),
            ProxyLifecycleState::Retired,
            None,
            "proxy.retired",
            "committed",
            occurred_at_micros,
            Some(input.request_id.as_str()),
        )?;
        insert_idempotency(
            &mut tx,
            IdempotencyRecord {
                request_id: input.request_id,
                operation: RETIRE_OPERATION,
                payload_hash,
                proxy_id: input.proxy_id.to_string(),
                revision_id: None,
                scope: input.scope,
            },
        )?;
        tx.commit().map_err(|_| configuration_error())?;
        load_proxy(&mut *client, &input.proxy_id.to_string(), None)
    }
}

mod query;

pub(super) use query::{
    load_proxy, load_revision, map_identity_error, query_proxy_for_update, query_revision_row,
};
