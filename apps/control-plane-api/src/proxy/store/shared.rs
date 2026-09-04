use std::collections::HashMap;

use serde_json::json;
use sha2::{Digest, Sha256};

use super::{
    CreateProxy, ListProxiesPage, McpProxy, McpProxySummary, PublishRevision, RetireProxy,
    UpdateProxyDraft,
};
use crate::ExactScope;
use crate::proxy::parse_proxy_spec_wire_json;
use crate::proxy::{
    McpProxyRevision, ProxyError, ProxyId, ProxyLifecycleState, ProxyRedactionStatus,
    ProxyRevisionId, ProxySpec, SecretRef, is_valid_slug, validate_proxy_spec,
};

pub(super) const CREATE_OPERATION: &str = "create";
pub(super) const UPDATE_DRAFT_OPERATION: &str = "update_draft";
pub(super) const PUBLISH_OPERATION: &str = "publish_revision";
pub(super) const RETIRE_OPERATION: &str = "retire_proxy";
pub(super) const ROTATE_OPERATION: &str = "rotate_proxy_credentials";
pub(super) const ROLLBACK_OPERATION: &str = "rollback_proxy";

#[derive(Debug, Clone, Default)]
pub(super) struct StoreState {
    pub(super) proxies: HashMap<String, StoreProxy>,
    pub(super) revisions: HashMap<String, StoredRevision>,
    pub(super) idempotency: HashMap<(String, &'static str), IdempotencyRecord>,
    pub(super) transitions: Vec<super::transitions::LifecycleTransition>,
}

#[derive(Debug, Clone)]
pub(super) struct StoreProxy {
    pub(super) proxy_id: ProxyId,
    pub(super) scope: ExactScope,
    pub(super) display_name: String,
    pub(super) slug: String,
    pub(super) description: Option<String>,
    pub(super) owner: Option<String>,
    pub(super) lifecycle_state: ProxyLifecycleState,
    pub(super) redaction_status: ProxyRedactionStatus,
    pub(super) active_revision_id: Option<ProxyRevisionId>,
    pub(super) draft_revision_id: Option<ProxyRevisionId>,
    pub(super) created_at_micros: u128,
}

#[derive(Debug, Clone)]
pub(super) struct StoredRevision {
    pub(super) revision: McpProxyRevision,
    pub(super) published: bool,
}

#[derive(Debug, Clone)]
pub(super) struct IdempotencyRecord {
    pub(super) request_id: String,
    pub(super) operation: &'static str,
    pub(super) payload_hash: String,
    pub(super) proxy_id: String,
    pub(super) revision_id: Option<String>,
    pub(super) scope: ExactScope,
}

impl StoreState {
    pub(super) fn check_idempotency(
        &self,
        operation: &'static str,
        request_id: &str,
        payload_hash: &str,
        scope: &ExactScope,
    ) -> Result<Option<IdempotencyRecord>, ProxyError> {
        let Some(record) = self.idempotency.get(&(request_id.to_owned(), operation)) else {
            return Ok(None);
        };
        check_idempotency_record(record, payload_hash, scope)?;
        Ok(Some(record.clone()))
    }

    pub(super) fn record_transition(
        &mut self,
        transition: super::transitions::LifecycleTransition,
    ) {
        self.transitions.push(transition);
    }

    pub(super) fn ensure_identity_available(
        &self,
        scope: &ExactScope,
        proxy_id: &ProxyId,
        slug: &str,
    ) -> Result<(), ProxyError> {
        if self.proxies.contains_key(&proxy_id.to_string())
            || self
                .proxies
                .values()
                .any(|proxy| proxy.scope == *scope && proxy.slug == slug)
        {
            return Err(ProxyError::identity_conflict());
        }
        Ok(())
    }

    pub(super) fn replay_proxy(&self, record: &IdempotencyRecord) -> Result<McpProxy, ProxyError> {
        let proxy = self
            .proxies
            .get(&record.proxy_id)
            .ok_or_else(ProxyError::proxy_not_found)?;
        let override_revision = record.revision_id.as_ref().and_then(|revision_id| {
            self.revisions
                .get(&format!("{}:{revision_id}", record.proxy_id))
        });
        Ok(proxy.to_proxy(&self.revisions, override_revision))
    }

    pub(super) fn replay_revision(
        &self,
        record: &IdempotencyRecord,
    ) -> Result<McpProxyRevision, ProxyError> {
        let revision_id = record
            .revision_id
            .as_ref()
            .ok_or_else(configuration_error)?;
        self.revisions
            .get(&format!("{}:{revision_id}", record.proxy_id))
            .map(|stored| stored.revision.clone())
            .ok_or_else(ProxyError::revision_not_found)
    }

    pub(super) fn record_idempotency(&mut self, record: IdempotencyRecord) {
        self.idempotency
            .insert((record.request_id.clone(), record.operation), record);
    }
}

impl StoreProxy {
    pub(super) fn to_proxy(
        &self,
        revisions: &HashMap<String, StoredRevision>,
        override_revision: Option<&StoredRevision>,
    ) -> McpProxy {
        let draft = override_revision.or_else(|| {
            self.draft_revision_id
                .as_ref()
                .and_then(|id| revisions.get(&revision_key(&self.proxy_id, id)))
        });
        let spec = draft
            .map(|revision| revision.revision.spec.clone())
            .or_else(|| {
                self.active_revision_id
                    .as_ref()
                    .and_then(|id| revisions.get(&revision_key(&self.proxy_id, id)))
                    .map(|revision| revision.revision.spec.clone())
            });
        McpProxy {
            proxy_id: self.proxy_id.clone(),
            scope: self.scope.clone(),
            display_name: self.display_name.clone(),
            slug: self.slug.clone(),
            description: self.description.clone(),
            owner: self.owner.clone(),
            lifecycle_state: self.lifecycle_state,
            redaction_status: self.redaction_status,
            active_revision_id: self.active_revision_id.clone(),
            draft_revision_id: draft
                .map(|revision| revision.revision.revision_id.clone())
                .or_else(|| self.draft_revision_id.clone()),
            spec,
        }
    }

    pub(super) fn to_summary(&self) -> McpProxySummary {
        McpProxySummary {
            proxy_id: self.proxy_id.clone(),
            scope: self.scope.clone(),
            display_name: self.display_name.clone(),
            slug: self.slug.clone(),
            lifecycle_state: self.lifecycle_state,
            redaction_status: self.redaction_status,
            active_revision_id: self.active_revision_id.clone(),
        }
    }
}

impl StoredRevision {
    pub(super) fn draft(revision: McpProxyRevision) -> Self {
        Self {
            revision,
            published: false,
        }
    }

    pub(super) fn published(revision: McpProxyRevision) -> Self {
        Self {
            revision,
            published: true,
        }
    }
}

pub(super) fn validate_request_id(request_id: &str) -> Result<u128, ProxyError> {
    let uuid = uuid::Uuid::parse_str(request_id).map_err(|_| ProxyError::invalid_request_id())?;
    if uuid.get_version_num() != 7 || uuid.hyphenated().to_string() != request_id {
        return Err(ProxyError::invalid_request_id());
    }
    let (secs, nanos) = uuid
        .get_timestamp()
        .ok_or_else(ProxyError::invalid_request_id)?
        .to_unix();
    Ok((secs as u128) * 1_000_000 + (nanos as u128) / 1_000)
}

pub(super) fn validate_scope(scope: &ExactScope) -> Result<(), ProxyError> {
    if !super::super::validation::is_scope_identifier(&scope.workspace_id)
        || !super::super::validation::is_scope_identifier(&scope.namespace_id)
    {
        return Err(ProxyError::invalid_proxy_scope());
    }
    Ok(())
}

pub(super) fn validate_create(
    input: &CreateProxy,
) -> Result<(String, Option<String>, Option<String>), ProxyError> {
    validate_request_id(&input.request_id)?;
    validate_scope(&input.scope)?;
    let display_name =
        super::super::validation::bounded_required_string(input.display_name.clone())?;
    let description = optional_bounded(input.description.clone())?;
    let owner = optional_bounded(input.owner.clone())?;
    if !is_valid_slug(&input.slug) {
        return Err(ProxyError::invalid_proxy_draft(
            "Proxy drafts require a non-empty bounded slug.",
        ));
    }
    Ok((display_name, description, owner))
}

pub(super) fn validate_update(input: &UpdateProxyDraft) -> Result<(String, String), ProxyError> {
    validate_request_id(&input.request_id)?;
    validate_scope(&input.scope)?;
    let actor_id = super::super::validation::bounded_required_string(input.actor_id.clone())?;
    validate_proxy_spec(&input.spec)?;
    let json = spec_json(&input.spec);
    Ok((actor_id, json))
}

pub(super) fn validate_publish(input: &PublishRevision) -> Result<String, ProxyError> {
    validate_request_id(&input.request_id)?;
    validate_scope(&input.scope)?;
    super::super::validation::bounded_required_string(input.actor_id.clone())
}

pub(super) fn validate_retire(input: &RetireProxy) -> Result<(), ProxyError> {
    validate_request_id(&input.request_id)?;
    validate_scope(&input.scope)
}

pub(super) fn create_payload_hash(
    input: &CreateProxy,
    display_name: &str,
    description: Option<&str>,
    owner: Option<&str>,
) -> String {
    hash_json(&json!({
        "request_id": input.request_id,
        "workspace_id": input.scope.workspace_id,
        "namespace_id": input.scope.namespace_id,
        "proxy_id": input.proxy_id.to_string(),
        "display_name": display_name,
        "slug": input.slug,
        "description": description.unwrap_or_default(),
        "owner": owner.unwrap_or_default()
    }))
}

pub(super) fn update_payload_hash(
    input: &UpdateProxyDraft,
    actor_id: &str,
    spec_json: &str,
) -> String {
    hash_json(&json!({
        "request_id": input.request_id,
        "workspace_id": input.scope.workspace_id,
        "namespace_id": input.scope.namespace_id,
        "proxy_id": input.proxy_id.to_string(),
        "expected_revision_id": input.expected_revision_id.as_ref().map(ToString::to_string).unwrap_or_default(),
        "actor_id": actor_id,
        "spec": spec_json
    }))
}

pub(super) fn publish_payload_hash(input: &PublishRevision, actor_id: &str) -> String {
    hash_json(&json!({
        "request_id": input.request_id,
        "workspace_id": input.scope.workspace_id,
        "namespace_id": input.scope.namespace_id,
        "proxy_id": input.proxy_id.to_string(),
        "draft_revision_id": input.draft_revision_id.to_string(),
        "expected_revision_id": input.expected_revision_id.as_ref().map(ToString::to_string).unwrap_or_default(),
        "actor_id": actor_id
    }))
}

pub(super) fn retire_payload_hash(input: &RetireProxy) -> String {
    hash_json(&json!({
        "request_id": input.request_id,
        "workspace_id": input.scope.workspace_id,
        "namespace_id": input.scope.namespace_id,
        "proxy_id": input.proxy_id.to_string(),
        "expected_revision_id": input.expected_revision_id.as_ref().map(ToString::to_string).unwrap_or_default()
    }))
}

pub(super) fn lifecycle_payload_hash(
    input: &super::TransitionProxyLifecycle,
    actor_id: &str,
    reason_code: &str,
) -> String {
    hash_json(&json!({
        "request_id": input.request_id,
        "workspace_id": input.scope.workspace_id,
        "namespace_id": input.scope.namespace_id,
        "proxy_id": input.proxy_id.to_string(),
        "revision_id": input.revision_id.to_string(),
        "expected_revision_id": input.expected_revision_id.as_ref().map(ToString::to_string),
        "actor_id": actor_id,
        "reason_code": reason_code,
        "operation": input.command.operation(),
        "approved": input.approved
    }))
}

pub(super) fn rotate_payload_hash(input: &super::RotateProxyCredentials, actor_id: &str) -> String {
    hash_json(&json!({
        "request_id": input.request_id,
        "workspace_id": input.scope.workspace_id,
        "namespace_id": input.scope.namespace_id,
        "proxy_id": input.proxy_id.to_string(),
        "revision_id": input.revision_id.to_string(),
        "expected_revision_id": input.expected_revision_id.as_ref().map(ToString::to_string),
        "actor_id": actor_id,
        "reason_code": input.reason_code,
        "secret_refs": input.secret_refs.iter().map(SecretRef::as_str).collect::<Vec<_>>()
    }))
}

pub(super) fn rollback_payload_hash(input: &super::RollbackProxy, actor_id: &str) -> String {
    hash_json(&json!({
        "request_id": input.request_id,
        "workspace_id": input.scope.workspace_id,
        "namespace_id": input.scope.namespace_id,
        "proxy_id": input.proxy_id.to_string(),
        "revision_id": input.revision_id.to_string(),
        "target_revision_id": input.target_revision_id.to_string(),
        "expected_revision_id": input.expected_revision_id.as_ref().map(ToString::to_string),
        "actor_id": actor_id,
        "reason_code": input.reason_code
    }))
}

pub(super) fn validate_reason_code(value: String) -> Result<String, ProxyError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || byte == b'_'
                || byte == b'.'
                || byte == b'-'
                || (index > 0 && byte == b'/')
        })
    {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy lifecycle reason codes must use bounded lowercase domain values.",
        ));
    }
    Ok(value)
}

pub(super) fn parse_cursor(token: &str) -> Result<Option<(u128, String)>, ProxyError> {
    if token.is_empty() {
        return Ok(None);
    }
    let Some((created_at, proxy_id)) = token.split_once('|') else {
        return Err(ProxyError::invalid_cursor());
    };
    let created_at_micros = created_at
        .parse::<u128>()
        .map_err(|_| ProxyError::invalid_cursor())?;
    Ok(Some((created_at_micros, proxy_id.to_owned())))
}

#[cfg(feature = "postgres")]
pub(super) fn parse_activity_cursor(token: &str) -> Result<(usize, ()), ProxyError> {
    if token.is_empty() {
        return Ok((0, ()));
    }
    token
        .parse::<usize>()
        .map(|offset| (offset, ()))
        .map_err(|_| ProxyError::invalid_cursor())
}

#[cfg(feature = "postgres")]
pub(super) fn list_activity_cursor(offset: usize) -> String {
    offset.to_string()
}

pub(super) fn encode_cursor(created_at_micros: u128, proxy_id: &ProxyId) -> String {
    format!("{created_at_micros}|{proxy_id}")
}

pub(super) fn revision_key(proxy_id: &ProxyId, revision_id: &ProxyRevisionId) -> String {
    format!("{proxy_id}:{revision_id}")
}

pub(super) fn build_revision(
    proxy_id: ProxyId,
    revision_id: ProxyRevisionId,
    spec: ProxySpec,
    created_by: String,
    lifecycle_state: ProxyLifecycleState,
    redaction_status: ProxyRedactionStatus,
    created_at_micros: u128,
) -> Result<McpProxyRevision, ProxyError> {
    let config_hash = hash_hex(spec_json(&spec).as_bytes());
    let mut revision =
        McpProxyRevision::new(proxy_id, revision_id, spec, config_hash, lifecycle_state)?;
    revision.redaction_status = redaction_status;
    revision.created_by = created_by;
    revision.created_at = format_rfc3339_micros(created_at_micros);
    Ok(revision)
}

pub(super) use super::canonical::spec_json;

#[allow(dead_code)]
pub(super) fn parse_spec_json(input: &str) -> Result<ProxySpec, ProxyError> {
    parse_proxy_spec_wire_json(input)
}

pub(super) fn list_from_rows(
    mut rows: Vec<StoreProxy>,
    query: &super::ListProxies,
) -> ListProxiesPage {
    rows.sort_unstable_by(|left, right| {
        left.created_at_micros
            .cmp(&right.created_at_micros)
            .then_with(|| left.proxy_id.to_string().cmp(&right.proxy_id.to_string()))
    });
    let cursor = parse_cursor(&query.page_token).unwrap_or(None);
    let mut proxies = Vec::with_capacity(query.page_size.max(1));
    let mut has_more = false;
    let mut last_cursor = None;
    for proxy in rows {
        if let Some((created_at_micros, proxy_id)) = cursor.as_ref()
            && (proxy.created_at_micros < *created_at_micros
                || (proxy.created_at_micros == *created_at_micros
                    && proxy.proxy_id.to_string() <= *proxy_id))
        {
            continue;
        }
        if proxies.len() >= query.page_size.max(1) {
            has_more = true;
            break;
        }
        last_cursor = Some((proxy.created_at_micros, proxy.proxy_id.clone()));
        proxies.push(proxy.to_summary());
    }
    let next_page_token = if has_more {
        let (created_at_micros, proxy_id) = last_cursor.expect("cursor");
        encode_cursor(created_at_micros, &proxy_id)
    } else {
        String::new()
    };
    ListProxiesPage {
        proxies,
        next_page_token,
    }
}

pub(super) fn ensure_scope_match(
    actual: &ExactScope,
    expected: &ExactScope,
) -> Result<(), ProxyError> {
    if actual != expected {
        return Err(ProxyError::proxy_not_found());
    }
    Ok(())
}

pub(super) fn check_idempotency_record(
    record: &IdempotencyRecord,
    expected_hash: &str,
    expected_scope: &ExactScope,
) -> Result<(), ProxyError> {
    ensure_scope_match(&record.scope, expected_scope)?;
    if record.payload_hash != expected_hash {
        return Err(ProxyError::idempotency_conflict());
    }
    Ok(())
}

fn optional_bounded(value: Option<String>) -> Result<Option<String>, ProxyError> {
    value
        .map(super::super::validation::bounded_required_string)
        .transpose()
}

fn hash_json(value: &serde_json::Value) -> String {
    hash_hex(value.to_string().as_bytes())
}

pub(super) fn hash_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from_digit(u32::from(byte >> 4), 16).expect("hex"));
        encoded.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("hex"));
    }
    encoded
}

pub(super) fn format_rfc3339_micros(total_micros: u128) -> String {
    let secs = (total_micros / 1_000_000) as i64;
    let micros = (total_micros % 1_000_000) as u32;
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{micros:06}Z")
}

pub(super) fn configuration_error() -> ProxyError {
    ProxyError::new(
        "PROXY_STORE_UNAVAILABLE",
        "The MCP proxy store failed to process the request.",
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
