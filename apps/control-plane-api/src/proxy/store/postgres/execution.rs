//! Bounded restart inventory and frozen execution evidence under the live fence.
use super::{PostgresProxyStore, configuration_error, operation_journal as journal};
use crate::{ExactScope, LeasedProxyOperation, ProxyError, ProxyId, ProxyLifecycleEvent, proto};
use apex_durability::{PostgresClientOps, PostgresTransaction};
use prost::Message;
use uuid::Uuid;

impl PostgresProxyStore {
    pub(crate) fn runtime_inventory(
        &self,
        scope: &ExactScope,
        after: Option<&ProxyId>,
    ) -> Result<Vec<ProxyId>, ProxyError> {
        let mut client = self.client.try_lock().map_err(|_| configuration_error())?;
        client.query("SELECT p.proxy_id FROM mcp_proxies p JOIN mcp_proxy_operations o
            ON o.proxy_id=p.proxy_id AND o.generation=p.deployment_generation
            LEFT JOIN mcp_proxy_controller_leases l ON l.proxy_id=p.proxy_id
            WHERE p.workspace_id=$1 AND p.namespace_id=$2 AND ($3::uuid IS NULL OR p.proxy_id>$3)
            AND o.observed_state IN (1,2,6,7)
            AND (l.proxy_id IS NULL OR l.generation<o.generation OR l.expires_at_micros<=floor(extract(epoch FROM clock_timestamp())*1000000)::bigint)
            ORDER BY p.proxy_id LIMIT 8", &[&scope.workspace_id,&scope.namespace_id,&after.map(ProxyId::as_uuid)])
            .map_err(|_|configuration_error())?.into_iter().map(|row| ProxyId::new(row.get::<_,Uuid>(0).to_string())).collect()
    }

    /// `None` means transport uncertainty, not proof that no runtime exists.
    pub(crate) fn observe_runtime_attempt(
        &self,
        lease: &LeasedProxyOperation,
        response: Option<&proto::RuntimeReconcileResponse>,
        installation: &str,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<proto::ProxyOperation, ProxyError> {
        check()?;
        let resource = lease
            .operation
            .scope
            .as_ref()
            .ok_or_else(configuration_error)?;
        let scope = ExactScope {
            workspace_id: resource.workspace_id.clone(),
            namespace_id: resource.namespace_id.clone(),
        };
        let proxy_id = ProxyId::new(&resource.proxy_id)?;
        let key = journal::Target {
            scope: &scope,
            proxy_id: &proxy_id,
        };
        let mut client = self.client.try_lock_checked(check)?;
        let mut tx = client.transaction().map_err(|_| configuration_error())?;
        journal::lock_proxy(&mut tx, key)?;
        check()?;
        let row=tx.query_one("SELECT request_bytes,outcome_event_id,uncertain_event_id,event_time_micros,response_bytes
            FROM mcp_proxy_runtime_attempts WHERE workspace_id=$1 AND namespace_id=$2 AND proxy_id=$3
            AND operation_id=$4 AND fencing_token=$5 FOR UPDATE",
            &[&scope.workspace_id,&scope.namespace_id,proxy_id.as_uuid(),&journal::request_uuid(&lease.operation.operation_id)?,
                &i64::try_from(lease.fencing_token).map_err(|_|configuration_error())?]).map_err(|_|configuration_error())?;
        let request = proto::RuntimeReconcileRequest::decode(row.get::<_, Vec<u8>>(0).as_slice())
            .map_err(|_| configuration_error())?;
        check()?;
        let desired = proto::ProxyDesiredState::try_from(lease.operation.desired_state)
            .map_err(|_| configuration_error())?;
        let stored = row
            .get::<_, Option<Vec<u8>>>(4)
            .map(|bytes| {
                proto::RuntimeReconcileResponse::decode(bytes.as_slice())
                    .map_err(|_| configuration_error())
            })
            .transpose()?;
        let response = stored.as_ref().or(response);
        if let Some(response) = response {
            crate::proxy::runtime_client::validate_response(&request, response, desired)?;
            crate::proxy::runtime_client::validate_installation(response, installation)?;
            explain_installed(&mut tx, response)?;
            check()?;
            if stored.is_none() {
                tx.execute(
                    "UPDATE mcp_proxy_runtime_attempts SET response_bytes=$2 WHERE proxy_id=$1",
                    &[proxy_id.as_uuid(), &response.encode_to_vec()],
                )
                .map_err(|_| configuration_error())?;
            }
        }
        let (state, error) = match response {
            Some(r) => (
                proto::ProxyObservedState::try_from(r.observed_state)
                    .map_err(|_| configuration_error())?,
                r.error_code.as_str(),
            ),
            None => (
                proto::ProxyObservedState::NotServing,
                "RUNTIME_EXECUTION_UNAVAILABLE",
            ),
        };
        let id: Uuid = row.get(if response.is_some() { 1 } else { 2 });
        let mut event = crate::proxy::events::managed_event(
            &ProxyLifecycleEvent {
                request_id: lease.operation.request_id.clone(),
                operation: "runtime_reconcile".into(),
                scope: scope.clone(),
                proxy_id: proxy_id.clone(),
                revision_id: Some(crate::ProxyRevisionId::new(&lease.operation.revision_id)?),
                actor_id: lease.worker_id.clone(),
                reason_code: if response.is_some() {
                    "runtime.observed"
                } else {
                    "runtime.uncertain"
                }
                .into(),
            },
            &id.to_string(),
            u64::try_from(row.get::<_, i64>(3)).map_err(|_| configuration_error())?,
        )?;
        let data = event.data.as_mut().ok_or_else(configuration_error)?;
        for (name, value) in [
            ("installation_id", installation.to_owned()),
            ("command_id", request.command_id.clone()),
            ("operation_id", request.operation_id.clone()),
            ("generation", lease.operation.generation.to_string()),
            ("fencing_token", lease.fencing_token.to_string()),
            (
                "execution_response",
                response
                    .map(serde_json::to_string)
                    .transpose()
                    .map_err(|_| configuration_error())?
                    .unwrap_or_default(),
            ),
        ] {
            data.fields.insert(
                name.into(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue(value)),
                },
            );
        }
        event
            .integrity
            .as_mut()
            .ok_or_else(configuration_error)?
            .event_hash =
            apex_durability::canonical_event_hash(&event).map_err(|_| configuration_error())?;
        let observed = journal::observe_operation(
            &mut tx,
            key,
            &journal::LeasedOperation {
                operation: lease.operation.clone(),
                worker_id: lease.worker_id.clone(),
                fencing_token: lease.fencing_token,
                lease_expires_at_micros: lease.lease_expires_at_micros,
            },
            state,
            (!error.is_empty()).then_some(error),
            &event,
        )?;
        check()?;
        // The nested observation has completed all SQL; outer transaction must
        // recheck again before committing its response snapshot as well.
        let now = journal::database_now(&mut tx)?;
        journal::exact_live_lease_expiry(
            &mut tx,
            key,
            &journal::request_uuid(&lease.operation.operation_id)?,
            i64::try_from(lease.operation.generation).map_err(|_| configuration_error())?,
            &lease.worker_id,
            i64::try_from(lease.fencing_token).map_err(|_| configuration_error())?,
            now,
        )?
        .ok_or_else(configuration_error)?;
        check()?;
        tx.commit().map_err(|_| configuration_error())?;
        Ok(observed)
    }

    /// Only the physical owner calls after an authenticated RPC completed. Keep
    /// the counter and a 30s cooldown; uncertainty retains the original 180s lease.
    pub(crate) fn finish_runtime_attempt(
        &self,
        lease: &LeasedProxyOperation,
    ) -> Result<(), ProxyError> {
        let mut client = self.client.try_lock().map_err(|_| configuration_error())?;
        client.execute("UPDATE mcp_proxy_controller_leases SET expires_at_micros=
            LEAST(expires_at_micros,floor(extract(epoch FROM clock_timestamp())*1000000)::bigint+30000000)
            WHERE operation_id=$1 AND worker_id=$2 AND fencing_token=$3 AND generation=$4",
            &[&journal::request_uuid(&lease.operation.operation_id)?,&lease.worker_id,
            &i64::try_from(lease.fencing_token).map_err(|_|configuration_error())?,
            &i64::try_from(lease.operation.generation).map_err(|_|configuration_error())?]).map_err(|_|configuration_error())?;
        Ok(())
    }
}

fn explain_installed(
    tx: &mut PostgresTransaction<'_>,
    response: &proto::RuntimeReconcileResponse,
) -> Result<(), ProxyError> {
    if let Some(runtime) = &response.runtime {
        let target = runtime.target.as_ref().ok_or_else(configuration_error)?;
        let found = tx
            .query_opt(
                "SELECT 1 FROM mcp_proxy_operations WHERE workspace_id=$1 AND namespace_id=$2
            AND proxy_id=$3 AND revision_id=$4 AND generation=$5",
                &[
                    &target.workspace_id,
                    &target.namespace_id,
                    &journal::request_uuid(&target.proxy_id)?,
                    &journal::request_uuid(&target.revision_id)?,
                    &i64::try_from(target.generation).map_err(|_| configuration_error())?,
                ],
            )
            .map_err(|_| configuration_error())?;
        if found.is_none() {
            return Err(configuration_error());
        }
    }
    Ok(())
}
