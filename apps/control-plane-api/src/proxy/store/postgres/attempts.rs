//! Fenced durable transport identity, independent of replica wall-clock order.
use super::{PostgresProxyStore, configuration_error, operation_journal as journal};
use crate::{ExactScope, LeasedProxyOperation, ProxyError, ProxyId, proto};
use apex_durability::PostgresClientOps;
use prost::Message;
use uuid::Uuid;

pub(super) fn prepare(
    store: &PostgresProxyStore,
    lease: &LeasedProxyOperation,
) -> Result<proto::RuntimeReconcileRequest, ProxyError> {
    prepare_checked(store, lease, &|| Ok(()))
}

pub(super) fn prepare_checked(
    store: &PostgresProxyStore,
    lease: &LeasedProxyOperation,
    check: &impl Fn() -> Result<(), ProxyError>,
) -> Result<proto::RuntimeReconcileRequest, ProxyError> {
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
    let target = proto::RuntimeTarget {
        workspace_id: scope.workspace_id.clone(),
        namespace_id: scope.namespace_id.clone(),
        proxy_id: proxy_id.to_string(),
        revision_id: lease.operation.revision_id.clone(),
        generation: lease.operation.generation,
        fencing_token: lease.fencing_token,
    };
    let snapshot = store.read_current_runtime_operation_checked(
        &target,
        &lease.operation.operation_id,
        &lease.worker_id,
        check,
    )?;
    let mut client = store.client.try_lock_checked(check)?;
    let mut tx = client.transaction().map_err(|_| configuration_error())?;
    let key = journal::Target {
        scope: &scope,
        proxy_id: &proxy_id,
    };
    let locked = journal::lock_proxy(&mut tx, key)?;
    check()?;
    if !journal::matches_live_target(&locked, &snapshot.operation)? {
        return Err(configuration_error());
    }
    let operation = journal::request_uuid(&snapshot.operation.operation_id)?;
    let fence = i64::try_from(lease.fencing_token).map_err(|_| configuration_error())?;
    let generation =
        i64::try_from(lease.operation.generation).map_err(|_| configuration_error())?;
    let now = journal::database_now(&mut tx)?;
    journal::exact_live_lease_expiry(
        &mut tx,
        key,
        &operation,
        generation,
        &lease.worker_id,
        fence,
        now,
    )?
    .ok_or_else(configuration_error)?;
    check()?;
    let prior = tx.query_opt("SELECT last_command_id,operation_id,fencing_token,request_bytes
        FROM mcp_proxy_runtime_attempts WHERE workspace_id=$1 AND namespace_id=$2 AND proxy_id=$3 FOR UPDATE",
        &[&scope.workspace_id,&scope.namespace_id,proxy_id.as_uuid()]).map_err(|_| configuration_error())?;
    if let Some(row) = &prior
        && row.get::<_, Uuid>(1) == operation
        && row.get::<_, i64>(2) == fence
    {
        let request = proto::RuntimeReconcileRequest::decode(row.get::<_, Vec<u8>>(3).as_slice())
            .map_err(|_| configuration_error())?;
        if request.target.as_ref() != Some(&target)
            || request.config_hash != snapshot.revision.config_hash
        {
            return Err(configuration_error());
        }
        let now = journal::database_now(&mut tx)?;
        journal::exact_live_lease_expiry(
            &mut tx,
            key,
            &operation,
            generation,
            &lease.worker_id,
            fence,
            now,
        )?
        .ok_or_else(configuration_error)?;
        check()?;
        tx.commit().map_err(|_| configuration_error())?;
        return Ok(request);
    }
    let command = increasing(prior.as_ref().map(|row| row.get(0)), Uuid::now_v7())?;
    check()?;
    let request = proto::RuntimeReconcileRequest {
        schema_version: 1,
        target: Some(target),
        operation_id: operation.to_string(),
        command_id: command.to_string(),
        config_hash: snapshot.revision.config_hash,
    };
    tx.execute("INSERT INTO mcp_proxy_runtime_attempts (workspace_id,namespace_id,proxy_id,last_command_id,
        operation_id,fencing_token,request_bytes,outcome_event_id,uncertain_event_id,event_time_micros)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(workspace_id,namespace_id,proxy_id)
        DO UPDATE SET last_command_id=$4,operation_id=$5,fencing_token=$6,request_bytes=$7,
        outcome_event_id=$8,uncertain_event_id=$9,event_time_micros=$10,response_bytes=NULL",
        &[&scope.workspace_id,&scope.namespace_id,proxy_id.as_uuid(),&command,&operation,&fence,&request.encode_to_vec(),
            &Uuid::now_v7(),&Uuid::now_v7(),&now]).map_err(|_| configuration_error())?;
    let now = journal::database_now(&mut tx)?;
    journal::exact_live_lease_expiry(
        &mut tx,
        key,
        &operation,
        generation,
        &lease.worker_id,
        fence,
        now,
    )?
    .ok_or_else(configuration_error)?;
    check()?;
    tx.commit().map_err(|_| configuration_error())?;
    Ok(request)
}

fn increasing(prior: Option<Uuid>, candidate: Uuid) -> Result<Uuid, ProxyError> {
    let Some(prior) = prior.filter(|prior| *prior >= candidate) else {
        return Ok(candidate);
    };
    let n = prior.as_u128();
    let payload = ((n >> 80) << 74) | (((n >> 64) & 0xfff) << 62) | (n & ((1u128 << 62) - 1));
    let next = payload
        .checked_add(1)
        .filter(|n| *n < 1u128 << 122)
        .ok_or_else(configuration_error)?;
    Ok(Uuid::from_u128(
        ((next >> 74) << 80)
            | (7u128 << 76)
            | (((next >> 62) & 0xfff) << 64)
            | (2u128 << 62)
            | (next & ((1u128 << 62) - 1)),
    ))
}
