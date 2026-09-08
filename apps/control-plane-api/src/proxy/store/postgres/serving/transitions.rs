//! No route projection here. Selection still requires a later applied SERVE ack.
use super::*;

pub(super) fn candidate<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
    lease: &LeasedProxyOperation,
    binding: &proto::ManagedDeploymentBinding,
) -> Result<postgres::Row, ProxyError> {
    let row = tx.deployment(key, binding)?;
    let target = binding.target.as_ref().ok_or_else(refused)?;
    if row.get::<_, i32>("mode") != 1
        || row.get::<_, bool>("terminated")
        || lease.operation.generation != target.generation
        || lease.operation.revision_id != target.revision_id
        || lease.operation.desired_state != proto::ProxyDesiredState::Serving as i32
    {
        return Err(refused());
    }
    renewal::eligible(tx, key, binding, 1)?;
    Ok(row)
}

pub(super) fn applied_prepare_expiry<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
    row: &postgres::Row,
) -> Result<i64, ProxyError> {
    if row.get::<_, i32>("applied_mode") != 1
        || row.get::<_, bool>("admitting")
        || row.get::<_, i64>("active_calls") != 0
    {
        return Err(refused());
    }
    let now = tx.now()?;
    let grant = tx.one("SELECT valid_until FROM mcp_proxy_grant_decisions WHERE instance_id=$1 AND sequence=$2 AND mode=1 AND valid_until>$3", &[&key.instance,&row.get::<_,i64>("applied_sequence"),&now])?;
    Ok(grant.get(0))
}

pub(super) fn readiness<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
    lease: &LeasedProxyOperation,
    binding: &proto::ManagedDeploymentBinding,
    observation: &CandidateReadiness,
    local_now: &impl Fn() -> std::time::Instant,
) -> Result<Uuid, ProxyError> {
    let report = &observation.report;
    let row = candidate(tx, key, lease, binding)?;
    let configuration = proto::RuntimeConfiguration::decode(
        row.get::<_, Vec<u8>>("configuration_bytes").as_slice(),
    )
    .map_err(|_| refused())?;
    if observation.admitting
        || observation.active_calls != 0
        || !report.live
        || !report.ready
        || report.target != binding.target
        || report.config_hash != binding.config_hash
        || report.process_instance_id != binding.process_instance_id
        || report.launch_context_hash != binding.launch_context_hash
        || report.runtime_manifest_hash != configuration.runtime_manifest_hash
        || positive(report.observed_at_unix_us).is_err()
        || report.encoded_len() > 16384
        || report.stages.len() > 32
        || report.checks.len() != 9
        || !(1..=9).all(|id| {
            report
                .checks
                .iter()
                .filter(|c| c.id == id && c.status == 2 && c.reason == 1)
                .count()
                == 1
        })
    {
        return Err(refused());
    }
    // Sample DB time BEFORE reading the remaining local lifetime. SQL latency
    // only shortens the persisted bound; no subtraction between host clocks.
    let applied_until = applied_prepare_expiry(tx, key, &row)?;
    let now = tx.now()?;
    let remaining_us = observation.remaining_us(local_now())?;
    let id = Uuid::now_v7();
    let until = now
        .checked_add(remaining_us)
        .ok_or_else(refused)?
        .min(applied_until);
    tx.require_valid_until(until);
    tx.execute("UPDATE mcp_proxy_deployments SET readiness_id=$2,readiness_bytes=$3,readiness_until=$4,readiness_fence=$5 WHERE instance_id=$1", &[&key.instance,&id,&report.encode_to_vec(),&until,&positive(lease.fencing_token)?])?;
    Ok(id)
}

pub(super) fn select<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
    lease: &LeasedProxyOperation,
    binding: &proto::ManagedDeploymentBinding,
    readiness: Uuid,
) -> Result<u64, ProxyError> {
    let row = candidate(tx, key, lease, binding)?;
    if row.get::<_, Option<Uuid>>("selected_instance").is_some()
        || row.get::<_, Option<Uuid>>("readiness_id") != Some(readiness)
        || row.get::<_, i64>("readiness_fence") != positive(lease.fencing_token)?
        || row.get::<_, i64>("readiness_until") <= tx.now()?
    {
        return Err(refused());
    }
    // The shared proxy row lock excludes concurrent accepted acknowledgements.
    // Recheck current physical state, including rows from older checkpoints,
    // and keep its applied grant valid through the transaction finish check.
    let applied_until = applied_prepare_expiry(tx, key, &row)?;
    tx.require_valid_until(applied_until);
    let blockers = tx.query("SELECT 1 FROM mcp_proxy_deployments WHERE proxy_id=$1 AND instance_id<>$2 AND NOT terminated AND (mode=2 OR active_calls<>0 OR admitting OR (last_serve_sequence>0 AND NOT(mode=3 AND applied_mode=3 AND applied_sequence>last_serve_sequence))) LIMIT 1", &[key.proxy.as_uuid(),&key.instance])?;
    if !blockers.is_empty() {
        return Err(refused());
    }
    tx.require_valid_until(row.get("readiness_until"));
    let epoch = advance(tx, key, Some(key.instance))?;
    tx.execute("UPDATE mcp_proxy_deployments SET mode=2,readiness_id=NULL,readiness_bytes=NULL,readiness_until=0 WHERE instance_id=$1", &[&key.instance])?;
    Ok(epoch)
}

pub(super) fn withdraw<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
    lease: &LeasedProxyOperation,
    binding: &proto::ManagedDeploymentBinding,
    reason: Withdrawal,
) -> Result<u64, ProxyError> {
    let row = tx.deployment(key, binding)?;
    let desired = match reason {
        Withdrawal::Replacement => proto::ProxyDesiredState::Serving,
        Withdrawal::Pause => proto::ProxyDesiredState::Paused,
        Withdrawal::Retire => proto::ProxyDesiredState::Retired,
    };
    if lease.operation.desired_state != desired as i32 {
        return Err(refused());
    }
    if matches!(reason, Withdrawal::Pause | Withdrawal::Retire) {
        return close_all(tx, key);
    }
    if row.get::<_, i32>("mode") == 3 {
        return u64::try_from(row.get::<_, i64>("epoch")).map_err(|_| refused());
    }
    if row.get::<_, Option<Uuid>>("selected_instance") != Some(key.instance) {
        return Err(refused());
    }
    let epoch = advance(tx, key, None)?;
    tx.execute("UPDATE mcp_proxy_deployments SET mode=3,readiness_id=NULL,readiness_bytes=NULL,readiness_until=0 WHERE instance_id=$1", &[&key.instance])?;
    Ok(epoch)
}

pub(super) fn close_all<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
) -> Result<u64, ProxyError> {
    let live = tx.query(
        "SELECT 1 FROM mcp_proxy_deployments WHERE proxy_id=$1 AND mode<>3 LIMIT 1",
        &[key.proxy.as_uuid()],
    )?;
    if live.is_empty() {
        return u64::try_from(
            tx.one(
                "SELECT epoch FROM mcp_proxy_serving_selection WHERE proxy_id=$1",
                &[key.proxy.as_uuid()],
            )?
            .get::<_, i64>(0),
        )
        .map_err(|_| refused());
    }
    let epoch = advance(tx, key, None)?;
    tx.execute("UPDATE mcp_proxy_deployments SET mode=3,readiness_id=NULL,readiness_bytes=NULL,readiness_until=0 WHERE proxy_id=$1 AND mode<>3", &[key.proxy.as_uuid()])?;
    Ok(epoch)
}

fn advance<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
    selected: Option<Uuid>,
) -> Result<u64, ProxyError> {
    let row = tx.one("UPDATE mcp_proxy_serving_selection SET epoch=epoch+1,selected_instance=$2 WHERE proxy_id=$1 AND epoch<9223372036854775807 RETURNING epoch", &[key.proxy.as_uuid(),&selected])?;
    u64::try_from(row.get::<_, i64>(0)).map_err(|_| refused())
}

pub(super) fn terminate<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
    binding: &proto::ManagedDeploymentBinding,
) -> Result<(), ProxyError> {
    let row = tx.deployment(key, binding)?;
    if row.get::<_, bool>("terminated") {
        return Ok(());
    }
    if row.get::<_, Option<Uuid>>("selected_instance") == Some(key.instance) {
        advance(tx, key, None)?;
    }
    tx.execute("UPDATE mcp_proxy_deployments SET mode=3,terminated=TRUE,admitting=FALSE,active_calls=0,readiness_id=NULL,readiness_bytes=NULL,readiness_until=0 WHERE instance_id=$1", &[&key.instance])?;
    Ok(())
}
