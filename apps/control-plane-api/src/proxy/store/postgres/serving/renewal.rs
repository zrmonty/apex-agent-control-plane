//! Server interval uses DB time; client owner must use original local start.
use super::*;

pub(super) fn renew<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
    input: &proto::ManagedDeploymentRenewal,
) -> Result<proto::ManagedDeploymentGrant, ProxyError> {
    let binding = input.binding.as_ref().ok_or_else(refused)?;
    let mut deployment = tx.deployment(key, binding)?;
    let sequence = positive(input.renewal_sequence)?;
    let highest: i64 = deployment.get("highest_sequence");
    // Never issue new PREPARE/SERVE after a persisted Pause/Retire, including if
    // the lifecycle worker has not yet called the explicit withdrawal seam.
    if tx.locked.get::<_, &str>(2) != "serving" {
        transitions::close_all(tx, key)?;
        deployment = tx.deployment(key, binding)?;
    }
    let existing = tx.query(
        "SELECT * FROM mcp_proxy_grant_decisions WHERE instance_id=$1 AND sequence=$2",
        &[&key.instance, &sequence],
    )?;
    if sequence <= highest {
        let row = existing.first().ok_or_else(refused)?;
        if row.get::<_, Vec<u8>>("request_bytes") != input.encode_to_vec()
            || row.get::<_, i64>("epoch") != deployment.get::<_, i64>("epoch")
            || row.get::<_, i32>("mode") != deployment.get::<_, i32>("mode")
        {
            return Err(refused());
        }
        eligible(tx, key, binding, deployment.get("mode"))?;
        return grant(tx, binding, input, row);
    }
    if let Some(applied) = &input.applied {
        acknowledge(tx, key, &deployment, applied)?;
    }
    let mode: i32 = deployment.get("mode");
    eligible(tx, key, binding, mode)?;
    if mode == 2 && deployment.get::<_, Option<Uuid>>("selected_instance") != Some(key.instance) {
        return Err(refused());
    }
    let now = tx.now()?;
    let until = now.checked_add(10_000_000).ok_or_else(refused)?;
    let epoch: i64 = deployment.get("epoch");
    let row = tx.one("INSERT INTO mcp_proxy_grant_decisions(instance_id,sequence,nonce,request_bytes,decision_id,epoch,mode,issued_at,valid_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *", &[&key.instance,&sequence,&input.nonce,&input.encode_to_vec(),&Uuid::now_v7(),&epoch,&mode,&now,&until])?;
    tx.execute("UPDATE mcp_proxy_deployments SET highest_sequence=$2,last_serve_sequence=CASE WHEN $3=2 THEN $2 ELSE last_serve_sequence END WHERE instance_id=$1", &[&key.instance,&sequence,&mode])?;
    // Last acknowledged decision remains known even through arbitrarily many
    // lost replies. The other 63 slots retain the newest issued decisions.
    tx.execute("DELETE FROM mcp_proxy_grant_decisions WHERE instance_id=$1 AND sequence NOT IN (SELECT sequence FROM mcp_proxy_grant_decisions WHERE instance_id=$1 AND sequence<>(SELECT applied_sequence FROM mcp_proxy_deployments WHERE instance_id=$1) ORDER BY sequence DESC LIMIT 63) AND sequence<>(SELECT applied_sequence FROM mcp_proxy_deployments WHERE instance_id=$1)", &[&key.instance])?;
    grant(tx, binding, input, &row)
}

fn grant<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    binding: &proto::ManagedDeploymentBinding,
    input: &proto::ManagedDeploymentRenewal,
    row: &postgres::Row,
) -> Result<proto::ManagedDeploymentGrant, ProxyError> {
    tx.require_valid_until(row.get("valid_until"));
    let remaining = row
        .get::<_, i64>("valid_until")
        .checked_sub(tx.now()?)
        .filter(|v| *v > 0 && *v <= 10_000_000)
        .ok_or_else(refused)?;
    Ok(proto::ManagedDeploymentGrant {
        binding: Some(binding.clone()),
        nonce: input.nonce.clone(),
        decision_id: row.get::<_, Uuid>("decision_id").to_string(),
        epoch: u64::try_from(row.get::<_, i64>("epoch")).map_err(|_| refused())?,
        mode: row.get("mode"),
        valid_for_us: u64::try_from(remaining).map_err(|_| refused())?,
        renewal_sequence: input.renewal_sequence,
    })
}

fn acknowledge<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
    deployment: &postgres::Row,
    ack: &proto::ManagedGrantAcknowledgement,
) -> Result<(), ProxyError> {
    let decision = journal::request_uuid(&ack.decision_id)?;
    let row = tx.one("SELECT sequence,epoch,mode FROM mcp_proxy_grant_decisions WHERE instance_id=$1 AND decision_id=$2", &[&key.instance,&decision])?;
    let sequence: i64 = row.get(0);
    let mode: i32 = row.get(2);
    if row.get::<_, i64>(1) != positive(ack.epoch)?
        || sequence > deployment.get::<_, i64>("highest_sequence")
        || (ack.admitting && mode != 2)
    {
        return Err(refused());
    }
    let progress: i64 = deployment.get("applied_sequence");
    if sequence < progress {
        return Ok(());
    } // Known stale acknowledgement cannot change physical state.
    if deployment.get::<_, bool>("terminated") {
        return Ok(());
    }
    if sequence == progress
        && mode == 3
        && i64::from(ack.active_calls) > deployment.get::<_, i64>("active_calls")
    {
        return Err(refused());
    }
    tx.execute("UPDATE mcp_proxy_deployments SET applied_sequence=$2,applied_mode=$3,admitting=$4,active_calls=$5 WHERE instance_id=$1", &[&key.instance,&sequence,&mode,&ack.admitting,&i64::from(ack.active_calls)])?;
    if mode != 1 || ack.admitting || ack.active_calls != 0 {
        // Accepted physical progress can contradict a previous probe. Later
        // quiescence must obtain a new probe, not resurrect that observation.
        tx.execute("UPDATE mcp_proxy_deployments SET readiness_id=NULL,readiness_bytes=NULL,readiness_until=0,readiness_fence=0 WHERE instance_id=$1", &[&key.instance])?;
    }
    Ok(())
}

pub(in crate::proxy::store::postgres) fn eligible<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
    binding: &proto::ManagedDeploymentBinding,
    mode: i32,
) -> Result<(), ProxyError> {
    if mode == 3 {
        return Ok(());
    } // Cleanup remains possible for ineligible publication.
    let target = binding.target.as_ref().ok_or_else(refused)?;
    if tx.locked.get::<_, &str>(2) != "serving" {
        return Err(refused());
    }
    if mode == 1
        && (tx.locked.get::<_, i64>(1) != positive(target.generation)?
            || tx.locked.get::<_, Option<Uuid>>(0)
                != Some(journal::request_uuid(&target.revision_id)?))
    {
        return Err(refused());
    }
    let row = tx.one("SELECT spec_json,config_hash FROM mcp_proxy_revisions WHERE proxy_id=$1 AND revision_id=$2 AND is_published", &[key.proxy.as_uuid(),&journal::request_uuid(&target.revision_id)?])?;
    let spec = crate::proxy::ProxySpec::try_from(
        serde_json::from_str::<proto::McpProxySpec>(row.get::<_, &str>(0))
            .map_err(|_| refused())?,
    )?;
    if row.get::<_, &str>(1) != binding.config_hash
        || super::super::super::shared::hash_hex(
            super::super::super::shared::spec_json(&spec).as_bytes(),
        ) != binding.config_hash
    {
        return Err(refused());
    }
    super::super::super::publish_capabilities::validate_publish_capabilities(&spec)
}
