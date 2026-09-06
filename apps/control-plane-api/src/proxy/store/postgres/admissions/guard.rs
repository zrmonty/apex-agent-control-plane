use super::*;

/// Point-in-time data under the exact proxy lock, never a transferable permit.
pub(super) fn admittable<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
    binding: &proto::ManagedDeploymentBinding,
) -> Result<(postgres::Row, i64), ProxyError> {
    let deployment = tx.deployment(key, binding)?;
    if deployment.get::<_, i32>("mode") != 2
        || deployment.get::<_, bool>("terminated")
        || deployment.get::<_, Option<Uuid>>("selected_instance") != Some(key.instance)
        || deployment.get::<_, i32>("applied_mode") != 2
        || !deployment.get::<_, bool>("admitting")
    {
        return Err(refused());
    }
    super::super::serving::renewal::eligible(tx, key, binding, 2)?;
    let now = tx.now()?;
    let applied=tx.one("SELECT valid_until FROM mcp_proxy_grant_decisions WHERE instance_id=$1 AND sequence=$2 AND epoch=$3 AND mode=2 AND valid_until>$4", &[&key.instance,&deployment.get::<_,i64>("applied_sequence"),&deployment.get::<_,i64>("epoch"),&now])?;
    let until = applied.get(0);
    tx.require_valid_until(until);
    Ok((deployment, until))
}
