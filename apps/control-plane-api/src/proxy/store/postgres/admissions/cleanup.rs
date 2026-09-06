use super::*;

pub(super) fn complete<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
    binding: &proto::ManagedDeploymentBinding,
    admission: Uuid,
    call: Uuid,
) -> Result<(), ProxyError> {
    tx.deployment(key, binding)?;
    let row=tx.one("SELECT released FROM mcp_proxy_call_admissions WHERE call_id=$1 AND admission_id=$2 AND proxy_id=$3 AND instance_id=$4", &[&call,&admission,key.proxy.as_uuid(),&key.instance])?;
    if row.get::<_, bool>(0) {
        return Ok(());
    }
    tx.execute(
        "UPDATE mcp_proxy_call_admissions SET released=TRUE WHERE call_id=$1",
        &[&call],
    )?;
    subtract(tx, key, 1)
}

pub(super) fn terminated<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
    binding: &proto::ManagedDeploymentBinding,
) -> Result<u64, ProxyError> {
    let deployment = tx.deployment(key, binding)?;
    if !deployment.get::<_, bool>("terminated") {
        return Err(refused());
    }
    let count=tx.execute("UPDATE mcp_proxy_call_admissions SET released=TRUE WHERE proxy_id=$1 AND instance_id=$2 AND NOT released", &[key.proxy.as_uuid(),&key.instance])?;
    if count > 0 {
        subtract(tx, key, i64::try_from(count).map_err(|_| refused())?)?;
    }
    Ok(count)
}

fn subtract<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
    count: i64,
) -> Result<(), ProxyError> {
    if tx.execute("UPDATE mcp_proxy_admission_counters SET active_calls=active_calls-$2 WHERE proxy_id=$1 AND active_calls>=$2", &[key.proxy.as_uuid(),&count])?!=1 {return Err(refused());}
    Ok(())
}
