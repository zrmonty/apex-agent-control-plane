use super::*;
use prost::Message;

pub(super) fn reserve<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
    input: &ManagedCallReservation,
) -> Result<ManagedCallAdmission, ProxyError> {
    let (deployment, applied_until) = guard::admittable(tx, key, &input.binding)?;
    let configuration = proto::RuntimeConfiguration::decode(
        deployment
            .get::<_, Vec<u8>>("configuration_bytes")
            .as_slice(),
    )
    .map_err(|_| refused())?;
    let spec = crate::proxy::ProxySpec::try_from(configuration.spec.ok_or_else(refused)?)?;
    let limits = &spec.governance_binding;
    let epoch: i64 = deployment.get("epoch");
    let now = tx.now()?;
    let old = tx.query(
        "SELECT * FROM mcp_proxy_call_admissions WHERE call_id=$1",
        &[&input.call_id],
    )?;
    if let Some(row) = old.first() {
        if row.get::<_, Uuid>("proxy_id") != *key.proxy.as_uuid()
            || row.get::<_, Uuid>("instance_id") != key.instance
            || row.get::<_, Vec<u8>>("semantic_sha256") != input.semantic_sha256
            || row.get::<_, String>("policy_id") != input.policy_id
            || row.get::<_, String>("policy_revision") != input.policy_revision.to_string()
        {
            return Err(ProxyError::new(
                "MANAGED_ADMISSION_CONFLICT",
                "Managed call identity conflicts.",
            ));
        }
        if row.get::<_, bool>("released") || row.get::<_, i64>("epoch") != epoch {
            return Err(refused());
        }
        return grant(tx, row, applied_until);
    }
    if limits.policy_id != input.policy_id {
        return Err(refused());
    }
    let minute = now / 60_000_000;
    let day = now / 86_400_000_000;
    tx.execute("INSERT INTO mcp_proxy_admission_counters(proxy_id,minute_bucket,minute_used,day_bucket,day_used,active_calls,total_admissions) VALUES($1,$2,0,$3,0,0,0) ON CONFLICT DO NOTHING", &[key.proxy.as_uuid(),&minute,&day])?;
    let changed=tx.execute("UPDATE mcp_proxy_admission_counters SET minute_bucket=$2,minute_used=CASE WHEN minute_bucket<$2 THEN 1 ELSE minute_used+1 END,day_bucket=$3,day_used=CASE WHEN day_bucket<$3 THEN 1 ELSE day_used+1 END,active_calls=active_calls+1,total_admissions=total_admissions+1 WHERE proxy_id=$1 AND minute_bucket<=$2 AND day_bucket<=$3 AND (minute_bucket<$2 OR minute_used<$4) AND (day_bucket<$3 OR day_used<$5) AND active_calls<$6 AND total_admissions<1000000", &[key.proxy.as_uuid(),&minute,&day,&i64::from(limits.rate_limit_per_minute),&i64::from(limits.budget_limit_per_day),&i64::from(limits.concurrency_limit.min(1024))])?;
    if changed != 1 {
        return Err(ProxyError::new(
            "MANAGED_ADMISSION_LIMIT",
            "Managed call capacity unavailable.",
        ));
    }
    let until = now
        .checked_add(10_000_000)
        .ok_or_else(refused)?
        .min(applied_until);
    let row=tx.one("INSERT INTO mcp_proxy_call_admissions(call_id,admission_id,proxy_id,instance_id,semantic_sha256,policy_id,policy_revision,epoch,issued_at,valid_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *", &[&input.call_id,&Uuid::now_v7(),key.proxy.as_uuid(),&key.instance,&&input.semantic_sha256[..],&input.policy_id,&input.policy_revision.to_string(),&epoch,&now,&until])?;
    grant(tx, &row, applied_until)
}

fn grant<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    row: &postgres::Row,
    applied_until: i64,
) -> Result<ManagedCallAdmission, ProxyError> {
    let expiry: i64 = row.get("valid_until");
    let until = expiry.min(applied_until);
    tx.require_valid_until(until);
    let remaining = until
        .checked_sub(tx.now()?)
        .filter(|v| *v > 0 && *v <= 10_000_000)
        .ok_or_else(refused)?;
    Ok(ManagedCallAdmission {
        admission_id: row.get("admission_id"),
        call_id: row.get("call_id"),
        epoch: u64::try_from(row.get::<_, i64>("epoch")).map_err(|_| refused())?,
        policy_revision: row
            .get::<_, String>("policy_revision")
            .parse()
            .map_err(|_| refused())?,
        expires_at_unix_us: u64::try_from(expiry).map_err(|_| refused())?,
        valid_for_us: u64::try_from(remaining).map_err(|_| refused())?,
    })
}
