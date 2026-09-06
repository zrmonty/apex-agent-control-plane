//! Exact stored credential binding and applied evidence, not authorization.
use super::*;

pub(in crate::proxy::store::postgres) fn read<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
    binding: &proto::ManagedDeploymentBinding,
) -> Result<DeploymentRecord, ProxyError> {
    let row = tx.deployment(key, binding)?;
    let sequence: i64 = row.get("applied_sequence");
    let applied = if sequence == 0 {
        None
    } else {
        let decision=tx.one("SELECT decision_id,epoch,mode,valid_until FROM mcp_proxy_grant_decisions WHERE instance_id=$1 AND sequence=$2",&[&key.instance,&sequence])?;
        Some(AppliedDecision {
            decision_id: decision.get(0),
            epoch: unsigned(decision.get(1))?,
            mode: proto::ManagedGrantMode::try_from(decision.get::<_, i32>(2))
                .map_err(|_| refused())?,
            sequence: unsigned(sequence)?,
            valid_until_unix_us: unsigned(decision.get(3))?,
            admitting: row.get("admitting"),
        })
    };
    Ok(DeploymentRecord {
        registration: DeploymentRegistration {
            binding: binding.clone(),
            configuration: proto::RuntimeConfiguration::decode(
                row.get::<_, Vec<u8>>("configuration_bytes").as_slice(),
            )
            .map_err(|_| refused())?,
            authority_profile_ref: row.get("profile_ref"),
            authority_profile_version: row.get("profile_version"),
            proof_sha256: row
                .get::<_, Vec<u8>>("proof_sha256")
                .try_into()
                .map_err(|_| refused())?,
        },
        epoch: unsigned(row.get("epoch"))?,
        mode: proto::ManagedGrantMode::try_from(row.get::<_, i32>("mode"))
            .map_err(|_| refused())?,
        selected_instance: row.get("selected_instance"),
        highest_sequence: unsigned(row.get("highest_sequence"))?,
        applied,
        active_calls: unsigned(row.get("active_calls"))?,
        terminated: row.get("terminated"),
    })
}

fn unsigned(value: i64) -> Result<u64, ProxyError> {
    u64::try_from(value).map_err(|_| refused())
}
