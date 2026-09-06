use super::transaction::digest;
use super::*;
use crate::proxy::{ProxyRevisionId, ProxySpec};

pub(super) fn register<F: Fn() -> Result<(), ProxyError>>(
    tx: &mut CheckedTransaction<'_, '_, F>,
    key: &BindingKey,
    lease: &LeasedProxyOperation,
    input: &DeploymentRegistration,
) -> Result<(), ProxyError> {
    let binding = &input.binding;
    let target = binding.target.as_ref().ok_or_else(refused)?;
    let config = &input.configuration;
    let config_bytes = config.encode_to_vec();
    if config_bytes.len() > 262144
        || binding.encoded_len() > 4096
        || !journal::bounded_identifier(&input.authority_profile_ref)
        || !journal::bounded_identifier(&input.authority_profile_version)
        || config.schema_version != 1
        || config.workspace_id != target.workspace_id
        || config.namespace_id != target.namespace_id
        || config.proxy_id != target.proxy_id
        || config.revision_id != target.revision_id
        || config.generation != target.generation
        || config.config_hash != binding.config_hash
        || !digest(&config.runtime_manifest_hash)
        || crate::proxy::runtime_manifest_hash(config)? != config.runtime_manifest_hash
        || lease.operation.desired_state != proto::ProxyDesiredState::Serving as i32
        || lease.operation.generation != target.generation
        || lease.operation.revision_id != target.revision_id
        || target.fencing_token > lease.fencing_token
    {
        return Err(refused());
    }
    let revision_id = ProxyRevisionId::new(&target.revision_id)?;
    // Exact scoped publication join; caller configuration alone is never evidence.
    let row = tx.one("SELECT r.spec_json,r.config_hash,r.is_published FROM mcp_proxy_revisions r JOIN mcp_proxies p ON p.proxy_id=r.proxy_id WHERE p.workspace_id=$1 AND p.namespace_id=$2 AND p.proxy_id=$3 AND r.revision_id=$4", &[&key.scope.workspace_id,&key.scope.namespace_id,key.proxy.as_uuid(),revision_id.as_uuid()])?;
    let spec = ProxySpec::try_from(
        serde_json::from_str::<proto::McpProxySpec>(row.get::<_, &str>(0))
            .map_err(|_| refused())?,
    )?;
    let config_spec = ProxySpec::try_from(config.spec.clone().ok_or_else(refused)?)?;
    if !row.get::<_, bool>(2)
        || row.get::<_, &str>(1) != binding.config_hash
        || spec != config_spec
        || super::super::super::shared::hash_hex(
            super::super::super::shared::spec_json(&spec).as_bytes(),
        ) != binding.config_hash
    {
        return Err(refused());
    }
    super::super::super::publish_capabilities::validate_publish_capabilities(&spec)?;
    let original = tx.one("SELECT operation_id,accepted_result FROM mcp_proxy_operations WHERE workspace_id=$1 AND namespace_id=$2 AND proxy_id=$3 AND revision_id=$4 AND generation=$5 AND desired_state='serving'", &[&key.scope.workspace_id,&key.scope.namespace_id,key.proxy.as_uuid(),revision_id.as_uuid(),&positive(target.generation)?])?;
    let op_id: Uuid = original.get(0);
    let accepted = proto::ProxyOperation::decode(original.get::<_, Vec<u8>>(1).as_slice())
        .map_err(|_| refused())?;
    if accepted.operation_id != op_id.to_string()
        || accepted.revision_id != target.revision_id
        || accepted.generation != target.generation
        || accepted.scope != lease.operation.scope
        || op_id != journal::request_uuid(&lease.operation.operation_id)?
    {
        return Err(refused());
    }
    let existing = tx.query(
        "SELECT * FROM mcp_proxy_deployments WHERE instance_id=$1",
        &[&key.instance],
    )?;
    if let Some(row) = existing.first() {
        if row.get::<_, Vec<u8>>("binding_bytes") != binding.encode_to_vec()
            || row.get::<_, Vec<u8>>("configuration_bytes") != config_bytes
            || row.get::<_, Vec<u8>>("proof_sha256") != input.proof_sha256
            || row.get::<_, &str>("profile_ref") != input.authority_profile_ref
            || row.get::<_, &str>("profile_version") != input.authority_profile_version
            || row.get::<_, Uuid>("original_operation") != op_id
        {
            return Err(refused());
        }
        return Ok(()); // Adoption preserves original bytes/fence, including CLOSED.
    }
    // Attempts are one mutable latest row: a current handoff may have replaced
    // the original request. Even an old request contains no original attestation.
    // No first enrollment of an unknown older launch from that metadata alone.
    if target.fencing_token != lease.fencing_token {
        return Err(refused());
    }
    tx.execute("INSERT INTO mcp_proxy_serving_selection(proxy_id,workspace_id,namespace_id,installation_id,epoch) VALUES($1,$2,$3,$4,1) ON CONFLICT DO NOTHING", &[key.proxy.as_uuid(),&key.scope.workspace_id,&key.scope.namespace_id,&key.installation])?;
    tx.one(
        "SELECT 1 FROM mcp_proxy_serving_selection WHERE proxy_id=$1 AND installation_id=$2",
        &[key.proxy.as_uuid(), &key.installation],
    )?;
    // Bound unresolved physical inventory; historical CLOSED identities remain
    // durable tombstones so an immutable process identity cannot be revived.
    let count: i64 = tx
        .one(
            "SELECT count(*) FROM mcp_proxy_deployments WHERE proxy_id=$1 AND mode<>3",
            &[key.proxy.as_uuid()],
        )?
        .get(0);
    if count >= 16 {
        return Err(refused());
    }
    tx.execute("INSERT INTO mcp_proxy_deployments(instance_id,proxy_id,binding_bytes,configuration_bytes,original_operation,profile_ref,profile_version,proof_sha256,mode) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1)", &[&key.instance,key.proxy.as_uuid(),&binding.encode_to_vec(),&config_bytes,&op_id,&input.authority_profile_ref,&input.authority_profile_version,&&input.proof_sha256[..]])?;
    Ok(())
}
