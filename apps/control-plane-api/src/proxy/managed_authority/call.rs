//! Pure interpretation of immutable published config, not transport or admission.
use super::Refused;
use crate::{GovernanceConfig, proto};
use prost::Message;
use sha2::{Digest, Sha256};

pub(super) struct Evaluation {
    pub decision: proto::GovernanceAuthorizationDecision,
    pub policy_revision: u64,
    pub semantic_sha256: [u8; 32],
}

pub(super) fn evaluate(
    input: &proto::ManagedCallAuthorizationRequest,
    config: &proto::RuntimeConfiguration,
    evidence_agent: &str,
    policy: &GovernanceConfig,
) -> Result<Evaluation, Refused> {
    let binding = input.binding.as_ref().ok_or(Refused)?;
    let target = binding.target.as_ref().ok_or(Refused)?;
    let scope = input.scope.as_ref().ok_or(Refused)?;
    let caller = input.caller.as_ref().ok_or(Refused)?;
    if input.encoded_len() > 16_384
        || !apex_domain::is_lowercase_uuidv7(&input.call_id)
        || !input.approval_id.is_empty()
        || super::profile::digest(&input.arguments_hash).is_err()
        || caller.agent_id != evidence_agent
        || scope.workspace_id != config.workspace_id
        || scope.namespace_id != config.namespace_id
        || input.proxy_id != config.proxy_id
        || input.revision_id != config.revision_id
        || input.generation != config.generation
        || target.workspace_id != scope.workspace_id
        || target.namespace_id != scope.namespace_id
        || target.proxy_id != input.proxy_id
        || target.revision_id != input.revision_id
        || target.generation != input.generation
        || binding.config_hash != config.config_hash
    {
        return Err(Refused);
    }
    let spec = config.spec.as_ref().ok_or(Refused)?;
    let governance = spec.governance_binding.as_ref().ok_or(Refused)?;
    let snapshot = policy.snapshot(scope.clone()).map_err(|_| Refused)?;
    if governance.policy_id != snapshot.policy_id
        || governance.approval_mode != "none"
        || !spec.cli_profiles.is_empty()
        || input.classification != governance.data_classification
    {
        return Err(Refused);
    }
    let mut tools = spec
        .exposed_tools
        .iter()
        .filter(|tool| tool.alias == input.tool_alias);
    let tool = tools.next().ok_or(Refused)?;
    if tools.next().is_some()
        || tool.classification != proto::McpProxyToolClassification::Read as i32
        || tool.tool_name != "portfolio.read"
        || tool.alias != "portfolio.read"
        || input.action != "read"
    {
        return Err(Refused);
    }
    let mut upstreams = spec
        .upstreams
        .iter()
        .filter(|upstream| upstream.upstream_id == tool.upstream_id);
    let upstream = upstreams.next().ok_or(Refused)?;
    if upstreams.next().is_some()
        || upstream.transport != proto::McpProxyTransport::StreamableHttp as i32
    {
        return Err(Refused);
    }
    let decision = policy
        .evaluate(proto::GovernanceAuthorizationRequest {
            caller: Some(caller.clone()),
            scope: Some(scope.clone()),
            tool: tool.tool_name.clone(),
            action: "read".into(),
            resource: input.resource.clone(),
            classification: governance.data_classification.clone(),
            trace: input.trace.clone(),
        })
        .map_err(|_| Refused)?;
    // Canonical typed protobuf has no maps here. Include every request field,
    // exact deployment and resolved upstream/tool, not merely the argument hash.
    let mut hash = Sha256::new();
    for part in [
        b"apex-managed-call-v1".as_slice(),
        &input.encode_to_vec(),
        upstream.upstream_id.as_bytes(),
        tool.tool_name.as_bytes(),
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    Ok(Evaluation {
        decision,
        policy_revision: snapshot.revision,
        semantic_sha256: hash.finalize().into(),
    })
}

#[cfg(test)]
mod tests;
