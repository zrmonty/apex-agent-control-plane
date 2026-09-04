use serde_json::json;

use crate::proxy::{ProxySpec, SecretRef};

pub(super) fn spec_json(spec: &ProxySpec) -> String {
    json!({
        "ingress": {
            "transport": transport_to_wire(spec.ingress.transport),
            "exposure": exposure_to_wire(spec.ingress.exposure),
            "host": spec.ingress.host,
            "path": spec.ingress.path,
            "allowed_origins": spec.ingress.allowed_origins,
            "protocol_revision": spec.ingress.protocol_revision,
            "inbound_authentication_required": spec.ingress.inbound_authentication_required
        },
        "upstreams": spec.upstreams.iter().map(|upstream| json!({
            "upstream_id": upstream.upstream_id,
            "display_name": upstream.display_name,
            "transport": transport_to_wire(upstream.transport),
            "endpoint_or_command_ref": upstream.endpoint_or_command_ref,
            "credential_ref": upstream.credential_ref.as_ref().map(SecretRef::as_str).unwrap_or_default(),
            "secret_refs": upstream.secret_refs.iter().map(SecretRef::as_str).collect::<Vec<_>>(),
            "server_identity": upstream.server_identity,
            "tool_catalog_hash": upstream.tool_catalog_hash.as_deref().unwrap_or_default()
        })).collect::<Vec<_>>(),
        "exposed_tools": spec.exposed_tools.iter().map(|tool| json!({
            "upstream_id": tool.upstream_id,
            "tool_name": tool.tool_name,
            "alias": tool.alias,
            "classification": classification_to_wire(tool.classification)
        })).collect::<Vec<_>>(),
        "cli_profiles": spec.cli_profiles.iter().map(|profile| json!({
            "profile_id": profile.profile_id,
            "executable_ref": profile.executable_ref,
            "executable_digest": profile.executable_digest,
            "argv_template": profile.fixed_argv,
            "argv_schema": {
                "fields": profile.argv_schema.fields.iter().map(|field| json!({
                    "name": field.name,
                    "required": field.required
                })).collect::<Vec<_>>()
            },
            "environment_allowlist": profile.environment_allowlist,
            "secret_refs": profile.secret_refs.iter().map(SecretRef::as_str).collect::<Vec<_>>(),
            "working_directory": profile.working_directory,
            "filesystem_policy": profile.filesystem_policy,
            "network_policy": profile.network_policy,
            "shell": profile.shell,
            "timeout_ms": profile.timeout_ms,
            "max_output_bytes": profile.max_output_bytes,
            "allowed_exit_codes": profile.allowed_exit_codes
        })).collect::<Vec<_>>(),
        "auth_bindings": spec.auth_bindings.iter().map(|binding| json!({
            "binding_id": binding.binding_id,
            "inbound_subject": binding.inbound_subject,
            "outbound_credential_ref": binding.outbound_credential_ref.as_ref().map(SecretRef::as_str).unwrap_or_default(),
            "scopes": binding.scopes
        })).collect::<Vec<_>>(),
        "governance_binding": {
            "policy_id": spec.governance_binding.policy_id,
            "approval_mode": approval_mode_to_wire(spec.governance_binding.approval_mode),
            "data_classification": data_classification_to_wire(spec.governance_binding.data_classification),
            "rate_limit": format!("{}/m", spec.governance_binding.rate_limit_per_minute),
            "concurrency_limit": spec.governance_binding.concurrency_limit.to_string(),
            "budget": format!("{}/d", spec.governance_binding.budget_limit_per_day),
            "retention": format!("{}d", spec.governance_binding.retention_days)
        },
        "runtime_profile": {
            "image_digest": spec.runtime_profile.image_digest,
            "cpu_limit": spec.runtime_profile.cpu_limit,
            "memory_limit": spec.runtime_profile.memory_limit,
            "network_policy": spec.runtime_profile.network_policy,
            "filesystem_policy": spec.runtime_profile.filesystem_policy,
            "rootless": spec.runtime_profile.rootless,
            "egress_destinations": spec.runtime_profile.network.destinations.iter().map(|destination| match destination {
                crate::proxy::EgressDestination::Https { host, port, private_allowance } => json!({
                    "host": host,
                    "port": port,
                    "private_destination_allowance": private_allowance_to_wire(*private_allowance)
                })
            }).collect::<Vec<_>>()
        }
    })
    .to_string()
}

fn transport_to_wire(value: crate::proxy::ProxyTransport) -> i32 {
    match value {
        crate::proxy::ProxyTransport::StreamableHttp => 1,
        crate::proxy::ProxyTransport::Stdio => 2,
    }
}

fn exposure_to_wire(value: crate::proxy::ProxyExposure) -> i32 {
    match value {
        crate::proxy::ProxyExposure::Private => 1,
        crate::proxy::ProxyExposure::External => 2,
    }
}

fn classification_to_wire(value: crate::proxy::ProxyToolClassification) -> i32 {
    match value {
        crate::proxy::ProxyToolClassification::Read => 1,
        crate::proxy::ProxyToolClassification::BusinessWrite => 2,
        crate::proxy::ProxyToolClassification::HighImpact => 3,
    }
}

fn approval_mode_to_wire(value: crate::proxy::ApprovalMode) -> &'static str {
    match value {
        crate::proxy::ApprovalMode::None => "none",
        crate::proxy::ApprovalMode::Operator => "operator",
        crate::proxy::ApprovalMode::DualOperator => "dual-operator",
    }
}

fn data_classification_to_wire(value: crate::proxy::DataClassification) -> &'static str {
    match value {
        crate::proxy::DataClassification::Public => "public",
        crate::proxy::DataClassification::Internal => "internal",
        crate::proxy::DataClassification::Confidential => "confidential",
        crate::proxy::DataClassification::Restricted => "restricted",
    }
}

fn private_allowance_to_wire(value: crate::proxy::PrivateDestinationAllowance) -> i32 {
    match value {
        crate::proxy::PrivateDestinationAllowance::Denied => 1,
        crate::proxy::PrivateDestinationAllowance::Allowed => 2,
    }
}
