use crate::proxy::{ApprovalMode, ProxyError, ProxySpec, ProxyToolClassification, ProxyTransport};

/// Publication-only gate for the staged read-only portfolio execution path.
///
/// Call on the selected stored draft inside the store's transaction/mutex, after
/// replay and conflict checks and before constructing a published revision.
/// Draft validation remains independent. This grants no runtime admission,
/// egress, schema, approval, or deployment authority.
pub(super) fn validate_publish_capabilities(spec: &ProxySpec) -> Result<(), ProxyError> {
    let ingress = &spec.ingress;
    let runtime = &spec.runtime_profile;
    let supported = ingress.transport == ProxyTransport::StreamableHttp
        && ingress.protocol_revision == "2025-11-25"
        && ingress.inbound_authentication_required
        && spec
            .upstreams
            .iter()
            .all(|upstream| upstream.transport == ProxyTransport::StreamableHttp)
        && spec.cli_profiles.is_empty()
        && spec.exposed_tools.iter().all(|tool| {
            tool.tool_name == "portfolio.read"
                && tool.alias == "portfolio.read"
                && tool.classification == ProxyToolClassification::Read
        })
        && spec.governance_binding.approval_mode == ApprovalMode::None
        && runtime.rootless
        && runtime.filesystem_policy == "read-only-rootfs"
        && runtime.network_policy == "default-deny";

    if !supported {
        return Err(ProxyError::invalid_proxy_spec(
            "Publication supports only authenticated Streamable HTTP 2025-11-25, read-only portfolio.read without CLI or approvals, and confined runtime policies.",
        ));
    }
    Ok(())
}
