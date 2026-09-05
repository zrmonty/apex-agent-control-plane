//! Separate bounded resolution surface, never an execution permit.
use super::{RuntimeAuthorityError, RuntimeAuthorityService};
use crate::proto;

/// Bound requests to 4 KiB and complete resolution replies to 264 KiB.
pub fn bounded_runtime_deployment_service_server(
    service: RuntimeAuthorityService,
) -> proto::runtime_deployment_service_server::RuntimeDeploymentServiceServer<RuntimeAuthorityService>
{
    proto::runtime_deployment_service_server::RuntimeDeploymentServiceServer::new(service)
        .max_decoding_message_size(4096)
        .max_encoding_message_size(270_336)
}

#[tonic::async_trait]
impl proto::runtime_deployment_service_server::RuntimeDeploymentService
    for RuntimeAuthorityService
{
    async fn resolve_runtime_deployment(
        &self,
        request: tonic::Request<proto::CheckRuntimeAuthorityRequest>,
    ) -> Result<tonic::Response<proto::RuntimeDeploymentSnapshot>, tonic::Status> {
        let observation = self.observe(request, true).await?;
        let (configuration, deployment_bindings_version) = observation
            .deployment
            .ok_or_else(|| RuntimeAuthorityError::Unavailable.status())?;
        let reply = proto::RuntimeDeploymentSnapshot {
            schema_version: 1,
            authority: Some(observation.authority),
            configuration: Some(configuration),
            deployment_bindings_version,
        };
        Ok(tonic::Response::new(reply))
    }
}
