//! Agent callback: preserve actual TLS transport through online observation.
use super::{RuntimeAuthorityError, RuntimeAuthorityService, request::RequestClaims};
use crate::{
    proto,
    proxy::managed_authority::{ManagedAuthorityService, RegistrationInput},
};
use prost::Message;
use std::time::Instant;

#[derive(Clone)]
pub struct RuntimeDeploymentRegistryService {
    authority: RuntimeAuthorityService,
    managed: ManagedAuthorityService,
}

/// Install only alongside the explicit deployment catalog and managed owner.
/// The private facade has no constructor accepting synthetic transport evidence.
pub fn bounded_runtime_deployment_registry_server(
    authority: RuntimeAuthorityService,
    managed: ManagedAuthorityService,
) -> proto::runtime_deployment_registry_server::RuntimeDeploymentRegistryServer<
    RuntimeDeploymentRegistryService,
> {
    proto::runtime_deployment_registry_server::RuntimeDeploymentRegistryServer::new(
        RuntimeDeploymentRegistryService { authority, managed },
    )
    .max_decoding_message_size(24_576)
    .max_encoding_message_size(16_384)
}

#[tonic::async_trait]
impl proto::runtime_deployment_registry_server::RuntimeDeploymentRegistry
    for RuntimeDeploymentRegistryService
{
    async fn register_deployment(
        &self,
        request: tonic::Request<proto::RegisterRuntimeDeploymentRequest>,
    ) -> Result<tonic::Response<proto::RuntimeDeploymentRegistrationReceipt>, tonic::Status> {
        let started = Instant::now();
        if request.get_ref().encoded_len() > 24_576 {
            return Err(RuntimeAuthorityError::InvalidRequest.status());
        }
        let (metadata, extensions, input) = request.into_parts();
        let claims = input
            .authority
            .ok_or_else(|| RuntimeAuthorityError::InvalidRequest.status())?;
        let attestation = input
            .attestation
            .filter(|a| a.encoded_len() <= 16_384)
            .ok_or_else(|| RuntimeAuthorityError::InvalidRequest.status())?;
        // Retain the exact acceptor-supplied extensions, not a manufactured peer.
        let request = tonic::Request::from_parts(metadata, extensions, claims);
        let budget = RequestClaims::parse(&request)
            .map_err(RuntimeAuthorityError::status)?
            .budget;
        let observation = self.authority.observe(request, true).await?;
        super::lifecycle::check_elapsed(started, budget).map_err(RuntimeAuthorityError::status)?;
        let (configuration, deployment_bindings_version) = observation
            .deployment
            .ok_or_else(|| RuntimeAuthorityError::Unavailable.status())?;
        let recheck = std::sync::Arc::clone(&observation.recheck);
        let result = self
            .managed
            .register_agent(RegistrationInput {
                lease: observation.lease,
                authority: observation.authority,
                configuration,
                deployment_bindings_version,
                attestation,
                recheck_authority: observation.recheck,
                started,
                budget,
            })
            .await?;
        super::lifecycle::check_elapsed(started, budget).map_err(RuntimeAuthorityError::status)?;
        if !recheck() {
            return Err(RuntimeAuthorityError::Unavailable.status());
        }
        Ok(tonic::Response::new(result))
    }
}
