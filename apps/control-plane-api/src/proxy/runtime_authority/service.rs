use prost::Message;
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use super::{
    RuntimeAuthorityError,
    enrollment::{EnrollmentBinding, EnrollmentSelection},
    executor::{Client, Lookup},
    lifecycle::{Shared, check_elapsed},
    policy::SelectedPolicy,
    request::RequestClaims,
};
use crate::proto::{self, CheckRuntimeAuthorityRequest, RuntimeAuthoritySnapshot};
use crate::proxy::RuntimeOperationSnapshot;

/// Cloneable callback facade; private construction prevents bypassing startup.
/// Successful replies are point-in-time data, never permission for effects.
#[derive(Clone)]
pub struct RuntimeAuthorityService {
    client: Client<RuntimeOperationSnapshot>,
    shared: Arc<Shared>,
}

impl RuntimeAuthorityService {
    pub(super) fn new(client: Client<RuntimeOperationSnapshot>, shared: Arc<Shared>) -> Self {
        Self { client, shared }
    }
}

impl fmt::Debug for RuntimeAuthorityService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuntimeAuthorityService { [redacted] }")
    }
}

/// Bound both generated binary envelopes to 4,096 bytes.
/// The main-owned build selects the generated redacted codec; this wrapper
/// neither changes that codec nor grants enrollment or listener registration.
pub fn bounded_runtime_authority_service_server(
    service: RuntimeAuthorityService,
) -> proto::runtime_authority_service_server::RuntimeAuthorityServiceServer<RuntimeAuthorityService>
{
    proto::runtime_authority_service_server::RuntimeAuthorityServiceServer::new(service)
        .max_decoding_message_size(4096)
        .max_encoding_message_size(4096)
}

#[tonic::async_trait]
impl proto::runtime_authority_service_server::RuntimeAuthorityService for RuntimeAuthorityService {
    async fn check_runtime_authority(
        &self,
        request: tonic::Request<CheckRuntimeAuthorityRequest>,
    ) -> Result<tonic::Response<RuntimeAuthoritySnapshot>, tonic::Status> {
        let started = Instant::now();
        let claims = RequestClaims::parse(&request).map_err(RuntimeAuthorityError::status)?;
        let budget = claims.budget;
        check_elapsed(started, budget).map_err(RuntimeAuthorityError::status)?;
        let selected = self
            .shared
            .current()
            .map_err(RuntimeAuthorityError::status)?;
        let worker_id = authorize(&selected, &request)?.1.worker_id.to_owned();
        let lookup = Lookup {
            claims,
            selected: Arc::clone(&selected),
            worker_id,
            started,
        };
        let result = self.client.request(lookup).await;
        // Re-evaluate the original transport Request, not a manufactured TLS view,
        // including after store errors. No locks or borrowed DB owners cross await.
        check_elapsed(started, budget).map_err(RuntimeAuthorityError::status)?;
        self.shared
            .recheck(&selected)
            .map_err(RuntimeAuthorityError::status)?;
        let (pair, binding) = authorize(&selected, &request)?;
        let stored = result?;
        let remaining = stored
            .lease_expires_at_unix_us
            .checked_sub(stored.checked_at_unix_us)
            .filter(|remaining| *remaining > 0)
            .ok_or_else(not_current)?;
        // Conservative lease-to-handoff bound uses only a local monotonic span
        // against the DB's own interval, never a cross-host wall-clock comparison.
        check_elapsed(started, Duration::from_micros(remaining)).map_err(|_| not_current())?;
        let claims = request.get_ref();
        let response = RuntimeAuthoritySnapshot {
            schema_version: 1,
            target: claims.target.clone(),
            operation_id: stored.operation.operation_id,
            command_id: claims.command_id.clone(),
            action: claims.action,
            installation_id: pair.installation_id().to_owned(),
            agent_identity_id: pair.agent_identity_id().to_owned(),
            observed_controller_identity_id: pair.observed_controller_identity_id().to_owned(),
            peer_policy_version: pair.policy_version().to_owned(),
            enrollment_version: binding.enrollment_version.to_owned(),
            host_policy_version: binding.host_policy_version.to_owned(),
            desired_state: stored.operation.desired_state,
            observed_state: stored.operation.observed_state,
            config_hash: stored.revision.config_hash,
            checked_at_unix_us: stored.checked_at_unix_us,
            lease_expires_at_unix_us: stored.lease_expires_at_unix_us,
        };
        if response.encoded_len() > 4096 {
            return Err(RuntimeAuthorityError::Unavailable.status());
        }
        check_elapsed(started, budget).map_err(RuntimeAuthorityError::status)?;
        check_elapsed(started, Duration::from_micros(remaining)).map_err(|_| not_current())?;
        self.shared
            .recheck(&selected)
            .map_err(RuntimeAuthorityError::status)?;
        Ok(tonic::Response::new(response))
    }
}

fn authorize<'a>(
    selected: &'a SelectedPolicy,
    request: &tonic::Request<CheckRuntimeAuthorityRequest>,
) -> Result<(apex_auth::RuntimePeerPair<'a>, EnrollmentBinding<'a>), tonic::Status> {
    let message = request.get_ref();
    let target = message
        .target
        .as_ref()
        .ok_or_else(|| RuntimeAuthorityError::InvalidRequest.status())?;
    let pin = message
        .observed_controller_certificate_sha256
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeAuthorityError::InvalidRequest.status())?;
    let pair = selected
        .peer
        .authorize_agent_observation(
            request,
            pin,
            &message.installation_id,
            &target.workspace_id,
            &target.namespace_id,
        )
        .map_err(peer_status)?;
    let binding = selected
        .enrollment
        .select(EnrollmentSelection {
            peer_policy_version: pair.policy_version(),
            agent_identity_id: pair.agent_identity_id(),
            observed_controller_identity_id: pair.observed_controller_identity_id(),
            installation_id: pair.installation_id(),
            workspace_id: pair.workspace_id(),
            namespace_id: pair.namespace_id(),
            checked_at_unix_us: pair.checked_at_unix_us(),
        })
        .map_err(RuntimeAuthorityError::status)?;
    Ok((pair, binding))
}

fn not_current() -> tonic::Status {
    tonic::Status::failed_precondition("PROXY_RUNTIME_OPERATION_NOT_CURRENT")
}

fn peer_status(error: apex_auth::RuntimePeerError) -> tonic::Status {
    use apex_auth::RuntimePeerError;
    let code = match error {
        RuntimePeerError::InvalidSelector => tonic::Code::InvalidArgument,
        RuntimePeerError::Unauthenticated => tonic::Code::Unauthenticated,
        RuntimePeerError::Denied => tonic::Code::PermissionDenied,
        RuntimePeerError::PolicyNotCurrent => tonic::Code::FailedPrecondition,
        _ => return RuntimeAuthorityError::Unavailable.status(),
    };
    tonic::Status::new(code, error.code())
}
