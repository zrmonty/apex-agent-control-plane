//! Controller-only physical observation; never a readiness or serving grant.
use super::*;
use proto::runtime_network_inspection_server::RuntimeNetworkInspection;

pub(crate) const BUDGET: Duration = Duration::from_secs(2);
pub(crate) const ERROR: &str = "RUNTIME_NETWORK_INSPECTION_REFUSED";

pub(crate) fn validate(body: &proto::RuntimeNetworkInspectionRequest) -> Result<(), Status> {
    let invalid = || Status::invalid_argument("RUNTIME_NETWORK_REQUEST_INVALID");
    let b = body.binding.as_ref().ok_or_else(invalid)?;
    let t = b.target.as_ref().ok_or_else(invalid)?;
    if body.schema_version != 1
        || body.nonce.len() != 32
        || !crate::shapes::uuid_v7(&b.installation_id)
        || !crate::shapes::uuid_v7(&b.process_instance_id)
        || !crate::shapes::hex_hash(&b.config_hash)
        || !crate::shapes::hex_hash(&b.launch_context_hash)
        || crate::check_runtime_target(t).is_err()
        || t.generation == 0
        || i64::try_from(t.generation).is_err()
        || t.fencing_token == 0
        || i64::try_from(t.fencing_token).is_err()
    {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn authorize(
    request: &Request<proto::RuntimeNetworkInspectionRequest>,
    installation: &str,
    metadata: &owner::Metadata,
) -> Result<(String, String), Status> {
    authorize_binding(
        request,
        request.get_ref().binding.as_ref(),
        installation,
        metadata,
    )
}

pub(crate) fn authorize_binding<T>(
    request: &Request<T>,
    binding: Option<&proto::ManagedDeploymentBinding>,
    installation: &str,
    metadata: &owner::Metadata,
) -> Result<(String, String), Status> {
    let denied = || Status::permission_denied("RUNTIME_PEER_DENIED");
    let b = binding.ok_or_else(denied)?;
    let t = b.target.as_ref().ok_or_else(denied)?;
    if b.installation_id != installation {
        return Err(denied());
    }
    metadata
        .policy
        .authorize(
            request,
            apex_auth::RuntimePeerRole::Controller,
            installation,
            &t.workspace_id,
            &t.namespace_id,
        )
        .map(|p| (p.identity_id().to_owned(), p.policy_version().to_owned()))
        .map_err(|_| denied())
}

#[tonic::async_trait]
impl RuntimeNetworkInspection for Arc<Ingress> {
    async fn check(
        &self,
        request: Request<proto::RuntimeNetworkInspectionRequest>,
    ) -> Result<Response<proto::RuntimeNetworkInspectionResponse>, Status> {
        let started = Instant::now();
        validate(request.get_ref())?;
        let metadata = owner::snapshot(&self.shared).map_err(Status::unavailable)?;
        authorize(&request, &self.installation, &metadata)?;
        let mut shutdown = self.shutdown.clone();
        if *shutdown.borrow() {
            return Err(Status::unavailable("RUNTIME_SHUTTING_DOWN"));
        }
        #[cfg(target_os = "linux")]
        if let Some(execution) = &self.execution {
            let expected = Arc::clone(&metadata);
            return tokio::select! {
                result = execution.inspect_network(request, started, metadata) => {
                    let result = result?;
                    let state = self.shared.lock().map_err(|_| Status::unavailable(owner::UNAVAILABLE))?;
                    if state.stopped || *shutdown.borrow() || state.read_started.elapsed() >= owner::FRESHNESS
                        || state.metadata.as_ref().is_none_or(|m| !Arc::ptr_eq(m, &expected))
                    { return Err(Status::unavailable(owner::UNAVAILABLE)); }
                    expected.current().map_err(Status::unavailable)?;
                    if started.elapsed() >= BUDGET { return Err(Status::deadline_exceeded("RUNTIME_DEADLINE")); }
                    Ok(Response::new(result))
                },
                _ = shutdown.changed() => Err(Status::unavailable("RUNTIME_SHUTTING_DOWN")),
            };
        }
        // Keep the same fail-closed implementation on unsupported platforms.
        let _ = (started, &mut shutdown, BUDGET);
        Err(Status::unavailable(ERROR))
    }
}
