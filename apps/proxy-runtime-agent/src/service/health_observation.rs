//! Controller-only fresh observation, never a cached reconciliation response.
use super::*;
use proto::runtime_health_observation_server::RuntimeHealthObservation;
pub(crate) const ERROR: &str = "RUNTIME_HEALTH_OBSERVATION_REFUSED";
pub(crate) const BUDGET: Duration = Duration::from_secs(10);

pub(crate) fn validate(body: &proto::RuntimeHealthObservationRequest) -> Result<(), Status> {
    network_readiness::validate(&proto::RuntimeNetworkInspectionRequest {
        schema_version: body.schema_version,
        binding: body.binding.clone(),
        nonce: body.nonce.clone(),
    })
    .map_err(|_| Status::invalid_argument("RUNTIME_HEALTH_REQUEST_INVALID"))
}

#[tonic::async_trait]
impl RuntimeHealthObservation for Arc<Ingress> {
    async fn observe(
        &self,
        request: Request<proto::RuntimeHealthObservationRequest>,
    ) -> Result<Response<proto::RuntimeHealthObservationResponse>, Status> {
        let started = Instant::now();
        validate(request.get_ref())?;
        let metadata = owner::snapshot(&self.shared).map_err(Status::unavailable)?;
        network_readiness::authorize_binding(
            &request,
            request.get_ref().binding.as_ref(),
            &self.installation,
            &metadata,
        )?;
        if *self.shutdown.borrow() {
            return Err(Status::unavailable("RUNTIME_SHUTTING_DOWN"));
        }
        #[cfg(target_os = "linux")]
        if let Some(execution) = &self.execution {
            let expected = Arc::clone(&metadata);
            let mut shutdown = self.shutdown.clone();
            return tokio::select! {
                result = execution.observe_health(request, started, metadata) => {
                    let result = result?;
                    let state = self.shared.lock().map_err(|_| Status::unavailable(owner::UNAVAILABLE))?;
                    if state.stopped || *shutdown.borrow() || state.read_started.elapsed() >= owner::FRESHNESS
                        || state.metadata.as_ref().is_none_or(|m| !Arc::ptr_eq(m, &expected))
                    { return Err(Status::unavailable(owner::UNAVAILABLE)); }
                    expected.current().map_err(Status::unavailable)?;
                    if started.elapsed() >= BUDGET { return Err(Status::deadline_exceeded("RUNTIME_DEADLINE")); }
                    result.handoff().map(Response::new).map_err(Status::unavailable)
                },
                _ = shutdown.changed() => Err(Status::unavailable("RUNTIME_SHUTTING_DOWN")),
            };
        }
        let _ = (started, BUDGET);
        // No observation without the physical execution owner.
        Err(Status::unavailable(ERROR))
    }
}
