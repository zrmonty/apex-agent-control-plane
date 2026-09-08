//! Authenticated non-admitting relay; physical agent I/O never occupies the PG worker.
use super::*;
use crate::proxy::runtime_client::network as transport;

#[derive(Clone)]
struct Observation {
    started: Instant,
    budget: Duration,
    binding: proto::ManagedDeploymentBinding,
    presentation: Arc<Presentation>,
    selected: Arc<Selection>,
    fresh: pool::Check,
}

#[tonic::async_trait]
impl proto::managed_network_readiness_server::ManagedNetworkReadiness for Service {
    async fn check(
        &self,
        request: Request<proto::RuntimeNetworkInspectionRequest>,
    ) -> Result<Response<proto::RuntimeNetworkInspectionResponse>, Status> {
        let started = Instant::now();
        let input = request.get_ref();
        if input.encoded_len() > 4096 || input.schema_version != 1 || input.nonce.len() != 32 {
            return Err(refused());
        }
        let binding = input.binding.as_ref().ok_or_else(refused)?;
        let context = self.context(&request, binding, started)?;
        let observation = Observation {
            started,
            budget: context.budget.min(transport::LIMIT),
            binding: binding.clone(),
            presentation: Arc::new(context.presentation),
            selected: context.selected,
            fresh: context.fresh,
        };
        let network = self.network.as_ref().ok_or_else(refused)?;
        // Cheap profile authentication precedes the database; actual registered
        // instance proof and current PREPARE/SERVE selection precede agent I/O.
        eligible(self, observation.clone()).await?;
        let original = request.into_inner();
        let input = original.clone();
        let reply = network
            .request(
                started,
                observation.budget,
                Arc::clone(&observation.fresh),
                move |transport, check| {
                    // Preserve classified agent contention as data through the
                    // physical worker; pool/cancellation failures stay terminal.
                    Ok(transport.inspect(&input, started, observation.budget, &|| {
                        check().map_err(|_| crate::proxy::runtime_client::unavailable())
                    }))
                },
            )
            .await
            .map_err(|_| refused())?;
        // A withdrawn selection, rotated credential/profile or lost registration
        // during inspection cannot release an earlier authorized observation.
        eligible(self, observation.clone()).await?;
        (observation.fresh)().map_err(|_| refused())?;
        if started.elapsed() >= observation.budget {
            return Err(refused());
        }
        let reply = reply.map_err(|error| match error {
            transport::InspectionFailure::Busy => {
                Status::resource_exhausted("MANAGED_NETWORK_BUSY")
            }
            transport::InspectionFailure::Refused => refused(),
        })?;
        transport::validate_response(&original, &reply, started.elapsed())
            .map_err(|_| refused())?;
        Ok(Response::new(reply))
    }
}

async fn eligible(service: &Service, observation: Observation) -> Result<(), Status> {
    service
        .client
        .request(
            observation.started,
            observation.budget,
            Arc::clone(&observation.fresh),
            move |backend, check| {
                let pg_check = || check().map_err(|_| crate::proxy::runtime_client::unavailable());
                let record = backend
                    .store
                    .read_eligible_deployment_checked(&observation.binding, &pg_check)
                    .map_err(|_| Refused)?;
                observation.presentation.verify(
                    &observation.selected.profile,
                    &record.registration,
                    unix_us()?,
                )?;
                backend.policy_for(&record.registration.configuration)?;
                check()
            },
        )
        .await
        .map_err(|_| refused())
}
