use super::*;
use crate::proxy::store::ManagedCallReservation;
use uuid::Uuid;

#[tonic::async_trait]
impl proto::managed_proxy_governance_server::ManagedProxyGovernance for Service {
    async fn authorize_managed_call(
        &self,
        request: Request<proto::ManagedCallAuthorizationRequest>,
    ) -> Result<Response<proto::ManagedCallAuthorizationDecision>, Status> {
        let started = Instant::now();
        let input = request.get_ref();
        if input.encoded_len() > 16_384 || !apex_domain::is_lowercase_uuidv7(&input.call_id) {
            return Err(refused());
        }
        let binding = input.binding.as_ref().ok_or_else(refused)?;
        let context = self.context(&request, binding, started)?;
        let input = request.into_inner();
        let result = self
            .client
            .request(
                started,
                context.budget,
                context.fresh,
                move |backend, check| {
                    let binding = input.binding.as_ref().ok_or(Refused)?;
                    let pg_check = || pg_check(check);
                    let record = backend
                        .store
                        .read_admittable_deployment_checked(binding, &pg_check)
                        .map_err(|_| Refused)?;
                    let profile = context.presentation.verify(
                        &context.selected.profile,
                        &record.registration,
                        unix_us()?,
                    )?;
                    let evaluated = super::super::call::evaluate(
                        &input,
                        &record.registration.configuration,
                        &profile.evidence_agent_id,
                        &backend.policy,
                    )?;
                    check()?;
                    if evaluated.decision.outcome != proto::GovernanceOutcome::Allowed as i32 {
                        // Policy denial never creates a reservation or returns start authority.
                        return Ok(proto::ManagedCallAuthorizationDecision {
                            decision: Some(evaluated.decision),
                            policy_revision: evaluated.policy_revision,
                            ..Default::default()
                        });
                    }
                    let reservation = ManagedCallReservation {
                        binding: binding.clone(),
                        call_id: Uuid::parse_str(&input.call_id).map_err(|_| Refused)?,
                        semantic_sha256: evaluated.semantic_sha256,
                        policy_id: evaluated.decision.policy_id.clone(),
                        policy_revision: evaluated.policy_revision,
                    };
                    // Second lock/eligibility check is mandatory: a withdrawal between
                    // interpretation and reservation must not inherit the earlier read.
                    let admission = backend
                        .store
                        .reserve_managed_call_checked(&reservation, &pg_check)
                        .map_err(|_| Refused)?;
                    Ok(proto::ManagedCallAuthorizationDecision {
                        decision: Some(evaluated.decision),
                        approval: None,
                        admission_id: admission.admission_id.to_string(),
                        expires_at_unix_us: admission.expires_at_unix_us,
                        policy_revision: admission.policy_revision,
                        valid_for_us: admission.valid_for_us,
                        epoch: admission.epoch,
                    })
                },
            )
            .await
            .map_err(|_| refused())?;
        Ok(Response::new(result))
    }
}

pub(super) async fn complete(
    service: &Service,
    request: Request<proto::ManagedCallCompletion>,
) -> Result<Response<proto::ManagedCallCompletionReceipt>, Status> {
    let started = Instant::now();
    let input = request.get_ref();
    if input.encoded_len() > 8192
        || !apex_domain::is_lowercase_uuidv7(&input.call_id)
        || !apex_domain::is_lowercase_uuidv7(&input.admission_id)
    {
        return Err(refused());
    }
    let binding = input.binding.as_ref().ok_or_else(refused)?;
    let context = service.context(&request, binding, started)?;
    let input = request.into_inner();
    let result = service
        .client
        .request(
            started,
            context.budget,
            context.fresh,
            move |backend, check| {
                let binding = input.binding.as_ref().ok_or(Refused)?;
                let pg_check = || pg_check(check);
                // Cleanup remains authenticated after withdrawal/publication changes.
                // A missing/revoked profile still refuses; only independent termination
                // reconciliation may release work whose completion cannot authenticate.
                let record = backend
                    .store
                    .read_deployment_checked(binding, &pg_check)
                    .map_err(|_| Refused)?;
                context.presentation.verify(
                    &context.selected.profile,
                    &record.registration,
                    unix_us()?,
                )?;
                backend
                    .store
                    .complete_managed_call_checked(
                        binding,
                        Uuid::parse_str(&input.admission_id).map_err(|_| Refused)?,
                        Uuid::parse_str(&input.call_id).map_err(|_| Refused)?,
                        &pg_check,
                    )
                    .map_err(|_| Refused)?;
                Ok(proto::ManagedCallCompletionReceipt {
                    binding: input.binding,
                    admission_id: input.admission_id,
                    call_id: input.call_id,
                    released: true,
                })
            },
        )
        .await
        .map_err(|_| refused())?;
    Ok(Response::new(result))
}

fn pg_check(check: &dyn Fn() -> Result<(), Refused>) -> Result<(), crate::ProxyError> {
    check().map_err(|_| {
        crate::ProxyError::new("MANAGED_AUTHORITY_REFUSED", "Managed authority refused.")
    })
}
