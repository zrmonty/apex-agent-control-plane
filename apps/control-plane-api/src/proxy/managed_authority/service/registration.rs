use super::*;
use crate::proxy::managed_authority::RegistrationInput;

impl Service {
    pub(crate) async fn register_agent(
        &self,
        input: RegistrationInput,
    ) -> Result<proto::RuntimeDeploymentRegistrationReceipt, Status> {
        let selected = self.profiles.current().map_err(|_| refused())?;
        let profiles = Arc::clone(&self.profiles);
        let publication = Arc::clone(&selected);
        let authority_current = Arc::clone(&input.recheck_authority);
        let (started, budget) = (input.started, input.budget.min(Duration::from_secs(5)));
        let fresh: pool::Check = Arc::new(move || {
            if Instant::now()
                .checked_duration_since(started)
                .is_none_or(|age| age >= budget)
                || !authority_current()
            {
                return Err(Refused);
            }
            profiles.recheck(&publication)?;
            let now = unix_us()?;
            if now < publication.profile.valid_from || now >= publication.profile.expires {
                return Err(Refused);
            }
            Ok(())
        });
        fresh().map_err(|_| refused())?;
        let config = &input.configuration;
        let entry = selected
            .profile
            .entries
            .iter()
            .find(|entry| {
                entry.installation_id == input.authority.installation_id
                    && entry.workspace_id == config.workspace_id
                    && entry.namespace_id == config.namespace_id
                    && entry.proxy_id == config.proxy_id
                    && entry.revision_id == config.revision_id
            })
            .ok_or_else(refused)?;
        let registration = entry
            .registration(
                &input.attestation,
                config,
                &input.authority.host_policy_version,
                &input.deployment_bindings_version,
            )
            .map_err(|_| refused())?;
        fresh().map_err(|_| refused())?;
        self.client
            .request(started, budget, fresh, move |backend, check| {
                backend.policy_for(&registration.configuration)?;
                let pg_check = || {
                    check().map_err(|_| {
                        crate::ProxyError::new(
                            "MANAGED_AUTHORITY_REFUSED",
                            "Managed authority refused.",
                        )
                    })
                };
                let hash = backend
                    .store
                    .register_attested_deployment_checked(
                        &input.lease,
                        &registration,
                        &input.attestation,
                        &input.authority,
                        &pg_check,
                    )
                    .map_err(|_| Refused)?;
                check()?;
                Ok(proto::RuntimeDeploymentRegistrationReceipt {
                    binding: Some(registration.binding),
                    attestation_sha256: hash,
                    authority: Some(input.authority),
                })
            })
            .await
            .map_err(|_| refused())
    }
}
