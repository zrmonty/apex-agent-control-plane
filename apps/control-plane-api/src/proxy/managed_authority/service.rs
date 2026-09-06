//! Private managed RPC composition; not yet installed in production startup.
use super::{Refused, pool, presentation::Presentation, refresh, state::Selection};
use crate::{GovernanceConfig, PostgresProxyStore, proto};
use prost::Message;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tonic::{Request, Response, Status};
use zeroize::Zeroizing;
mod business;
mod registration;

pub(super) struct Backend {
    store: PostgresProxyStore,
    policy: GovernanceConfig,
}
#[derive(Clone)]
pub struct Service {
    client: pool::Client<Backend>,
    profiles: Arc<refresh::Shared>,
}
pub(super) struct Owner {
    refresh: refresh::RefreshOwner,
    database: pool::Owner<Backend>,
}
impl Owner {
    pub(super) fn request_shutdown(&self) {
        self.refresh.shared.stop();
    }
    pub(super) fn new() -> Result<Self, Refused> {
        Ok(Self {
            refresh: refresh::RefreshOwner::new()?,
            database: pool::Owner::new()?,
        })
    }
    pub(super) fn start(
        &mut self,
        path: PathBuf,
        base: PathBuf,
        database: &str,
        policy: GovernanceConfig,
    ) -> Result<Service, Refused> {
        self.refresh.start(path, base)?;
        let database = Zeroizing::new(database.to_owned());
        let client = self.database.start(move || {
            Ok(Backend {
                store: PostgresProxyStore::connect(&database).map_err(|_| Refused)?,
                policy,
            })
        })?;
        Ok(Service {
            client,
            profiles: Arc::clone(&self.refresh.shared),
        })
    }
    pub(super) fn shutdown(&mut self) -> Result<(), Refused> {
        self.refresh.shared.stop();
        let database = self.database.shutdown();
        let refresh = self.refresh.shutdown();
        database.and(refresh)
    }
}

#[tonic::async_trait]
impl proto::managed_runtime_authority_server::ManagedRuntimeAuthority for Service {
    async fn renew_deployment(
        &self,
        request: Request<proto::ManagedDeploymentRenewal>,
    ) -> Result<Response<proto::ManagedDeploymentGrant>, Status> {
        let started = Instant::now();
        let input = request.get_ref();
        if input.encoded_len() > 8192
            || input.nonce.len() != 32
            || input.renewal_sequence == 0
            || input.renewal_sequence > i64::MAX as u64
        {
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
                    let pg_check = || {
                        check().map_err(|_| {
                            crate::ProxyError::new(
                                "MANAGED_AUTHORITY_REFUSED",
                                "Managed authority refused.",
                            )
                        })
                    };
                    let record = backend
                        .store
                        .read_deployment_checked(binding, &pg_check)
                        .map_err(|_| Refused)?;
                    context.presentation.verify(
                        &context.selected.profile,
                        &record.registration,
                        unix_us()?,
                    )?;
                    if record.mode != proto::ManagedGrantMode::Closed {
                        backend.policy_for(&record.registration.configuration)?;
                    }
                    check()?;
                    backend
                        .store
                        .renew_deployment_checked(&input, &pg_check)
                        .map_err(|_| Refused)
                },
            )
            .await
            .map_err(|_| refused())?;
        Ok(Response::new(result))
    }
    async fn get_managed_policy(
        &self,
        request: Request<proto::ManagedPolicyRequest>,
    ) -> Result<Response<proto::ManagedPolicySnapshot>, Status> {
        let started = Instant::now();
        if request.get_ref().encoded_len() > 8192 || request.get_ref().nonce.len() != 32 {
            return Err(refused());
        }
        let binding = request.get_ref().binding.as_ref().ok_or_else(refused)?;
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
                    let pg_check = || {
                        check().map_err(|_| {
                            crate::ProxyError::new(
                                "MANAGED_AUTHORITY_REFUSED",
                                "Managed authority refused.",
                            )
                        })
                    };
                    let record = backend
                        .store
                        .read_eligible_deployment_checked(binding, &pg_check)
                        .map_err(|_| Refused)?;
                    context.presentation.verify(
                        &context.selected.profile,
                        &record.registration,
                        unix_us()?,
                    )?;
                    let snapshot = backend.policy_for(&record.registration.configuration)?;
                    check()?;
                    Ok(proto::ManagedPolicySnapshot {
                        binding: Some(binding.clone()),
                        nonce: input.nonce,
                        policy_id: snapshot.policy_id,
                        revision: snapshot.revision,
                        field_restrictions: backend.policy.restrictions(),
                    })
                },
            )
            .await
            .map_err(|_| refused())?;
        Ok(Response::new(result))
    }
    async fn complete_managed_call(
        &self,
        request: Request<proto::ManagedCallCompletion>,
    ) -> Result<Response<proto::ManagedCallCompletionReceipt>, Status> {
        business::complete(self, request).await
    }
}

struct Context {
    presentation: Presentation,
    selected: Arc<Selection>,
    budget: Duration,
    fresh: pool::Check,
}

impl Service {
    fn context<T>(
        &self,
        request: &Request<T>,
        binding: &proto::ManagedDeploymentBinding,
        started: Instant,
    ) -> Result<Context, Status> {
        let present = Presentation::from_request(request).map_err(|_| refused())?;
        let target = binding.target.as_ref().ok_or_else(refused)?;
        if binding.encoded_len() > 4096
            || !apex_domain::is_lowercase_uuidv7(&binding.process_instance_id)
            || super::profile::digest(&binding.config_hash).is_err()
            || super::profile::digest(&binding.launch_context_hash).is_err()
            || target.generation == 0
            || target.generation > i64::MAX as u64
            || target.fencing_token == 0
            || target.fencing_token > i64::MAX as u64
        {
            return Err(refused());
        }
        let selected = self.profiles.current().map_err(|_| refused())?;
        present
            .select(
                &selected.profile,
                binding,
                unix_us().map_err(|_| refused())?,
            )
            .map_err(|_| refused())?;
        let budget = budget(request.metadata()).map_err(|_| refused())?;
        let (profiles, publication) = (Arc::clone(&self.profiles), Arc::clone(&selected));
        let fresh: pool::Check = Arc::new(move || {
            if started.elapsed() >= budget {
                return Err(Refused);
            }
            profiles.recheck(&publication)?;
            let now = unix_us()?;
            if now < publication.profile.valid_from || now >= publication.profile.expires {
                return Err(Refused);
            }
            Ok(())
        });
        Ok(Context {
            presentation: present,
            selected,
            budget,
            fresh,
        })
    }
}
impl Backend {
    fn policy_for(
        &self,
        config: &proto::RuntimeConfiguration,
    ) -> Result<proto::GovernancePolicySnapshot, Refused> {
        let snapshot = self
            .policy
            .snapshot(proto::GovernanceScope {
                workspace_id: config.workspace_id.clone(),
                namespace_id: config.namespace_id.clone(),
            })
            .map_err(|_| Refused)?;
        let binding = config
            .spec
            .as_ref()
            .and_then(|spec| spec.governance_binding.as_ref())
            .ok_or(Refused)?;
        if snapshot.policy_id != binding.policy_id {
            return Err(Refused);
        }
        Ok(snapshot)
    }
}
fn unix_us() -> Result<u64, Refused> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Refused)?
            .as_micros(),
    )
    .map_err(|_| Refused)
}
fn budget(metadata: &tonic::metadata::MetadataMap) -> Result<Duration, Refused> {
    if metadata.get_all("grpc-timeout").iter().count() > 1 {
        return Err(Refused);
    }
    let Some(value) = metadata.get("grpc-timeout") else {
        return Ok(Duration::from_secs(10));
    };
    let value = value.to_str().map_err(|_| Refused)?.as_bytes();
    if !(2..=9).contains(&value.len()) {
        return Err(Refused);
    }
    let (unit, digits) = value.split_last().ok_or(Refused)?;
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(Refused);
    }
    let count = digits
        .iter()
        .fold(0u64, |n, b| n * 10 + u64::from(b - b'0'));
    let scale = match unit {
        b'H' => 3_600_000_000_000u64,
        b'M' => 60_000_000_000,
        b'S' => 1_000_000_000,
        b'm' => 1_000_000,
        b'u' => 1_000,
        b'n' => 1,
        _ => return Err(Refused),
    };
    let nanos = u128::from(count) * u128::from(scale);
    if nanos == 0 {
        return Err(Refused);
    }
    Ok(Duration::from_nanos(nanos.min(10_000_000_000) as u64))
}
fn refused() -> Status {
    Status::permission_denied("MANAGED_AUTHORITY_REFUSED")
}

#[cfg(test)]
mod budget_tests;
#[cfg(all(test, target_os = "linux"))]
mod tests;
