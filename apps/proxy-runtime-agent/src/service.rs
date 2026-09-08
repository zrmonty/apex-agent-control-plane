//! Production reconciliation only. No legacy mutation registration or effect seam.
use crate::{
    authority::{AuthorityOperation, RuntimeAuthorityClient},
    owner, proto,
};
use proto::runtime_execution_service_server::RuntimeExecutionService;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Semaphore, watch};
use tonic::{Request, Response, Status};

pub(crate) mod health_observation;
pub(crate) mod network_readiness;
#[cfg(target_os = "linux")]
mod startup;
pub(crate) mod validation;
#[cfg(target_os = "linux")]
pub use startup::run;

const BUDGET: Duration = Duration::from_secs(5);
pub(crate) const NOT_SERVING: &str = "RUNTIME_NOT_SERVING_EFFECT_OWNER_UNAVAILABLE";

struct Ingress {
    authority: Arc<RuntimeAuthorityClient>,
    installation: String,
    shared: owner::Shared,
    slots: Semaphore,
    shutdown: watch::Receiver<bool>,
    #[cfg(target_os = "linux")]
    execution: Option<crate::execution::Facility>,
}

#[tonic::async_trait]
impl RuntimeExecutionService for Arc<Ingress> {
    async fn reconcile_runtime(
        &self,
        request: Request<proto::RuntimeReconcileRequest>,
    ) -> Result<Response<proto::RuntimeReconcileResponse>, Status> {
        #[cfg(target_os = "linux")]
        if let Some(execution) = &self.execution {
            let mut shutdown = self.shutdown.clone();
            if *shutdown.borrow() {
                return Err(Status::unavailable("RUNTIME_SHUTTING_DOWN"));
            }
            return tokio::select! {
                result = execution.execute(request) => result.map(Response::new),
                _ = shutdown.changed() => Err(Status::unavailable("RUNTIME_SHUTTING_DOWN")),
            };
        }
        let _slot = self
            .slots
            .try_acquire()
            .map_err(|_| Status::resource_exhausted("RUNTIME_OVERLOADED"))?;
        let mut shutdown = self.shutdown.clone();
        if *shutdown.borrow() {
            return Err(Status::unavailable("RUNTIME_SHUTTING_DOWN"));
        }
        tokio::select! {
            result = tokio::time::timeout(BUDGET,self.reconcile(&request)) => result.map_err(|_| Status::deadline_exceeded("RUNTIME_DEADLINE"))?,
            _ = shutdown.changed() => Err(Status::unavailable("RUNTIME_SHUTTING_DOWN")),
        }
    }
}

impl Ingress {
    async fn reconcile(
        &self,
        request: &Request<proto::RuntimeReconcileRequest>,
    ) -> Result<Response<proto::RuntimeReconcileResponse>, Status> {
        let started = Instant::now();
        let body = request.get_ref();
        validation::request(body)?;
        let metadata = owner::snapshot(&self.shared).map_err(Status::unavailable)?;
        let target = body
            .target
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("RUNTIME_REQUEST_INVALID"))?;
        let authorize = |metadata: &owner::Metadata| {
            metadata
                .policy
                .authorize(
                    request,
                    apex_auth::RuntimePeerRole::Controller,
                    &self.installation,
                    &target.workspace_id,
                    &target.namespace_id,
                )
                .map(|p| (p.identity_id().to_owned(), p.policy_version().to_owned()))
                .map_err(|_| Status::permission_denied("RUNTIME_PEER_DENIED"))
        };
        let identity = authorize(&metadata)?;
        let resolved = self
            .authority
            .resolve(
                request,
                &metadata.policy,
                AuthorityOperation {
                    target,
                    operation_id: &body.operation_id,
                    command_id: &body.command_id,
                    config_hash: &body.config_hash,
                },
                BUDGET,
            )
            .await
            .map_err(|_| Status::unavailable("RUNTIME_AUTHORITY_REFUSED"))?;
        validation::states(resolved.authority())?;
        let current = owner::snapshot(&self.shared).map_err(Status::unavailable)?;
        if !Arc::ptr_eq(&current, &metadata) || authorize(&current)? != identity {
            return Err(Status::unavailable(owner::UNAVAILABLE));
        }
        // Temporary no-effects preparation only: Task 3 must select/adopt its
        // instance from the durable journal, not retain per-call UUID semantics.
        // Paused and Retired never select an instance or prepare a launch.
        let prepared =
            if resolved.authority().desired_state == i32::from(proto::ProxyDesiredState::Serving) {
                Some(
                    current
                        .catalog
                        .prepare(&resolved, &uuid::Uuid::now_v7().to_string())
                        .map_err(|_| Status::failed_precondition("RUNTIME_LAUNCH_REFUSED"))?,
                )
            } else {
                None
            };
        // Serialize the final local handoff with metadata replacement. Never use
        // remote wall time minus local wall time as an elapsed budget.
        let state = self
            .shared
            .lock()
            .map_err(|_| Status::unavailable(owner::UNAVAILABLE))?;
        if state.stopped
            || state.read_started.elapsed() >= owner::FRESHNESS
            || !state
                .metadata
                .as_ref()
                .is_some_and(|m| Arc::ptr_eq(m, &current))
            || current.current().is_err()
            || authorize(&current)? != identity
        {
            return Err(Status::unavailable(owner::UNAVAILABLE));
        }
        let authority = resolved.authority();
        let interval = authority
            .lease_expires_at_unix_us
            .checked_sub(authority.checked_at_unix_us)
            .ok_or_else(|| Status::unavailable("RUNTIME_AUTHORITY_REFUSED"))?;
        if started.elapsed() >= BUDGET || started.elapsed() >= Duration::from_micros(interval) {
            return Err(Status::deadline_exceeded("RUNTIME_DEADLINE"));
        }
        // Task 3 replaces this INTERNAL refusal with its concrete durable owner.
        // No public executor injection, signatures, staging, engine calls or ready response.
        drop(prepared);
        Err(Status::unavailable(NOT_SERVING))
    }
}

// Shared by the binary and listener tests; never installs ProxyRuntimeAgent.
fn router(
    ingress: Ingress,
    tls: tonic::transport::ServerTlsConfig,
) -> Result<tonic::transport::server::Router, &'static str> {
    let ingress = Arc::new(ingress);
    let service = bounded_service(Arc::clone(&ingress));
    let inspection = proto::runtime_network_inspection_server::RuntimeNetworkInspectionServer::new(
        Arc::clone(&ingress),
    )
    .max_decoding_message_size(4096)
    .max_encoding_message_size(4096);
    let health =
        proto::runtime_health_observation_server::RuntimeHealthObservationServer::new(ingress)
            .max_decoding_message_size(4096)
            .max_encoding_message_size(32_768);
    Ok(tonic::transport::Server::builder()
        .tls_config(tls)
        .map_err(|_| "RUNTIME_TLS_INVALID")?
        .max_concurrent_streams(8)
        .timeout(Duration::from_secs(120))
        .add_service(service)
        .add_service(inspection)
        .add_service(health))
}
fn bounded_service<S: RuntimeExecutionService>(
    service: S,
) -> proto::runtime_execution_service_server::RuntimeExecutionServiceServer<S> {
    proto::runtime_execution_service_server::RuntimeExecutionServiceServer::new(service)
        .max_decoding_message_size(4096)
        .max_encoding_message_size(16_384)
}

#[cfg(test)]
pub(crate) mod tests;
