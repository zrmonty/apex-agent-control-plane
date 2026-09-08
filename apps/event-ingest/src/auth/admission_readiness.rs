//! Authenticated, non-admitting observation of the actual admission pool.
use super::AuthenticatedGrpcService;
use crate::{AuthenticatedIngestAdapter, EventPublisher, GatewayErrorCode, proto};
use apex_auth::{CallerVerifier, PeerIdentity};
use prost::Message;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, atomic::AtomicUsize};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

pub struct AdmissionReadiness<P: EventPublisher, V: CallerVerifier> {
    adapters: Arc<Vec<Mutex<AuthenticatedIngestAdapter<P>>>>,
    next_adapter: Arc<AtomicUsize>,
    verifier: Arc<V>,
    blocking_limit: Arc<Semaphore>,
    slots: Arc<Semaphore>,
}

impl<P: EventPublisher, V: CallerVerifier> AuthenticatedGrpcService<P, V> {
    /// Shares exact verifier and store owners; no second pool or credential table.
    pub fn admission_readiness_service(&self) -> AdmissionReadiness<P, V> {
        AdmissionReadiness {
            adapters: self.adapters.clone(),
            next_adapter: self.next_adapter.clone(),
            verifier: self.verifier.clone(),
            blocking_limit: self.blocking_limit.clone(),
            slots: Arc::new(Semaphore::new(4)),
        }
    }
}

#[tonic::async_trait]
impl<P: EventPublisher + Send + 'static, V: CallerVerifier>
    proto::evidence_admission_readiness_server::EvidenceAdmissionReadiness
    for AdmissionReadiness<P, V>
{
    async fn check(
        &self,
        request: tonic::Request<proto::EvidenceAdmissionProbeRequest>,
    ) -> Result<tonic::Response<proto::EvidenceAdmissionProbeResponse>, tonic::Status> {
        let peer = PeerIdentity::from_request(&request)
            .ok_or_else(|| tonic::Status::unauthenticated("readiness rejected safely"))?;
        self.check_peer(request, peer).await
    }
}

impl<P: EventPublisher + Send + 'static, V: CallerVerifier> AdmissionReadiness<P, V> {
    async fn check_peer(
        &self,
        request: tonic::Request<proto::EvidenceAdmissionProbeRequest>,
        peer: PeerIdentity,
    ) -> Result<tonic::Response<proto::EvidenceAdmissionProbeResponse>, tonic::Status> {
        let deadline = Instant::now() + Duration::from_secs(2);
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| unavailable())?;
        let permit = self
            .blocking_limit
            .clone()
            .try_acquire_owned()
            .map_err(|_| unavailable())?;
        let value = request.get_ref();
        if value.encoded_len() > 1024
            || value.schema_version != 1
            || value.request_nonce.len() != 32
            || !crate::validation::is_scope_identifier(&value.workspace_id)
            || !crate::validation::is_scope_identifier(&value.namespace_id)
            || !crate::validation::is_scope_identifier(&value.agent_id)
        {
            return Err(tonic::Status::invalid_argument(
                "readiness request rejected safely",
            ));
        }
        let value = value.clone();
        let reply = proto::EvidenceAdmissionProbeResponse {
            schema_version: 1,
            request_nonce: value.request_nonce.clone(),
            workspace_id: value.workspace_id.clone(),
            namespace_id: value.namespace_id.clone(),
            agent_id: value.agent_id.clone(),
            valid_for_us: 10000000,
            ready: true,
        };
        let adapters = self.adapters.clone();
        let next = self.next_adapter.clone();
        let verifier = self.verifier.clone();
        let work = tokio::task::spawn_blocking(move || {
            // These leases survive RPC cancellation and its logical timeout.
            // Authentication can block too: retain capacity through final auth.
            let (_slot, _permit) = (slot, permit);
            let verify = || {
                catch_unwind(AssertUnwindSafe(|| {
                    verifier.verify_with_peer(request.metadata(), Some(&peer))
                }))
                .map_err(|_| unavailable())?
                .map_err(|_| tonic::Status::unauthenticated("readiness rejected safely"))
            };
            if Instant::now() >= deadline {
                return Err(unavailable());
            }
            let caller = verify()?;
            if Instant::now() >= deadline {
                return Err(unavailable());
            }
            let mut adapter =
                super::grpc::try_lock_pool(&adapters, &next).map_err(|_| unavailable())?;
            if Instant::now() >= deadline {
                return Err(unavailable());
            }
            catch_unwind(AssertUnwindSafe(|| {
                adapter.check_admission_readiness(
                    &caller,
                    &value.workspace_id,
                    &value.namespace_id,
                    &value.agent_id,
                )
            }))
            .map_err(|_| unavailable())?
            .map_err(|error| match error.code {
                GatewayErrorCode::Unauthenticated => {
                    tonic::Status::unauthenticated("readiness rejected safely")
                }
                GatewayErrorCode::ScopeDenied => {
                    tonic::Status::permission_denied("readiness rejected safely")
                }
                _ => unavailable(),
            })?;
            drop(adapter);
            // Storage cannot revive revoked enrollment or extend the deadline.
            // Reuse the original metadata/TLS peer and require the same Caller.
            if Instant::now() >= deadline {
                return Err(unavailable());
            }
            if verify()? != caller || Instant::now() >= deadline {
                return Err(unavailable());
            }
            Ok(())
        });
        tokio::time::timeout_at(deadline.into(), work)
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())??;
        if Instant::now() >= deadline {
            return Err(unavailable());
        }
        Ok(tonic::Response::new(reply))
    }
}

fn unavailable() -> tonic::Status {
    tonic::Status::unavailable("readiness unavailable")
}

#[cfg(all(test, feature = "test-support"))]
#[path = "admission_readiness_tests.rs"]
mod tests;
