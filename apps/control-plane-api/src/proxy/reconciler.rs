//! Idempotent desired/observed runtime reconciliation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::{McpProxyRevision, ProxyError, ProxyId, ProxyRevisionId};
use super::provider::{Readiness, RuntimeHandle};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RuntimeKey {
    proxy_id: ProxyId,
    revision_id: ProxyRevisionId,
}

pub trait RuntimeOperations: Send + Sync {
    fn provision(&self, revision: &McpProxyRevision) -> Result<RuntimeHandle, ProxyError>;
    fn readiness(&self, handle: &RuntimeHandle) -> Result<Readiness, ProxyError>;
    fn drain(&self, handle: &RuntimeHandle) -> Result<(), ProxyError>;
    fn terminate(&self, handle: &RuntimeHandle) -> Result<(), ProxyError>;
}

pub struct ProxyRuntimeReconciler<P: RuntimeOperations> {
    provider: Arc<P>,
    active: Mutex<HashMap<RuntimeKey, RuntimeHandle>>,
}

impl<P: RuntimeOperations> ProxyRuntimeReconciler<P> {
    pub fn new(provider: Arc<P>) -> Self {
        Self { provider, active: Mutex::new(HashMap::new()) }
    }

    pub fn reconcile(&self, revision: &McpProxyRevision) -> Result<RuntimeHandle, ProxyError> {
        let key = RuntimeKey { proxy_id: revision.proxy_id.clone(), revision_id: revision.revision_id.clone() };
        if let Some(handle) = self.active.lock().map_err(|_| ProxyError::provider_failed())?.get(&key).cloned()
            && self.provider.readiness(&handle)? == Readiness::Ready
        {
            return Ok(handle);
        }
        let handle = self.provider.provision(revision)?;
        if self.provider.readiness(&handle)? != Readiness::Ready {
            return Err(ProxyError::provider_failed());
        }
        let old = {
            let mut active = self.active.lock().map_err(|_| ProxyError::provider_failed())?;
            let old = active.iter().filter(|(candidate, _)| candidate.proxy_id == revision.proxy_id && candidate.revision_id != revision.revision_id).map(|(_, handle)| handle.clone()).collect::<Vec<_>>();
            active.retain(|candidate, _| candidate.proxy_id != revision.proxy_id || candidate.revision_id == revision.revision_id);
            active.insert(key, handle.clone());
            old
        };
        for old_handle in old {
            self.provider.drain(&old_handle)?;
            self.provider.terminate(&old_handle)?;
        }
        Ok(handle)
    }

    pub fn pause(&self, proxy_id: &ProxyId, revision_id: &ProxyRevisionId) -> Result<(), ProxyError> {
        let key = RuntimeKey { proxy_id: proxy_id.clone(), revision_id: revision_id.clone() };
        let handle = self.active.lock().map_err(|_| ProxyError::provider_failed())?.get(&key).cloned().ok_or_else(ProxyError::provider_failed)?;
        self.provider.drain(&handle)
    }

    pub fn retire(&self, proxy_id: &ProxyId, revision_id: &ProxyRevisionId) -> Result<(), ProxyError> {
        let key = RuntimeKey { proxy_id: proxy_id.clone(), revision_id: revision_id.clone() };
        let handle = self.active.lock().map_err(|_| ProxyError::provider_failed())?.remove(&key).ok_or_else(ProxyError::provider_failed)?;
        self.provider.drain(&handle)?;
        self.provider.terminate(&handle)
    }

    pub fn active_count(&self) -> Result<usize, ProxyError> {
        Ok(self.active.lock().map_err(|_| ProxyError::provider_failed())?.len())
    }
}

impl RuntimeOperations for super::provider::DockerProxyProvider {
    fn provision(&self, revision: &McpProxyRevision) -> Result<RuntimeHandle, ProxyError> { self.provision(revision) }
    fn readiness(&self, handle: &RuntimeHandle) -> Result<Readiness, ProxyError> { self.readiness(handle) }
    fn drain(&self, handle: &RuntimeHandle) -> Result<(), ProxyError> { self.drain(handle) }
    fn terminate(&self, handle: &RuntimeHandle) -> Result<(), ProxyError> { self.terminate(handle) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProxyId, ProxyRevisionId};
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeProvider { provisions: Mutex<usize>, drains: Mutex<usize>, terminations: Mutex<usize>, fail_readiness: Mutex<bool> }

    impl RuntimeOperations for FakeProvider {
        fn provision(&self, revision: &McpProxyRevision) -> Result<RuntimeHandle, ProxyError> {
            *self.provisions.lock().unwrap() += 1;
            Ok(RuntimeHandle { container_name: format!("proxy-{}", revision.revision_id), container_id: "id".into(), proxy_id: revision.proxy_id.to_string(), revision_id: revision.revision_id.to_string() })
        }
        fn readiness(&self, _handle: &RuntimeHandle) -> Result<Readiness, ProxyError> {
            Ok(if *self.fail_readiness.lock().unwrap() { Readiness::Failed } else { Readiness::Ready })
        }
        fn drain(&self, _handle: &RuntimeHandle) -> Result<(), ProxyError> { *self.drains.lock().unwrap() += 1; Ok(()) }
        fn terminate(&self, _handle: &RuntimeHandle) -> Result<(), ProxyError> { *self.terminations.lock().unwrap() += 1; Ok(()) }
    }

    #[test]
    fn converges_without_duplicate_runtime_and_cleans_old_revision() {
        let provider = Arc::new(FakeProvider::default());
        let reconciler = ProxyRuntimeReconciler::new(provider.clone());
        let first = revision("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e85");
        let second = revision("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e86");
        reconciler.reconcile(&first).unwrap();
        reconciler.reconcile(&first).unwrap();
        assert_eq!(*provider.provisions.lock().unwrap(), 1);
        reconciler.reconcile(&second).unwrap();
        assert_eq!(reconciler.active_count().unwrap(), 1);
        assert_eq!(*provider.drains.lock().unwrap(), 1);
        assert_eq!(*provider.terminations.lock().unwrap(), 1);
    }

    #[test]
    fn failed_readiness_is_retryable_and_pause_retire_are_provider_operations() {
        let provider = Arc::new(FakeProvider::default());
        *provider.fail_readiness.lock().unwrap() = true;
        let reconciler = ProxyRuntimeReconciler::new(provider.clone());
        let revision = revision("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e85");
        assert_eq!(reconciler.reconcile(&revision).unwrap_err().code(), "PROXY_PROVIDER_FAILED");
        assert_eq!(reconciler.active_count().unwrap(), 0);
        *provider.fail_readiness.lock().unwrap() = false;
        reconciler.reconcile(&revision).unwrap();
        reconciler.pause(&revision.proxy_id, &revision.revision_id).unwrap();
        reconciler.retire(&revision.proxy_id, &revision.revision_id).unwrap();
        assert_eq!(*provider.drains.lock().unwrap(), 2);
        assert_eq!(*provider.terminations.lock().unwrap(), 1);
    }

    fn revision(revision_id: &str) -> McpProxyRevision {
        McpProxyRevision::new(ProxyId::new("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84").unwrap(), ProxyRevisionId::new(revision_id).unwrap(), crate::proxy::tests::valid_proxy_spec(), "a".repeat(64), super::super::ProxyLifecycleState::Ready).unwrap()
    }
}
