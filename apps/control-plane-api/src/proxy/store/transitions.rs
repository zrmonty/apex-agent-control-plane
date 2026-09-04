use crate::ExactScope;
use crate::proxy::{ProxyId, ProxyLifecycleState, ProxyRevisionId};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(super) struct LifecycleTransition {
    pub(super) operation: &'static str,
    pub(super) scope: ExactScope,
    pub(super) proxy_id: ProxyId,
    pub(super) revision_id: Option<ProxyRevisionId>,
    pub(super) prior_state: Option<ProxyLifecycleState>,
    pub(super) next_state: ProxyLifecycleState,
    pub(super) actor_id: Option<String>,
    pub(super) reason_code: &'static str,
    pub(super) status: &'static str,
}

impl LifecycleTransition {
    pub(super) fn new(
        operation: &'static str,
        scope: ExactScope,
        proxy_id: ProxyId,
        revision_id: Option<ProxyRevisionId>,
        prior_state: Option<ProxyLifecycleState>,
        next_state: ProxyLifecycleState,
        actor_id: Option<String>,
        reason_code: &'static str,
        status: &'static str,
    ) -> Self {
        Self {
            operation,
            scope,
            proxy_id,
            revision_id,
            prior_state,
            next_state,
            actor_id,
            reason_code,
            status,
        }
    }

    #[cfg(test)]
    pub(super) fn is_metadata_only(&self) -> bool {
        let identity = !self.operation.is_empty()
            && !self.scope.workspace_id.is_empty()
            && !self.scope.namespace_id.is_empty()
            && !self.proxy_id.to_string().is_empty();
        let optional_values = self
            .revision_id
            .as_ref()
            .is_none_or(|revision| !revision.to_string().is_empty())
            && self.prior_state.is_none_or(|state| {
                state != ProxyLifecycleState::Retired
                    || self.next_state == ProxyLifecycleState::Retired
            })
            && self.actor_id.as_ref().is_none_or(|actor| !actor.is_empty());
        identity && optional_values && !self.reason_code.is_empty() && !self.status.is_empty()
    }
}
