use std::collections::HashSet;

use crate::{GatewayError, is_scope_identifier};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    authenticated: bool,
    subject: Option<String>,
    bound_agent_id: Option<String>,
    allowed_scopes: HashSet<String>,
}

const MAX_SUBJECT_BYTES: usize = 256;
const MAX_ALLOWED_SCOPES: usize = 256;

impl Caller {
    /// Internal test/seam constructor for callers that do not represent an
    /// agent workload. Production admission rejects unbound callers; external
    /// resolvers must use `authenticated_for_agent`.
    #[cfg(test)]
    pub(crate) fn authenticated(
        subject: impl Into<String>,
        allowed_scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::build(subject.into(), None, allowed_scopes)
            .expect("test caller identity must satisfy caller validation")
    }

    /// Creates an authenticated caller whose workload identity is bound to a
    /// single agent identifier. The gateway enforces this binding before any
    /// event reaches a publisher.
    pub fn authenticated_for_agent(
        subject: impl Into<String>,
        agent_id: impl Into<String>,
        allowed_scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, GatewayError> {
        Self::build(subject.into(), Some(agent_id.into()), allowed_scopes)
            .map_err(|_| GatewayError::invalid_authorization())
    }

    fn build(
        subject: String,
        bound_agent_id: Option<String>,
        allowed_scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, ()> {
        if !is_valid_subject(&subject) {
            return Err(());
        }
        if let Some(agent_id) = &bound_agent_id
            && !is_scope_identifier(agent_id)
        {
            return Err(());
        }
        let mut scopes = HashSet::new();
        for raw_scope in allowed_scopes {
            let scope = raw_scope.into();
            let Some((workspace, namespace)) = scope.split_once('/') else {
                return Err(());
            };
            if !is_scope_identifier(workspace) || !is_scope_identifier(namespace) {
                return Err(());
            }
            scopes.insert(scope);
            if scopes.len() > MAX_ALLOWED_SCOPES {
                return Err(());
            }
        }
        Ok(Self {
            authenticated: true,
            subject: Some(subject),
            bound_agent_id,
            allowed_scopes: scopes,
        })
    }

    pub(crate) fn is_valid(&self) -> bool {
        self.authenticated
            && self
                .subject
                .as_ref()
                .is_some_and(|subject| is_valid_subject(subject))
            && self
                .bound_agent_id
                .as_ref()
                .is_none_or(|agent_id| is_scope_identifier(agent_id))
            && self.allowed_scopes.len() <= MAX_ALLOWED_SCOPES
            && self.allowed_scopes.iter().all(|scope| {
                scope.split_once('/').is_some_and(|(workspace, namespace)| {
                    is_scope_identifier(workspace) && is_scope_identifier(namespace)
                })
            })
    }

    pub fn bound_agent_id(&self) -> Option<&str> {
        self.bound_agent_id.as_deref()
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Stable workload identity for audit attribution. The value is never
    /// included in redacted diagnostics or event payloads.
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// Returns true only when this authenticated caller is explicitly allowed
    /// to act in the exact workspace/namespace scope.
    pub fn allows_scope(&self, scope: &str) -> bool {
        self.is_valid()
            && self
                .subject
                .as_ref()
                .is_some_and(|subject| !subject.is_empty())
            && self.allowed_scopes.contains(scope)
    }

    pub fn anonymous() -> Self {
        Self {
            authenticated: false,
            subject: None,
            bound_agent_id: None,
            allowed_scopes: HashSet::new(),
        }
    }
}

fn is_valid_subject(subject: &str) -> bool {
    if subject.len() > MAX_SUBJECT_BYTES || !subject.is_ascii() {
        return false;
    }
    if is_scope_identifier(subject) {
        return true;
    }
    let Some(path) = subject.strip_prefix("spiffe://") else {
        return false;
    };
    let mut parts = path.split('/');
    parts.next().is_some_and(is_scope_identifier) && parts.all(is_scope_identifier)
}
