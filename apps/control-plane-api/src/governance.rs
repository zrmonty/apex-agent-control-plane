//! Live Apex governance authority for the narrow MCP vertical slice.
//!
//! This service is intentionally separate from the operator command gateway.
//! It accepts only a dedicated gateway credential, evaluates one immutable
//! read-only policy, and returns decision metadata. The TypeScript process
//! remains a client of this authority rather than carrying a second policy.

use std::collections::HashSet;
use std::io;
use std::sync::Arc;

use apex_durability::Caller;
use apex_policy::{
    ActionName, AuthorizationRequest, DataClassification, FieldPath, GovernanceScope, PolicyId,
    ResourceName, ToolName, TraceContext,
};
use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};

use crate::auth::GatewayTokenAuthenticator;
use crate::proto;

const TOOL: &str = "portfolio.read";
const ACTION: &str = "read";
const CLASSIFICATION: &str = "confidential";
const ALLOWED_REASON: &str = "policy.allowed";
const DENIED_REASON: &str = "policy.denied";

/// Immutable policy configuration owned by the Apex control-plane process.
#[derive(Clone)]
pub struct GovernanceConfig {
    allowed_resources: HashSet<ResourceName>,
    allowed_scopes: HashSet<GovernanceScope>,
    policy_id: PolicyId,
    revision: u64,
    field_restrictions: Vec<FieldPath>,
}

impl GovernanceConfig {
    /// Builds the narrow policy from validated portfolio IDs and exact scopes.
    pub fn new<P, S, F, PI, SI, FI>(
        portfolio_ids: P,
        scopes: S,
        policy_id: impl Into<String>,
        revision: u64,
        field_restrictions: F,
    ) -> Result<Self, io::Error>
    where
        P: IntoIterator<Item = PI>,
        PI: AsRef<str>,
        S: IntoIterator<Item = SI>,
        SI: AsRef<str>,
        F: IntoIterator<Item = FI>,
        FI: AsRef<str>,
    {
        let mut allowed_resources = HashSet::new();
        for portfolio_id in portfolio_ids {
            let portfolio_id = portfolio_id.as_ref();
            if !is_portfolio_id(portfolio_id) {
                return Err(invalid_config());
            }
            allowed_resources.insert(
                ResourceName::new(portfolio_resource_reference(portfolio_id))
                    .map_err(|_| invalid_config())?,
            );
        }
        if allowed_resources.is_empty() {
            return Err(invalid_config());
        }

        let mut allowed_scopes = HashSet::new();
        for scope in scopes {
            let (workspace, namespace) =
                scope.as_ref().split_once('/').ok_or_else(invalid_config)?;
            allowed_scopes
                .insert(GovernanceScope::new(workspace, namespace).map_err(|_| invalid_config())?);
        }
        if allowed_scopes.is_empty() {
            return Err(invalid_config());
        }

        let policy_id = PolicyId::new(policy_id.into()).map_err(|_| invalid_config())?;
        let field_restrictions = field_restrictions
            .into_iter()
            .map(|field| FieldPath::new(field.as_ref()).map_err(|_| invalid_config()))
            .collect::<Result<Vec<_>, _>>()?;
        if revision == 0 {
            return Err(invalid_config());
        }

        Ok(Self {
            allowed_resources,
            allowed_scopes,
            policy_id,
            revision,
            field_restrictions,
        })
    }

    fn allows(&self, request: &AuthorizationRequest) -> bool {
        self.allowed_scopes.contains(request.scope())
            && self.allowed_resources.contains(request.resource())
            && request.tool().as_str() == TOOL
            && request.action().as_str() == ACTION
            && request.classification() == DataClassification::Confidential
    }
}

/// Dedicated Apex governance RPC service.
#[derive(Clone)]
pub struct GovernanceGatewayService {
    config: Arc<GovernanceConfig>,
    auth: Arc<GatewayTokenAuthenticator>,
}

impl GovernanceGatewayService {
    /// Creates a service with immutable policy and a separate gateway token.
    pub fn new(config: GovernanceConfig, auth: GatewayTokenAuthenticator) -> Self {
        Self {
            config: Arc::new(config),
            auth: Arc::new(auth),
        }
    }
}

#[tonic::async_trait]
impl proto::governance_gateway_server::GovernanceGateway for GovernanceGatewayService {
    async fn authorize(
        &self,
        request: Request<proto::GovernanceAuthorizationRequest>,
    ) -> Result<Response<proto::GovernanceAuthorizationDecision>, Status> {
        self.auth
            .authenticate(request.metadata())
            .map_err(|error| error.into_status())?;
        let request = parse_authorization_request(request.into_inner())?;
        let allowed = self.config.allows(&request);
        let decision = if allowed {
            proto::GovernanceAuthorizationDecision {
                outcome: proto::GovernanceOutcome::Allowed as i32,
                policy_id: self.config.policy_id.as_str().to_owned(),
                reason_code: ALLOWED_REASON.to_owned(),
                field_restrictions: self
                    .config
                    .field_restrictions
                    .iter()
                    .map(|field| field.as_str().to_owned())
                    .collect(),
            }
        } else {
            proto::GovernanceAuthorizationDecision {
                outcome: proto::GovernanceOutcome::Denied as i32,
                policy_id: self.config.policy_id.as_str().to_owned(),
                reason_code: DENIED_REASON.to_owned(),
                field_restrictions: Vec::new(),
            }
        };
        Ok(Response::new(decision))
    }

    async fn get_policy(
        &self,
        request: Request<proto::GovernancePolicyRequest>,
    ) -> Result<Response<proto::GovernancePolicySnapshot>, Status> {
        self.auth
            .authenticate(request.metadata())
            .map_err(|error| error.into_status())?;
        let scope = request.into_inner().scope.ok_or_else(invalid_request)?;
        let scope = GovernanceScope::new(scope.workspace_id, scope.namespace_id)
            .map_err(|_| invalid_request())?;
        if !self.config.allowed_scopes.contains(&scope) {
            return Err(Status::permission_denied(
                "GOVERNANCE_SCOPE_DENIED: request rejected safely",
            ));
        }
        Ok(Response::new(proto::GovernancePolicySnapshot {
            scope: Some(proto::GovernanceScope {
                workspace_id: scope.workspace_id().to_owned(),
                namespace_id: scope.namespace_id().to_owned(),
            }),
            policy_id: self.config.policy_id.as_str().to_owned(),
            revision: self.config.revision,
        }))
    }
}

fn parse_authorization_request(
    input: proto::GovernanceAuthorizationRequest,
) -> Result<AuthorizationRequest, Status> {
    let caller = input.caller.ok_or_else(invalid_request)?;
    let scope = input.scope.ok_or_else(invalid_request)?;
    let trace = input.trace.ok_or_else(invalid_request)?;
    let scope = GovernanceScope::new(scope.workspace_id, scope.namespace_id)
        .map_err(|_| invalid_request())?;
    let caller = Caller::authenticated_for_agent(caller.principal, caller.agent_id, [scope.key()])
        .map_err(|_| invalid_request())?;
    let tool = ToolName::new(input.tool).map_err(|_| invalid_request())?;
    let action = ActionName::new(input.action).map_err(|_| invalid_request())?;
    let resource = ResourceName::new(input.resource).map_err(|_| invalid_request())?;
    let classification = match input.classification.as_str() {
        "public" => DataClassification::Public,
        "internal" => DataClassification::Internal,
        CLASSIFICATION => DataClassification::Confidential,
        "restricted" => DataClassification::Restricted,
        _ => return Err(invalid_request()),
    };
    let trace = TraceContext::new(
        trace.trace_id,
        Some(trace.span_id),
        None::<String>,
        None::<String>,
    )
    .map_err(|_| invalid_request())?;
    AuthorizationRequest::new(caller, scope, tool, action, resource, classification, trace)
        .map_err(|_| invalid_request())
}

fn invalid_config() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid governance configuration",
    )
}

fn invalid_request() -> Status {
    Status::invalid_argument("INVALID_GOVERNANCE_REQUEST: request rejected safely")
}

fn is_portfolio_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
}

fn portfolio_resource_reference(portfolio_id: &str) -> String {
    format!(
        "portfolio:sha256:{:x}",
        Sha256::digest(portfolio_id.as_bytes())
    )
}
