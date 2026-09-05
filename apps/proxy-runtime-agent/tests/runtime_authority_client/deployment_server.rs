//! Resolution adapter for the existing real two-hop TLS fixture only.

use super::{Callback, Ingress};
use crate::support::{HASH, snapshot, status, target};
use apex_proxy_runtime_agent::{
    authority::AuthorityOperation,
    proto::{
        self, runtime_authority_service_server::RuntimeAuthorityService,
        runtime_deployment_service_server::RuntimeDeploymentService,
    },
};
use std::sync::{Arc, atomic::Ordering};
use tonic::{Request, Response, Status};

pub fn deployment_snapshot() -> proto::RuntimeDeploymentSnapshot {
    // Independent wire golden, adapted to the existing TLS fixture's scope and
    // large generation. No field is taken from the caller's request/manifest.
    let mut configuration: proto::RuntimeConfiguration =
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/fixtures/mcp-proxy/runtime-revision.json"
        )))
        .unwrap();
    let target = target();
    configuration.workspace_id = target.workspace_id;
    configuration.namespace_id = target.namespace_id;
    configuration.proxy_id = target.proxy_id;
    configuration.revision_id = target.revision_id;
    configuration.generation = target.generation;
    configuration.config_hash = HASH.into();
    configuration.runtime_manifest_hash =
        apex_proxy_runtime_agent::runtime_manifest_hash(&configuration).unwrap();
    proto::RuntimeDeploymentSnapshot {
        schema_version: 1,
        authority: Some(snapshot()),
        configuration: Some(configuration),
        deployment_bindings_version: "bindings-1".into(),
    }
}

#[tonic::async_trait]
impl RuntimeDeploymentService for Callback {
    async fn resolve_runtime_deployment(
        &self,
        request: Request<proto::CheckRuntimeAuthorityRequest>,
    ) -> Result<Response<proto::RuntimeDeploymentSnapshot>, Status> {
        self.state.resolve_calls.fetch_add(1, Ordering::SeqCst);
        // Reuse the callback's actual agent TLS/controller-pin authorization,
        // metadata checks, bounded counter, hold/cancellation and remote errors.
        self.check_runtime_authority(request).await?;
        Ok(Response::new(self.state.deployment.lock().unwrap().clone()))
    }
}

#[tonic::async_trait]
impl RuntimeDeploymentService for Ingress {
    async fn resolve_runtime_deployment(
        &self,
        request: Request<proto::CheckRuntimeAuthorityRequest>,
    ) -> Result<Response<proto::RuntimeDeploymentSnapshot>, Status> {
        let (policy, budget, config_hash) = {
            let settings = self.state.settings.lock().unwrap();
            (
                Arc::clone(&settings.policy),
                settings.budget,
                settings.config_hash.clone(),
            )
        };
        let body = request.get_ref();
        let operation = AuthorityOperation {
            target: body
                .target
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("test target"))?,
            operation_id: &body.operation_id,
            command_id: &body.command_id,
            config_hash: &config_hash,
        };
        // Borrow the original controller TLS request through the production API.
        // Only the validated read-only accessors can cross this test wire bridge.
        tokio::select! {
            result = self.client.resolve(&request, &policy, operation, budget) => {
                let resolved = result.map_err(status)?;
                assert_eq!(format!("{resolved:?}"), "ResolvedDeployment { [redacted] }");
                Ok(Response::new(proto::RuntimeDeploymentSnapshot {
                    schema_version: 1,
                    authority: Some(resolved.authority().clone()),
                    configuration: Some(resolved.configuration().clone()),
                    deployment_bindings_version: resolved.bindings_version().into(),
                }))
            }
            () = self.state.cancel.notified() => Err(Status::cancelled("test owner cancelled")),
        }
    }
}
