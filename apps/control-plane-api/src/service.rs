//! The `ControlGateway` tonic service: authenticate the operator, validate
//! and canonicalize the command into a `control` event, and durably enqueue
//! it. Modeled on `apex_event_ingest`'s `AuthenticatedGrpcService`
//! (`apps/event-ingest/src/auth/service.rs`), but with its own independent
//! auth boundary and without any dependency on the ingest data path being
//! reachable.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::auth::{OperatorCredentialResolver, OperatorTokenAuthenticator};
use crate::envelope::{ControlCommandInput, build_control_request};
use crate::errors::CommandError;
use crate::outbox::{ControlOutboxBackend, submit_command};
use crate::proto;

/// Admission rate limit applied per authenticated operator subject, after
/// auth succeeds. This is a separate control from
/// `OperatorTokenAuthenticator`'s auth-failure throttling: it bounds how
/// many *accepted-auth* commands a single operator identity can submit, so
/// a legitimate-but-compromised or malfunctioning operator credential
/// cannot flood the durable outbox.
const MAX_COMMANDS_PER_WINDOW: u32 = 50;
const ADMISSION_WINDOW: Duration = Duration::from_secs(1);
const MAX_TRACKED_OPERATORS: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct AdmissionBucket {
    window_started: Instant,
    count: u32,
}

pub struct ControlGatewayService<R: OperatorCredentialResolver> {
    auth: Arc<OperatorTokenAuthenticator<R>>,
    outbox: Arc<ControlOutboxBackend>,
    admission: Mutex<HashMap<String, AdmissionBucket>>,
}

impl<R: OperatorCredentialResolver> ControlGatewayService<R> {
    pub fn new(auth: OperatorTokenAuthenticator<R>, outbox: Arc<ControlOutboxBackend>) -> Self {
        Self {
            auth: Arc::new(auth),
            outbox,
            admission: Mutex::new(HashMap::new()),
        }
    }

    fn admit(&self, subject: &str) -> Result<(), CommandError> {
        let Ok(mut buckets) = self.admission.lock() else {
            return Err(CommandError::internal());
        };
        let now = Instant::now();
        if !buckets.contains_key(subject) && buckets.len() >= MAX_TRACKED_OPERATORS {
            return Err(CommandError::rate_limited());
        }
        let bucket = buckets.entry(subject.to_owned()).or_insert(AdmissionBucket {
            window_started: now,
            count: 0,
        });
        if bucket.window_started.elapsed() >= ADMISSION_WINDOW {
            *bucket = AdmissionBucket {
                window_started: now,
                count: 0,
            };
        }
        if bucket.count >= MAX_COMMANDS_PER_WINDOW {
            return Err(CommandError::rate_limited());
        }
        bucket.count += 1;
        Ok(())
    }
}

pub fn bounded_control_gateway_server<R>(
    service: ControlGatewayService<R>,
) -> proto::control_gateway_server::ControlGatewayServer<ControlGatewayService<R>>
where
    R: OperatorCredentialResolver,
{
    proto::control_gateway_server::ControlGatewayServer::new(service)
        .max_decoding_message_size(crate::MAX_CONTROL_REQUEST_BYTES)
}

#[tonic::async_trait]
impl<R: OperatorCredentialResolver> proto::control_gateway_server::ControlGateway
    for ControlGatewayService<R>
{
    async fn submit_command(
        &self,
        request: tonic::Request<proto::ControlCommandRequest>,
    ) -> Result<tonic::Response<proto::ControlCommandResponse>, tonic::Status> {
        // Independent auth boundary: never falls through to any ingest-path
        // credential, and failures here never touch the ingest rate-limit or
        // idempotency state.
        let operator = self
            .auth
            .authenticate(request.metadata())
            .map_err(CommandError::into_status)?;
        self.admit(operator.subject()).map_err(CommandError::into_status)?;

        let input = ControlCommandInput::from_request(request.into_inner());
        let (command_id, ingest_request) =
            build_control_request(input, &operator).map_err(CommandError::into_status)?;

        let outbox = self.outbox.clone();
        let outcome = tokio::task::spawn_blocking(move || submit_command(&outbox, &ingest_request))
            .await
            .map_err(|_| CommandError::internal().into_status())?
            .map_err(CommandError::into_status)?;

        Ok(tonic::Response::new(proto::ControlCommandResponse {
            duplicate: outcome.duplicate,
            command_id,
            delivered: outcome.delivered,
        }))
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use apex_event_ingest::InMemoryOutbox;
    use prost_types::Struct as ProstStruct;

    use super::*;
    use crate::auth::{OperatorCaller, StaticOperatorTokenResolver};
    use crate::proto::control_gateway_server::ControlGateway as _;

    fn service() -> ControlGatewayService<StaticOperatorTokenResolver> {
        let resolver = StaticOperatorTokenResolver::new().with_token(
            "op-token",
            OperatorCaller::scoped("operator:zack", ["acme/prod"]).unwrap(),
        );
        let outbox: Box<dyn apex_event_ingest::EventOutbox + Send> =
            Box::new(InMemoryOutbox::new(64).unwrap());
        ControlGatewayService::new(
            OperatorTokenAuthenticator::new(resolver),
            Arc::new(ControlOutboxBackend::new(outbox)),
        )
    }

    fn authed_request(body: proto::ControlCommandRequest) -> tonic::Request<proto::ControlCommandRequest> {
        let mut request = tonic::Request::new(body);
        request
            .metadata_mut()
            .insert("authorization", "Bearer op-token".parse().unwrap());
        request
    }

    fn stop_request() -> proto::ControlCommandRequest {
        proto::ControlCommandRequest {
            command_id: None,
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            agent_id: "agent-1".to_owned(),
            run_id: "run-1".to_owned(),
            parent_run_id: None,
            trace_id: "trace-1".to_owned(),
            action: proto::ControlAction::Stop as i32,
            reason_code: Some("operator.request".to_owned()),
            parameters: Some(ProstStruct::default()),
        }
    }

    #[tokio::test]
    async fn submit_command_accepts_a_well_formed_stop_command() {
        let service = service();
        let response = service
            .submit_command(authed_request(stop_request()))
            .await
            .unwrap()
            .into_inner();
        assert!(!response.duplicate);
        assert!(!response.command_id.is_empty());
    }

    #[tokio::test]
    async fn submit_command_is_idempotent_for_a_repeated_command_id() {
        let service = service();
        let mut request = stop_request();
        request.command_id = Some("018f0000-0000-7000-8000-000000000001".to_owned());
        let first = service
            .submit_command(authed_request(request.clone()))
            .await
            .unwrap()
            .into_inner();
        let second = service
            .submit_command(authed_request(request))
            .await
            .unwrap()
            .into_inner();
        assert!(!first.duplicate);
        assert!(second.duplicate);
        assert_eq!(first.command_id, second.command_id);
    }

    #[tokio::test]
    async fn submit_command_rejects_a_reused_command_id_with_different_fields() {
        let service = service();
        let mut first_request = stop_request();
        first_request.command_id = Some("018f0000-0000-7000-8000-000000000002".to_owned());
        service
            .submit_command(authed_request(first_request))
            .await
            .unwrap();

        let mut second_request = stop_request();
        second_request.command_id = Some("018f0000-0000-7000-8000-000000000002".to_owned());
        second_request.action = proto::ControlAction::Pause as i32; // different fields, same id.
        let status = service
            .submit_command(authed_request(second_request))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn submit_command_rate_limits_a_single_operator_after_the_per_second_ceiling() {
        let service = service();
        for index in 0..MAX_COMMANDS_PER_WINDOW {
            let mut request = stop_request();
            request.command_id = Some(format!("018f0000-0000-7000-8000-{index:012}"));
            service
                .submit_command(authed_request(request))
                .await
                .unwrap();
        }
        let mut request = stop_request();
        request.command_id = Some("018f0000-0000-7000-8000-999999999999".to_owned());
        let status = service
            .submit_command(authed_request(request))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn submit_command_handles_concurrent_duplicate_submissions_without_a_torn_write() {
        let service = Arc::new(service());
        let command_id = "018f0000-0000-7000-8000-0000000000ab".to_owned();
        let mut handles = Vec::new();
        for _ in 0..8 {
            let service = service.clone();
            let mut request = stop_request();
            request.command_id = Some(command_id.clone());
            handles.push(tokio::spawn(async move {
                service.submit_command(authed_request(request)).await
            }));
        }
        let mut accepted_non_duplicate = 0;
        for handle in handles {
            let response = handle.await.unwrap().unwrap().into_inner();
            assert_eq!(response.command_id, command_id);
            if !response.duplicate {
                accepted_non_duplicate += 1;
            }
        }
        // Exactly one concurrent submission of the same command_id with the
        // same fields is the "first" acceptance; every other racer must see
        // it as a duplicate, never as a second independent enqueue.
        assert_eq!(accepted_non_duplicate, 1);
    }

    #[tokio::test]
    async fn submit_command_rejects_a_scope_the_operator_does_not_hold() {
        let service = service();
        let mut request = stop_request();
        request.workspace_id = "other-workspace".to_owned();
        let status = service
            .submit_command(authed_request(request))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn submit_command_rejects_missing_authentication() {
        let service = service();
        let request = tonic::Request::new(stop_request());
        let status = service.submit_command(request).await.unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn submit_command_rejects_inject_without_untrusted_classification() {
        let service = service();
        let mut request = stop_request();
        request.action = proto::ControlAction::Inject as i32;
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "content".to_owned(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue("hello".to_owned())),
            },
        );
        // Missing content_classification: "untrusted" -- must be rejected.
        request.parameters = Some(ProstStruct {
            fields: fields.into_iter().collect(),
        });
        let status = service
            .submit_command(authed_request(request))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn submit_command_rejects_a_negative_budget_limit() {
        let service = service();
        let mut request = stop_request();
        request.action = proto::ControlAction::SetBudget as i32;
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "budget_kind".to_owned(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue("tokens".to_owned())),
            },
        );
        fields.insert(
            "limit".to_owned(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::NumberValue(-1.0)),
            },
        );
        request.parameters = Some(ProstStruct {
            fields: fields.into_iter().collect(),
        });
        let status = service
            .submit_command(authed_request(request))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }
}
