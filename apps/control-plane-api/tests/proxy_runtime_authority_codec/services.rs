use super::support::*;
use apex_control_plane_api::proto;
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tonic::{
    Request, Response, Status,
    body::Body,
    codegen::{BoxFuture, Service, http},
};

pub struct MarkerService(pub Arc<AtomicUsize>);

#[tonic::async_trait]
impl proto::runtime_authority_service_server::RuntimeAuthorityService for MarkerService {
    async fn check_runtime_authority(
        &self,
        request: Request<proto::CheckRuntimeAuthorityRequest>,
    ) -> Result<Response<proto::RuntimeAuthoritySnapshot>, Status> {
        assert_eq!(request.into_inner(), authority_request());
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Status::unimplemented(MARKER))
    }
}

// All generated legacy trait methods are marker-only; only SubmitCommand is
// exercised. No production handler, authentication, outbox or action executes.
macro_rules! legacy_markers {
    ($(($method:ident, $input:ident, $output:ident)),+ $(,)?) => {
        #[tonic::async_trait]
        impl proto::control_gateway_server::ControlGateway for MarkerService {
            $(async fn $method(&self, request: Request<proto::$input>)
                -> Result<Response<proto::$output>, Status> {
                assert!(prost::Message::encoded_len(request.get_ref()) + 5 <= LIMIT);
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(Status::unimplemented(MARKER))
            })+
        }
    };
}
legacy_markers! {
    (submit_command, ControlCommandRequest, ControlCommandResponse),
    (poll_commands, PollCommandsRequest, PollCommandsResponse),
    (ack_command, AckCommandRequest, AckCommandResponse),
    (get_command_status, GetCommandStatusRequest, GetCommandStatusResponse),
    (list_commands, ListCommandsRequest, ListCommandsResponse),
    (cancel_command, CancelCommandRequest, CancelCommandResponse),
    (submit_bulk_command, SubmitBulkCommandRequest, SubmitBulkCommandResponse),
}

#[derive(Clone, Default)]
pub struct MalformedReply {
    pub calls: Arc<AtomicUsize>,
    pub corrupt: Arc<AtomicBool>,
}

impl tonic::server::NamedService for MalformedReply {
    const NAME: &'static str = "apex.v1.RuntimeAuthorityService";
}

impl tonic::server::UnaryService<proto::CheckRuntimeAuthorityRequest> for MalformedReply {
    type Response = Vec<u8>;
    type Future = BoxFuture<Response<Vec<u8>>, Status>;
    fn call(&mut self, request: Request<proto::CheckRuntimeAuthorityRequest>) -> Self::Future {
        assert_eq!(request.into_inner(), authority_request());
        self.calls.fetch_add(1, Ordering::SeqCst);
        let corrupt = self.corrupt.load(Ordering::SeqCst);
        Box::pin(async move {
            if corrupt {
                Ok(Response::new(BAD_TARGET.to_vec()))
            } else {
                Err(Status::unimplemented(MARKER))
            }
        })
    }
}

impl Service<http::Request<Body>> for MalformedReply {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;
    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Infallible>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let service = self.clone();
        Box::pin(async move {
            if request.uri().path() != AUTHORITY_PATH {
                return Ok(Status::unimplemented("TEST_ONLY_WRONG_PATH").into_http());
            }
            let mut grpc = tonic::server::Grpc::new(
                RawCodec::<proto::CheckRuntimeAuthorityRequest>::default(),
            )
            .max_decoding_message_size(LIMIT)
            .max_encoding_message_size(LIMIT);
            Ok(grpc.unary(service, request).await)
        })
    }
}
