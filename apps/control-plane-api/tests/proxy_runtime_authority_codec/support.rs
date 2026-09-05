use apex_control_plane_api::proto;
use prost::{Message, bytes::BufMut};
use std::{future::Future, marker::PhantomData, time::Duration};
use tokio::{sync::oneshot, task::JoinHandle, time::timeout};
use tonic::{
    Code, Request, Response, Status,
    codec::{BufferSettings, Codec, EncodeBuf, Encoder},
    transport::{
        Channel, Endpoint,
        server::{Router, TcpIncoming},
    },
};

pub const LIMIT: usize = 4096;
pub const RPC: Duration = Duration::from_secs(2);
const CASE: Duration = Duration::from_secs(12);
const CLEANUP: Duration = Duration::from_secs(2);
pub const MARKER: &str = "TEST_ONLY_CODEC_HANDLER_UNIMPLEMENTED";
pub const AUTHORITY_PATH: &str = "/apex.v1.RuntimeAuthorityService/CheckRuntimeAuthority";
pub const LEGACY_PATH: &str = "/apex.v1.ControlGateway/SubmitCommand";
// Complete protobuf field2 RuntimeTarget, with invalid UTF-8 in field1 workspace_id.
pub const BAD_TARGET: &[u8] = &[0x12, 0x03, 0x0a, 0x01, 0xff];
pub const BAD_LEGACY: &[u8] = &[0x12, 0x01, 0xff];

pub fn authority_request() -> proto::CheckRuntimeAuthorityRequest {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/fixtures/mcp-proxy/runtime-authority.json"
    ))
    .unwrap();
    let request: proto::CheckRuntimeAuthorityRequest =
        serde_json::from_value(fixture["request"].clone()).unwrap();
    assert!(request.encoded_len() + 5 <= LIMIT);
    request
}

pub fn legacy_request() -> proto::ControlCommandRequest {
    let request = proto::ControlCommandRequest {
        workspace_id: "codec-test".into(),
        ..Default::default()
    };
    assert!(request.encoded_len() + 5 <= LIMIT);
    request
}

pub fn request<T>(value: T) -> Request<T> {
    let mut request = Request::new(value);
    request.set_timeout(RPC);
    request
}

pub async fn within<F: Future>(future: F) -> F::Output {
    timeout(RPC, future)
        .await
        .expect("transport deadline is test failure")
}

pub async fn connect(endpoint: String) -> Channel {
    within(
        Endpoint::from_shared(endpoint)
            .unwrap()
            .connect_timeout(RPC)
            .timeout(RPC)
            .connect(),
    )
    .await
    .expect("owned loopback connection")
}

pub fn marker(status: Status) {
    assert_eq!(status.code(), Code::Unimplemented);
    assert_eq!(status.message(), MARKER);
    assert!(status.details().is_empty());
}

pub fn redacted(status: Status) {
    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(
        status.message(),
        "INVALID_ENVELOPE: The event envelope could not be decoded."
    );
    assert!(status.details().is_empty());
    let public_debug = format!("{status:?}");
    for graph in [
        "CheckRuntimeAuthorityRequest",
        "RuntimeAuthoritySnapshot",
        "RuntimeTarget",
        "ControlCommandRequest",
        "workspace_id",
        "failed to decode Protobuf message",
        "invalid string value",
    ] {
        assert!(
            !public_debug.contains(graph),
            "public status leaked {graph}"
        );
    }
}

pub fn malformed_control<T: Message + Default>(bytes: &[u8], message: &str) {
    assert!(bytes.len() + 5 <= LIMIT);
    let Err(error) = T::decode(bytes) else {
        panic!("fixture must fail actual prost decoding")
    };
    let graph = error.to_string();
    assert!(
        graph.contains(message) && graph.contains("workspace_id"),
        "wrong malformed fixture"
    );
}

// Only the encoder bypasses protobuf construction. Tonic still supplies actual
// HTTP/2 and complete gRPC framing; the receiving generated codec is under test.
pub struct RawCodec<T>(PhantomData<T>);
impl<T> Default for RawCodec<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}
impl<T: Message + Default + Send + 'static> Codec for RawCodec<T> {
    type Encode = Vec<u8>;
    type Decode = T;
    type Encoder = RawEncoder;
    type Decoder = apex_contract::RedactedProstDecoder<T>;
    fn encoder(&mut self) -> Self::Encoder {
        RawEncoder
    }
    fn decoder(&mut self) -> Self::Decoder {
        Default::default()
    }
}

pub struct RawEncoder;
impl Encoder for RawEncoder {
    type Item = Vec<u8>;
    type Error = Status;
    fn encode(&mut self, item: Vec<u8>, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        if item.len() > LIMIT - 5 {
            return Err(Status::resource_exhausted("TEST_ONLY_WIRE_LIMIT"));
        }
        dst.put_slice(&item);
        Ok(())
    }
    fn buffer_settings(&self) -> BufferSettings {
        BufferSettings::new(LIMIT, LIMIT)
    }
}

pub async fn raw_call<T: Message + Default + Send + Sync + 'static>(
    channel: Channel,
    path: &'static str,
    bytes: &[u8],
) -> Status {
    assert!(bytes.len() + 5 <= LIMIT);
    let mut client = tonic::client::Grpc::new(channel)
        .max_encoding_message_size(LIMIT)
        .max_decoding_message_size(LIMIT);
    within(client.ready()).await.expect("raw client ready");
    let result: Result<Response<T>, Status> = within(client.unary(
        request(bytes.to_vec()),
        tonic::codegen::http::uri::PathAndQuery::from_static(path),
        RawCodec::<T>::default(),
    ))
    .await;
    match result {
        Err(status) => status,
        Ok(_) => panic!("malformed request unexpectedly returned a message"),
    }
}

struct OwnedTask<T>(JoinHandle<T>);
impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// Body assertions run in an owned task: even a semantic RED/panic is joined,
// then the listener is stopped/joined before that failure reaches the test owner.
pub async fn exercise<F, Fut>(router: Router, body: F)
where
    F: FnOnce(String) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = incoming.local_addr().unwrap();
    assert!(address.ip().is_loopback());
    let endpoint = format!("http://{address}");
    let (stop, stopped) = oneshot::channel();
    let mut server = OwnedTask(tokio::spawn(async move {
        router
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stopped.await;
            })
            .await
    }));
    let mut case = OwnedTask(tokio::spawn(async move { body(endpoint).await }));
    let outcome = timeout(CASE, &mut case.0).await;
    let body_reaped = if outcome.is_err() {
        case.0.abort();
        timeout(CLEANUP, &mut case.0).await.is_ok()
    } else {
        true
    };
    let _ = stop.send(());
    let graceful = match timeout(CLEANUP, &mut server.0).await {
        Ok(Ok(Ok(()))) => true,
        Ok(_) => false,
        Err(_) => {
            server.0.abort();
            let _ = timeout(CLEANUP, &mut server.0).await;
            false
        }
    };
    assert!(body_reaped, "test body abort/reap deadline failed");
    assert!(
        graceful,
        "listener must join gracefully; abort/timeout is failure"
    );
    drop(TcpIncoming::bind(address).expect("exact owned listener must be released"));
    outcome
        .expect("case watchdog is failure, never a skip")
        .expect("test body failed after owned listener cleanup");
}
