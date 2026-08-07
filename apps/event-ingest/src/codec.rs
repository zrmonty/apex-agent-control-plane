//! gRPC codec that keeps decoder failures inside the gateway's error contract.
//!
//! `tonic_prost::ProstCodec` maps every protobuf decode failure to
//! `Status::internal(error.to_string())`. Two problems with that at this
//! boundary:
//!
//! 1. **It leaks internals.** `prost::DecodeError::to_string()` renders the
//!    full field path it failed on, e.g.
//!    `failed to decode Protobuf message: EventEnvelope.data: Struct.fields:
//!    Value.struct_value: recursion limit reached`. Every other rejection the
//!    gateway emits goes through `GatewayError`, which is deliberately
//!    redacted. A caller probing the decoder should not learn more about the
//!    internal message graph than a caller probing anything else.
//!
//! 2. **`Internal` is the wrong code, and it is the wrong code in the
//!    dangerous direction.** A malformed or over-nested envelope is caller
//!    error -- `InvalidArgument` -- not server fault. gRPC clients widely
//!    treat `Internal` as retryable, so a client with a deterministic bad
//!    payload will resend it indefinitely, turning a client bug into inbound
//!    load the gateway must keep rejecting.
//!
//! This surfaced concretely on deep nesting: prost's own recursion limit fires
//! while decoding `EventEnvelope.data` *before* the envelope ever reaches
//! `validation::convert::MAX_STRUCT_DEPTH`, so the gateway's own depth check
//! never got the chance to produce its redacted `InvalidArgument`. Nothing
//! landed in either case -- this is a diagnostics and back-pressure fix, not a
//! data-admission one.
//!
//! Wired in through `tonic_prost_build`'s `codec_path`, so every generated
//! client and server in this crate uses it.

use std::marker::PhantomData;

use prost::Message;
use tonic::Status;
use tonic::codec::{BufferSettings, Codec, DecodeBuf, Decoder};

use crate::{GatewayError, GatewayErrorCode};

/// `ProstCodec` with a decoder that reports failures the way the rest of the
/// gateway reports rejections.
#[derive(Debug, Clone)]
pub struct RedactedProstCodec<T, U> {
    inner: tonic_prost::ProstCodec<T, U>,
}

impl<T, U> Default for RedactedProstCodec<T, U> {
    fn default() -> Self {
        Self {
            inner: tonic_prost::ProstCodec::default(),
        }
    }
}

impl<T, U> Codec for RedactedProstCodec<T, U>
where
    T: Message + Send + 'static,
    U: Message + Default + Send + 'static,
{
    type Encode = T;
    type Decode = U;

    type Encoder = tonic_prost::ProstEncoder<T>;
    type Decoder = RedactedProstDecoder<U>;

    fn encoder(&mut self) -> Self::Encoder {
        // Encoding is gateway-authored data, not caller input; nothing to
        // redact on the way out that the error table does not already handle.
        self.inner.encoder()
    }

    fn decoder(&mut self) -> Self::Decoder {
        RedactedProstDecoder {
            _pd: PhantomData,
            buffer_settings: BufferSettings::default(),
        }
    }
}

/// Decoder that answers with the gateway's redacted `INVALID_ENVELOPE`
/// instead of prost's internal field path.
#[derive(Debug, Clone, Default)]
pub struct RedactedProstDecoder<U> {
    _pd: PhantomData<U>,
    buffer_settings: BufferSettings,
}

impl<U: Message + Default> Decoder for RedactedProstDecoder<U> {
    type Item = U;
    type Error = Status;

    fn decode(&mut self, buf: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        match Message::decode(buf) {
            Ok(item) => Ok(Some(item)),
            // Deliberately drops `error`. Its Display carries the internal
            // message graph, and this boundary already treats every other
            // rejection reason as non-disclosable.
            Err(_) => Err(redacted_decode_status()),
        }
    }

    fn buffer_settings(&self) -> BufferSettings {
        self.buffer_settings
    }
}

/// The single status every decode failure collapses to.
///
/// Split out because `DecodeBuf`/`EncodeBuf` cannot be constructed outside
/// tonic (`pub(crate)` constructors), so the mapping is unit-tested here and
/// the wiring is proven end to end over real gRPC by
/// `tests/adversarial_ingest.rs`.
pub(crate) fn redacted_decode_status() -> Status {
    GatewayError::new(GatewayErrorCode::InvalidEnvelope).grpc_status_value()
}

/// Encoder side is unchanged; re-exported so `codec_path` users get a complete
/// codec module without depending on `tonic_prost` directly.
pub use tonic_prost::ProstEncoder as RedactedProstEncoder;

#[cfg(test)]
mod tests {
    use super::*;

    /// What `tonic_prost` would have produced for the deep-nesting case: the
    /// real `prost::DecodeError::to_string()` for a recursion-limit failure.
    /// Pinned here so the test states exactly what is being suppressed.
    fn upstream_message() -> String {
        let mut deepest = prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue("bottom".to_owned())),
        };
        for _ in 0..200 {
            let mut level = prost_types::Struct::default();
            level.fields.insert("n".to_owned(), deepest);
            deepest = prost_types::Value {
                kind: Some(prost_types::value::Kind::StructValue(level)),
            };
        }
        let mut data = prost_types::Struct::default();
        data.fields.insert("deep".to_owned(), deepest);
        let envelope = crate::proto::EventEnvelope {
            data: Some(data),
            ..Default::default()
        };
        let encoded = envelope.encode_to_vec();
        let error = <crate::proto::EventEnvelope as Message>::decode(encoded.as_slice())
            .expect_err("200-level nesting must exceed prost's recursion limit");
        error.to_string()
    }

    /// The upstream default is `Internal` carrying prost's field path. Both
    /// halves of that are wrong at this boundary.
    #[test]
    fn decode_failures_are_redacted_invalid_argument_not_internal() {
        let status = redacted_decode_status();
        assert_eq!(
            status.code(),
            tonic::Code::InvalidArgument,
            "a malformed envelope is caller error; `Internal` reads as a server \
             fault and is widely retried by gRPC clients, so a deterministic bad \
             payload would be resent forever"
        );
        assert!(
            status.message().contains("INVALID_ENVELOPE"),
            "decode failures must route through the gateway error table: {}",
            status.message()
        );
    }

    /// Nothing prost says about the internal message graph may reach a caller.
    #[test]
    fn decode_failures_do_not_leak_the_internal_message_graph() {
        let leaked = upstream_message();
        // Sanity: the upstream string really does carry internal structure, so
        // this test is suppressing something real rather than asserting on an
        // empty set.
        assert!(
            leaked.contains("EventEnvelope") && leaked.contains("recursion limit"),
            "expected prost to name the failing field path, got: {leaked}"
        );

        let message = redacted_decode_status().message().to_owned();
        for leak in [
            "EventEnvelope",
            "Struct.fields",
            "struct_value",
            "recursion limit",
            "failed to decode Protobuf message",
        ] {
            assert!(
                !message.contains(leak),
                "decoder status leaked internal detail {leak:?}: {message}"
            );
        }
    }
}
