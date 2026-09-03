//! gRPC codec that keeps decoder failures inside the contract's public error
//! boundary.
//!
//! `tonic_prost::ProstCodec` maps every protobuf decode failure to
//! `Status::internal(error.to_string())`, which leaks the generated message
//! graph and presents caller-controlled malformed input as a retryable server
//! failure. The contract crate collapses those failures to one stable,
//! redacted `INVALID_ENVELOPE` invalid-argument status.

use std::marker::PhantomData;

use prost::Message;
use tonic::Status;
use tonic::codec::{BufferSettings, Codec, DecodeBuf, Decoder};

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
        self.inner.encoder()
    }

    fn decoder(&mut self) -> Self::Decoder {
        RedactedProstDecoder {
            _pd: PhantomData,
            buffer_settings: BufferSettings::default(),
        }
    }
}

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
            Err(_) => Err(redacted_decode_status()),
        }
    }

    fn buffer_settings(&self) -> BufferSettings {
        self.buffer_settings
    }
}

pub fn redacted_decode_status() -> Status {
    Status::invalid_argument("INVALID_ENVELOPE: The event envelope could not be decoded.")
}

pub use tonic_prost::ProstEncoder as RedactedProstEncoder;

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn decode_failures_are_redacted_invalid_argument_not_internal() {
        let status = redacted_decode_status();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(status.message().contains("INVALID_ENVELOPE"));
    }

    #[test]
    fn decode_failures_do_not_leak_the_internal_message_graph() {
        let leaked = upstream_message();
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
