//! Versioned, transport-neutral Apex event contracts.
//!
//! This crate owns the generated v1 event API and its redacted gRPC codec so
//! service applications can share the wire contract without depending on one
//! another's implementation modules.

mod codec;

pub use codec::{RedactedProstCodec, RedactedProstDecoder, RedactedProstEncoder};

pub mod proto {
    tonic::include_proto!("apex.v1");
}
