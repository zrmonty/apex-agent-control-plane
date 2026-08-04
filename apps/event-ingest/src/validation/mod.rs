//! Event envelope admission: identifiers, structure, control shape, secret
//! policy, and RFC 8785 integrity hashing.

mod caller;
mod canonical;
mod control;
mod convert;
mod identifiers;
mod request;
mod secrets;

#[cfg(test)]
mod tests;

pub use caller::Caller;
pub use request::IngestRequest;

pub(crate) use identifiers::{is_lowercase_uuidv7, is_scope_identifier};
