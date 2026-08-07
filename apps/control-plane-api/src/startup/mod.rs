//! Binary process startup: env parsing, secret loading, TLS, and service
//! wiring. Bin-only (declared from `main.rs`, not from `lib.rs`), mirroring
//! `apps/event-ingest/src/startup/`.

mod env;
mod secrets;
mod service;

#[cfg(test)]
mod tests;

pub(crate) use service::run;
