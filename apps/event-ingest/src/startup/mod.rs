//! Binary process startup: env, secrets, auth resolver, and service wiring.

mod auth;
mod env;
mod error;
mod secrets;
mod service;

#[cfg(test)]
mod tests;

pub(crate) use service::run;
