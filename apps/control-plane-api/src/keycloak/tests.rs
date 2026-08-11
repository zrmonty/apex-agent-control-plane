//! Offline verification tests for [`super`].
//!
//! Every rejection the resolver has to make is exercised here against locally
//! minted tokens, so the whole taxonomy is covered in ordinary unit CI with no
//! network. `tests/live_control_keycloak.rs` then proves the same code path
//! against a *real* Keycloak's real JWKS and real issued tokens, because a
//! hand-rolled JWT mock can agree with a hand-rolled verifier while both
//! disagree with the identity provider.
//!
//! Grouped the same way the implementation is: `verify` (the token-rejection
//! taxonomy), `config` (`KeycloakConfig::validate`), and `resolver`
//! (`KeycloakOperatorCredentialResolver`'s staleness/error-uniformity
//! contract). `support` holds the fixtures -- including the throwaway RSA
//! key material -- shared across all three.

mod config;
mod resolver;
mod support;
mod verify;
