//! Live operator-credential tests against a **real Keycloak**.
//!
//! Enabled only when `APEX_CONTROL_LIVE_KEYCLOAK=1`, so offline unit CI stays
//! green. Start the stack with
//! `deploy/compose/compose.gateway-ref.yaml -f compose.control-keycloak.yaml`.
//!
//! `src/keycloak/tests.rs` already covers every rejection offline against
//! locally minted tokens and a fixture JWKS. This file exists because that is
//! not the same claim: a hand-rolled mock and a hand-rolled verifier can agree
//! with each other while both disagree with the identity provider. What only a
//! real Keycloak can establish is that the verifier works against the shape
//! Keycloak actually emits -- `aud` as an *array* carrying `account` alongside
//! the audience we asked for, `typ` as a payload claim rather than a header
//! one, a `kid` that is a base64url thumbprint, roles nested under
//! `realm_access.roles`, and a JWKS that publishes an `RSA-OAEP`/`use: enc`
//! key next to the signing key.
//!
//! The last of those is the one worth stating plainly: Keycloak's JWKS
//! contains a key this verifier must never verify a signature with, and it is
//! there by default, in every realm, with no misconfiguration required.
//!
//! Two halves, `verifier` and `deployed`; `support` holds the fixtures shared
//! across both (minting real tokens through Keycloak's own
//! `client_credentials` grant, the lab mTLS CA, and the resolver-under-test
//! constructor):
//!
//!  1. `verifier`: `KeycloakOperatorCredentialResolver` driven directly,
//!     fetching the real JWKS over HTTPS and verifying real tokens. This is
//!     where the negative cases live, because minting them requires driving
//!     Keycloak's own clients (a one-second token lifespan, a second realm,
//!     an over-broad claim mapper).
//!  2. `deployed`: a `control-plane-api` container configured with
//!     `APEX_CONTROL_KEYCLOAK_ISSUER` and nothing else, accepting a real
//!     Keycloak token over mTLS. Without this, `build_operator_resolver`'s
//!     third branch would be untested in the only place it actually runs --
//!     the class of gap that has already reached `master` in this repository
//!     twice (an unwired fanout worker, an inert `postgres` feature).

// Integration-test crate roots resolve a bodiless `mod x;` relative to
// `tests/` itself (like `src/main.rs`/`src/lib.rs` do for `src/`), not a
// `tests/live_control_keycloak/` subdirectory named after this file -- hence
// the explicit `#[path]` on each, pointing at the actual sibling-directory
// layout (the same pattern `tests/live_control_poll.rs` uses).
#[path = "live_control_keycloak/deployed.rs"]
mod deployed;
#[path = "live_control_keycloak/support.rs"]
mod support;
#[path = "live_control_keycloak/verifier.rs"]
mod verifier;
