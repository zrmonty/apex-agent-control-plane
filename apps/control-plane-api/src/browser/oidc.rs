//! OIDC code flow using fixed deployment endpoints, library protocol/JOSE
//! validation and a bounded HTTP transport. Access grants remain in Keycloak's
//! existing operator resolver, separate from ID-token login validation.

pub mod config;
mod protocol;
pub mod verify;
pub use protocol::AuthorizationChallenge;
mod http;
mod provider;
mod tokens;
pub use provider::OidcProvider;
pub use tokens::VerifiedProviderTokens;
