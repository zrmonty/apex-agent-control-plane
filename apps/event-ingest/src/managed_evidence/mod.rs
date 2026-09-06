//! Protected per-proxy credentials for the incumbent authenticated ingest path.

mod json;
mod owner;
mod profile;
mod protected;
pub use owner::ManagedEvidenceOwner;

use crate::{BearerTokenResolver, Caller, GatewayError, PeerIdentity};
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Snapshot {
    profile: profile::Profile,
    read_started: Instant,
}

/// Read-only snapshot handle. Requests never perform filesystem IO.
#[derive(Clone)]
pub struct ManagedEvidenceResolver {
    snapshot: Arc<RwLock<Option<Snapshot>>>,
    active: Arc<std::sync::atomic::AtomicBool>,
}

impl BearerTokenResolver for ManagedEvidenceResolver {
    fn resolve(&self, _token: &str) -> Result<Caller, GatewayError> {
        Err(GatewayError::unauthenticated())
    }
    fn resolve_with_peer(
        &self,
        token: &str,
        peer: Option<&PeerIdentity>,
    ) -> Result<Caller, GatewayError> {
        let denied = GatewayError::unauthenticated;
        if !self.active.load(std::sync::atomic::Ordering::Acquire) {
            return Err(denied());
        }
        let peer = peer.ok_or_else(denied)?;
        if token.is_empty() || token.len() > 4096 || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(denied());
        }
        let token: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let snapshot = self.snapshot.try_read().map_err(|_| denied())?;
        let snapshot = snapshot.as_ref().ok_or_else(denied)?;
        let now = now_us().map_err(|_| denied())?;
        if snapshot.read_started.elapsed() >= Duration::from_secs(5)
            || now < snapshot.profile.valid_from
            || now >= snapshot.profile.expires
        {
            return Err(denied());
        }
        let mut selected = None;
        for credential in &snapshot.profile.credentials {
            let difference = credential
                .token
                .iter()
                .zip(token)
                .chain(credential.certificate.iter().zip(peer.certificate_sha256))
                .fold(0u8, |difference, (a, b)| difference | (a ^ b));
            if difference == 0 {
                if selected.is_some() {
                    return Err(denied());
                }
                selected = Some(credential.caller.clone());
            }
        }
        selected.ok_or_else(denied)
    }
}

fn now_us() -> Result<i64, EnrollmentError> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| EnrollmentError)?
            .as_micros(),
    )
    .map_err(|_| EnrollmentError)
}

/// Enrollment failures deliberately carry no source data or filesystem paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollmentError;

impl std::fmt::Display for EnrollmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("managed evidence enrollment refused")
    }
}
impl std::error::Error for EnrollmentError {}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "test-support"))]
mod tls_tests;

#[cfg(all(test, feature = "test-support"))]
mod typed_client_tests;
