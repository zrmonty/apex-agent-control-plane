use std::collections::HashSet;
use std::env;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use apex_event_ingest::{BearerTokenResolver, Caller, PeerIdentity};

use super::env::valid_identifier;
use super::secrets::{read_token, trusted_secret_path};

const TOKEN_RELOAD_INTERVAL: Duration = Duration::from_secs(5);

struct TokenCache {
    token: Zeroizing<String>,
    loaded_at: Instant,
}

pub(crate) struct FileBearerResolver {
    token_path: PathBuf,
    trusted_base: PathBuf,
    token_cache: Arc<Mutex<TokenCache>>,
    pub(crate) subject: String,
    pub(crate) agent_id: String,
    pub(crate) scopes: Arc<HashSet<String>>,
    pub(crate) expected_peer_certificate: [u8; 32],
}

impl FileBearerResolver {
    pub(crate) fn new(
        token: Zeroizing<String>,
        token_path: PathBuf,
        trusted_base: PathBuf,
        subject: String,
        agent_id: String,
        scopes: Arc<HashSet<String>>,
        expected_peer_certificate: [u8; 32],
    ) -> Self {
        Self {
            token_path,
            trusted_base,
            token_cache: Arc::new(Mutex::new(TokenCache {
                token,
                loaded_at: Instant::now(),
            })),
            subject,
            agent_id,
            scopes,
            expected_peer_certificate,
        }
    }
}

impl BearerTokenResolver for FileBearerResolver {
    fn resolve(&self, token: &str) -> Result<Caller, apex_event_ingest::GatewayError> {
        self.resolve_with_peer(token, None)
    }

    fn resolve_with_peer(
        &self,
        token: &str,
        peer: Option<&PeerIdentity>,
    ) -> Result<Caller, apex_event_ingest::GatewayError> {
        let peer = peer.ok_or_else(apex_event_ingest::GatewayError::unauthenticated)?;
        if peer.certificate_sha256 != self.expected_peer_certificate {
            return Err(apex_event_ingest::GatewayError::unauthenticated());
        }
        let reload = self
            .token_cache
            .lock()
            .map(|cache| cache.loaded_at.elapsed() >= TOKEN_RELOAD_INTERVAL)
            .unwrap_or(true);
        if reload {
            let refreshed = trusted_secret_path(
                &self.token_path,
                &self.trusted_base,
                4096,
                true,
                "APEX_BEARER_TOKEN_FILE",
            )
            .and_then(|path| read_token(&path, "APEX_BEARER_TOKEN_FILE"));
            if let Ok(mut cache) = self.token_cache.lock() {
                // Retain the last known-good credential if a projected-secret
                // refresh is briefly unreadable. Replacing it with an empty
                // value converts a recoverable mount race into a total auth
                // outage. A successful read remains the only rotation path.
                if let Ok(token) = refreshed {
                    cache.token = Zeroizing::new(token);
                }
                cache.loaded_at = Instant::now();
            }
        }
        let matches = self
            .token_cache
            .lock()
            .map(|cache| constant_time_token_eq(token, &cache.token))
            .unwrap_or(false);
        if !matches {
            return Err(apex_event_ingest::GatewayError::unauthenticated());
        }
        Caller::authenticated_for_agent(
            self.subject.clone(),
            self.agent_id.clone(),
            self.scopes.iter().cloned(),
        )
    }
}

pub(crate) fn constant_time_token_eq(left: &str, right: &str) -> bool {
    const MAX_TOKEN_BYTES: usize = 4096;
    if left.is_empty() || right.is_empty() {
        return false;
    }
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut difference = left.len() ^ right.len();
    for index in 0..MAX_TOKEN_BYTES {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

pub(crate) fn bearer_subject(agent_id: &str) -> Result<String, io::Error> {
    let subject =
        env::var("APEX_BEARER_SUBJECT").unwrap_or_else(|_| default_bearer_subject(agent_id));
    validate_bearer_subject(&subject)?;
    Ok(subject)
}

pub(crate) fn default_bearer_subject(agent_id: &str) -> String {
    format!("spiffe://apex/workload/{agent_id}")
}

pub(crate) fn bearer_agent_id() -> Result<String, io::Error> {
    let agent_id = env::var("APEX_BEARER_AGENT_ID").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_BEARER_AGENT_ID is required; the file bearer cannot run unbound",
        )
    })?;
    if !valid_identifier(&agent_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_BEARER_AGENT_ID must be a safe 1-256 character identifier",
        ));
    }
    Ok(agent_id)
}

/// The file bearer is deliberately a single-agent staging credential, not a
/// fleet identity provider. Requiring an explicit acknowledgement prevents it
/// from being enabled accidentally in a multi-tenant deployment.
pub(crate) fn require_single_agent_file_bearer_ack() -> Result<(), io::Error> {
    if env::var("APEX_FILE_BEARER_MODE").ok().as_deref() == Some("single-agent-staging") {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "APEX_FILE_BEARER_MODE=single-agent-staging is required; file bearer auth is not approved for multi-agent or multi-tenant production use",
    ))
}

pub(crate) fn bearer_peer_certificate_sha256() -> Result<[u8; 32], io::Error> {
    let value = env::var("APEX_BEARER_CERT_SHA256").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_BEARER_CERT_SHA256 is required; the bearer token must be bound to one client certificate",
        )
    })?;
    parse_bearer_peer_certificate_sha256(&value)
}

pub(crate) fn parse_bearer_peer_certificate_sha256(value: &str) -> Result<[u8; 32], io::Error> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_BEARER_CERT_SHA256 must be exactly 64 hexadecimal characters",
        ));
    }
    let mut output = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(chunk[0]) << 4) | hex_nibble(chunk[1]);
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => unreachable!("validated hexadecimal input"),
    }
}

pub(crate) fn validate_bearer_subject(subject: &str) -> Result<(), io::Error> {
    if subject.is_empty()
        || subject.len() > 256
        || subject.chars().any(|character| character.is_control())
        || (!valid_identifier(subject) && !valid_spiffe_subject(subject))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_BEARER_SUBJECT must be a safe identifier or a canonical spiffe:// subject",
        ));
    }
    Ok(())
}

fn valid_spiffe_subject(subject: &str) -> bool {
    let Some(path) = subject.strip_prefix("spiffe://") else {
        return false;
    };
    let mut parts = path.split('/');
    let Some(trust_domain) = parts.next() else {
        return false;
    };
    valid_identifier(trust_domain) && parts.all(|part| !part.is_empty() && valid_identifier(part))
}
