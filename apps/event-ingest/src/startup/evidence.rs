use std::{ffi::OsString, io, path::PathBuf};

const LEGACY: [&str; 6] = [
    "APEX_FILE_BEARER_MODE",
    "APEX_BEARER_TOKEN_FILE",
    "APEX_BEARER_AGENT_ID",
    "APEX_BEARER_SUBJECT",
    "APEX_ALLOWED_SCOPES",
    "APEX_BEARER_CERT_SHA256",
];

fn managed_path(
    managed: Option<OsString>,
    legacy_present: [bool; 6],
) -> Result<Option<PathBuf>, io::Error> {
    let Some(path) = managed else {
        return Ok(None);
    };
    if path.is_empty() || legacy_present.into_iter().any(|present| present) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_MANAGED_EVIDENCE_ENROLLMENT_FILE requires a nonempty path and is incompatible with all legacy bearer bindings",
        ));
    }
    Ok(Some(path.into()))
}

use super::{
    auth::{
        FileBearerResolver, bearer_agent_id, bearer_peer_certificate_sha256, bearer_subject,
        require_single_agent_file_bearer_ack,
    },
    env::{allowed_scopes, path},
    secrets::{read_token, trusted_secret_path},
};
use apex_event_ingest::{
    BearerTokenResolver, Caller, GatewayError, PeerIdentity,
    managed_evidence::{ManagedEvidenceOwner, ManagedEvidenceResolver},
};
use std::{path::Path, sync::Arc};

pub(super) enum Resolver {
    Legacy(FileBearerResolver),
    Managed(ManagedEvidenceResolver),
}
impl BearerTokenResolver for Resolver {
    fn resolve(&self, token: &str) -> Result<Caller, GatewayError> {
        self.resolve_with_peer(token, None)
    }
    fn resolve_with_peer(
        &self,
        token: &str,
        peer: Option<&PeerIdentity>,
    ) -> Result<Caller, GatewayError> {
        match self {
            Self::Legacy(r) => r.resolve_with_peer(token, peer),
            Self::Managed(r) => r.resolve_with_peer(token, peer),
        }
    }
}

pub(super) fn build(
    base: &Path,
) -> Result<(Resolver, Option<ManagedEvidenceOwner>), Box<dyn std::error::Error>> {
    let managed = managed_path(
        std::env::var_os("APEX_MANAGED_EVIDENCE_ENROLLMENT_FILE"),
        LEGACY.map(|name| std::env::var_os(name).is_some()),
    )?;
    if let Some(path) = managed {
        let (owner, resolver) = ManagedEvidenceOwner::start(&path, base)?;
        return Ok((Resolver::Managed(resolver), Some(owner)));
    }
    // Preserve legacy validation order and its explicit staging acknowledgement.
    let token_path = trusted_secret_path(
        &path("APEX_BEARER_TOKEN_FILE")?,
        base,
        4096,
        true,
        "APEX_BEARER_TOKEN_FILE",
    )?;
    let token = zeroize::Zeroizing::new(read_token(&token_path, "APEX_BEARER_TOKEN_FILE")?);
    require_single_agent_file_bearer_ack()?;
    let agent_id = bearer_agent_id()?;
    let subject = bearer_subject(&agent_id)?;
    let certificate = bearer_peer_certificate_sha256()?;
    let scopes = allowed_scopes()?;
    Ok((
        Resolver::Legacy(FileBearerResolver::new(
            token,
            token_path,
            base.into(),
            subject,
            agent_id,
            Arc::new(scopes),
            certificate,
        )),
        None,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn managed_evidence_mode_is_explicit_and_rejects_every_legacy_binding() {
        assert_eq!(
            managed_path(Some("enrollment.json".into()), [false; 6]).unwrap(),
            Some(PathBuf::from("enrollment.json"))
        );
        assert!(managed_path(Some("".into()), [false; 6]).is_err());
        assert_eq!(managed_path(None, [false; 6]).unwrap(), None);
        for (index, name) in LEGACY.iter().enumerate() {
            let mut present = [false; 6];
            present[index] = true;
            assert!(
                managed_path(Some("enrollment.json".into()), present).is_err(),
                "{name}"
            );
        }
    }
}
