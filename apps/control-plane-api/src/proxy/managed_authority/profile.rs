use super::Refused;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
mod launch;
use launch::LaunchEnrollment;

/// Digest-only protected document. Parsing is not TLS authentication or a grant.
pub(super) struct Profile {
    pub version: String,
    pub valid_from: u64,
    pub expires: u64,
    pub entries: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u32,
    version: String,
    valid_from_unix_us: String,
    expires_at_unix_us: String,
    profiles: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub installation_id: String,
    pub workspace_id: String,
    pub namespace_id: String,
    pub proxy_id: String,
    pub revision_id: String,
    pub authority_profile_ref: String,
    pub authority_profile_version: String,
    pub evidence_agent_id: String,
    pub credentials: Vec<Credential>,
    #[serde(default, deserialize_with = "launch::optional")]
    launch: Option<LaunchEnrollment>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Credential {
    certificate_sha256: String,
    token_sha256: String,
}

impl Credential {
    pub(super) fn matches(&self, certificate: &[u8; 32], token: &[u8; 32]) -> bool {
        use subtle::ConstantTimeEq;
        let Ok(expected_certificate) = digest(&self.certificate_sha256) else {
            return false;
        };
        let Ok(expected_token) = digest(&self.token_sha256) else {
            return false;
        };
        bool::from(expected_certificate.ct_eq(certificate) & expected_token.ct_eq(token))
    }
}

impl Profile {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, Refused> {
        if bytes.is_empty() || bytes.len() > 262_144 {
            return Err(Refused);
        }
        let original = crate::contract_json::parse_unique_json(bytes).map_err(|_| Refused)?;
        let document: Document = serde_json::from_value(original).map_err(|_| Refused)?;
        let from = epoch(&document.valid_from_unix_us)?;
        let expires = epoch(&document.expires_at_unix_us)?;
        if document.schema_version != 1
            || !identifier(&document.version)
            || from >= expires
            || document.profiles.len() > 64
        {
            return Err(Refused);
        }
        let mut selectors = BTreeSet::new();
        let mut agents = BTreeMap::new();
        let mut credential_owners = BTreeMap::new();
        for entry in &document.profiles {
            if let Some(launch) = &entry.launch {
                launch.validate()?;
            }
            if [&entry.installation_id, &entry.proxy_id, &entry.revision_id]
                .into_iter()
                .any(|id| !apex_domain::is_lowercase_uuidv7(id))
                || [
                    &entry.workspace_id,
                    &entry.namespace_id,
                    &entry.evidence_agent_id,
                ]
                .into_iter()
                .any(|id| !apex_domain::is_scope_identifier(id))
                || !identifier(&entry.authority_profile_ref)
                || !identifier(&entry.authority_profile_version)
                || !(1..=2).contains(&entry.credentials.len())
            {
                return Err(Refused);
            }
            let owner = (
                &entry.installation_id,
                &entry.workspace_id,
                &entry.namespace_id,
                &entry.proxy_id,
            );
            if !selectors.insert((owner, &entry.revision_id))
                || agents
                    .insert(&entry.evidence_agent_id, owner)
                    .is_some_and(|old| old != owner)
            {
                return Err(Refused);
            }
            let mut local_pairs = BTreeSet::new();
            for credential in &entry.credentials {
                let pair = (
                    digest(&credential.certificate_sha256)?,
                    digest(&credential.token_sha256)?,
                );
                if !local_pairs.insert(pair)
                    || credential_owners
                        .insert(pair, owner)
                        .is_some_and(|old| old != owner)
                {
                    return Err(Refused);
                }
            }
        }
        Ok(Self {
            version: document.version,
            valid_from: from,
            expires,
            entries: document.profiles,
        })
    }
}

fn epoch(text: &str) -> Result<u64, Refused> {
    if text.is_empty()
        || text.len() > 19
        || text.starts_with('0')
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Refused);
    }
    text.parse::<u64>()
        .ok()
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or(Refused)
}
fn identifier(value: &str) -> bool {
    value.len() <= 128 && apex_domain::is_scope_identifier(value)
}
pub(super) fn digest(text: &str) -> Result<[u8; 32], Refused> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Refused);
    }
    let mut result = [0; 32];
    for (byte, pair) in result.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let hex = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        *byte = hex(pair[0]) * 16 + hex(pair[1]);
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
