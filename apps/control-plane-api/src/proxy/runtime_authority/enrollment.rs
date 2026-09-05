//! Private deployment-document boundary, not a wire model or forged TLS view.
//! Parsing establishes bounded deployment metadata, not TLS provenance.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde_json::{Map, Value};

use super::RuntimeAuthorityError;

pub(super) struct Enrollment {
    version: String,
    peer_policy_version: String,
    valid_from_unix_us: u64,
    expires_at_unix_us: u64,
    controllers: BTreeMap<String, String>,
    installations: BTreeMap<String, Installation>,
}

struct Installation {
    agent_identity_id: String,
    revoked: bool,
    host_policy_version: String,
    scopes: BTreeSet<(String, String)>,
}

impl Enrollment {
    pub(super) fn parse_json(input: &[u8]) -> Result<Self, RuntimeAuthorityError> {
        preflight(input)?;
        // The only JSON decoder: retain original decoded-duplicate/entry checks.
        let value = crate::contract_json::parse_unique_json(input)
            .map_err(|_| RuntimeAuthorityError::Unavailable)?;
        let root = object(
            &value,
            &[
                "schemaVersion",
                "version",
                "peerPolicyVersion",
                "validFromUnixUs",
                "expiresAtUnixUs",
                "controllers",
                "installations",
            ],
        )?;
        if root.get("schemaVersion").and_then(Value::as_u64) != Some(1) {
            return Err(RuntimeAuthorityError::Unavailable);
        }
        let valid_from_unix_us = epoch(root, "validFromUnixUs")?;
        let expires_at_unix_us = epoch(root, "expiresAtUnixUs")?;
        if valid_from_unix_us == 0 || expires_at_unix_us <= valid_from_unix_us {
            return Err(RuntimeAuthorityError::Unavailable);
        }
        let mut controllers = BTreeMap::new();
        let mut workers = BTreeSet::new();
        for row in items(root, "controllers", 128)? {
            let row = object(row, &["identityId", "workerId"])?;
            let identity = identifier(row, "identityId", 128)?;
            let worker = text(row, "workerId", 128)?;
            // EXACT journal grammar, including '..'. Do not apply domain-ID
            // normalization/restrictions to an explicitly configured worker.
            if !worker.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')
            }) || !workers.insert(worker)
                || controllers
                    .insert(identity.to_owned(), worker.to_owned())
                    .is_some()
            {
                return Err(RuntimeAuthorityError::Unavailable);
            }
        }
        let mut installations = BTreeMap::new();
        let mut total_scopes = 0_usize;
        for row in items(root, "installations", 128)? {
            let row = object(
                row,
                &[
                    "installationId",
                    "agentIdentityId",
                    "revoked",
                    "hostPolicyVersion",
                    "scopes",
                ],
            )?;
            let id = text(row, "installationId", 36)?;
            if !apex_domain::is_lowercase_uuidv7(id) {
                return Err(RuntimeAuthorityError::Unavailable);
            }
            let rows = items(row, "scopes", 64)?;
            total_scopes = total_scopes
                .checked_add(rows.len())
                .ok_or(RuntimeAuthorityError::Unavailable)?;
            if total_scopes > 1024 {
                return Err(RuntimeAuthorityError::Unavailable);
            }
            let mut scopes = BTreeSet::new();
            for scope in rows {
                let scope = object(scope, &["workspaceId", "namespaceId"])?;
                if !scopes.insert((
                    identifier(scope, "workspaceId", 256)?.to_owned(),
                    identifier(scope, "namespaceId", 256)?.to_owned(),
                )) {
                    return Err(RuntimeAuthorityError::Unavailable);
                }
            }
            let installation = Installation {
                agent_identity_id: identifier(row, "agentIdentityId", 128)?.to_owned(),
                revoked: row
                    .get("revoked")
                    .and_then(Value::as_bool)
                    .ok_or(RuntimeAuthorityError::Unavailable)?,
                host_policy_version: identifier(row, "hostPolicyVersion", 128)?.to_owned(),
                scopes,
            };
            if installations.insert(id.to_owned(), installation).is_some() {
                return Err(RuntimeAuthorityError::Unavailable);
            }
        }
        Ok(Self {
            version: identifier(root, "version", 128)?.to_owned(),
            peer_policy_version: identifier(root, "peerPolicyVersion", 128)?.to_owned(),
            valid_from_unix_us,
            expires_at_unix_us,
            controllers,
            installations,
        })
    }

    pub(super) fn version(&self) -> &str {
        &self.version
    }
    pub(super) fn peer_policy_version(&self) -> &str {
        &self.peer_policy_version
    }
    pub(super) fn valid_from_unix_us(&self) -> u64 {
        self.valid_from_unix_us
    }
    pub(super) fn expires_at_unix_us(&self) -> u64 {
        self.expires_at_unix_us
    }

    pub(super) fn select(
        &self,
        selection: EnrollmentSelection<'_>,
    ) -> Result<EnrollmentBinding<'_>, RuntimeAuthorityError> {
        let denied = RuntimeAuthorityError::EnrollmentDenied;
        if selection.peer_policy_version != self.peer_policy_version
            || selection.checked_at_unix_us < self.valid_from_unix_us
            || selection.checked_at_unix_us >= self.expires_at_unix_us
        {
            return Err(denied);
        }
        let installation = self
            .installations
            .get(selection.installation_id)
            .ok_or(denied)?;
        if installation.revoked
            || installation.agent_identity_id != selection.agent_identity_id
            || !installation.scopes.iter().any(|(workspace, namespace)| {
                workspace == selection.workspace_id && namespace == selection.namespace_id
            })
        {
            return Err(denied);
        }
        let worker_id = self
            .controllers
            .get(selection.observed_controller_identity_id)
            .ok_or(denied)?;
        Ok(EnrollmentBinding {
            worker_id,
            host_policy_version: &installation.host_policy_version,
            enrollment_version: &self.version,
        })
    }
}

impl fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Enrollment { [redacted] }")
    }
}

// Private scalar seam for intersection tests; production will fill it only from
// the real borrowed RuntimePeerPair. This is neither public nor deserializable.
#[derive(Clone, Copy)]
pub(super) struct EnrollmentSelection<'a> {
    pub peer_policy_version: &'a str,
    pub agent_identity_id: &'a str,
    pub observed_controller_identity_id: &'a str,
    pub installation_id: &'a str,
    pub workspace_id: &'a str,
    pub namespace_id: &'a str,
    pub checked_at_unix_us: u64,
}

pub(super) struct EnrollmentBinding<'a> {
    pub worker_id: &'a str,
    pub host_policy_version: &'a str,
    pub enrollment_version: &'a str,
}

impl fmt::Debug for EnrollmentBinding<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnrollmentBinding { [redacted] }")
    }
}

// Separate lexical guard seam permits depth tests with no competing shape guard.
pub(super) fn preflight(input: &[u8]) -> Result<(), RuntimeAuthorityError> {
    let invalid = RuntimeAuthorityError::Unavailable;
    if input.is_empty() || input.len() > 65_536 || std::str::from_utf8(input).is_err() {
        return Err(invalid);
    }
    let (mut quoted, mut escaped, mut depth) = (false, false, 0_usize);
    for &byte in input {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > 32 {
                        return Err(invalid);
                    }
                }
                b'}' | b']' => depth = depth.checked_sub(1).ok_or(invalid)?,
                _ => {}
            }
        }
    }
    if quoted || depth != 0 {
        return Err(invalid);
    }
    // Only lexical bounds here; the shared original-JSON guard checks grammar.
    Ok(())
}

fn object<'a>(
    value: &'a Value,
    fields: &[&str],
) -> Result<&'a Map<String, Value>, RuntimeAuthorityError> {
    let value = value
        .as_object()
        .ok_or(RuntimeAuthorityError::Unavailable)?;
    if value.len() != fields.len() || !fields.iter().all(|field| value.contains_key(*field)) {
        return Err(RuntimeAuthorityError::Unavailable);
    }
    Ok(value)
}

fn text<'a>(
    value: &'a Map<String, Value>,
    field: &str,
    max: usize,
) -> Result<&'a str, RuntimeAuthorityError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty() && text.len() <= max)
        .ok_or(RuntimeAuthorityError::Unavailable)
}

fn identifier<'a>(
    value: &'a Map<String, Value>,
    field: &str,
    max: usize,
) -> Result<&'a str, RuntimeAuthorityError> {
    let text = text(value, field, max)?;
    if !apex_domain::is_scope_identifier(text) {
        return Err(RuntimeAuthorityError::Unavailable);
    }
    Ok(text)
}

fn items<'a>(
    value: &'a Map<String, Value>,
    field: &str,
    max: usize,
) -> Result<&'a [Value], RuntimeAuthorityError> {
    value
        .get(field)
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty() && items.len() <= max)
        .map(Vec::as_slice)
        .ok_or(RuntimeAuthorityError::Unavailable)
}

fn epoch(value: &Map<String, Value>, field: &str) -> Result<u64, RuntimeAuthorityError> {
    let text = text(value, field, 20)?;
    if !text.bytes().all(|byte| byte.is_ascii_digit()) || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(RuntimeAuthorityError::Unavailable);
    }
    text.parse().map_err(|_| RuntimeAuthorityError::Unavailable)
}
