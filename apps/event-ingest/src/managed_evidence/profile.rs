use super::{
    EnrollmentError as Error,
    json::{self, Value},
};
use crate::{
    Caller,
    validation::{is_lowercase_uuidv7, is_scope_identifier},
};
use std::collections::{BTreeMap, HashSet};

pub(super) struct Credential {
    pub(super) certificate: [u8; 32],
    pub(super) token: [u8; 32],
    pub(super) caller: Caller,
}
pub(super) struct Profile {
    pub(super) valid_from: i64,
    pub(super) expires: i64,
    pub(super) credentials: Vec<Credential>,
}
impl Profile {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut root = json::parse(bytes)?.object()?;
        if take(&mut root, "schema_version")?.integer()? != 1 {
            return Err(Error);
        }
        let version = string(&mut root, "version")?;
        if version.len() > 128 || !is_scope_identifier(&version) {
            return Err(Error);
        }
        let valid_from = take(&mut root, "valid_from_unix_us")?.integer()?;
        let expires = take(&mut root, "expires_at_unix_us")?.integer()?;
        if valid_from <= 0 || expires <= valid_from {
            return Err(Error);
        }
        let enrollments = take(&mut root, "enrollments")?.array()?;
        if !root.is_empty() || enrollments.len() > 64 {
            return Err(Error);
        }
        let mut credentials = Vec::new();
        let mut agents = HashSet::new();
        let mut proxies = HashSet::new();
        let mut pairs = HashSet::new();
        for enrollment in enrollments {
            let mut e = enrollment.object()?;
            let installation = string(&mut e, "installation_id")?;
            let proxy = string(&mut e, "proxy_id")?;
            let workspace = string(&mut e, "workspace_id")?;
            let namespace = string(&mut e, "namespace_id")?;
            let subject = string(&mut e, "subject")?;
            let agent = string(&mut e, "agent_id")?;
            if !is_lowercase_uuidv7(&installation)
                || !is_lowercase_uuidv7(&proxy)
                || [&workspace, &namespace, &subject, &agent]
                    .iter()
                    .any(|s| !is_scope_identifier(s))
                || !agents.insert(agent.clone())
                || !proxies.insert((installation, workspace.clone(), namespace.clone(), proxy))
            {
                return Err(Error);
            }
            let caller = Caller::authenticated_for_agent(
                subject,
                agent,
                [format!("{workspace}/{namespace}")],
            )
            .map_err(|_| Error)?;
            let keys = take(&mut e, "credentials")?.array()?;
            if !e.is_empty() || keys.is_empty() || keys.len() > 2 {
                return Err(Error);
            }
            for key in keys {
                let mut key = key.object()?;
                let certificate = digest(&string(&mut key, "certificate_sha256")?)?;
                let token = digest(&string(&mut key, "token_sha256")?)?;
                if !key.is_empty() || !pairs.insert((certificate, token)) {
                    return Err(Error);
                }
                credentials.push(Credential {
                    certificate,
                    token,
                    caller: caller.clone(),
                });
            }
        }
        Ok(Self {
            valid_from,
            expires,
            credentials,
        })
    }
}

fn take(o: &mut BTreeMap<String, Value>, key: &str) -> Result<Value, Error> {
    o.remove(key).ok_or(Error)
}
fn string(o: &mut BTreeMap<String, Value>, key: &str) -> Result<String, Error> {
    take(o, key)?.string()
}
fn digest(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error);
    }
    let mut result = [0; 32];
    for (byte, chunk) in result.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let hex = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        *byte = (hex(chunk[0]) << 4) | hex(chunk[1]);
    }
    Ok(result)
}
