//! Strict deployment catalogs and privately constructed complete-stage selection.
use crate::{image_catalog::ImageCatalog, launch::PreparedLaunch, proto, shapes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
mod ingress;
pub(super) mod strict;
use strict::Object;
const ERROR: &str = "RUNTIME_EXECUTION_METADATA_INVALID";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document<T> {
    schema_version: u32,
    version: String,
    valid_from_unix_us: u64,
    expires_at_unix_us: u64,
    profiles: Vec<Object<T>>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Transport {
    endpoint: String,
    tls_server_name: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorityProfile {
    installation_id: String,
    workspace_id: String,
    namespace_id: String,
    proxy_id: String,
    host_policy_version: String,
    reference: String,
    version: String,
    governance: Object<Transport>,
    evidence: Object<Transport>,
    #[serde(
        default,
        deserialize_with = "present_mode",
        skip_serializing_if = "Option::is_none"
    )]
    mode: Option<AuthorityMode>,
    #[serde(
        default,
        deserialize_with = "present_managed",
        skip_serializing_if = "Option::is_none"
    )]
    managed: Option<Object<ingress::Managed>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuthorityMode {
    // Registration only. No ingress key purpose, container start or serving.
    ManagedPreparation,
    // Explicit TLS purpose/profile metadata, still not start or serving authority.
    ManagedIngress,
}

fn present_mode<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<AuthorityMode>, D::Error> {
    // Require a string, not Serde's alternate externally tagged object form.
    // Explicit null is still not absence; schema 1 uses the field default.
    match String::deserialize(d)?.as_str() {
        "managed_preparation" => Ok(Some(AuthorityMode::ManagedPreparation)),
        "managed_ingress" => Ok(Some(AuthorityMode::ManagedIngress)),
        _ => Err(serde::de::Error::custom(ERROR)),
    }
}
fn present_managed<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Object<ingress::Managed>>, D::Error> {
    Object::deserialize(d).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolProfile {
    installation_id: String,
    workspace_id: String,
    namespace_id: String,
    proxy_id: String,
    revision_id: String,
    host_policy_version: String,
    deployment_bindings_version: String,
    config_hash: String,
    entries: Vec<Object<Tool>>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Tool {
    pub reference: String,
    pub version: String,
    pub source_name: String,
}
pub(crate) struct Catalogs {
    pub images: ImageCatalog,
    authority: Document<AuthorityProfile>,
    tools: Document<ToolProfile>,
}
// Fields are visible only inside the crate; callers cannot mint selected values.
pub(crate) struct Selected {
    pub(crate) authority_json: Vec<u8>,
    pub(crate) tools_json: Vec<u8>,
    pub(crate) tools: Vec<Tool>,
    pub(crate) registration_required: bool,
}
impl Catalogs {
    pub(crate) fn parse(
        image: &[u8],
        authority: &[u8],
        tools: &[u8],
    ) -> Result<Self, &'static str> {
        let authority: Document<AuthorityProfile> = document(authority, &[1, 2, 3])?;
        let tools: Document<ToolProfile> = document(tools, &[1])?;
        let mut selectors = BTreeSet::new();
        for Object(p) in &authority.profiles {
            if !scope(
                &p.installation_id,
                &p.workspace_id,
                &p.namespace_id,
                &p.proxy_id,
            ) || !version(&p.host_policy_version)
                || !version(&p.reference)
                || !version(&p.version)
                || !transport(&p.governance.0)
                || !transport(&p.evidence.0)
                || !ingress::profile(authority.schema_version, p)
                || !selectors.insert((
                    &p.installation_id,
                    &p.workspace_id,
                    &p.namespace_id,
                    &p.proxy_id,
                    &p.host_policy_version,
                    &p.reference,
                    &p.version,
                ))
            {
                return Err(ERROR);
            }
        }
        let mut selectors = BTreeSet::new();
        for Object(p) in &tools.profiles {
            if !scope(
                &p.installation_id,
                &p.workspace_id,
                &p.namespace_id,
                &p.proxy_id,
            ) || !shapes::uuid_v7(&p.revision_id)
                || !shapes::hex_hash(&p.config_hash)
                || !version(&p.host_policy_version)
                || !version(&p.deployment_bindings_version)
                || p.entries.len() > 32
                || !selectors.insert((
                    &p.installation_id,
                    &p.workspace_id,
                    &p.namespace_id,
                    &p.proxy_id,
                    &p.revision_id,
                    &p.host_policy_version,
                    &p.deployment_bindings_version,
                    &p.config_hash,
                ))
            {
                return Err(ERROR);
            }
            let mut refs = BTreeSet::new();
            let mut sources = BTreeSet::new();
            for Object(t) in &p.entries {
                if !reference(&t.reference)
                    || !version(&t.version)
                    || !source(&t.source_name)
                    || !refs.insert(&t.reference)
                    || !sources.insert(&t.source_name)
                {
                    return Err(ERROR);
                }
            }
        }
        Ok(Self {
            images: ImageCatalog::parse(image).map_err(|_| ERROR)?,
            authority,
            tools,
        })
    }
    pub(crate) fn current(&self, now: u64) -> Result<(), &'static str> {
        if now < self.authority.valid_from_unix_us
            || now >= self.authority.expires_at_unix_us
            || now < self.tools.valid_from_unix_us
            || now >= self.tools.expires_at_unix_us
        {
            return Err(ERROR);
        }
        Ok(())
    }
    pub(crate) fn select(
        &self,
        authority: &proto::RuntimeAuthoritySnapshot,
        bindings: &str,
        configuration: &proto::RuntimeConfiguration,
        launch: &PreparedLaunch,
    ) -> Result<Selected, &'static str> {
        self.current(authority.checked_at_unix_us)?;
        let t = authority.target.as_ref().ok_or(ERROR)?;
        let context = launch.context();
        let p = &self
            .authority
            .profiles
            .iter()
            .find(|Object(p)| {
                p.installation_id == authority.installation_id
                    && p.workspace_id == t.workspace_id
                    && p.namespace_id == t.namespace_id
                    && p.proxy_id == t.proxy_id
                    && p.host_policy_version == authority.host_policy_version
                    && p.reference == context.authority_profile_ref
                    && p.version == context.authority_profile_version
            })
            .ok_or(ERROR)?
            .0;
        let tools = &self
            .tools
            .profiles
            .iter()
            .find(|Object(p)| {
                p.installation_id == authority.installation_id
                    && p.workspace_id == t.workspace_id
                    && p.namespace_id == t.namespace_id
                    && p.proxy_id == t.proxy_id
                    && p.revision_id == t.revision_id
                    && p.host_policy_version == authority.host_policy_version
                    && p.deployment_bindings_version == bindings
                    && p.config_hash == authority.config_hash
            })
            .ok_or(ERROR)?
            .0;
        let expected: BTreeSet<_> = configuration.secret_refs.iter().collect();
        if configuration.secret_refs.len() > 32
            || expected.len() != configuration.secret_refs.len()
            || expected != tools.entries.iter().map(|Object(t)| &t.reference).collect()
            || tools.entries.iter().any(|Object(t)| {
                launch
                    .materials()
                    .iter()
                    .any(|m| m.reference == t.reference || m.source_name == t.source_name)
            })
        {
            return Err(ERROR);
        }
        let tool_list: Vec<_> = tools.entries.iter().map(|Object(t)| serde_json::json!({
            "reference":t.reference,"version":t.version,"filename":tool_filename(&t.reference)
        })).collect();
        Ok(Selected {
            registration_required: p.mode.is_some(),
            authority_json: serde_json::to_vec(&serde_json::json!({"schema_version":self.authority.schema_version,"catalog_version":self.authority.version,"profile":p})).map_err(|_| ERROR)?,
            tools_json: serde_json::to_vec(&serde_json::json!({"schema_version":1,"catalog_version":self.tools.version,
                "installation_id":p.installation_id,"workspace_id":t.workspace_id,"namespace_id":t.namespace_id,
                "proxy_id":t.proxy_id,"revision_id":t.revision_id,"config_hash":authority.config_hash,
                "host_policy_version":authority.host_policy_version,"deployment_bindings_version":bindings,"entries":tool_list})).map_err(|_| ERROR)?,
            tools: tools.entries.iter().map(|Object(t)| t.clone()).collect(),
        })
    }
}
pub(crate) fn tool_filename(reference: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("tool-{:x}", Sha256::digest(reference.as_bytes()))
}
fn document<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    versions: &[u32],
) -> Result<Document<T>, &'static str> {
    if !(1..=262_144).contains(&bytes.len()) {
        return Err(ERROR);
    }
    let Object(d): Object<Document<T>> = serde_json::from_slice(bytes).map_err(|_| ERROR)?;
    if !versions.contains(&d.schema_version)
        || !version(&d.version)
        || d.valid_from_unix_us == 0
        || d.valid_from_unix_us >= d.expires_at_unix_us
        || d.expires_at_unix_us > i64::MAX as u64
        || !(1..=32).contains(&d.profiles.len())
    {
        return Err(ERROR);
    }
    Ok(d)
}
fn version(v: &str) -> bool {
    v.len() <= 128 && shapes::scope(v)
}
fn scope(i: &str, w: &str, n: &str, p: &str) -> bool {
    shapes::uuid_v7(i) && shapes::uuid_v7(p) && shapes::scope(w) && shapes::scope(n)
}
fn source(v: &str) -> bool {
    (1..=255).contains(&v.len())
        && v.as_bytes()[0].is_ascii_alphanumeric()
        && !v.contains("..")
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
fn reference(v: &str) -> bool {
    v.len() <= 256
        && v.strip_prefix("secret://").is_some_and(|s| {
            s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && s.split('/').all(|p| p != "." && shapes::scope(p))
        })
}
fn transport(t: &Transport) -> bool {
    let Ok(u) = url::Url::parse(&t.endpoint) else {
        return false;
    };
    t.endpoint.len() <= 2048
        && !t.endpoint.contains('\\')
        && u.scheme() == "https"
        && u.host_str().is_some()
        && u.username().is_empty()
        && u.password().is_none()
        && u.query().is_none()
        && u.fragment().is_none()
        && u.path() == "/"
        && (u.as_str() == t.endpoint || u.as_str() == format!("{}/", t.endpoint))
        && (1..=253).contains(&t.tls_server_name.len())
        && t.tls_server_name.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
#[cfg(test)]
mod tests;
