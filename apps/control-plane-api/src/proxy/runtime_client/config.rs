//! Protected immutable transport generation; changes require owner restart.
use super::unavailable;
use crate::{ExactScope, ProxyError};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::Instant,
};
use tonic::transport::{Certificate, ClientTlsConfig, Identity};
use zeroize::Zeroizing;
#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;

use crate::proxy::runtime_authority::material::startup_secrets as secrets;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u32,
    installation_id: String,
    worker_id: String,
    endpoint: String,
    server_name: String,
    ca_file: PathBuf,
    client_cert_file: PathBuf,
    client_key_file: PathBuf,
    scopes: Vec<Scope>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    workspace_id: String,
    namespace_id: String,
}

#[derive(Clone)]
pub struct RuntimeExecutionConfig {
    pub(crate) installation_id: String,
    pub(crate) worker_id: String,
    pub(crate) scopes: Vec<ExactScope>,
    pub(super) endpoint: String,
    pub(super) tls: ClientTlsConfig,
    files: Vec<(PathBuf, bool, [u8; 32])>,
    base: PathBuf,
}

impl RuntimeExecutionConfig {
    #[cfg(test)]
    pub(crate) fn ownership_test_value() -> Self {
        // Component ownership only: never connected, admitted, or exported in
        // production. Real transport/config acceptance has separate live gates.
        Self {
            installation_id: String::new(),
            worker_id: String::new(),
            scopes: vec![],
            endpoint: String::new(),
            tls: ClientTlsConfig::new(),
            files: vec![],
            base: PathBuf::new(),
        }
    }
    /// Only deployment-owned files under the existing trusted base are allowed.
    pub fn load(base: &Path, path: &Path) -> Result<Self, ProxyError> {
        let start = Instant::now();
        let (path, bytes) = read(base, path, true)?;
        let doc = parse(&bytes)?;
        let mut files = vec![(path, true, Sha256::digest(&bytes).into())];
        let mut material = Vec::with_capacity(3);
        for (path, private) in [
            (&doc.ca_file, false),
            (&doc.client_cert_file, false),
            (&doc.client_key_file, true),
        ] {
            let (path, bytes) = read(base, path, private)?;
            files.push((path, private, Sha256::digest(&bytes).into()));
            material.push(bytes);
        }
        if start.elapsed() > std::time::Duration::from_secs(5) {
            return Err(unavailable());
        }
        let tls = ClientTlsConfig::new()
            .domain_name(doc.server_name)
            .ca_certificate(Certificate::from_pem(&*material[0]))
            .identity(Identity::from_pem(&*material[1], &*material[2]));
        // Validate TLS parsing now; connect happens only after the callback listener serves.
        tonic::transport::Endpoint::from_shared(doc.endpoint.clone())
            .map_err(|_| unavailable())?
            .tls_config(tls.clone())
            .map_err(|_| unavailable())?;
        Ok(Self {
            installation_id: doc.installation_id,
            worker_id: doc.worker_id,
            scopes: doc
                .scopes
                .into_iter()
                .map(|s| ExactScope {
                    workspace_id: s.workspace_id,
                    namespace_id: s.namespace_id,
                })
                .collect(),
            endpoint: doc.endpoint,
            tls,
            files,
            base: base.to_owned(),
        })
    }

    /// No cached credentials continue dispatch after invalid replacement.
    pub(crate) fn recheck(&self) -> Result<(), ProxyError> {
        let start = Instant::now();
        for (path, private, digest) in &self.files {
            let (_, bytes) = read(&self.base, path, *private)?;
            if <[u8; 32]>::from(Sha256::digest(&bytes)) != *digest
                || start.elapsed() > std::time::Duration::from_secs(5)
            {
                return Err(unavailable());
            }
        }
        Ok(())
    }
}

fn parse(bytes: &[u8]) -> Result<Document, ProxyError> {
    if bytes.is_empty() || bytes.len() > 65536 {
        return Err(unavailable());
    }
    let value = crate::contract_json::parse_unique_json(bytes).map_err(|_| unavailable())?;
    if !value.is_object()
        || value
            .get("scopes")
            .and_then(serde_json::Value::as_array)
            .is_none_or(|scopes| scopes.iter().any(|scope| !scope.is_object()))
    {
        return Err(unavailable());
    }
    let doc: Document = serde_json::from_value(value).map_err(|_| unavailable())?;
    let url = url::Url::parse(&doc.endpoint).map_err(|_| unavailable())?;
    if doc.schema_version != 1
        || !apex_domain::is_lowercase_uuidv7(&doc.installation_id)
        || !identifier(&doc.worker_id)
        || doc.endpoint.len() > 512
        || url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || doc.server_name.is_empty()
        || doc.server_name.len() > 253
        || !doc
            .server_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        || doc.scopes.is_empty()
        || doc.scopes.len() > 64
    {
        return Err(unavailable());
    }
    let mut seen = BTreeSet::new();
    for scope in &doc.scopes {
        if !crate::proxy::is_scope_identifier(&scope.workspace_id)
            || !crate::proxy::is_scope_identifier(&scope.namespace_id)
            || !seen.insert((&scope.workspace_id, &scope.namespace_id))
        {
            return Err(unavailable());
        }
    }
    for path in [&doc.ca_file, &doc.client_cert_file, &doc.client_key_file] {
        if path.as_os_str().is_empty() {
            return Err(unavailable());
        }
    }
    Ok(doc)
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
}
fn read(
    base: &Path,
    path: &Path,
    private: bool,
) -> Result<(PathBuf, Zeroizing<Vec<u8>>), ProxyError> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    };
    if !base.is_absolute() {
        return Err(unavailable());
    }
    let checked =
        secrets::trusted_secret_path(&path, base, 65536, private, "runtime execution material")
            .map_err(|_| unavailable())?;
    // Deployment owns filesystem mutation; check original components as well as
    // resolved confinement. No symlink/unsafe ancestor fallback is permitted.
    for part in path.ancestors() {
        let meta = std::fs::symlink_metadata(part).map_err(|_| unavailable())?;
        if meta.file_type().is_symlink() {
            return Err(unavailable());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let base_owner = std::fs::metadata(base).map_err(|_| unavailable())?.uid();
            if meta.mode() & 0o022 != 0 || (meta.uid() != 0 && meta.uid() != base_owner) {
                return Err(unavailable());
            }
        }
    }
    let bytes = Zeroizing::new(
        secrets::read_bounded(&checked, 65536, "runtime execution material")
            .map_err(|_| unavailable())?,
    );
    Ok((checked, bytes))
}

impl std::fmt::Debug for RuntimeExecutionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RuntimeExecutionConfig { [redacted] }")
    }
}
