//! Explicit ingress purpose. Parsing never grants start, routing or admission.
use super::{AuthorityMode, AuthorityProfile, Object, Transport, shapes, version};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Managed {
    evidence_agent_id: String,
    upstream_credentials: String,
    network_policy: Object<NetworkPolicy>,
    ingress: Object<Ingress>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NetworkPolicy {
    reference: String,
    version: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ingress {
    port: u16,
    tls_server_name: String,
    edge_certificate_sha256: Vec<String>,
}

pub(super) fn profile(schema: u32, profile: &AuthorityProfile) -> bool {
    match (schema, profile.mode, &profile.managed) {
        (1, None, None) | (2, Some(AuthorityMode::ManagedPreparation), None) => true,
        (3, Some(AuthorityMode::ManagedIngress), Some(Object(managed))) => {
            let ingress = &managed.ingress.0;
            let pins = &ingress.edge_certificate_sha256;
            version(&managed.evidence_agent_id)
                && managed.upstream_credentials == "managed_upstream_v1"
                && version(&managed.network_policy.0.reference)
                && version(&managed.network_policy.0.version)
                && ingress.port == 8080
                && dns(&ingress.tls_server_name)
                && (1..=2).contains(&pins.len())
                && pins
                    .iter()
                    .all(|s| shapes::hex_hash(s) && s.bytes().any(|b| b != b'0'))
                && pins.iter().collect::<BTreeSet<_>>().len() == pins.len()
                && transport(&profile.governance.0)
                && transport(&profile.evidence.0)
        }
        _ => false,
    }
}

fn transport(value: &Transport) -> bool {
    dns(&value.tls_server_name)
        && url::Url::parse(&value.endpoint).is_ok_and(|url| {
            matches!(url.host(), Some(url::Host::Domain(host)) if host == value.tls_server_name)
        })
}
fn dns(value: &str) -> bool {
    (1..=253).contains(&value.len())
        && value.bytes().any(|b| b.is_ascii_lowercase())
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
