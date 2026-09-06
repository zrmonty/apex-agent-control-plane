use super::{Data, ERROR, Installed};
use crate::{
    execution::network_owner::topology::Document, image_catalog::SelectedImage,
    network_catalog::NetworkCatalog,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Write};

#[derive(Serialize)]
struct Configuration<'a> {
    schema_version: u8,
    profile: &'static str,
    installation_id: &'a str,
    process_instance_id: &'a str,
    network_binding_sha256: &'a str,
    network_topology_sha256: &'a str,
    not_before_unix_us: String,
    not_after_unix_us: String,
    topology: Topology<'a>,
    routes: Vec<super::routes::Route>,
}
#[derive(Serialize)]
struct Topology<'a> {
    internal_pool: &'a str,
    outer_subnet: &'a str,
    slot: u16,
    capacity: u16,
    outer_gateway: &'a str,
    edge_address: &'a str,
}
struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > 262144 - self.0.len() {
            return Err(std::io::Error::other(ERROR));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
// Private fixed-schema serialization only, not arbitrary JSON-to-launch.
pub(super) fn data(
    installation: &str,
    i: &Installed,
    d: &Document,
    c: &NetworkCatalog,
    (from, until): (u64, u64),
    routes: Vec<super::routes::Route>,
    image: SelectedImage<'_>,
) -> Result<Data, &'static str> {
    let b = i.network.as_ref().ok_or(ERROR)?;
    let config = Configuration {
        schema_version: 1,
        profile: "isolated-bridge-v1",
        installation_id: installation,
        process_instance_id: &i.instance,
        network_binding_sha256: &b.binding_hash,
        network_topology_sha256: &d.topology_hash,
        not_before_unix_us: from.to_string(),
        not_after_unix_us: until.to_string(),
        topology: Topology {
            internal_pool: c.internal_pool(),
            outer_subnet: c.outer().subnet(),
            slot: b.slot,
            capacity: c.capacity(),
            outer_gateway: c.outer().gateway(),
            edge_address: c.outer().edge_address(),
        },
        routes,
    };
    let mut writer = Bounded(Vec::new());
    serde_json::to_writer(&mut writer, &config).map_err(|_| ERROR)?;
    let bytes = writer.0;
    let files = BTreeMap::from([(
        "guard-config.json".into(),
        format!("{:x}", Sha256::digest(&bytes)),
    )]);
    let manifest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&files).map_err(|_| ERROR)?)
    );
    let environment = [
        ("NODE_ENV", "production"),
        ("HOME", "/tmp/apex"),
        ("APEX_MCP_PROFILE", "guard"),
        ("APEX_MCP_GUARD_BOOTSTRAP", "sealed-stage-v1"),
        ("APEX_INSTALLATION_ID", installation),
        ("APEX_PROCESS_INSTANCE_ID", i.instance.as_str()),
        ("APEX_STAGE_MANIFEST_SHA256", manifest.as_str()),
        ("APEX_NETWORK_BINDING_SHA256", b.binding_hash.as_str()),
        ("APEX_NETWORK_TOPOLOGY_SHA256", d.topology_hash.as_str()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    Ok(Data {
        bytes,
        files,
        manifest,
        environment,
        image_catalog_id: image.catalog_id.into(),
        image_ref: image.image_ref.into(),
    })
}
