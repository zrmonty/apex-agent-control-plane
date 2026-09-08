//! Current catalog reconstruction and rejection of stale/replaced sealed data.
use super::*;
use crate::owner;
use sha2::{Digest, Sha256};

pub(in crate::execution) fn metadata(f: &Fixture) -> owner::Metadata {
    reload(f)().unwrap()
}

// Immutable synthetic catalog inputs, reparsed by the real metadata reader.
pub(in crate::execution) fn reload(
    f: &Fixture,
) -> impl FnMut() -> Result<owner::Metadata, &'static str> + Send + 'static {
    let i = &f.i;
    let t = i.original.target.as_ref().unwrap();
    let document = |version: &str, profile: serde_json::Value| {
        json!({"schema_version":1,
        "version":version,"valid_from_unix_us":1,"expires_at_unix_us":i64::MAX,"profiles":[profile]})
    };
    let profile = json!({"installation_id":INSTALL,"workspace_id":t.workspace_id,"namespace_id":t.namespace_id,
        "proxy_id":t.proxy_id,"revision_id":t.revision_id,"host_policy_version":"host-v1",
        "deployment_bindings_version":"bindings-v1","config_hash":i.original.config_hash,
        "authority_profile_ref":"live","authority_profile_version":"v1","image_catalog_id":"gateway",
        "materials":f.launch.materials().iter().map(|m|json!({"role":m.role.as_str_name(),"reference":m.reference,"version":m.version,"source_name":m.source_name})).collect::<Vec<_>>()});
    let launch = document("v1", profile);
    let authority: serde_json::Value = serde_json::from_str(&i.authority_json).unwrap();
    let mut authority_doc = document("v1", authority["profile"].clone());
    authority_doc["schema_version"] = json!(3);
    let mut tools: serde_json::Value = serde_json::from_str(&i.tools_json).unwrap();
    tools.as_object_mut().unwrap().remove("schema_version");
    tools.as_object_mut().unwrap().remove("catalog_version");
    tools["entries"] = json!(f.selected.tools);
    let images = json!({"schema_version":1,"images":[
        {"id":"gateway","image_ref":f.launch.context().image_ref,"signing":{"certificate_oidc_issuer":"https://issuer.example","certificate_identity":"fixture@example.com"}},
        {"id":"guard-v1","image_ref":format!("registry.example/guard@sha256:{}","b".repeat(64)),"signing":{"certificate_oidc_issuer":"https://issuer.example","certificate_identity":"guard@example.com"}}]});
    let (p, _) = owner::tests::documents();
    let launch = serde_json::to_vec(&launch).unwrap();
    let images = serde_json::to_vec(&images).unwrap();
    let authority = serde_json::to_vec(&authority_doc).unwrap();
    let tools = serde_json::to_vec(&document("v1", tools)).unwrap();
    let network = serde_json::to_vec(&f.network_json).unwrap();
    move || {
        owner::Metadata::parse(&p, &launch)?
            .with_execution(&images, &authority, &tools)?
            .with_network(&network, INSTALL, "host-v1")
    }
}

fn current_storage() -> Storage {
    let mut s = Storage::new();
    let f = &mut s.fixture;
    make_current(f);
    f.rebind();
    s.record.installed = Some(f.i.clone());
    prepared(&mut s);
    s
}
pub(in crate::execution) fn make_current(f: &mut Fixture) {
    f.network_json["valid_from_unix_us"] = json!(1);
    let signing = f
        .catalogs
        .images
        .select(f.launch.image_catalog_id(), &f.launch.context().image_ref)
        .unwrap();
    f.i.publication_hash = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&(
                f.launch.materials(),
                &f.selected.tools,
                f.launch.catalog_version(),
                signing.catalog_id,
                signing.certificate_identity,
                signing.certificate_oidc_issuer
            ))
            .unwrap()
        )
    );
}
#[test]
fn network_inspection_current_catalogs_and_material_sources_are_required() {
    let s = current_storage();
    let m = metadata(&s.fixture);
    let i = s.record.installed.as_ref().unwrap();
    let check = |m: &owner::Metadata, i: &Installed| {
        read::current::check(&s.staging, INSTALL, i, m, &mut || Ok(()))
    };
    assert!(
        check(&m, i).is_ok(),
        "current protected catalogs and sealed stages must join"
    );
    let mut missing = metadata(&s.fixture);
    missing.network = None;
    assert!(check(&missing, i).is_err());
    let mut missing = metadata(&s.fixture);
    missing.execution = None;
    assert!(check(&missing, i).is_err());
    let mut changed = i.clone();
    changed.publication_hash = "f".repeat(64);
    assert!(check(&m, &changed).is_err());
    let path = s.root.join("material/m2");
    let bytes = fs::read(&path).unwrap();
    // Identical bytes at a new inode cannot substitute for the protected source.
    fs::rename(&path, s.root.join("material/m2-before")).unwrap();
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(check(&m, i).is_err());
}
