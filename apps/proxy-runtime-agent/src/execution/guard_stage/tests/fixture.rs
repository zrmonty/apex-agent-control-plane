use super::*;
use crate::{
    execution::{
        metadata::Catalogs,
        network,
        network_owner::topology::{Phase, Topology},
        record,
    },
    launch::LaunchCatalog,
    proto,
};
use serde_json::{Value, json};
pub(super) const NOW: u64 = 9_007_199_254_740_993;
pub(super) const INSTALL: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01";
pub(super) const INSTANCE: &str = "0191b7f1-7f2c-7c13-9a61-2f29f2be1003";
pub(super) struct Fixture {
    pub i: Installed,
    pub launch: PreparedLaunch,
    pub selected: Selected,
    pub catalogs: Catalogs,
    pub catalog: NetworkCatalog,
    pub document: Document,
    pub network_json: Value,
}
impl Fixture {
    pub fn new() -> Self {
        let path = std::env::var_os("APEX_RUNTIME_FIXTURE_PATH").unwrap();
        let config: proto::RuntimeConfiguration =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let a = proto::RuntimeAuthoritySnapshot {
            target: Some(proto::RuntimeTarget {
                workspace_id: config.workspace_id.clone(),
                namespace_id: config.namespace_id.clone(),
                proxy_id: config.proxy_id.clone(),
                revision_id: config.revision_id.clone(),
                generation: config.generation,
                fencing_token: NOW,
            }),
            installation_id: INSTALL.into(),
            host_policy_version: "host-v1".into(),
            config_hash: config.config_hash.clone(),
            checked_at_unix_us: NOW,
            ..Default::default()
        };
        let scope = json!({"installation_id":INSTALL,"workspace_id":config.workspace_id,"namespace_id":config.namespace_id,
            "proxy_id":config.proxy_id,"revision_id":config.revision_id,"host_policy_version":"host-v1",
            "deployment_bindings_version":"bindings-v1","config_hash":config.config_hash});
        let doc = |profile: Value| {
            json!({"schema_version":1,"version":"v1","valid_from_unix_us":1,
            "expires_at_unix_us":i64::MAX,"profiles":[profile]})
        };
        let mut p = scope.clone();
        p["authority_profile_ref"] = json!("live");
        p["authority_profile_version"] = json!("v1");
        p["image_catalog_id"] = json!("gateway");
        p["materials"] = json!((1..=13).map(|n| json!({"role":proto::RuntimeMaterialRole::try_from(n).unwrap().as_str_name(),
            "reference":format!("secret://deployment/material-{n}"),"version":"v1","source_name":format!("m{n}")})).collect::<Vec<_>>());
        let launch = LaunchCatalog::parse(&serde_json::to_vec(&doc(p)).unwrap())
            .unwrap()
            .fixture_prepare_data(&a, &config, "bindings-v1", INSTANCE)
            .unwrap();
        let mut p = scope.clone();
        for k in ["revision_id", "deployment_bindings_version", "config_hash"] {
            p.as_object_mut().unwrap().remove(k);
        }
        p["reference"] = json!("live");
        p["version"] = json!("v1");
        p["mode"] = json!("managed_ingress");
        for purpose in ["governance", "evidence"] {
            p[purpose] = json!({"endpoint":format!("https://{purpose}.example"),"tls_server_name":format!("{purpose}.example")});
        }
        p["managed"] = json!({"evidence_agent_id":"managed-evidence","upstream_credentials":"managed_upstream_v1",
            "network_policy":{"reference":"net","version":"v1"},"ingress":{"port":8080,"tls_server_name":"gateway.example","edge_certificate_sha256":["a".repeat(64)]}});
        let mut auth = doc(p);
        auth["schema_version"] = json!(3);
        let mut p = scope;
        p["entries"] = json!(
            config
                .secret_refs
                .iter()
                .enumerate()
                .map(
                    |(n, r)| json!({"reference":r,"version":"v1","source_name":format!("tool{n}")})
                )
                .collect::<Vec<_>>()
        );
        let images = json!({"schema_version":1,"images":[
            {"id":"gateway","image_ref":config.image_ref,"signing":{"certificate_oidc_issuer":"https://issuer.example","certificate_identity":"fixture@example.com"}},
            {"id":"guard-v1","image_ref":format!("registry.example/guard@sha256:{}","b".repeat(64)),"signing":{"certificate_oidc_issuer":"https://issuer.example","certificate_identity":"guard@example.com"}}]});
        let catalogs = Catalogs::parse(
            &serde_json::to_vec(&images).unwrap(),
            &serde_json::to_vec(&auth).unwrap(),
            &serde_json::to_vec(&doc(p)).unwrap(),
        )
        .unwrap();
        let selected = catalogs
            .select(&a, "bindings-v1", &config, &launch)
            .unwrap();
        let i = Installed {
            original: proto::RuntimeReconcileRequest {
                schema_version: 1,
                target: a.target,
                config_hash: a.config_hash,
                operation_id: INSTANCE.into(),
                command_id: INSTANCE.into(),
            },
            instance: INSTANCE.into(),
            launch_json: String::from_utf8(launch.launch_json().to_vec()).unwrap(),
            configuration_json: String::from_utf8(launch.configuration_json().to_vec()).unwrap(),
            authority_json: String::from_utf8(selected.authority_json.clone()).unwrap(),
            tools_json: String::from_utf8(selected.tools_json.clone()).unwrap(),
            publication_hash: "b".repeat(64),
            image_id: String::new(),
            mount_profile: "private-stage-v1".into(),
            unset_env: vec![],
            container_id: String::new(),
            phase: record::Phase::Intent,
            files: BTreeMap::new(),
            instance_proof_version: Some(1),
            network: None,
        };
        let mut network_json = crate::network_catalog::tests::fixture();
        network_json["valid_from_unix_us"] = json!(NOW);
        network_json["profiles"][0]["grants"][2] = json!({"purpose":"upstream","host":"portfolio-api.apex.test","port":443,"cidrs":["8.8.8.0/24"]});
        let catalog = NetworkCatalog::parse(&serde_json::to_vec(&network_json).unwrap()).unwrap();
        let mut f = Self {
            i,
            launch,
            selected,
            catalogs,
            catalog,
            document: Document::prepared(dummy()).unwrap(),
            network_json,
        };
        f.rebind();
        f
    }
    pub fn rebind(&mut self) {
        self.catalog =
            NetworkCatalog::parse(&serde_json::to_vec(&self.network_json).unwrap()).unwrap();
        let c = &self.catalog;
        let o = c.outer();
        let layout = network::hash(&(
            c.installation_id(),
            c.internal_pool(),
            c.capacity(),
            o.network_id(),
            o.subnet(),
            o.gateway(),
            o.edge_address(),
        ))
        .unwrap();
        self.i.network = Some(
            network::Binding::new(
                INSTALL,
                INSTANCE,
                0,
                layout,
                network::owner_hash(&self.i).unwrap(),
            )
            .unwrap(),
        );
        self.document =
            Document::prepared(Topology::new(c, INSTALL, &self.i, "c".repeat(64), NOW).unwrap())
                .unwrap();
        self.document.phase = Phase::Observed;
        self.document.observation = Some("d".repeat(64));
    }
    pub fn input(&self) -> Inputs<'_> {
        Inputs {
            installation: INSTALL,
            installed: &self.i,
            launch: &self.launch,
            selected: &self.selected,
            catalog: &self.catalog,
            images: &self.catalogs.images,
            source_digest: "c".repeat(64),
            observed: &self.document,
            now: NOW,
        }
    }
}
fn dummy() -> Topology {
    // Placeholder solely to assemble the fixture before creating its real bound topology.
    serde_json::from_value(json!({"schema_version":1,"installation":"","instance":"","original":{},
        "binding":{"schema_version":1,"slot":0,"layout_hash":"","owner_hash":"","binding_hash":""},"launch_json":"",
        "selected_catalog_json":"","source_digest":"","internal_subnet":"","ipam_gateway":"",
        "gateway_workload_address":"","guard_internal_address":"","guard_outer_address":""})).unwrap()
}
