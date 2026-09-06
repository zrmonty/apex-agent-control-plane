use super::*;
use apex_control_plane_api::*;
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use uuid::Uuid;
pub const INSTALL: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01";
pub const IMAGE: &str = "ghcr.io/sigstore/cosign/cosign@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8";
pub const TOKEN: &str = "task3b-disposable-operator-token";

pub struct Proxy {
    pub scope: ExactScope,
    pub id: ProxyId,
    pub revision: McpProxyRevision,
}
pub struct Fixture {
    pub store: PostgresProxyStore,
    pub database: recovery::Database,
    pub root: PathBuf,
    pub pki: pki::Pki,
    pub proxies: Vec<Proxy>,
    pub cp: SocketAddr,
    pub agent: SocketAddr,
}
impl Fixture {
    pub fn new() -> Self {
        Self::prepare(false)
    }
    pub fn for_registration() -> Self {
        Self::prepare(true)
    }
    fn prepare(registration: bool) -> Self {
        let base = PathBuf::from(
            std::env::var_os("APEX_TASK3B_ROOT").expect("scoped owned Docker volume required"),
        );
        assert_eq!(
            base,
            Path::new("/var/lib/docker/volumes/apex-task3a-01a073bf-owned/_data")
        );
        let root = base.join(format!("task3b-{}", Uuid::now_v7()));
        directory(&root);
        for dir in [
            "control", "config", "journal", "staging", "material", "docker", "cosign",
        ] {
            directory(&root.join(dir));
        }
        let database = recovery::Database::new();
        let store = PostgresProxyStore::connect(&database.url).unwrap();
        let mut proxies = vec![];
        for namespace in ["namespace", "namespace-two"] {
            let scope = ExactScope {
                workspace_id: "workspace".into(),
                namespace_id: namespace.into(),
            };
            let id = ProxyId::new(Uuid::now_v7().to_string()).unwrap();
            store
                .create(CreateProxy {
                    request_id: Uuid::now_v7().to_string(),
                    scope: scope.clone(),
                    proxy_id: id.clone(),
                    display_name: "Joint dormant fixture".into(),
                    slug: id.to_string(),
                    description: None,
                    owner: None,
                })
                .unwrap();
            let mut spec = spec::supported_spec();
            if registration {
                spec.governance_binding.policy_id = "apex-mcp-read-v1".into();
            }
            spec.runtime_profile.image_digest = IMAGE.split('@').nth(1).unwrap().into();
            let draft = store
                .update_draft(UpdateProxyDraft {
                    request_id: Uuid::now_v7().to_string(),
                    scope: scope.clone(),
                    proxy_id: id.clone(),
                    expected_revision_id: None,
                    actor_id: "operator".into(),
                    spec,
                })
                .unwrap();
            let revision = store
                .publish_revision(PublishRevision {
                    request_id: Uuid::now_v7().to_string(),
                    scope: scope.clone(),
                    proxy_id: id.clone(),
                    draft_revision_id: draft.draft_revision_id.unwrap(),
                    expected_revision_id: None,
                    actor_id: "operator".into(),
                })
                .unwrap();
            proxies.push(Proxy {
                scope,
                id,
                revision,
            });
        }
        let cp = port();
        let agent = port();
        let f = Self {
            store,
            database,
            root,
            pki: pki::Pki::require(),
            proxies,
            cp,
            agent,
        };
        metadata::write(&f);
        if registration {
            super::registration::configuration::write(&f);
        }
        f
    }
    pub fn target(&self, index: usize) -> proto::ProxyResourceScope {
        let p = &self.proxies[index];
        proto::ProxyResourceScope {
            workspace_id: p.scope.workspace_id.clone(),
            namespace_id: p.scope.namespace_id.clone(),
            proxy_id: p.id.to_string(),
        }
    }
    pub fn observed(&self, operation: &proto::ProxyOperation) -> proto::ProxyOperation {
        let p = self
            .proxies
            .iter()
            .find(|p| p.id.to_string() == operation.scope.as_ref().unwrap().proxy_id)
            .unwrap();
        self.store
            .get_proxy_operation(&p.scope, &p.id, &operation.operation_id)
            .unwrap()
            .unwrap()
    }
    pub fn runtime_response(&self, index: usize) -> proto::RuntimeReconcileResponse {
        use prost::Message;
        let bytes: Vec<u8> = self
            .database
            .client()
            .query_one(
                "SELECT response_bytes FROM mcp_proxy_runtime_attempts WHERE proxy_id=$1",
                &[self.proxies[index].id.as_uuid()],
            )
            .unwrap()
            .get(0);
        proto::RuntimeReconcileResponse::decode(bytes.as_slice()).unwrap()
    }
    pub fn expire(&self, index: usize) {
        self.database
            .client()
            .execute(
                "UPDATE mcp_proxy_controller_leases SET expires_at_micros=0 WHERE proxy_id=$1",
                &[self.proxies[index].id.as_uuid()],
            )
            .unwrap();
    }
}
pub fn write(root: &Path, name: &str, bytes: &[u8]) {
    assert!(!name.contains(['/', '\\']));
    fs::write(root.join(name), bytes).unwrap();
    fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
}
pub fn json(root: &Path, name: &str, value: &serde_json::Value) {
    write(root, name, &serde_json::to_vec(value).unwrap());
}
fn directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn port() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
