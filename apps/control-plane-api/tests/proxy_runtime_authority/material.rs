use super::{
    operation::Fixture,
    pki::{self, Pki},
};
use apex_control_plane_api::{RuntimeAuthorityOwner, RuntimeAuthorityPolicyFiles};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub const INSTALLATION: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01";

pub struct Materials {
    root: PathBuf,
    parent: PathBuf,
    pub peer: Value,
    pub enrollment: Value,
}

impl Materials {
    pub fn new(fixture: &Fixture, pki: &Pki) -> Self {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let root = parent.join(format!("apex-authority-live-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&root).expect("fresh owned metadata fixture");
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros(),
        )
        .unwrap();
        let from = (now - 60_000_000).to_string();
        let until = (now + 300_000_000).to_string();
        let scope = json!({"workspaceId":fixture.target.workspace_id,
            "namespaceId":fixture.target.namespace_id});
        let mut grant = scope.clone();
        grant["installationId"] = INSTALLATION.into();
        let peer = json!({"schemaVersion":1,"version":"live-policy-1",
            "validFromUnixUs":from,"expiresAtUnixUs":until,
            "peers":[
                {"certificateSha256":pki::hex(&pki.pin(pki::AGENT)),"identityId":"live-agent",
                    "role":"agent","revoked":false,"grants":[grant.clone()]},
                {"certificateSha256":pki::hex(&pki.pin(pki::CONTROLLER)),"identityId":"live-controller",
                    "role":"controller","revoked":false,"grants":[grant]}]});
        let enrollment = json!({"schemaVersion":1,"version":"live-enrollment-1",
            "peerPolicyVersion":"live-policy-1","validFromUnixUs":from,"expiresAtUnixUs":until,
            "controllers":[{"identityId":"live-controller","workerId":"controller-a"}],
            "installations":[{"installationId":INSTALLATION,"agentIdentityId":"live-agent",
                "revoked":false,"hostPolicyVersion":"live-host-policy-1","scopes":[scope]}]});
        let value = Self {
            root,
            parent,
            peer,
            enrollment,
        };
        value.write();
        value
    }

    pub fn write(&self) {
        for (name, value) in [
            ("peer.json", &self.peer),
            ("enrollment.json", &self.enrollment),
        ] {
            fs::write(self.root.join(name), serde_json::to_vec(value).unwrap()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(self.root.join(name), fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
        }
    }

    pub fn remove_enrollment(&self) {
        fs::remove_file(self.root.join("enrollment.json")).unwrap();
    }

    pub fn enrollment_path(&self) -> PathBuf {
        self.root.join("enrollment.json")
    }

    pub fn owner(&self, url: &str) -> OwnerGuard {
        let files = RuntimeAuthorityPolicyFiles::new(
            self.root.clone(),
            "peer.json".into(),
            "enrollment.json".into(),
        )
        .unwrap();
        OwnerGuard(RuntimeAuthorityOwner::new(files, url).unwrap())
    }
}

/// Tests retain and observe root cleanup even when an assertion unwinds.
pub struct OwnerGuard(RuntimeAuthorityOwner);
impl std::ops::Deref for OwnerGuard {
    type Target = RuntimeAuthorityOwner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for OwnerGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for OwnerGuard {
    fn drop(&mut self) {
        let observed = self.0.shutdown();
        if !std::thread::panicking() {
            assert!(
                observed.cleanup_complete,
                "test-owned worker cleanup incomplete"
            );
        }
    }
}

impl Drop for Materials {
    fn drop(&mut self) {
        assert_eq!(self.root.parent(), Some(self.parent.as_path()));
        assert!(
            self.root
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("apex-authority-live-")
        );
        assert!(
            !fs::symlink_metadata(&self.root)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(self.root.canonicalize().unwrap(), self.root);
        fs::remove_dir_all(&self.root).expect("remove exact owned fixture only");
    }
}
