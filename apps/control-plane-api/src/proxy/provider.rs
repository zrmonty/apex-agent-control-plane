//! Runtime-provider boundaries for managed MCP proxy containers.
//!
//! The control plane owns desired state and governance. This module owns only
//! the narrow OCI command surface needed to create, inspect, drain, and remove
//! a runtime. All commands are constructed from validated server-side values;
//! callers cannot supply arbitrary Docker flags or a runtime socket.

use std::process::Command;
use std::sync::Arc;

use crate::proto;

use super::{McpProxyRevision, ProxyError, ProxyRuntimeProvider};

const RUNTIME_NETWORK: &str = "apex-mcp-proxy-egress";
const RUNTIME_USER: &str = "10001:10001";
const TMPFS: &str = "/tmp:rw,noexec,nosuid,size=64m";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeHandle {
    pub container_name: String,
    pub container_id: String,
    pub proxy_id: String,
    pub revision_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    Ready,
    Starting,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCommandOutput {
    pub status: i32,
    pub stdout: String,
}

pub trait RuntimeCommandRunner: Send + Sync {
    fn run(&self, args: &[String]) -> Result<RuntimeCommandOutput, ProxyError>;
}

#[derive(Debug, Default)]
pub struct DockerCommandRunner;

impl RuntimeCommandRunner for DockerCommandRunner {
    fn run(&self, args: &[String]) -> Result<RuntimeCommandOutput, ProxyError> {
        let output = Command::new("docker")
            .args(args)
            .output()
            .map_err(|_| ProxyError::provider_failed())?;
        Ok(RuntimeCommandOutput {
            status: output.status.code().unwrap_or(1),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        })
    }
}

pub struct DockerProxyProvider {
    runner: Arc<dyn RuntimeCommandRunner>,
    network: String,
}

impl DockerProxyProvider {
    pub fn new(runner: Arc<dyn RuntimeCommandRunner>) -> Result<Self, ProxyError> {
        Self::with_network(runner, RUNTIME_NETWORK)
    }

    pub fn with_network(
        runner: Arc<dyn RuntimeCommandRunner>,
        network: impl Into<String>,
    ) -> Result<Self, ProxyError> {
        let network = network.into();
        if network.is_empty()
            || network.len() > 64
            || !network
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ProxyError::invalid_proxy_spec(
                "Proxy runtime network must be a bounded provider-owned name.",
            ));
        }
        Ok(Self { runner, network })
    }

    pub fn provision(&self, revision: &McpProxyRevision) -> Result<RuntimeHandle, ProxyError> {
        let (container_name, proxy_id, revision_id) = identity(revision);
        let inspect = self.run(["container", "inspect", &container_name]);
        if let Ok(output) = inspect
            && output.status == 0
        {
            let container_id = bounded_id(&output.stdout)?;
            return Ok(RuntimeHandle { container_name, container_id, proxy_id, revision_id });
        }

        let args = self.run_args(revision, &container_name);
        let output = self.runner.run(&args)?;
        if output.status != 0 {
            return Err(ProxyError::provider_failed());
        }
        let container_id = bounded_id(&output.stdout)?;
        Ok(RuntimeHandle { container_name, container_id, proxy_id, revision_id })
    }

    pub fn readiness(&self, handle: &RuntimeHandle) -> Result<Readiness, ProxyError> {
        let output = self.run(["container", "inspect", "--format", "{{.State.Status}}", &handle.container_name])?;
        if output.status != 0 {
            return Err(ProxyError::provider_failed());
        }
        match output.stdout.as_str() {
            "running" => Ok(Readiness::Ready),
            "created" | "restarting" => Ok(Readiness::Starting),
            _ => Ok(Readiness::Failed),
        }
    }

    pub fn drain(&self, handle: &RuntimeHandle) -> Result<(), ProxyError> {
        let output = self.run(["container", "stop", "--timeout", "5", &handle.container_name])?;
        if output.status == 0 || output.stdout.contains("No such container") {
            Ok(())
        } else {
            Err(ProxyError::provider_failed())
        }
    }

    pub fn terminate(&self, handle: &RuntimeHandle) -> Result<(), ProxyError> {
        let output = self.run(["container", "rm", "--force", &handle.container_name])?;
        if output.status == 0 || output.stdout.contains("No such container") {
            Ok(())
        } else {
            Err(ProxyError::provider_failed())
        }
    }

    fn run_args(&self, revision: &McpProxyRevision, container_name: &str) -> Vec<String> {
        let runtime = &revision.spec.runtime_profile;
        vec![
            "run".into(), "--detach".into(), "--name".into(), container_name.into(),
            "--label".into(), format!("apex.proxy.id={}", revision.proxy_id),
            "--label".into(), format!("apex.proxy.revision={}", revision.revision_id),
            "--label".into(), format!("apex.proxy.config_hash={}", revision.config_hash),
            "--user".into(), RUNTIME_USER.into(), "--read-only".into(),
            "--security-opt".into(), "no-new-privileges:true".into(), "--cap-drop".into(), "ALL".into(),
            "--tmpfs".into(), TMPFS.into(), "--cpus".into(), runtime.cpu_limit.clone(),
            "--memory".into(), runtime.memory_limit.clone(), "--pids-limit".into(), "128".into(),
            "--network".into(), self.network.clone(), runtime.image_digest.clone(),
        ]
    }

    fn run<const N: usize>(&self, args: [&str; N]) -> Result<RuntimeCommandOutput, ProxyError> {
        self.runner.run(&args.into_iter().map(str::to_owned).collect::<Vec<_>>())
    }
}

impl ProxyRuntimeProvider for DockerProxyProvider {
    fn reconcile(&self, revision: &McpProxyRevision) -> Result<(), ProxyError> {
        let handle = self.provision(revision)?;
        if self.readiness(&handle)? != Readiness::Ready {
            return Err(ProxyError::provider_failed());
        }
        Ok(())
    }

    fn discover(&self, _revision: &McpProxyRevision, _upstream_id: &str) -> Result<proto::ProxyUpstreamDiscovery, ProxyError> {
        Err(ProxyError::provider_failed())
    }

    fn test_connection(&self, _revision: &McpProxyRevision, _upstream_id: &str) -> Result<proto::ProxyConnectionTest, ProxyError> {
        Err(ProxyError::provider_failed())
    }
}

fn identity(revision: &McpProxyRevision) -> (String, String, String) {
    let proxy_id = revision.proxy_id.to_string();
    let revision_id = revision.revision_id.to_string();
    (format!("apex-mcp-proxy-{proxy_id}-{revision_id}"), proxy_id, revision_id)
}

fn bounded_id(value: &str) -> Result<String, ProxyError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(ProxyError::provider_failed());
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProxyId, ProxyRevisionId};
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeRunner {
        calls: Mutex<Vec<Vec<String>>>,
        responses: Mutex<Vec<RuntimeCommandOutput>>,
    }

    impl RuntimeCommandRunner for FakeRunner {
        fn run(&self, args: &[String]) -> Result<RuntimeCommandOutput, ProxyError> {
            self.calls.lock().unwrap().push(args.to_vec());
            Ok(self.responses.lock().unwrap().pop().unwrap_or(RuntimeCommandOutput { status: 0, stdout: "container-id".into() }))
        }
    }

    #[test]
    fn provision_builds_one_hardened_fixed_command_and_is_idempotent() {
        let runner = Arc::new(FakeRunner::default());
        runner.responses.lock().unwrap().extend([
            RuntimeCommandOutput { status: 0, stdout: "running".into() },
            RuntimeCommandOutput { status: 0, stdout: "container-id".into() },
            RuntimeCommandOutput { status: 1, stdout: "not found".into() },
        ]);
        let provider = DockerProxyProvider::new(runner.clone()).unwrap();
        let revision = revision();
        let first = provider.provision(&revision).unwrap();
        let second = provider.provision(&revision).unwrap();
        assert_eq!(first.container_name, second.container_name);
        let calls = runner.calls.lock().unwrap();
        let run = calls.iter().find(|call| call.first().map(String::as_str) == Some("run")).unwrap();
        assert!(run.contains(&"--read-only".into()));
        assert!(run.contains(&"--cap-drop".into()));
        assert!(run.contains(&"ALL".into()));
        assert!(run.contains(&"--security-opt".into()));
        assert!(run.contains(&"no-new-privileges:true".into()));
        assert!(!run.iter().any(|value| value == "--privileged" || value == "/var/run/docker.sock"));
    }

    #[test]
    fn readiness_requires_a_running_container() {
        let runner = Arc::new(FakeRunner::default());
        runner.responses.lock().unwrap().push(RuntimeCommandOutput { status: 0, stdout: "created".into() });
        let provider = DockerProxyProvider::new(runner).unwrap();
        let handle = RuntimeHandle { container_name: "proxy".into(), container_id: "id".into(), proxy_id: "proxy".into(), revision_id: "revision".into() };
        assert_eq!(provider.readiness(&handle).unwrap(), Readiness::Starting);
    }

    fn revision() -> McpProxyRevision {
        McpProxyRevision::new(
            ProxyId::new("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84").unwrap(),
            ProxyRevisionId::new("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e85").unwrap(),
            crate::proxy::tests::valid_proxy_spec(),
            "a".repeat(64),
            super::super::ProxyLifecycleState::Ready,
        ).unwrap()
    }
}
