//! Fixed effects for immutable stopped-pair ownership and subsequent guarded start.
//! Child modules independently inspect stopped and running state for recovery.
use super::*;
use crate::execution::paired::{Pair, Phase};
use std::collections::BTreeMap;
pub(in crate::execution) mod inspect;
mod inventory;
pub(in crate::execution) mod running;
#[cfg(test)]
mod shutdown;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::execution) enum Role {
    Gateway,
    Guard,
}
impl Role {
    pub(in crate::execution) fn name(self, i: &Installed) -> String {
        format!(
            "apex-{}-{}",
            if self == Self::Gateway {
                "runtime"
            } else {
                "guard"
            },
            i.instance
        )
    }
    pub(in crate::execution) fn id(self, p: &Pair) -> &str {
        if self == Self::Gateway {
            &p.gateway_id
        } else {
            &p.guard_id
        }
    }
    pub(in crate::execution) fn image(self, p: &Pair) -> &str {
        if self == Self::Gateway {
            &p.gateway_image_id
        } else {
            &p.guard_image_id
        }
    }
    pub(in crate::execution) fn keys(self, p: &Pair) -> &[String] {
        if self == Self::Gateway {
            &p.gateway_unset_env
        } else {
            &p.guard_unset_env
        }
    }
}
pub(in crate::execution) fn environment(
    installation: &str,
    i: &Installed,
    role: Role,
) -> Result<Vec<String>, &'static str> {
    let guard = i.guard_stage.as_ref().ok_or(ERROR)?;
    if role == Role::Guard {
        return Ok(guard
            .environment
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect());
    }
    let mut projection = i.clone();
    projection.files = i.gateway_stage.as_ref().ok_or(ERROR)?.files.clone();
    let mut env = handoff::environment(installation, &projection)?;
    let mode = env
        .iter_mut()
        .find(|v| *v == "APEX_MCP_MANAGED_BOOTSTRAP=sealed-stage-v1")
        .ok_or(ERROR)?;
    *mode = "APEX_MCP_MANAGED_BOOTSTRAP=sealed-stage-v2".into();
    env.extend([
        "APEX_MCP_NETWORK_PROFILE=isolated-bridge-v1".into(),
        format!(
            "APEX_MCP_GUARD_ADDRESS={}",
            guard.topology.0.topology.0.guard_internal_address
        ),
        format!(
            "APEX_MCP_NETWORK_BINDING_SHA256={}",
            i.network.as_ref().ok_or(ERROR)?.binding_hash
        ),
    ]);
    Ok(env)
}
pub(in crate::execution) fn labels(
    installation: &str,
    i: &Installed,
    role: Role,
) -> Result<BTreeMap<String, String>, &'static str> {
    let l = serde_json::from_str(&i.launch_json).map_err(|_| ERROR)?;
    let p = i.paired_containers.as_ref().ok_or(ERROR)?;
    let g = i.guard_stage.as_ref().ok_or(ERROR)?;
    let mut labels: BTreeMap<_, _> = super::inspect::labels(installation, &l)?
        .into_iter()
        .map(|(k, v)| (format!("io.apex.runtime.{k}"), v))
        .collect();
    for (k, v) in [
        (
            "container-role",
            if role == Role::Gateway {
                "gateway".into()
            } else {
                "guard".into()
            },
        ),
        ("pair-binding-hash", p.binding_hash.clone()),
        ("network-topology-hash", g.topology.0.topology_hash.clone()),
        (
            "paired-container-name",
            if role == Role::Gateway {
                Role::Guard.name(i)
            } else {
                Role::Gateway.name(i)
            },
        ),
    ] {
        labels.insert(format!("io.apex.runtime.{k}"), v);
    }
    Ok(labels)
}
impl Engine {
    pub(in crate::execution) fn pair_pull(
        &self,
        image: &crate::signature::VerifiedImage,
        gate: &mut dyn command::Dispatch,
        cancel: &AtomicBool,
    ) -> Result<(), &'static str> {
        self.pair_effect(
            vec!["image".into(), "pull".into(), image.image_ref().into()],
            gate,
            cancel,
        )
    }
    pub(in crate::execution) fn pair_create(
        &self,
        installation: &str,
        i: &Installed,
        role: Role,
        gate: &mut dyn command::Dispatch,
        cancel: &AtomicBool,
    ) -> Result<(), &'static str> {
        let p = i.paired_containers.as_ref().ok_or(ERROR)?;
        p.validate(installation, i)?;
        if p.phase
            != if role == Role::Gateway {
                Phase::GatewayIntent
            } else {
                Phase::GuardIntent
            }
            || i.mount_profile != self.mount.name()
        {
            return Err(ERROR);
        }
        let g = i.guard_stage.as_ref().ok_or(ERROR)?;
        let t = &g.topology.0.topology.0;
        let env = environment(installation, i, role)?;
        let mut args: Vec<String> = [
            "container",
            "create",
            "--cgroupns=private",
            "--restart=no",
            "--user=10001:10001",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--memory=268435456",
            "--memory-swap=268435456",
            "--cpus=1",
            "--pids-limit=128",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777",
            "--entrypoint=/usr/local/bin/node",
            "--workdir=/app/apps/mcp-gateway",
            "--no-healthcheck",
            "--log-driver=none",
            "--dns-search=.",
            "--dns-option=ndots:0",
            "--sysctl=net.ipv4.ip_forward=0",
            "--sysctl=net.ipv6.conf.all.forwarding=0",
            "--sysctl=net.ipv6.conf.all.disable_ipv6=1",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        if role == Role::Gateway {
            args.push("--dns=127.0.0.1".into());
        }
        args.extend([
            format!("--network={}", g.topology.0.observation.as_ref().ok_or(ERROR)?),
            format!("--ip={}", if role == Role::Gateway { &t.gateway_workload_address } else { &t.guard_internal_address }),
            format!("--name={}",role.name(i)),
            format!("--mount=type=bind,source={},target=/apex/runtime,readonly,bind-propagation={},bind-recursive=disabled",
                self.paths.staging_root.join(role.name(i)).display(),self.mount.propagation()),
        ]);
        for (k, v) in labels(installation, i, role)? {
            args.push(format!("--label={k}={v}"));
        }
        for k in role.keys(p) {
            if !env
                .iter()
                .any(|e| e.split_once('=').is_some_and(|(key, _)| key == k))
            {
                args.push(format!("--env={k}"));
            }
        }
        args.extend(env.into_iter().map(|e| format!("--env={e}")));
        args.push(role.image(p).into());
        args.push(
            if role == Role::Gateway {
                "/app/apps/mcp-gateway/dist/index.js"
            } else {
                "/app/apps/mcp-gateway/dist/managed/guard/main.js"
            }
            .into(),
        );
        self.pair_effect(args, gate, cancel)
    }
    pub(in crate::execution) fn pair_connect(
        &self,
        i: &Installed,
        gate: &mut dyn command::Dispatch,
        cancel: &AtomicBool,
    ) -> Result<(), &'static str> {
        let p = i.paired_containers.as_ref().ok_or(ERROR)?;
        let t = &i.guard_stage.as_ref().ok_or(ERROR)?.topology.0.topology.0;
        if p.phase != Phase::ConnectIntent || !shapes::hex_hash(&p.guard_id) {
            return Err(ERROR);
        }
        self.pair_effect(
            vec![
                "network".into(),
                "connect".into(),
                format!("--ip={}", t.guard_outer_address),
                t.catalog()?.outer().network_id().into(),
                p.guard_id.clone(),
            ],
            gate,
            cancel,
        )
    }
    fn pair_effect(
        &self,
        arguments: Vec<String>,
        gate: &mut dyn command::Dispatch,
        cancel: &AtomicBool,
    ) -> Result<(), &'static str> {
        self.check()?;
        #[cfg(test)]
        crate::execution::testing::at(
            crate::execution::testing::Point::Preflight,
            Some(gate.deadline()?),
        )?;
        let mut args: Vec<OsString> = vec![
            format!("--host=unix://{}", self.paths.docker_socket.display()).into(),
            format!("--config={}", self.paths.docker_config_root.display()).into(),
        ];
        args.extend(arguments.into_iter().map(OsString::from));
        let executable = PathBuf::from(format!("/proc/self/fd/{}", self.executable.as_raw_fd()));
        // Create stdout is deliberately discarded, never an identity source.
        let _output = Zeroizing::new(command::run_guarded(
            CommandInput {
                executable: &executable,
                arguments: &args,
                directory: &self.paths.docker_config_root,
                home: None,
                budget: Duration::from_secs(30),
                cancelled: cancel,
            },
            gate,
        )?);
        Ok(())
    }
    pub(in crate::execution) fn pair_inspect(
        &self,
        installation: &str,
        i: &Installed,
        role: Role,
        attachment: (&str, bool),
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<String, &'static str> {
        let bytes = self.run(
            vec!["container".into(), "inspect".into(), role.name(i)],
            deadline,
            cancel,
        )?;
        inspect::check(
            &bytes,
            installation,
            i,
            role,
            &self.paths.staging_root.join(role.name(i)),
            attachment.0,
            attachment.1,
        )
    }
}
