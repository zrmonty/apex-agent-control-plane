//! Independent Docker29 never-started observation grammar; no create-output adoption.
use super::{ERROR, Installed, Role};
use crate::execution::engine::inspect::{Json, empty};
use serde_json::{Value, json};
use std::path::Path;

pub(in crate::execution) fn check(
    bytes: &[u8],
    installation: &str,
    i: &Installed,
    role: Role,
    stage: &Path,
    outer_name: &str,
    connected: bool,
) -> Result<String, &'static str> {
    let parsed = Json::parse(bytes)?;
    let v = &parsed.0.as_array().filter(|a| a.len() == 1).ok_or(ERROR)?[0];
    let p = i.paired_containers.as_ref().ok_or(ERROR)?;
    p.validate(installation, i)?;
    let id = v["Id"]
        .as_str()
        .filter(|v| crate::shapes::hex_hash(v))
        .ok_or(ERROR)?;
    if (!role.id(p).is_empty() && role.id(p) != id)
        || v["Name"] != format!("/{}", role.name(i))
        || v["Image"] != role.image(p)
        || v["Config"]["Image"] != role.image(p)
        || v["Platform"] != "linux"
        || v["State"]["FinishedAt"] != "0001-01-01T00:00:00Z"
        || v["RestartCount"] != 0
        || v["State"]["ExitCode"] != 0
        || v["State"]["Error"] != ""
    {
        return Err(ERROR);
    }
    super::running::state(v, p, role)?;
    for key in ["Paused", "Restarting", "Dead", "OOMKilled"] {
        if v["State"][key] != false {
            return Err(ERROR);
        }
    }
    let actual = v["Config"]["Labels"]
        .as_object()
        .filter(|l| l.len() <= 64)
        .ok_or(ERROR)?;
    let labels = super::labels(installation, i, role)?;
    if labels
        .iter()
        .any(|(k, val)| actual.get(k).and_then(Value::as_str) != Some(val))
        || actual
            .keys()
            .any(|k| k.starts_with("io.apex.runtime.") && !labels.contains_key(k))
    {
        return Err(ERROR);
    }
    let mut env = super::environment(installation, i, role)?;
    for k in role.keys(p) {
        if !env
            .iter()
            .any(|e| e.split_once('=').is_some_and(|(key, _)| key == k))
        {
            env.push(k.clone());
        }
    }
    let mut observed: Vec<&str> = v["Config"]["Env"]
        .as_array()
        .ok_or(ERROR)?
        .iter()
        .map(|v| v.as_str().ok_or(ERROR))
        .collect::<Result<_, _>>()?;
    env.sort_unstable();
    observed.sort_unstable();
    if observed != env {
        return Err(ERROR);
    }
    let entry = if role == Role::Gateway {
        "/app/apps/mcp-gateway/dist/index.js"
    } else {
        "/app/apps/mcp-gateway/dist/managed/guard/main.js"
    };
    let c = &v["Config"];
    if c["User"] != "10001:10001"
        || c["Entrypoint"] != json!(["/usr/local/bin/node"])
        || c["Cmd"] != json!([entry])
        || v["Path"] != "/usr/local/bin/node"
        || v["Args"] != json!([entry])
        || c["WorkingDir"] != "/app/apps/mcp-gateway"
        || c["Healthcheck"]["Test"] != json!(["NONE"])
        || !empty(&c["Volumes"])
        || !empty(&c["ExposedPorts"])
        || c["Tty"] != false
        || c["OpenStdin"] != false
        || c["StdinOnce"] != false
        || c["Domainname"] != ""
        || c["Hostname"] != id[..12]
    {
        return Err(ERROR);
    }
    sandbox(v, stage, &i.mount_profile)?;
    let h = &v["HostConfig"];
    if h["Dns"]
        != if role == Role::Gateway {
            json!(["127.0.0.1"])
        } else {
            Value::Null
        }
        || h["DnsSearch"] != json!(["."])
        || h["DnsOptions"] != json!(["ndots:0"])
        || h["Sysctls"]
            != json!({"net.ipv4.ip_forward":"0", "net.ipv6.conf.all.forwarding":"0", "net.ipv6.conf.all.disable_ipv6":"1"})
    {
        return Err(ERROR);
    }
    networks(v, i, role, outer_name, connected)?;
    Ok(id.into())
}

fn sandbox(v: &Value, stage: &Path, profile: &str) -> Result<(), &'static str> {
    let h = &v["HostConfig"];
    if h["CgroupnsMode"] != "private"
        || h["ReadonlyRootfs"] != true
        || h["Privileged"] != false
        || h["CapDrop"] != json!(["ALL"])
        || !empty(&h["CapAdd"])
        || h["SecurityOpt"] != json!(["no-new-privileges:true"])
        || h["Memory"] != 268435456
        || h["MemorySwap"] != 268435456
        || h["NanoCpus"] != 1_000_000_000u64
        || h["PidsLimit"] != 128
        || h["RestartPolicy"] != json!({"Name":"no","MaximumRetryCount":0})
        || h["PublishAllPorts"] != false
        || h["AutoRemove"] != false
        || h["LogConfig"] != json!({"Type":"none","Config":{}})
        || h["Tmpfs"] != json!({"/tmp":"rw,noexec,nosuid,nodev,size=16777216,mode=1777"})
        || h["IpcMode"] != "private"
        || h["Runtime"] != "runc"
        // Docker29 normalizes the unset OOM-killer override from false at create
        // to explicit null after start. Missing and true are never accepted.
        || (h["OomKillDisable"] != false
            && !(v["State"]["Running"] == true
                && h.as_object().and_then(|m| m.get("OomKillDisable")) == Some(&Value::Null)))
    {
        return Err(ERROR);
    }
    for key in [
        "Binds",
        "PortBindings",
        "Devices",
        "DeviceRequests",
        "DeviceCgroupRules",
        "VolumesFrom",
        "Links",
        "GroupAdd",
        "ExtraHosts",
        "Ulimits",
        "BlkioWeightDevice",
        "BlkioDeviceReadBps",
        "BlkioDeviceWriteBps",
        "BlkioDeviceReadIOps",
        "BlkioDeviceWriteIOps",
        "StorageOpt",
    ] {
        if !empty(&h[key]) {
            return Err(ERROR);
        }
    }
    for key in [
        "PidMode",
        "UTSMode",
        "UsernsMode",
        "CgroupParent",
        "Cgroup",
        "VolumeDriver",
        "Isolation",
        "ContainerIDFile",
        "CpusetCpus",
        "CpusetMems",
    ] {
        if h[key] != "" {
            return Err(ERROR);
        }
    }
    for key in [
        "CpuShares",
        "CpuPeriod",
        "CpuQuota",
        "CpuRealtimePeriod",
        "CpuRealtimeRuntime",
        "MemoryReservation",
        "OomScoreAdj",
        "BlkioWeight",
        "CpuCount",
        "CpuPercent",
        "IOMaximumIOps",
        "IOMaximumBandwidth",
    ] {
        if h[key] != 0 {
            return Err(ERROR);
        }
    }
    if !empty(&v["NetworkSettings"]["Ports"]) || !empty(&v["ExecIDs"]) {
        return Err(ERROR);
    }
    let propagation = match profile {
        "private-stage-v1" => "rprivate",
        "owned-daemon-volume-v1" => "rslave",
        _ => return Err(ERROR),
    };
    let mounts = v["Mounts"]
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or(ERROR)?;
    let m = &mounts[0];
    if m["Type"] != "bind"
        || m["Source"].as_str() != stage.to_str()
        || m["Destination"] != "/apex/runtime"
        || m["RW"] != false
        || m["Propagation"] != propagation
    {
        return Err(ERROR);
    }
    let mounts = h["Mounts"]
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or(ERROR)?;
    if mounts[0]
        != json!({"Type":"bind","Source":stage.to_str().ok_or(ERROR)?,"Target":"/apex/runtime",
        "ReadOnly":true,"BindOptions":{"Propagation":propagation,"NonRecursive":true}})
    {
        return Err(ERROR);
    }
    Ok(())
}

pub(in crate::execution) fn networks(
    v: &Value,
    i: &Installed,
    role: Role,
    outer_name: &str,
    connected: bool,
) -> Result<(), &'static str> {
    let g = i.guard_stage.as_ref().ok_or(ERROR)?;
    let t = &g.topology.0.topology.0;
    let n = &v["NetworkSettings"];
    if v["State"]["Running"] == true {
        return super::running::networks(v, i, role, outer_name, connected);
    }
    if v["HostConfig"]["NetworkMode"].as_str() != g.topology.0.observation.as_deref()
        || n["SandboxID"] != ""
        || n["SandboxKey"] != ""
    {
        return Err(ERROR);
    }
    let configs = n["Networks"].as_object().ok_or(ERROR)?;
    let two = role == Role::Guard && connected;
    if configs.len() != if two { 2 } else { 1 } {
        return Err(ERROR);
    }
    let address = if role == Role::Gateway {
        &t.gateway_workload_address
    } else {
        &t.guard_internal_address
    };
    endpoint(configs.get(&t.name()).ok_or(ERROR)?, address, None)?;
    if two {
        let id = v["Id"]
            .as_str()
            .filter(|s| crate::shapes::hex_hash(s))
            .ok_or(ERROR)?;
        endpoint(
            configs.get(outer_name).ok_or(ERROR)?,
            &t.guard_outer_address,
            Some((&role.name(i), &id[..12])),
        )?;
    }
    Ok(())
}
pub(super) fn endpoint(e: &Value, ip: &str, dns: Option<(&str, &str)>) -> Result<(), &'static str> {
    let object = e.as_object().ok_or(ERROR)?;
    if object.keys().any(|k| {
        !matches!(
            k.as_str(),
            "IPAMConfig"
                | "Links"
                | "Aliases"
                | "DriverOpts"
                | "GwPriority"
                | "NetworkID"
                | "EndpointID"
                | "Gateway"
                | "IPAddress"
                | "MacAddress"
                | "IPPrefixLen"
                | "IPv6Gateway"
                | "GlobalIPv6Address"
                | "GlobalIPv6PrefixLen"
                | "DNSNames"
        )
    }) || e["IPAMConfig"] != json!({"IPv4Address":ip})
        || !empty(&e["Links"])
        || !empty(&e["Aliases"])
        || !empty(&e["DriverOpts"])
        || e["GwPriority"] != 0
        || e["IPPrefixLen"] != 0
        || e["GlobalIPv6PrefixLen"] != 0
    {
        return Err(ERROR);
    }
    for key in [
        "NetworkID",
        "EndpointID",
        "Gateway",
        "IPAddress",
        "MacAddress",
        "IPv6Gateway",
        "GlobalIPv6Address",
    ] {
        if e[key] != "" {
            return Err(ERROR);
        }
    }
    if if let Some((name, short)) = dns {
        e["DNSNames"] != json!([name, short])
    } else {
        !empty(&e["DNSNames"])
    } {
        return Err(ERROR);
    }
    Ok(())
}

#[cfg(test)]
mod running_native_tests {
    use super::*;
    #[test]
    fn task4z_recorded_native_running_sandbox_preserves_oom_kill() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/task4z-running-guard.json"
        ));
        let v = Json::parse(bytes).unwrap();
        let v = &v.0[0];
        let stage = Path::new(v["Mounts"][0]["Source"].as_str().unwrap());
        assert!(
            sandbox(v, stage, "owned-daemon-volume-v1").is_ok(),
            "actual Docker running sandbox must retain the OOM-killer default"
        );
        let mut changed = v.clone();
        changed["HostConfig"]["OomKillDisable"] = json!(true);
        assert!(sandbox(&changed, stage, "owned-daemon-volume-v1").is_err());
        changed["HostConfig"]
            .as_object_mut()
            .unwrap()
            .remove("OomKillDisable");
        assert!(sandbox(&changed, stage, "owned-daemon-volume-v1").is_err());
    }
}
