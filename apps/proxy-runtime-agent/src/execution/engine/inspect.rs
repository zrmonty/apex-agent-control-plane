use super::*;
use serde_json::{Value, json};
pub(crate) mod json;
pub(super) use json::Json;
pub(super) fn empty(v: &Value) -> bool {
    v.is_null()
        || v.as_array().is_some_and(Vec::is_empty)
        || v.as_object().is_some_and(|o| o.is_empty())
}
pub(in crate::execution) fn labels(
    installation: &str,
    l: &proto::RuntimeLaunchContext,
) -> Result<Vec<(&'static str, String)>, &'static str> {
    let t = l.target.as_ref().ok_or(ERROR)?;
    Ok(vec![
        ("installation-id", installation.into()),
        ("workspace-id", t.workspace_id.clone()),
        ("namespace-id", t.namespace_id.clone()),
        ("proxy-id", t.proxy_id.clone()),
        ("revision-id", t.revision_id.clone()),
        ("generation", t.generation.to_string()),
        ("fencing-token", t.fencing_token.to_string()),
        ("config-hash", l.config_hash.clone()),
        ("runtime-manifest-hash", l.runtime_manifest_hash.clone()),
        ("launch-context-hash", l.launch_context_hash.clone()),
        ("process-instance-id", l.process_instance_id.clone()),
    ])
}
pub(super) fn check(
    bytes: &[u8],
    installation: &str,
    i: &Installed,
    stage: &Path,
) -> Result<String, &'static str> {
    let l: proto::RuntimeLaunchContext = serde_json::from_str(&i.launch_json).map_err(|_| ERROR)?;
    let v = Json::parse(bytes)?;
    let a = v.0.as_array().filter(|a| a.len() == 1).ok_or(ERROR)?;
    let v = &a[0];
    let id = v["Id"]
        .as_str()
        .filter(|s| shapes::hex_hash(s))
        .ok_or(ERROR)?;
    if !i.container_id.is_empty() && i.container_id != id {
        return Err(ERROR);
    }
    let expected = crate::ExpectedRuntimeOwnership::from_unverified(crate::RuntimeOwnershipInput {
        installation_id: installation.into(),
        container_id: id.into(),
        image_id: i.image_id.clone(),
        name: format!("apex-runtime-{}", i.instance),
        target: i.original.target.clone().ok_or(ERROR)?,
        config_hash: i.original.config_hash.clone(),
        runtime_manifest_hash: l.runtime_manifest_hash,
        launch_context_hash: l.launch_context_hash,
        process_instance_id: i.instance.clone(),
    });
    let text = std::str::from_utf8(bytes).map_err(|_| ERROR)?;
    let owned = crate::check_owned_inspect(text, &expected).map_err(|_| ERROR)?;
    if owned.state() != crate::EngineState::Created
        || v["State"]["Running"] != false
        || v["State"]["Pid"] != 0
        || v["State"]["StartedAt"] != "0001-01-01T00:00:00Z"
    {
        return Err(ERROR);
    }
    let h = &v["HostConfig"];
    let c = &v["Config"];
    let mut env: Vec<_> = c["Env"]
        .as_array()
        .ok_or(ERROR)?
        .iter()
        .map(|v| v.as_str().ok_or(ERROR))
        .collect::<Result<_, _>>()?;
    env.sort_unstable();
    let environment = handoff::environment(installation, i)?;
    let mut fixed: Vec<&str> = environment.iter().map(String::as_str).collect();
    // Docker records an explicitly unset inherited variable as a bare key.
    // Accept only the independently pinned image's exact bounded key set.
    for key in &i.unset_env {
        if !environment
            .iter()
            .any(|e| e.split_once('=').is_some_and(|(k, _)| k == key))
        {
            fixed.push(key);
        }
    }
    fixed.sort_unstable();
    if env != fixed
        || c["User"] != "10001:10001"
        || c["Entrypoint"] != json!(["/usr/local/bin/node"])
        || c["Cmd"] != json!(["/app/apps/mcp-gateway/dist/index.js"])
        || c["WorkingDir"] != "/app/apps/mcp-gateway"
        || c["Healthcheck"]["Test"] != json!(["NONE"])
        || !empty(&c["Volumes"])
        || h["NetworkMode"] != "none"
        || h["CgroupnsMode"] != "private"
        || h["ReadonlyRootfs"] != true
        || h["Privileged"] != false
        || h["CapDrop"] != json!(["ALL"])
        || !empty(&h["CapAdd"])
        || h["SecurityOpt"] != json!(["no-new-privileges:true"])
        || h["Memory"] != 268435456
        || h["MemorySwap"] != 268435456
        || h["NanoCpus"] != 1000000000u64
        || h["PidsLimit"] != 128
        || h["RestartPolicy"]["Name"] != "no"
        || h["RestartPolicy"]["MaximumRetryCount"] != 0
        || h["PublishAllPorts"] != false
        || h["AutoRemove"] != false
        || h["LogConfig"]["Type"] != "none"
        || h["Tmpfs"] != json!({"/tmp":"rw,noexec,nosuid,nodev,size=16777216,mode=1777"})
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
        "Sysctls",
    ] {
        if !empty(&h[key]) {
            return Err(ERROR);
        }
    }
    for key in ["PidMode", "UTSMode", "UsernsMode", "CgroupParent"] {
        if h[key] != "" {
            return Err(ERROR);
        }
    }
    if !matches!(h["IpcMode"].as_str(), Some("private" | ""))
        || !empty(&v["NetworkSettings"]["Ports"])
    {
        return Err(ERROR);
    }
    let mounts = v["Mounts"]
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or(ERROR)?;
    let m = &mounts[0];
    let propagation = match i.mount_profile.as_str() {
        "private-stage-v1" => "rprivate",
        "owned-daemon-volume-v1" => "rslave",
        _ => return Err(ERROR),
    };
    if m["Type"] != "bind"
        || m["Source"].as_str() != stage.to_str()
        || m["Destination"] != "/apex/runtime"
        || m["RW"] != false
        || m["Propagation"] != propagation
    {
        return Err(ERROR);
    }
    let hm = h["Mounts"]
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or(ERROR)?;
    if hm[0]["Type"] != "bind"
        || hm[0]["Source"].as_str() != stage.to_str()
        || hm[0]["Target"] != "/apex/runtime"
        || hm[0]["ReadOnly"] != true
        || hm[0]["BindOptions"]["Propagation"] != propagation
        || hm[0]["BindOptions"]["NonRecursive"] != true
    {
        return Err(ERROR);
    }
    Ok(id.into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_nested_engine_fields_are_refused_without_retaining_canary() {
        assert!(
            Json::parse(br#"[{"Config":{"Env":[],"Env":["SECRET=engine-canary"]}}]"#).is_err(),
            "duplicate engine fields must refuse"
        );
    }
}
