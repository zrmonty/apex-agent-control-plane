//! Running is an observation only. It never proves readiness or grants dispatch.
use super::{ERROR, Engine, Installed, Pair, Role};
use crate::execution::paired::start::{Receipt, Step};
use serde_json::{Value, json};
use std::{sync::atomic::AtomicBool, time::Instant};

fn permitted(p: &Pair, role: Role) -> bool {
    p.start.as_ref().is_some_and(|s| {
        role == Role::Guard || matches!(s.phase, Step::GatewayIntent | Step::Running)
    })
}
pub(super) fn state(v: &Value, p: &Pair, role: Role) -> Result<(), &'static str> {
    if v["State"]["Running"] == true {
        if !permitted(p, role)
            || v["State"]["Status"] != "running"
            || !v["State"]["Pid"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= i32::MAX as u64)
            || !v["State"]["StartedAt"].as_str().is_some_and(timestamp)
        {
            return Err(ERROR);
        }
        let saved = p.start.as_ref().and_then(|s| {
            if role == Role::Guard {
                s.guard.as_ref()
            } else {
                s.gateway.as_ref()
            }
        });
        if saved.is_some_and(|saved| process(v).as_ref() != Ok(saved)) {
            return Err(ERROR);
        }
    } else {
        let required = p.start.as_ref().is_some_and(|s| {
            if role == Role::Guard {
                s.phase != Step::GuardIntent
            } else {
                s.phase == Step::Running
            }
        });
        if required
            || v["State"]["Running"] != false
            || v["State"]["Status"] != "created"
            || v["State"]["Pid"] != 0
            || v["State"]["StartedAt"] != "0001-01-01T00:00:00Z"
        {
            return Err(ERROR);
        }
    }
    Ok(())
}
fn timestamp(s: &str) -> bool {
    s.len() >= 20
        && s.len() <= 30
        && s != "0001-01-01T00:00:00Z"
        && s.ends_with('Z')
        && s.bytes()
            .all(|b| b.is_ascii_digit() || b"-:T.Z".contains(&b))
}
pub(super) fn networks(
    v: &Value,
    i: &Installed,
    role: Role,
    outer: &str,
    connected: bool,
) -> Result<(), &'static str> {
    let p = i.paired_containers.as_ref().ok_or(ERROR)?;
    if !permitted(p, role) {
        return Err(ERROR);
    }
    let g = i.guard_stage.as_ref().ok_or(ERROR)?;
    let t = &g.topology.0.topology.0;
    let n = &v["NetworkSettings"];
    let sandbox = n["SandboxID"]
        .as_str()
        .filter(|s| crate::shapes::hex_hash(s))
        .ok_or(ERROR)?;
    if n["SandboxKey"] != format!("/var/run/docker/netns/{}", &sandbox[..12])
        || v["HostConfig"]["NetworkMode"].as_str() != g.topology.0.observation.as_deref()
    {
        return Err(ERROR);
    }
    let configs = n["Networks"].as_object().ok_or(ERROR)?;
    let two = role == Role::Guard && connected;
    if configs.len() != if two { 2 } else { 1 } {
        return Err(ERROR);
    }
    let id = v["Id"]
        .as_str()
        .filter(|s| crate::shapes::hex_hash(s))
        .ok_or(ERROR)?;
    if role.id(p) != id {
        return Err(ERROR);
    }
    let name = role.name(i);
    let ip = if role == Role::Gateway {
        &t.gateway_workload_address
    } else {
        &t.guard_internal_address
    };
    endpoint(
        configs.get(&t.name()).ok_or(ERROR)?,
        ip,
        g.topology.0.observation.as_deref().ok_or(ERROR)?,
        "",
        29,
        (&name, &id[..12]),
    )?;
    if two {
        let c = t.catalog()?;
        let o = c.outer();
        let prefix = o
            .subnet()
            .split_once('/')
            .ok_or(ERROR)?
            .1
            .parse::<u64>()
            .map_err(|_| ERROR)?;
        endpoint(
            configs.get(outer).ok_or(ERROR)?,
            &t.guard_outer_address,
            o.network_id(),
            o.gateway(),
            prefix,
            (&name, &id[..12]),
        )?;
    }
    Ok(())
}
fn endpoint(
    e: &Value,
    ip: &str,
    network: &str,
    gateway: &str,
    prefix: u64,
    dns: (&str, &str),
) -> Result<(), &'static str> {
    if e["NetworkID"] != network
        || e["IPAddress"] != ip
        || e["Gateway"] != gateway
        || e["IPPrefixLen"] != prefix
        || !e["EndpointID"]
            .as_str()
            .is_some_and(crate::shapes::hex_hash)
        || !e["MacAddress"].as_str().is_some_and(mac)
    {
        return Err(ERROR);
    }
    // Apply the same closed configured-attachment grammar after verifying every
    // active-only field; no active member is accepted by the empty inspector.
    let mut stopped = e.clone();
    for key in [
        "NetworkID",
        "EndpointID",
        "IPAddress",
        "Gateway",
        "MacAddress",
    ] {
        stopped[key] = json!("");
    }
    stopped["IPPrefixLen"] = json!(0);
    super::inspect::endpoint(&stopped, ip, Some(dns))
}
fn mac(s: &str) -> bool {
    s.len() == 17
        && s.split(':').count() == 6
        && s.split(':').all(|p| {
            p.len() == 2
                && p.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
}

fn process(v: &Value) -> Result<Receipt, &'static str> {
    Ok(Receipt {
        process_hash: crate::execution::network::hash(&(
            "apex.runtime.paired-process-observation.v1",
            &v["Id"],
            &v["State"]["StartedAt"],
            &v["State"]["Pid"],
            &v["NetworkSettings"]["SandboxID"],
            &v["NetworkSettings"]["Networks"],
        ))?,
    })
}
impl Engine {
    pub(in crate::execution) fn pair_start(
        &self,
        installation: &str,
        i: &Installed,
        role: Role,
        gate: &mut dyn crate::command::Dispatch,
        cancel: &AtomicBool,
    ) -> Result<(), &'static str> {
        let p = i.paired_containers.as_ref().ok_or(ERROR)?;
        p.validate(installation, i)?;
        let expected = if role == Role::Guard {
            Step::GuardIntent
        } else {
            Step::GatewayIntent
        };
        if p.start.as_ref().is_none_or(|s| s.phase != expected) {
            return Err(ERROR);
        }
        self.pair_effect(
            vec!["container".into(), "start".into(), role.id(p).into()],
            gate,
            cancel,
        )
    }
    pub(in crate::execution) fn pair_start_preflight(
        &self,
        installation: &str,
        i: &Installed,
        role: Role,
        outer: &str,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<(), &'static str> {
        for peer in [Role::Guard, Role::Gateway] {
            let v = self.pair_observe(installation, i, peer, outer, deadline, cancel)?;
            let expected = peer == Role::Guard && role == Role::Gateway;
            if v["State"]["Running"] != expected {
                return Err(ERROR);
            }
        }
        Ok(())
    }
    pub(in crate::execution) fn pair_running(
        &self,
        installation: &str,
        i: &Installed,
        role: Role,
        outer: &str,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Receipt, &'static str> {
        let v = self.pair_observe(installation, i, role, outer, deadline, cancel)?;
        if v["State"]["Running"] != true {
            return Err(ERROR);
        }
        process(&v)
    }
    fn pair_observe(
        &self,
        installation: &str,
        i: &Installed,
        role: Role,
        outer: &str,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Value, &'static str> {
        let p = i.paired_containers.as_ref().ok_or(ERROR)?;
        let bytes = self.run(
            vec!["container".into(), "inspect".into(), role.id(p).into()],
            deadline,
            cancel,
        )?;
        super::inspect::check(
            &bytes,
            installation,
            i,
            role,
            &self.paths.staging_root.join(role.name(i)),
            outer,
            role == Role::Guard,
        )?;
        let parsed = super::super::inspect::Json::parse(&bytes)?;
        Ok(parsed.0.as_array().filter(|a| a.len() == 1).ok_or(ERROR)?[0].clone())
    }
}
