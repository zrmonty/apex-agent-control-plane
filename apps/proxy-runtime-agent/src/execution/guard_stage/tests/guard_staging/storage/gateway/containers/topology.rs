use super::*;
fn endpoint(ip: &str) -> serde_json::Value {
    // Recorded Docker29 stopped shape, independent of the production argv builder.
    json!({"IPAMConfig":{"IPv4Address":ip},"Links":null,"Aliases":null,"DriverOpts":null,
        "GwPriority":0,"NetworkID":"","EndpointID":"","Gateway":"","IPAddress":"","MacAddress":"",
        "IPPrefixLen":0,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"DNSNames":null})
}
pub(super) fn observation(role: Role) -> serde_json::Value {
    let mut networks = json!({format!("apex-net-{INSTANCE}"):endpoint(if role == Role::Gateway {"10.240.0.2"}else{"10.240.0.3"})});
    if role == Role::Guard {
        let mut outer = endpoint("172.31.250.16");
        outer["Aliases"] = json!([]);
        outer["DriverOpts"] = json!({});
        outer["DNSNames"] = json!([format!("apex-guard-{INSTANCE}"), "eeeeeeeeeeee"]);
        networks["protected-outer"] = outer;
    }
    json!({"Id":"e".repeat(64),"HostConfig":{"NetworkMode":"d".repeat(64)},
        "NetworkSettings":{"SandboxID":"","SandboxKey":"","Networks":networks}})
}
#[test]
fn task4y_stopped_topology_checks_configured_memberships_without_inventing_active_endpoints() {
    let mut s = Storage::new();
    prepared(&mut s);
    let i = s.record.installed.as_ref().unwrap();
    for role in [Role::Gateway, Role::Guard] {
        let original = observation(role);
        assert!(
            engine_pair::inspect::networks(
                &original,
                i,
                role,
                "protected-outer",
                role == Role::Guard
            )
            .is_ok()
        );
        for (field, bad) in [
            ("EndpointID", json!("e".repeat(64))),
            ("NetworkID", json!("d".repeat(64))),
            ("Aliases", json!(["foreign"])),
            ("DriverOpts", json!({"arbitrary":"option"})),
            ("IPAMConfig", json!({"IPv4Address":"10.240.0.4"})),
            ("DNSNames", json!(["foreign"])),
        ] {
            let mut v = original.clone();
            v["NetworkSettings"]["Networks"][format!("apex-net-{INSTANCE}")][field] = bad;
            assert!(
                engine_pair::inspect::networks(&v, i, role, "protected-outer", role == Role::Guard)
                    .is_err(),
                "{field}"
            );
        }
        for field in ["SandboxID", "SandboxKey"] {
            let mut v = original.clone();
            v["NetworkSettings"][field] = json!("active");
            assert!(
                engine_pair::inspect::networks(&v, i, role, "protected-outer", role == Role::Guard)
                    .is_err()
            );
        }
        let mut missing = original.clone();
        missing["NetworkSettings"]["Networks"]
            .as_object_mut()
            .unwrap()
            .remove(&format!("apex-net-{INSTANCE}"));
        assert!(
            engine_pair::inspect::networks(
                &missing,
                i,
                role,
                "protected-outer",
                role == Role::Guard
            )
            .is_err()
        );
        let mut extra = original.clone();
        extra["NetworkSettings"]["Networks"]["unguarded"] = endpoint("10.240.0.5");
        assert!(
            engine_pair::inspect::networks(&extra, i, role, "protected-outer", role == Role::Guard)
                .is_err()
        );
    }
}
#[test]
fn task4y_two_instance_pair_and_stage_identity_cannot_be_cross_adopted() {
    let mut first = Storage::new();
    prepared(&mut first);
    let mut second = Storage::with_instance("0191b7f1-7f2c-7c13-9a61-2f29f2be1004");
    prepared(&mut second);
    let a = first.record.installed.as_ref().unwrap();
    let b = second.record.installed.as_ref().unwrap();
    assert_ne!(
        a.paired_containers.as_ref().unwrap().binding_hash,
        b.paired_containers.as_ref().unwrap().binding_hash
    );
    assert!(
        a.paired_containers
            .as_ref()
            .unwrap()
            .validate(INSTALL, b)
            .is_err()
    );
    assert!(
        engine_pair::inspect::networks(
            &observation(Role::Gateway),
            b,
            Role::Gateway,
            "protected-outer",
            false
        )
        .is_err()
    );
    assert_ne!(
        a.gateway_stage.as_ref().unwrap().files["instance-proof"],
        b.gateway_stage.as_ref().unwrap().files["instance-proof"]
    );
}
