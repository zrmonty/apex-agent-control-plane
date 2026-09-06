use super::*;
fn fixture() -> Value {
    json!([{"Name":"native-shape","Id":"a".repeat(64),"Scope":"local","Driver":"bridge",
        "EnableIPv4":true,"EnableIPv6":false,"Internal":true,"Attachable":false,"Ingress":false,
        "ConfigOnly":false,"ConfigFrom":{"Network":""},"IPAM":{"Driver":"default","Options":{},
        "Config":[{"Subnet":"10.248.0.0/29","Gateway":"10.248.0.1"}]},
        "Options":{"com.docker.network.bridge.gateway_mode_ipv4":"isolated"},"Containers":{},"Labels":{}}])
}
fn parse(v: &Value) -> Result<Inspected, &'static str> {
    Inspected::parse(&serde_json::to_vec(v).unwrap())
}
#[test]
fn explicit_native_shape_separates_ipam_from_workload_address() {
    let n = parse(&fixture()).unwrap();
    assert!(n.profile(true, "10.248.0.0/29", "10.248.0.1").is_ok());
    assert!(n.profile(true, "10.248.0.0/29", "10.248.0.2").is_err());
}
#[test]
fn auxiliary_and_endpoint_allocations_cannot_duplicate_reserved_gateway() {
    let mut v = fixture();
    v[0]["IPAM"]["Config"][0]["AuxiliaryAddresses"] = json!({"collision":"10.248.0.1"});
    assert!(
        parse(&v).is_err(),
        "duplicate auxiliary allocation must refuse"
    );
    v = fixture();
    v[0]["Containers"] = json!({"b".repeat(64):{"IPv4Address":"10.248.0.1/29","IPv6Address":""}});
    assert!(
        parse(&v).is_err(),
        "endpoint cannot collide with IPAM gateway"
    );
}
#[test]
fn exact_flags_and_geometry_are_not_defaulted() {
    for field in [
        "EnableIPv4",
        "EnableIPv6",
        "Internal",
        "Attachable",
        "Ingress",
        "ConfigOnly",
    ] {
        let mut v = fixture();
        v[0].as_object_mut().unwrap().remove(field);
        assert!(
            parse(&v)
                .unwrap()
                .profile(true, "10.248.0.0/29", "10.248.0.1")
                .is_err()
        );
    }
    let mut v = fixture();
    v[0]["Options"]["com.docker.network.bridge.enable_ip_masquerade"] = json!("true");
    assert!(
        parse(&v)
            .unwrap()
            .profile(true, "10.248.0.0/29", "10.248.0.1")
            .is_err()
    );
}
#[test]
fn all_ipam_subnets_and_foreign_endpoint_ranges_are_validated() {
    let mut v = fixture();
    v[0]["IPAM"]["Config"]
        .as_array_mut()
        .unwrap()
        .push(json!({"Subnet":"10.248.0.0/24","Gateway":"10.248.0.2"}));
    assert!(parse(&v).is_err());
    v = fixture();
    v[0]["Containers"] = json!({"b".repeat(64):{"IPv4Address":"10.249.0.2/29","IPv6Address":""}});
    assert!(parse(&v).is_err());
    v = fixture();
    v[0]["IPAM"]["Config"][0]["IPRange"] = json!("10.249.0.0/29");
    assert!(parse(&v).is_err());
}
#[test]
fn opaque_plugin_empty_bridge_and_positional_ipam_refuse() {
    let mut v = fixture();
    v[0]["Driver"] = json!("opaque");
    assert!(parse(&v).is_err());
    v = fixture();
    v[0]["IPAM"]["Config"] = json!([]);
    assert!(parse(&v).is_err());
    v = fixture();
    v[0]["IPAM"]["Config"] = json!([["10.248.0.0/29", "10.248.0.1"]]);
    assert!(parse(&v).is_err());
}
#[test]
fn duplicate_json_and_oversized_inspect_refuse() {
    assert!(Inspected::parse(b"[{\"Id\":\"a\",\"Id\":\"b\"}]").is_err());
    assert!(Inspected::parse(&vec![b' '; 262145]).is_err());
}
#[test]
fn interval_intersection_detects_both_directions_and_address_families() {
    let small = Range::parse("10.248.0.8/29", true).unwrap();
    assert!(small.overlaps(Range::parse("10.248.0.0/24", true).unwrap()));
    assert!(!small.overlaps(Range::parse("10.248.0.0/29", true).unwrap()));
    assert!(!small.overlaps(Range::parse("fd00::/64", true).unwrap()));
}
