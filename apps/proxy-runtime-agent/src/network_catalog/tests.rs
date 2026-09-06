use super::*;
use serde_json::{Value, json};
pub(crate) fn fixture() -> Value {
    json!({"schema_version":1,"version":"net-v1",
        "installation_id":"018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01","host_policy_version":"host-v1",
        "valid_from_unix_us":1,"expires_at_unix_us":9223372036854775807u64,
        "capacity":128,"internal_pool":"10.240.0.0/22",
        "outer":{"network_id":"a".repeat(64),"subnet":"172.31.250.0/24",
            "gateway":"172.31.250.1","edge_address":"172.31.250.2"},
        "profiles":[{"reference":"net","version":"v1","guard_image_catalog_id":"guard-v1",
            "guard_image_ref":format!("registry.example/guard@sha256:{}", "b".repeat(64)),
            "grants":[{"purpose":"governance","host":"governance.example","port":443,"cidrs":["10.30.0.0/24"]},
                {"purpose":"evidence","host":"evidence.example","port":443,"cidrs":["10.31.0.0/24"]},
                {"purpose":"upstream","host":"upstream.example","port":443,"cidrs":["203.0.113.8/32"]}]}]})
}
#[test]
fn protected_network_catalog_accepts_complete_bound_policy() {
    assert!(NetworkCatalog::parse(&serde_json::to_vec(&fixture()).unwrap()).is_ok());
}
fn parse(v: &Value) -> Result<NetworkCatalog, &'static str> {
    NetworkCatalog::parse(&serde_json::to_vec(v).unwrap())
}
#[test]
fn strict_shapes_bounds_and_purposes_refuse() {
    let cases = [
        ("/schema_version", json!(2)),
        ("/schema_version", json!(1.0)),
        ("/version", json!("")),
        ("/version", json!("x".repeat(129))),
        ("/installation_id", json!("not-an-installation")),
        ("/host_policy_version", json!("..")),
        ("/valid_from_unix_us", json!(0)),
        ("/expires_at_unix_us", json!(1)),
        ("/expires_at_unix_us", json!(9223372036854775808u64)),
        ("/capacity", json!(0)),
        ("/capacity", json!(129)),
        ("/capacity", json!(-1)),
        ("/capacity", json!(1.5)),
        ("/outer", json!([])),
        ("/outer/network_id", json!("a".repeat(63))),
        ("/outer/network_id", json!("A".repeat(64))),
        ("/outer/gateway", json!("172.31.250.2")),
        ("/outer/edge_address", json!("172.31.250.16")),
        ("/outer/edge_address", json!("172.31.250.0")),
        ("/outer/edge_address", json!("172.31.251.2")),
        ("/outer/edge_address", json!("0172.31.250.2")),
        ("/profiles", json!([])),
        ("/profiles/0", json!([])),
        ("/profiles/0/reference", json!("..")),
        ("/profiles/0/version", json!(null)),
        ("/profiles/0/guard_image_catalog_id", json!("../guard")),
        (
            "/profiles/0/guard_image_ref",
            json!("registry.example/guard:latest"),
        ),
        ("/profiles/0/grants", json!([])),
        ("/profiles/0/grants/0", json!([])),
        ("/profiles/0/grants/0/purpose", json!({"governance":null})),
        ("/profiles/0/grants/0/purpose", json!("dns")),
        ("/profiles/0/grants/0/port", json!(0)),
        ("/profiles/0/grants/0/port", json!(65536)),
        ("/profiles/0/grants/0/cidrs", json!([])),
    ];
    for (path, bad) in cases {
        let mut v = fixture();
        *v.pointer_mut(path).unwrap() = bad;
        assert_eq!(parse(&v).err(), Some(ERROR), "{path}");
    }
    for path in ["", "/outer", "/profiles/0", "/profiles/0/grants/0"] {
        let mut v = fixture();
        v.pointer_mut(path).unwrap()["canary-secret"] = json!("CANARY");
        assert_eq!(parse(&v).err(), Some(ERROR));
        let mut v = fixture();
        *v.pointer_mut(path).unwrap() = Value::Null;
        assert_eq!(parse(&v).err(), Some(ERROR));
    }
}
#[test]
fn original_duplicates_unknowns_and_oversized_bytes_refuse() {
    let text = serde_json::to_string(&fixture()).unwrap();
    for (key, value) in [
        ("schema_version", "1"),
        ("network_id", "\"a\""),
        ("reference", "\"net\""),
        ("purpose", "\"governance\""),
    ] {
        let token = format!("\"{key}\":");
        let bad = text.replacen(&token, &format!("{token}{value},{token}"), 1);
        assert_eq!(NetworkCatalog::parse(bad.as_bytes()).err(), Some(ERROR));
    }
    let escaped = text.replacen(
        "\"schema_version\":",
        "\"schema_versi\\u006fn\":1,\"schema_version\":",
        1,
    );
    for bytes in [
        vec![],
        vec![b' '; 262_145],
        b"[]".to_vec(),
        b"null".to_vec(),
        [text.as_bytes(), b" false"].concat(),
        escaped.into_bytes(),
        vec![0xff],
    ] {
        assert_eq!(NetworkCatalog::parse(&bytes).err(), Some(ERROR));
    }
}
#[test]
fn canonical_dns_only_no_url_ip_or_localhost_alias() {
    for host in [
        "localhost",
        "a.localhost",
        "127.0.0.1",
        "1.2.3",
        "::1",
        "*.example",
        "EXAMPLE",
        "a.",
        "a..b",
        "-a.example",
        "a-.example",
        "a_b.example",
        "https://a.example",
        "a.example:443",
        "a\n.example",
        "é.example",
    ] {
        let mut v = fixture();
        v["profiles"][0]["grants"][0]["host"] = json!(host);
        assert_eq!(parse(&v).err(), Some(ERROR), "{host}");
    }
    for host in ["governance", "xn--test.example", "a1-b.example"] {
        let mut v = fixture();
        v["profiles"][0]["grants"][0]["host"] = json!(host);
        assert!(parse(&v).is_ok());
    }
}
#[test]
fn pools_and_entire_egress_cidr_ranges_are_checked() {
    for pool in [
        "10.240.0.0/21",
        "10.240.0.0/30",
        "10.240.0.0/023",
        "10.240.0.1/22",
        "11.0.0.0/22",
        "0.0.0.0/0",
        "::/22",
        "10.240.0.0/33",
        "10.240.0.0/-1",
    ] {
        let mut v = fixture();
        v["internal_pool"] = json!(pool);
        assert_eq!(parse(&v).err(), Some(ERROR));
    }
    for pool in ["10.240.0.0/24", "172.31.250.0/25", "203.0.113.0/24"] {
        let mut v = fixture();
        v["outer"]["subnet"] = json!(pool);
        assert_eq!(parse(&v).err(), Some(ERROR));
    }
    for cidr in [
        "0.0.0.0/0",
        "0.1.2.3/32",
        "127.0.0.1/32",
        "126.0.0.0/7",
        "169.254.169.254/32",
        "169.0.0.0/8",
        "224.0.0.0/3",
        "240.1.2.3/32",
        "10.240.0.0/22",
        "10.0.0.0/8",
        "10.240.3.255/32",
        "172.31.250.143/32",
        "172.16.0.0/12",
        "10.30.0.1/24",
        "10.30.0.0/024",
        "::/0",
    ] {
        let mut v = fixture();
        v["profiles"][0]["grants"][0]["cidrs"] = json!([cidr]);
        assert_eq!(parse(&v).err(), Some(ERROR), "{cidr}");
    }
    for cidr in [
        "10.239.255.255/32",
        "10.240.4.0/32",
        "172.31.249.255/32",
        "172.31.251.0/32",
        "8.8.8.8/32",
    ] {
        let mut v = fixture();
        v["profiles"][0]["grants"][0]["cidrs"] = json!([cidr]);
        assert!(parse(&v).is_ok());
    }
}
#[test]
fn no_duplicate_selector_grant_or_cidr_and_bounded_collections() {
    for (path, max) in [
        ("/profiles", 32),
        ("/profiles/0/grants", 64),
        ("/profiles/0/grants/0/cidrs", 32),
    ] {
        let mut v = fixture();
        let array = v.pointer_mut(path).unwrap().as_array_mut().unwrap();
        array.push(array[0].clone());
        assert_eq!(parse(&v).err(), Some(ERROR));
        let mut v = fixture();
        let first = v.pointer(path).unwrap()[0].clone();
        *v.pointer_mut(path).unwrap() = json!(vec![first; max + 1]);
        assert_eq!(parse(&v).err(), Some(ERROR));
    }
    for purpose in ["governance", "evidence"] {
        let mut v = fixture();
        v["profiles"][0]["grants"]
            .as_array_mut()
            .unwrap()
            .retain(|g| g["purpose"] != purpose);
        assert_eq!(parse(&v).err(), Some(ERROR));
    }
}
#[test]
fn all_candidate_slots_disjoint_and_capacity_is_not_an_allocation() {
    let catalog = parse(&fixture()).unwrap();
    let mut internal = std::collections::BTreeSet::new();
    let mut outer = std::collections::BTreeSet::new();
    for slot in 0..128 {
        let a = catalog.candidate_addresses(slot).unwrap();
        assert!(internal.insert(a.gateway));
        assert!(internal.insert(a.guard_internal));
        assert!(outer.insert(a.guard_outer));
        assert_eq!(u32::from(a.guard_internal), u32::from(a.gateway) + 1);
        assert_eq!(a, catalog.candidate_addresses(slot).unwrap());
    }
    let last = catalog.candidate_addresses(127).unwrap();
    assert_eq!(last.internal_subnet, "10.240.3.248/29");
    assert_eq!(last.guard_outer.to_string(), "172.31.250.143");
    assert!(catalog.candidate_addresses(128).is_err());
    for prefix in 22..=29 {
        let mut v = fixture();
        v["internal_pool"] = json!(format!("10.240.0.0/{prefix}"));
        let capacity = 1 << (29 - prefix);
        v["capacity"] = json!(capacity);
        assert!(parse(&v).is_ok());
        v["capacity"] = json!(capacity + 1);
        assert!(parse(&v).is_err());
    }
}
#[test]
fn selection_is_exact_scoped_and_time_bounded() {
    let v = fixture();
    let c = parse(&v).unwrap();
    let installation = v["installation_id"].as_str().unwrap();
    assert!(c.select(installation, "host-v1", "net", "v1", 1).is_ok());
    assert!(
        c.select(installation, "host-v1", "net", "v1", i64::MAX as u64 - 1)
            .is_ok()
    );
    for now in [0, i64::MAX as u64, u64::MAX] {
        assert_eq!(c.current(now), Err(ERROR));
    }
    for (i, h, r, v) in [
        ("wrong", "host-v1", "net", "v1"),
        (installation, "wrong", "net", "v1"),
        (installation, "host-v1", "wrong", "v1"),
        (installation, "host-v1", "net", "wrong"),
    ] {
        assert!(c.select(i, h, r, v, 1).is_err());
    }
}
#[test]
fn guard_selection_joins_exact_protected_image_not_tags() {
    let v = fixture();
    let c = parse(&v).unwrap();
    let images = json!({"schema_version":1,"images":[{"id":"guard-v1",
        "image_ref":v["profiles"][0]["guard_image_ref"],"signing":{
        "certificate_oidc_issuer":"https://issuer.example","certificate_identity":"release@example.com"}}]});
    let parse_image = |v: &Value| ImageCatalog::parse(&serde_json::to_vec(v).unwrap()).unwrap();
    assert!(c.join_images(&parse_image(&images)).is_ok());
    let mut bad = images.clone();
    bad["images"][0]["id"] = json!("wrong");
    assert!(c.join_images(&parse_image(&bad)).is_err());
    let mut bad = images;
    bad["images"][0]["image_ref"] =
        json!(format!("registry.example/guard@sha256:{}", "c".repeat(64)));
    assert!(c.join_images(&parse_image(&bad)).is_err());
}

#[test]
fn collection_maxima_and_integer_microseconds_remain_exact() {
    let mut v = fixture();
    v["valid_from_unix_us"] = json!(9_007_199_254_740_993u64);
    v["expires_at_unix_us"] = json!(9_007_199_254_741_992u64);
    let mut grants = vec![
        v["profiles"][0]["grants"][0].clone(),
        v["profiles"][0]["grants"][1].clone(),
    ];
    for n in 0..62 {
        grants.push(
            json!({"purpose":"upstream","host":format!("g{n}.example"),"port":65535,
        "cidrs":(0..32).map(|i|format!("10.32.0.{i}/32")).collect::<Vec<_>>()}),
        );
    }
    v["profiles"][0]["grants"] = json!(grants);
    let p = v["profiles"][0].clone();
    v["profiles"] = json!(
        (0..32)
            .map(|n| {
                let mut p = p.clone();
                p["reference"] = json!(format!("n{n}"));
                p
            })
            .collect::<Vec<_>>()
    );
    // Full Cartesian maxima exceed the original byte cap and are intentionally refused.
    assert!(serde_json::to_vec(&v).unwrap().len() > 262144);
    assert!(parse(&v).is_err());
    v["profiles"] = json!([p]);
    let c = parse(&v).unwrap();
    assert!(c.current(9_007_199_254_740_992).is_err());
    assert!(c.current(9_007_199_254_740_993).is_ok());
    assert!(c.current(9_007_199_254_741_991).is_ok());
    assert!(c.current(9_007_199_254_741_992).is_err());
    v["profiles"][0]["grants"] = fixture()["profiles"][0]["grants"].clone();
    let p = v["profiles"][0].clone();
    v["profiles"] = json!(
        (0..32)
            .map(|n| {
                let mut p = p.clone();
                p["reference"] = json!(format!("n{n}"));
                p
            })
            .collect::<Vec<_>>()
    );
    assert!(parse(&v).is_ok());
}

#[test]
fn dns_only_catalog_refuses_native_numeric_aliases() {
    for host in [
        "0x7f000001",
        "0x7f.0.0.1",
        "0x0a000001",
        "0x7f.1",
        "127.0x1",
        "0x7f.00.0x00.01",
        "0177.0.0.1",
        "017700000001",
        "2130706433",
        "127.1",
        "127.0.0.1",
        "0x100000000",
    ] {
        let mut v = fixture();
        v["profiles"][0]["grants"][0]["host"] = json!(host);
        assert_eq!(
            parse(&v).err(),
            Some(ERROR),
            "numeric address alias: {host}"
        );
    }
    for host in [
        "governance",
        "a1-b.example",
        "xn--test.example",
        "0x7f.example",
        "0xguard",
    ] {
        let mut v = fixture();
        v["profiles"][0]["grants"][0]["host"] = json!(host);
        assert!(parse(&v).is_ok(), "DNS control: {host}");
    }
}
