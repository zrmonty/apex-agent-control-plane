use super::*;
use crate::proto::RuntimeNetworkGrant;
use serde_json::{Value, json};

fn grant(host: &str, private: bool, cidrs: &[&str]) -> RuntimeNetworkGrant {
    RuntimeNetworkGrant {
        grant_id: host.into(),
        host: host.into(),
        port: 443,
        private_destination: private,
        approved_cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
    }
}
fn run(
    network: &Value,
    published: &[RuntimeNetworkGrant],
    authority: &Value,
) -> Result<Value, &'static str> {
    let c = NetworkCatalog::parse(&serde_json::to_vec(network).unwrap())?;
    let p = c.select(INSTALL, "host-v1", "net", "v1", NOW)?;
    let r = super::super::routes::derive(published, authority, p, &c)?;
    Ok(serde_json::to_value(r).unwrap())
}
fn authority() -> Value {
    json!({"governance":{"endpoint":"https://governance.example"},"evidence":{"endpoint":"https://evidence.example:443"}})
}
fn network() -> Value {
    let mut v = crate::network_catalog::tests::fixture();
    v["profiles"][0]["grants"][2]["cidrs"] = json!(["8.8.8.0/24"]);
    v
}
#[test]
fn public_empty_is_bounded_private_empty_and_wrong_purpose_refuse() {
    let mut n = network();
    let p = [grant("upstream.example", false, &[])];
    let r = run(&n, &p, &authority()).unwrap();
    assert_eq!(r[2]["declared_cidrs"], json!(["8.8.8.0/24"]));
    assert!(run(&n, &[grant("upstream.example", true, &[])], &authority()).is_err());
    n["profiles"][0]["grants"][2]["purpose"] = json!("governance");
    assert!(run(&n, &p, &authority()).is_err());
}
#[test]
fn every_required_purpose_and_published_selector_requires_its_own_bound() {
    for purpose in ["upstream", "governance", "evidence"] {
        let mut n = network();
        for g in n["profiles"][0]["grants"].as_array_mut().unwrap() {
            if g["purpose"] == purpose {
                g["host"] = json!("unused.example");
            }
        }
        assert!(
            run(&n, &[grant("upstream.example", false, &[])], &authority()).is_err(),
            "{purpose}"
        );
    }
    let n = network();
    assert!(run(&n, &[grant("missing.example", false, &[])], &authority()).is_err());
    let mut n = n;
    n["profiles"][0]["grants"].as_array_mut().unwrap().push(
        json!({"purpose":"upstream","host":"unused.example","port":443,"cidrs":["9.9.9.0/24"]}),
    );
    let r = run(&n, &[grant("upstream.example", false, &[])], &authority()).unwrap();
    assert_eq!(r.as_array().unwrap().len(), 3);
    assert!(!r.to_string().contains("unused"));
}
#[test]
fn shared_selector_intersects_all_three_purposes_never_unions_or_first_match() {
    let mut n = network();
    for (index, cidrs) in [
        json!(["8.8.8.0/25", "8.8.8.192/26"]),
        json!(["8.8.8.64/26", "8.8.8.128/25"]),
        json!(["8.8.8.0/24"]),
    ]
    .into_iter()
    .enumerate()
    {
        n["profiles"][0]["grants"][index]["host"] = json!("shared.example");
        n["profiles"][0]["grants"][index]["cidrs"] = cidrs;
    }
    let a = json!({"governance":{"endpoint":"https://shared.example"},"evidence":{"endpoint":"https://shared.example:443"}});
    let p = [grant("shared.example", false, &["8.8.8.0/24"])];
    let r = run(&n, &p, &a).unwrap();
    assert_eq!(r.as_array().unwrap().len(), 1);
    assert_eq!(
        r[0]["declared_cidrs"],
        json!(["8.8.8.64/26", "8.8.8.192/26"])
    );
    assert_eq!(r[0]["protected_cidrs"], r[0]["declared_cidrs"]);
    n["profiles"][0]["grants"][1]["cidrs"] = json!(["8.8.9.0/24"]);
    assert!(run(&n, &p, &a).is_err());
    n["profiles"][0]["grants"][1]["cidrs"] = json!(["10.30.0.0/24"]);
    assert!(run(&n, &p, &a).is_err());
}
#[test]
fn cidrs_are_canonical_reduced_disjoint_and_do_not_widen() {
    let mut n = network();
    n["profiles"][0]["grants"][2]["cidrs"] = json!(["8.8.8.128/25", "8.8.8.0/25", "8.8.8.0/26"]);
    let r = run(&n, &[grant("upstream.example", false, &[])], &authority()).unwrap();
    assert_eq!(r[2]["protected_cidrs"], json!(["8.8.8.0/24"]));
    for cidrs in [
        &["8.8.9.0/24"][..],
        &["8.8.8.1/24"],
        &["8.8.8.0/024"],
        &["8.8.8.0/0"],
        &["::/64"],
        &["8.8.8.0/24", "8.8.8.0/24"],
    ] {
        assert!(
            run(&n, &[grant("upstream.example", false, cidrs)], &authority()).is_err(),
            "{cidrs:?}"
        );
    }
}
#[test]
fn more_than_32_effective_ranges_refuses_instead_of_widening() {
    let mut n = network();
    n["profiles"][0]["grants"][2]["cidrs"] = json!(["8.8.8.0/24"]);
    let mut p = grant("upstream.example", false, &[]);
    p.approved_cidrs = (0..33).map(|x| format!("8.8.8.{}/32", x * 2)).collect();
    assert!(run(&n, &[p.clone()], &authority()).is_err());
    p.approved_cidrs.pop();
    assert_eq!(
        run(&n, &[p], &authority()).unwrap()[2]["declared_cidrs"]
            .as_array()
            .unwrap()
            .len(),
        32
    );
}
#[test]
fn mixed_special_use_and_both_entire_deployment_pools_refuse() {
    for cidrs in [
        json!(["8.8.8.0/24", "10.30.0.0/24"]),
        json!(["0.0.0.0/8"]),
        json!(["100.64.0.0/10"]),
        json!(["127.0.0.0/8"]),
        json!(["169.254.0.0/16"]),
        json!(["192.0.0.0/24"]),
        json!(["192.0.2.0/24"]),
        json!(["192.88.99.0/24"]),
        json!(["198.18.0.0/15"]),
        json!(["198.51.100.0/24"]),
        json!(["203.0.113.0/24"]),
        json!(["224.0.0.0/4"]),
        json!(["240.0.0.0/4"]),
        json!(["10.240.3.248/29"]),
        json!(["172.31.250.254/32"]),
    ] {
        let mut n = network();
        n["profiles"][0]["grants"][2]["cidrs"] = cidrs.clone();
        assert!(
            run(&n, &[grant("upstream.example", false, &[])], &authority()).is_err(),
            "{cidrs}"
        );
    }
}
#[test]
fn dns_aliases_and_public_internal_names_refuse_without_resolution() {
    for name in [
        "127.1",
        "2130706433",
        "0177.0.0.1",
        "0x7f000001",
        "0x7f.0.0.1",
        "localhost",
        "a.localhost",
        "metadata.google.internal",
        "instance-data.ec2.internal",
        "host.docker.internal",
        "gateway.docker.internal",
        "foo.internal",
        "foo.local",
        "UPSTREAM.example",
        "upstream.example.",
    ] {
        let mut n = network();
        n["profiles"][0]["grants"][2]["host"] = json!(name);
        assert!(
            run(&n, &[grant(name, false, &[])], &authority()).is_err(),
            "{name}"
        );
    }
    let mut n = network();
    n["profiles"][0]["grants"][2]["host"] = json!("foo.internal");
    n["profiles"][0]["grants"][2]["cidrs"] = json!(["10.32.0.0/24"]);
    assert!(
        run(
            &n,
            &[grant("foo.internal", true, &["10.32.0.0/25"])],
            &authority()
        )
        .is_ok()
    );
    assert!(run(&n, &[grant("foo.internal", false, &[])], &authority()).is_err());
}
#[test]
fn duplicate_selectors_ids_and_non_https_authority_refuse() {
    let n = network();
    let p = grant("upstream.example", false, &[]);
    assert!(run(&n, &[p.clone(), p.clone()], &authority()).is_err());
    for endpoint in [
        "http://governance.example",
        "https://user@governance.example",
        "https://governance.example/path",
        "https://governance.example?query",
        "https://governance.example#frag",
    ] {
        let mut a = authority();
        a["governance"]["endpoint"] = json!(endpoint);
        assert!(run(&n, std::slice::from_ref(&p), &a).is_err());
    }
}
#[test]
fn prefix_oracle_checks_every_address_against_every_required_input() {
    // Independent bitset oracle over a /24; output must equal all four input sets.
    let prefixes = [
        (0, 24),
        (0, 25),
        (128, 25),
        (64, 26),
        (192, 26),
        (80, 28),
        (81, 32),
    ];
    for &(a, pa) in &prefixes {
        for &(b, pb) in &prefixes {
            for &(c, pc) in &prefixes {
                let mut n = network();
                for (index, (base, prefix)) in [(a, pa), (b, pb), (c, pc)].into_iter().enumerate() {
                    n["profiles"][0]["grants"][index]["host"] = json!("shared.example");
                    n["profiles"][0]["grants"][index]["cidrs"] =
                        json!([format!("8.8.8.{base}/{prefix}")]);
                }
                let a_doc = json!({"governance":{"endpoint":"https://shared.example"},"evidence":{"endpoint":"https://shared.example"}});
                let result = run(
                    &n,
                    &[grant("shared.example", false, &["8.8.8.0/24"])],
                    &a_doc,
                );
                let expected: Vec<u32> = (0..256)
                    .filter(|x| {
                        [(a, pa), (b, pb), (c, pc)]
                            .iter()
                            .all(|(base, p)| *x >= *base && *x < base + (1 << (32 - p)))
                    })
                    .collect();
                if expected.is_empty() {
                    assert!(result.is_err());
                    continue;
                }
                let result = result.unwrap();
                let mut actual = Vec::new();
                for s in result[0]["declared_cidrs"].as_array().unwrap() {
                    let (ip, p) = s.as_str().unwrap().split_once('/').unwrap();
                    let base: u32 = ip.rsplit('.').next().unwrap().parse().unwrap();
                    let p: u32 = p.parse().unwrap();
                    actual.extend(base..base + (1 << (32 - p)));
                }
                assert_eq!(actual, expected, "{a}/{pa} {b}/{pb} {c}/{pc}");
            }
        }
    }
}
