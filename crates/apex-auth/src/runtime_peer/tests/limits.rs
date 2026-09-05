use super::*;

#[test]
fn original_byte_limit_accepts_exact_boundary_and_rejects_one_more() {
    let mut bytes = serde_json::to_vec(&document()).unwrap();
    bytes.resize(65_536, b' ');
    assert_eq!(
        RuntimePeerPolicy::parse_json(&bytes).unwrap().version(),
        "policy-1"
    );
    bytes.push(b' ');
    assert_eq!(
        RuntimePeerPolicy::parse_json(&bytes).unwrap_err(),
        RuntimePeerError::InvalidPolicy
    );
}

#[test]
fn malformed_utf8_bom_trailing_json_and_incomplete_input_reject() {
    for input in [b"".as_slice(), b"\xff", b"\xc0\xaf", b"{", b"[]", b"null"] {
        assert_eq!(
            RuntimePeerPolicy::parse_json(input).unwrap_err(),
            RuntimePeerError::InvalidPolicy
        );
    }
    let good = serde_json::to_vec(&document()).unwrap();
    for suffix in [b"{}".as_slice(), b"\xff", b" false", b"/*comment*/"] {
        let mut bytes = good.clone();
        bytes.extend_from_slice(suffix);
        assert_eq!(
            RuntimePeerPolicy::parse_json(&bytes).unwrap_err(),
            RuntimePeerError::InvalidPolicy
        );
    }
    let mut bom = b"\xef\xbb\xbf".to_vec();
    bom.extend_from_slice(&good);
    assert_eq!(
        RuntimePeerPolicy::parse_json(&bom).unwrap_err(),
        RuntimePeerError::InvalidPolicy
    );
}

#[test]
fn oversized_multibyte_original_input_and_deep_nesting_are_refused() {
    let bytes = format!("\"{}\"", "é".repeat(32_768));
    assert!(bytes.chars().count() < 65_536 && bytes.len() > 65_536);
    assert_eq!(
        RuntimePeerPolicy::parse_json(bytes.as_bytes()).unwrap_err(),
        RuntimePeerError::InvalidPolicy
    );
    // The policy schema also refuses these shapes; this is not an independent
    // proof that the allocation-free nesting preflight runs before serde.
    for depth in [32, 33, 512] {
        let bytes = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        assert_eq!(
            RuntimePeerPolicy::parse_json(bytes.as_bytes()).unwrap_err(),
            RuntimePeerError::InvalidPolicy
        );
    }
}

#[test]
fn policy_and_identity_maximum_is_128_bytes_scope_maximum_is_256() {
    for (field, maximum) in [
        ("version", 128),
        ("identityId", 128),
        ("workspaceId", 256),
        ("namespaceId", 256),
    ] {
        let mut input = document();
        for (length, accepted) in [(maximum, true), (maximum + 1, false)] {
            match field {
                "version" => input[field] = json!("a".repeat(length)),
                "identityId" => input["peers"][0][field] = json!("a".repeat(length)),
                _ => input["peers"][0]["grants"][0][field] = json!("a".repeat(length)),
            }
            assert_eq!(parse(&input).is_ok(), accepted, "identifier boundary");
        }
    }
}

#[test]
fn peer_count_accepts_128_and_rejects_129_within_original_byte_cap() {
    let mut input = document();
    let peers: Vec<_> = (0..128)
        .map(|index| {
            let mut entry = document()["peers"][0].clone();
            entry["certificateSha256"] = json!(format!("{index:064x}"));
            entry["identityId"] = json!(format!("controller-{index}"));
            entry
        })
        .collect();
    input["peers"] = json!(peers);
    assert!(serde_json::to_vec(&input).unwrap().len() < 65_536);
    assert!(parse(&input).is_ok());
    let mut extra = input["peers"][0].clone();
    extra["certificateSha256"] = json!(format!("{:064x}", 128));
    extra["identityId"] = json!("controller-128");
    input["peers"].as_array_mut().unwrap().push(extra);
    assert!(serde_json::to_vec(&input).unwrap().len() < 65_536);
    invalid(&input);
}

#[test]
fn per_peer_grant_count_accepts_64_and_rejects_65() {
    let mut input = document();
    input["peers"][0]["grants"] = json!(
        (0..64)
            .map(|i| grant(INSTALL_A, "work", &format!("ns-{i}")))
            .collect::<Vec<_>>()
    );
    assert!(parse(&input).is_ok());
    input["peers"][0]["grants"]
        .as_array_mut()
        .unwrap()
        .push(grant(INSTALL_A, "work", "ns-64"));
    assert!(serde_json::to_vec(&input).unwrap().len() < 65_536);
    invalid(&input);
}

#[test]
fn more_than_1024_total_grants_are_rejected_without_claiming_an_isolated_total_gate() {
    let mut input = document();
    input["peers"] = json!(
        (0..17)
            .map(|index| {
                let mut entry = document()["peers"][0].clone();
                entry["certificateSha256"] = json!(format!("{index:064x}"));
                entry["identityId"] = json!(format!("controller-{index}"));
                entry["grants"] = json!(
                    (0..64)
                        .map(|i| grant(INSTALL_A, "w", &format!("n{i}")))
                        .collect::<Vec<_>>()
                );
                entry
            })
            .collect::<Vec<_>>()
    );
    // 17 * 64 = 1088 grants, with valid individual peer/grant counts. The
    // original 64-KiB byte bound necessarily fires first for this JSON shape.
    assert!(serde_json::to_vec(&input).unwrap().len() > 65_536);
    invalid(&input);
}
