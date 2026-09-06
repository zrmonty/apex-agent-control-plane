use super::profile::Profile;
use super::*;
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn resolver(bytes: &[u8], age: Duration) -> ManagedEvidenceResolver {
    ManagedEvidenceResolver {
        snapshot: Arc::new(RwLock::new(Some(Snapshot {
            profile: Profile::parse(bytes).unwrap(),
            read_started: Instant::now() - age,
        }))),
        active: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    }
}

#[test]
fn managed_evidence_exact_pair_selects_fixed_identity_and_scope() {
    let a = enrollment(
        "agent-a",
        "000000000001",
        &hex(&Sha256::digest(b"token-a")),
        &"bb".repeat(32),
    );
    let b = enrollment(
        "agent-b",
        "000000000002",
        &hex(&Sha256::digest(b"token-b")),
        &"cc".repeat(32),
    );
    let resolver = resolver(&document(&format!("{a},{b}")), Duration::ZERO);
    for (token, leaf, agent) in [("token-a", 0xbb, "agent-a"), ("token-b", 0xcc, "agent-b")] {
        let caller = resolver
            .resolve_with_peer(
                token,
                Some(&PeerIdentity {
                    certificate_sha256: [leaf; 32],
                }),
            )
            .expect("exact enrolled pair");
        assert_eq!(caller.bound_agent_id(), Some(agent));
        assert_eq!(caller.subject(), Some(format!("subject-{agent}").as_str()));
        assert!(caller.allows_scope(&format!("work/{agent}")));
        assert!(!caller.allows_scope("work/other"));
    }
    for (token, peer) in [
        ("token-b", Some(0xbb)),
        ("token-a", Some(0xcc)),
        ("token-a", None),
        (" token-a", Some(0xbb)),
        ("token-a ", Some(0xbb)),
    ] {
        assert!(
            resolver
                .resolve_with_peer(
                    token,
                    peer.map(|leaf| PeerIdentity {
                        certificate_sha256: [leaf; 32]
                    })
                    .as_ref()
                )
                .is_err()
        );
    }
}

pub(super) fn document(enrollments: &str) -> Vec<u8> {
    format!(r#"{{"schema_version":1,"version":"enrollment-1","valid_from_unix_us":1,"expires_at_unix_us":9223372036854775807,"enrollments":[{enrollments}]}}"#).into_bytes()
}

pub(super) fn enrollment(
    agent: &str,
    proxy_suffix: &str,
    token_digest: &str,
    leaf: &str,
) -> String {
    format!(
        r#"{{"installation_id":"01990000-0000-7000-8000-000000000001","workspace_id":"work","namespace_id":"{agent}","proxy_id":"01990000-0000-7000-8000-{proxy_suffix}","subject":"subject-{agent}","agent_id":"{agent}","credentials":[{{"certificate_sha256":"{leaf}","token_sha256":"{token_digest}"}}]}}"#
    )
}

pub(super) fn valid_document() -> Vec<u8> {
    document(&enrollment(
        "agent-a",
        "000000000001",
        &"a".repeat(64),
        &"b".repeat(64),
    ))
}

#[test]
fn managed_evidence_schema_accepts_exact_profile_and_refuses_ambiguous_json() {
    let valid = valid_document();
    assert!(
        Profile::parse(&valid).is_ok(),
        "valid explicit enrollment must parse"
    );
    let text = String::from_utf8(valid).unwrap();
    for bad in [
        text.replace(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
        ),
        text.replace("\"schema_version\":1", "\"schema_version\":1,\"unknown\":1"),
        text.replace("\"valid_from_unix_us\":1", "\"valid_from_unix_us\":1.0"),
        text.replace("\"valid_from_unix_us\":1", "\"valid_from_unix_us\":1e0"),
        text.replace("\"valid_from_unix_us\":1", "\"valid_from_unix_us\":0"),
        text.replace("9223372036854775807", "9223372036854775808"),
        text.replace(
            "\"valid_from_unix_us\":1",
            "\"valid_from_unix_us\":9223372036854775807",
        ),
    ] {
        assert!(Profile::parse(bad.as_bytes()).is_err());
    }
}

#[test]
fn managed_evidence_rejects_duplicate_pairs_actor_reuse_and_invalid_bounds() {
    let a = enrollment("agent-a", "000000000001", &"a".repeat(64), &"b".repeat(64));
    let b = enrollment("agent-b", "000000000002", &"a".repeat(64), &"b".repeat(64));
    assert!(
        Profile::parse(&document(&format!("{a},{b}"))).is_err(),
        "pair shared across proxies"
    );
    let reused = enrollment("agent-a", "000000000002", &"c".repeat(64), &"d".repeat(64));
    assert!(
        Profile::parse(&document(&format!("{a},{reused}"))).is_err(),
        "actor reused across proxies"
    );
    let text = String::from_utf8(document(&a)).unwrap();
    for bad in [
        text.replace(&"a".repeat(64), &"A".repeat(64)),
        text.replace(
            "\"subject\":\"subject-agent-a\"",
            "\"subject\":\"subject-agent-a\",\"subject\":\"other\"",
        ),
        text.replace(
            "\"token_sha256\":",
            "\"raw_token\":\"forbidden\",\"token_sha256\":",
        ),
        text.replace("\"agent-a\"", "\"agent/other\""),
        text.replace("enrollment-1", &"v".repeat(129)),
        text.replace("subject-agent-a", &"s".repeat(257)),
        text.replace("01990000-0000-7000", "01990000-0000-4000"),
        text.replace("\"schema_version\":1", "\"schema_version\":01"),
        text.replace("\"schema_version\":1", "\"schema_version\":true"),
        text.replace("\"valid_from_unix_us\":1", "\"valid_from_unix_us\":-1"),
        format!("{text}null"),
        format!("{text}{}", " ".repeat(262_144)),
        "[".repeat(10000),
    ] {
        assert!(Profile::parse(bad.as_bytes()).is_err());
    }
    let too_many = (1..=65)
        .map(|i| {
            enrollment(
                &format!("a{i}"),
                &format!("{i:012}"),
                &format!("{i:064x}"),
                &"b".repeat(64),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    assert!(Profile::parse(&document(&too_many)).is_err());
    let at_limit = (1..=64)
        .map(|i| {
            enrollment(
                &format!("a{i}"),
                &format!("{i:012}"),
                &format!("{i:064x}"),
                &"b".repeat(64),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    assert!(Profile::parse(&document(&at_limit)).is_ok());
}

#[test]
fn managed_evidence_rotation_is_bounded_and_expiry_and_staleness_close() {
    let key_a = format!(
        r#"{{"certificate_sha256":"{}","token_sha256":"{:x}"}}"#,
        "bb".repeat(32),
        Sha256::digest(b"token-a")
    );
    let key_b = key_a.replace(
        &format!("{:x}", Sha256::digest(b"token-a")),
        &format!("{:x}", Sha256::digest(b"token-b")),
    );
    let original = enrollment(
        "agent-a",
        "000000000001",
        &format!("{:x}", Sha256::digest(b"token-a")),
        &"bb".repeat(32),
    );
    let rotated = original.replace(&key_a, &format!("{key_a},{key_b}"));
    let bytes = document(&rotated);
    let r = resolver(&bytes, Duration::ZERO);
    let peer = PeerIdentity {
        certificate_sha256: [0xbb; 32],
    };
    for token in ["token-a", "token-b"] {
        assert!(r.resolve_with_peer(token, Some(&peer)).is_ok());
    }
    assert!(
        Profile::parse(&document(
            &original.replace(&key_a, &format!("{key_a},{key_b},{key_b}"))
        ))
        .is_err()
    );
    assert!(
        Profile::parse(&document(
            &original.replace(&key_a, &format!("{key_a},{key_a}"))
        ))
        .is_err()
    );
    assert!(
        resolver(&bytes, Duration::from_secs(5))
            .resolve_with_peer("token-a", Some(&peer))
            .is_err()
    );
    let expired = String::from_utf8(bytes)
        .unwrap()
        .replace("9223372036854775807", "2");
    assert!(
        resolver(expired.as_bytes(), Duration::ZERO)
            .resolve_with_peer("token-a", Some(&peer))
            .is_err()
    );
    let removed = resolver(&document(""), Duration::ZERO);
    assert!(removed.resolve_with_peer("token-a", Some(&peer)).is_err());
}
