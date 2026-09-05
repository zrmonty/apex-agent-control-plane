use super::support::*;
use apex_proxy_runtime_agent::{check_runtime_target, check_target_configuration_binding, proto};

#[test]
fn complete_synthetic_config_has_exact_target_relation_not_integrity_or_authority() {
    let config = configuration();
    assert!(config.spec.is_some() && config.auth.is_some() && config.telemetry.is_some());
    assert!(!config.tool_schemas.is_empty() && !config.network_grants.is_empty());
    assert_eq!(check_runtime_target(&target()), Ok(()));
    assert_eq!(
        check_target_configuration_binding(&target(), &config),
        Ok(())
    );
    // No publication, signature, executable policy or live lease is provided.
}

#[test]
fn u64_metadata_above_javascript_precision_and_max_is_not_rounded_or_derived() {
    for (generation, fencing_token) in [(1, 2), (BIG, 3), (u64::MAX, BIG), (BIG, u64::MAX)] {
        let value = proto::RuntimeTarget {
            generation,
            fencing_token,
            ..target()
        };
        let config = proto::RuntimeConfiguration {
            generation,
            ..configuration()
        };
        assert_eq!(check_runtime_target(&value), Ok(()));
        assert_eq!(check_target_configuration_binding(&value, &config), Ok(()));
    }
}

#[test]
fn control_scope_grammar_is_exact_bounded_and_not_trimmed() {
    for valid in ["A.b_c:d-1".to_owned(), "_".into(), "a".repeat(256)] {
        let value = proto::RuntimeTarget {
            workspace_id: valid.clone(),
            namespace_id: valid,
            ..target()
        };
        assert_eq!(check_runtime_target(&value), Ok(()));
    }
    for invalid in [
        "".to_owned(),
        "a/b".into(),
        " a".into(),
        "a ".into(),
        "a\n".into(),
        "a\0".into(),
        "a..b".into(),
        "é".into(),
        "a".repeat(257),
    ] {
        let mut value = target();
        value.workspace_id = invalid.clone();
        assert!(check_runtime_target(&value).is_err());
        let mut value = target();
        value.namespace_id = invalid;
        assert!(check_runtime_target(&value).is_err());
    }
}

#[test]
fn target_requires_lowercase_canonical_uuidv7_for_both_ids() {
    for invalid in [
        "".to_owned(),
        PROXY.to_uppercase(),
        PROXY.replace('-', ""),
        format!("urn:uuid:{PROXY}"),
        format!("{{{PROXY}}}"),
        format!(" {PROXY}"),
        PROXY.replace("-7c13-", "-4c13-"),
        PROXY.replace("-9a61-", "-ca61-"),
        "00000000-0000-0000-0000-000000000000".into(),
        format!("{PROXY}\n"),
    ] {
        for revision in [false, true] {
            let mut value = target();
            if revision {
                value.revision_id = invalid.clone();
            } else {
                value.proxy_id = invalid.clone();
            }
            assert!(check_runtime_target(&value).is_err());
        }
    }
}

#[test]
fn default_zero_generation_and_zero_fence_are_refused() {
    assert!(check_runtime_target(&proto::RuntimeTarget::default()).is_err());
    for (generation, fencing_token) in [(0, 1), (1, 0), (0, 0)] {
        let value = proto::RuntimeTarget {
            generation,
            fencing_token,
            ..target()
        };
        assert!(check_runtime_target(&value).is_err());
        let config = proto::RuntimeConfiguration {
            generation,
            ..configuration()
        };
        assert!(check_target_configuration_binding(&value, &config).is_err());
    }
}

#[test]
fn each_configuration_target_relation_field_must_match_exactly() {
    for field in ["workspace", "namespace", "proxy", "revision", "generation"] {
        let mut config = configuration();
        match field {
            "workspace" => config.workspace_id = "foreign".into(),
            "namespace" => config.namespace_id = "foreign".into(),
            "proxy" => config.proxy_id = OTHER.into(),
            "revision" => config.revision_id = OTHER.into(),
            "generation" => config.generation = BIG + 1,
            _ => unreachable!(),
        }
        assert!(
            check_target_configuration_binding(&target(), &config).is_err(),
            "{field}"
        );
    }
    assert!(
        check_target_configuration_binding(&target(), &proto::RuntimeConfiguration::default())
            .is_err()
    );
    assert!(
        check_target_configuration_binding(&proto::RuntimeTarget::default(), &configuration())
            .is_err()
    );
}

#[test]
fn configuration_version_and_both_hash_shapes_are_required() {
    for schema_version in [0, 2, u32::MAX] {
        let config = proto::RuntimeConfiguration {
            schema_version,
            ..configuration()
        };
        assert!(check_target_configuration_binding(&target(), &config).is_err());
    }
    for hash in [
        "".into(),
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
        format!("sha256:{}", "a".repeat(64)),
        format!("{} ", "a".repeat(64)),
    ] {
        for manifest in [false, true] {
            let mut config = configuration();
            if manifest {
                config.runtime_manifest_hash = hash.clone();
            } else {
                config.config_hash = hash.clone();
            }
            assert!(check_target_configuration_binding(&target(), &config).is_err());
        }
    }
}

#[test]
fn equal_hash_values_are_not_rejected_as_if_distinct_meaning_required_inequality() {
    let mut config = configuration();
    config.runtime_manifest_hash = config.config_hash.clone();
    assert_eq!(
        check_target_configuration_binding(&target(), &config),
        Ok(())
    );
    // Neither these equal synthetic bytes nor any shaped hash proves integrity.
}

#[test]
fn configuration_image_must_be_bounded_digest_pinned_not_a_command_or_mutable_tag() {
    let digest = "a".repeat(64);
    for image_ref in [
        String::new(),
        "registry.example.test/apex/gateway:latest".into(),
        format!(
            "registry.example.test/apex/gateway@sha256:{}",
            "a".repeat(63)
        ),
        format!(
            "registry.example.test/apex/gateway@sha256:{}",
            "A".repeat(64)
        ),
        format!("https://registry.example.test/apex/gateway@sha256:{digest}"),
        format!("registry.example.test/apex/../gateway@sha256:{digest}"),
        format!("registry.example.test/apex/gateway@sha256:{digest}\n"),
        format!("registry.example.test/apex/gateway@sha256:{digest};echo"),
        format!(
            "registry.example.test/{}/gateway@sha256:{digest}",
            "a".repeat(512)
        ),
    ] {
        let config = proto::RuntimeConfiguration {
            image_ref,
            ..configuration()
        };
        assert!(check_target_configuration_binding(&target(), &config).is_err());
    }
}

#[test]
fn configuration_image_v1_accepts_underscore_registry() {
    let config = proto::RuntimeConfiguration {
        image_ref: concat!(
            "registry_a.example.test/apex/mcp-gateway@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .into(),
        ..configuration()
    };
    // Selected v1 reference-shape contract, not registry approval or integrity.
    assert_eq!(
        check_target_configuration_binding(&target(), &config),
        Ok(())
    );
}

#[test]
fn configuration_image_v1_accepts_trailing_dot_registry() {
    let config = proto::RuntimeConfiguration {
        image_ref: concat!(
            "registry.example.test./apex/mcp-gateway@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .into(),
        ..configuration()
    };
    // Literal accepted spelling must not be narrowed to a new DNS-label policy.
    assert_eq!(
        check_target_configuration_binding(&target(), &config),
        Ok(())
    );
}

#[test]
fn configuration_image_v1_refuses_normalization_and_forbidden_reference_parts() {
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    for (case, name) in [
        (
            "host case normalization",
            "REGISTRY.example.test/apex/gateway",
        ),
        (
            "host percent normalization",
            "%72egistry.example.test/apex/gateway",
        ),
        (
            "host IDNA normalization",
            "régistry.example.test/apex/gateway",
        ),
        (
            "explicit default port",
            "registry.example.test:443/apex/gateway",
        ),
        (
            "port normalization",
            "registry.example.test:08443/apex/gateway",
        ),
        ("short IPv4 alias", "127.1/apex/gateway"),
        ("hex IPv4 alias", "0x7f.0.0.1/apex/gateway"),
        ("dotted registry required", "localhost/apex/gateway"),
        ("username", "reader@registry.example.test/apex/gateway"),
        (
            "password",
            "reader:unused@registry.example.test/apex/gateway",
        ),
        ("empty userinfo", "@registry.example.test/apex/gateway"),
        ("query", "registry.example.test?key=value/apex/gateway"),
        ("empty query", "registry.example.test?/apex/gateway"),
        ("fragment", "registry.example.test#fragment/apex/gateway"),
        ("empty fragment", "registry.example.test#/apex/gateway"),
        ("backslash", "registry.example.test\\other/apex/gateway"),
        ("host tab", "registry.example.test\t/apex/gateway"),
        ("dot path segment", "registry.example.test/apex/./gateway"),
        ("empty path segment", "registry.example.test/apex//gateway"),
        ("trailing path slash", "registry.example.test/apex/gateway/"),
        ("encoded path", "registry.example.test/apex/%2e/gateway"),
        ("repository case", "registry.example.test/apex/Gateway"),
        (
            "tag plus digest",
            "registry.example.test/apex/gateway:latest",
        ),
    ] {
        let config = proto::RuntimeConfiguration {
            image_ref: format!("{name}@sha256:{digest}"),
            ..configuration()
        };
        assert_eq!(
            check_target_configuration_binding(&target(), &config),
            Err(apex_proxy_runtime_agent::RuntimeError::InvalidConfigurationBinding),
            "{case}"
        );
    }
    // Retain the separate original test's mutable tag, path traversal, invalid
    // digest length/case, scheme, byte limit and trailing command/control cases.
    for suffix in [
        format!("sha512:{digest}"),
        format!("sha256:{digest}@sha256:{digest}"),
        format!("sha256:{digest}?query"),
        format!("sha256:{digest}#fragment"),
        format!("sha256:{digest}/path"),
    ] {
        let config = proto::RuntimeConfiguration {
            image_ref: format!("registry.example.test/apex/gateway@{suffix}"),
            ..configuration()
        };
        assert!(check_target_configuration_binding(&target(), &config).is_err());
    }
}
