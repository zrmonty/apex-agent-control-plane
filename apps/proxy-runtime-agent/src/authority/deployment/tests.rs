use super::*;

fn reply() -> proto::RuntimeDeploymentSnapshot {
    let mut configuration: proto::RuntimeConfiguration =
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/fixtures/mcp-proxy/runtime-revision.json"
        )))
        .unwrap();
    // Repository wire golden uses a placeholder self-hash; independent exporter digest.
    configuration.runtime_manifest_hash =
        "db5ddc4670e5f901240e1c2910d9f78dd8a65237c86f197d13938be967afe5da".into();
    let target = proto::RuntimeTarget {
        workspace_id: configuration.workspace_id.clone(),
        namespace_id: configuration.namespace_id.clone(),
        proxy_id: configuration.proxy_id.clone(),
        revision_id: configuration.revision_id.clone(),
        generation: configuration.generation,
        fencing_token: 7,
    };
    proto::RuntimeDeploymentSnapshot {
        schema_version: 1,
        authority: Some(proto::RuntimeAuthoritySnapshot {
            target: Some(target),
            config_hash: configuration.config_hash.clone(),
            ..Default::default()
        }),
        configuration: Some(configuration),
        deployment_bindings_version: "bindings-1".into(),
    }
}

#[test]
fn valid_manifest_is_returned_with_redacted_debug() {
    let reply = reply();
    let valid = ResolvedDeployment::parse(reply.clone()).unwrap();
    assert_eq!(valid.configuration(), reply.configuration.as_ref().unwrap());
    assert_eq!(valid.bindings_version(), "bindings-1");
    assert_eq!(format!("{valid:?}"), "ResolvedDeployment { [redacted] }");
}

#[test]
fn malformed_or_substituted_configuration_is_refused() {
    let mutations: &[fn(&mut proto::RuntimeDeploymentSnapshot)] = &[
        |r| r.schema_version = 2,
        |r| r.authority = None,
        |r| r.configuration = None,
        |r| r.deployment_bindings_version.clear(),
        |r| r.deployment_bindings_version = "x".repeat(129),
        |r| r.deployment_bindings_version = "../escape".into(),
        |r| r.authority.as_mut().unwrap().target = None,
        |r| r.authority.as_mut().unwrap().config_hash = "c".repeat(64),
        |r| r.configuration.as_mut().unwrap().generation += 1,
        |r| {
            r.configuration.as_mut().unwrap().resource_url =
                "https://substituted.invalid/mcp".into()
        },
        |r| {
            r.configuration
                .as_mut()
                .unwrap()
                .spec
                .as_mut()
                .unwrap()
                .upstreams[0]
                .endpoint_or_command_ref = "https://substituted.invalid/mcp".into()
        },
        |r| {
            r.configuration
                .as_mut()
                .unwrap()
                .secret_refs
                .push("secret://substituted/credential".into())
        },
        |r| r.configuration.as_mut().unwrap().runtime_manifest_hash = "b".repeat(64),
        |r| r.configuration.as_mut().unwrap().resource_url = "x".repeat(270_337),
    ];
    for mutate in mutations {
        let mut value = reply();
        mutate(&mut value);
        assert!(ResolvedDeployment::parse(value).is_err());
    }
}

#[test]
fn configuration_json_size_boundary_uses_self_consistent_manifests() {
    use prost::Message;
    let mut value = reply();
    let configuration = value.configuration.as_mut().unwrap();
    let initial = serde_json::to_vec(configuration).unwrap().len();
    configuration
        .resource_url
        .push_str(&"x".repeat(262_144 - initial));
    configuration.runtime_manifest_hash = crate::runtime_manifest_hash(configuration).unwrap();
    assert_eq!(serde_json::to_vec(configuration).unwrap().len(), 262_144);
    assert!(value.encoded_len() < 270_336);
    assert!(ResolvedDeployment::parse(value.clone()).is_ok());
    let configuration = value.configuration.as_mut().unwrap();
    configuration.resource_url.push('x');
    configuration.runtime_manifest_hash = crate::runtime_manifest_hash(configuration).unwrap();
    assert_eq!(serde_json::to_vec(configuration).unwrap().len(), 262_145);
    assert!(
        value.encoded_len() < 270_336,
        "the JSON guard, not wire size, must refuse"
    );
    assert_eq!(
        ResolvedDeployment::parse(value).unwrap_err(),
        AuthorityClientError::InvalidSnapshot
    );
}
