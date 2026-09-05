use super::*;

pub(crate) fn config() -> OidcConfig {
    OidcConfig {
        issuer: "https://identity.example/realms/apex".into(),
        client_id: "apex-browser".into(),
        client_secret: Zeroizing::new("fixture-confidential-client-secret".into()),
        public_origin: "https://console.example:8443".into(),
        provider_ca_pem: vec![1],
        authorization_endpoint: "https://identity.example/realms/apex/protocol/openid-connect/auth"
            .into(),
        token_endpoint: "https://identity.example/realms/apex/protocol/openid-connect/token".into(),
        jwks_uri: "https://identity.example/realms/apex/protocol/openid-connect/certs".into(),
        revocation_endpoint: "https://identity.example/realms/apex/protocol/openid-connect/revoke"
            .into(),
    }
}

pub(crate) fn discovery() -> serde_json::Value {
    let config = config();
    serde_json::json!({
        "issuer":config.issuer,"authorization_endpoint":config.authorization_endpoint,
        "token_endpoint":config.token_endpoint,"jwks_uri":config.jwks_uri,
        "revocation_endpoint":config.revocation_endpoint,"response_types_supported":["code"],
        "response_modes_supported":["query"],"grant_types_supported":["authorization_code","refresh_token"],
        "subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],
        "token_endpoint_auth_methods_supported":["client_secret_basic"],
        "revocation_endpoint_auth_methods_supported":["client_secret_basic"],
        "code_challenge_methods_supported":["S256"],"scopes_supported":["openid"]
    })
}

#[test]
fn config_requires_confidential_client_fixed_https_origin_and_trusted_ca() {
    assert!(config().validate().is_ok());
    for secret in [
        "".to_owned(),
        "short".to_owned(),
        "x".repeat(4097),
        "secret\nvalue".to_owned(),
    ] {
        let mut value = config();
        value.client_secret = Zeroizing::new(secret);
        assert!(value.validate().is_err());
    }
    for id in ["", "account", "client id", "client\nvalue"] {
        let mut value = config();
        value.client_id = id.into();
        assert!(value.validate().is_err());
    }
    let mut value = config();
    value.provider_ca_pem.clear();
    assert!(value.validate().is_err());
    let mut value = config();
    value.public_origin = "http://console.example".into();
    assert!(value.validate().is_err());
    assert!(!format!("{:?}", config()).contains("fixture-confidential"));
}

#[test]
fn provider_endpoints_reject_insecure_or_ambiguous_urls() {
    for bad in [
        "http://identity.example",
        "https:identity.example",
        "https://user:pass@identity.example",
        "https://identity.example/#fragment",
        "https://identity.example/?next=attacker",
        "https://identity.example/../keys",
        "https://identity.example\\keys",
        "https://identity.example/keys\n",
        "https://identity.example/keys%2fother",
    ] {
        for field in 0..5 {
            let mut value = config();
            match field {
                0 => value.issuer = bad.into(),
                1 => value.authorization_endpoint = bad.into(),
                2 => value.token_endpoint = bad.into(),
                3 => value.jwks_uri = bad.into(),
                _ => value.revocation_endpoint = bad.into(),
            }
            assert!(value.validate().is_err(), "field={field} {bad}");
        }
    }
}

#[test]
fn discovery_and_callback_are_derived_from_fixed_validated_configuration() {
    assert_eq!(
        config().callback_uri().unwrap().as_str(),
        "https://console.example:8443/auth/callback"
    );
    assert_eq!(
        config().discovery_uri().unwrap().as_str(),
        "https://identity.example/realms/apex/.well-known/openid-configuration"
    );
    let mut value = config();
    value.issuer.push('/');
    assert_eq!(
        value.discovery_uri().unwrap().as_str(),
        "https://identity.example/realms/apex/.well-known/openid-configuration"
    );
}

#[test]
fn exact_discovery_identity_and_configured_endpoints_are_mandatory() {
    assert!(
        config()
            .validate_discovery(&serde_json::to_vec(&discovery()).unwrap())
            .is_ok()
    );
    for (field, bad) in [
        ("issuer", "https://IDENTITY.example/realms/apex"),
        ("issuer", "https://identity.example:443/realms/apex"),
        ("issuer", "https://identity.example/realms/other"),
        ("jwks_uri", "https://attacker.example/keys"),
        ("authorization_endpoint", "https://attacker.example/auth"),
        ("token_endpoint", "https://attacker.example/token"),
        ("revocation_endpoint", "https://attacker.example/revoke"),
    ] {
        let mut value = discovery();
        value[field] = bad.into();
        assert!(
            config()
                .validate_discovery(&serde_json::to_vec(&value).unwrap())
                .is_err(),
            "{field}"
        );
    }
    let mut conf = config();
    conf.jwks_uri = "https://trusted-split-horizon.example/keys".into();
    let mut value = discovery();
    value["jwks_uri"] = conf.jwks_uri.clone().into();
    assert!(
        conf.validate_discovery(&serde_json::to_vec(&value).unwrap())
            .is_ok()
    );
}

#[test]
fn provider_must_advertise_required_code_pkce_refresh_and_signing_capabilities() {
    for (field, bad) in [
        ("response_types_supported", "token"),
        ("response_modes_supported", "fragment"),
        ("grant_types_supported", "client_credentials"),
        ("id_token_signing_alg_values_supported", "HS256"),
        ("token_endpoint_auth_methods_supported", "none"),
        ("revocation_endpoint_auth_methods_supported", "none"),
        ("code_challenge_methods_supported", "plain"),
        ("scopes_supported", "offline_access"),
    ] {
        let mut value = discovery();
        value[field] = serde_json::json!([bad]);
        assert!(
            config()
                .validate_discovery(&serde_json::to_vec(&value).unwrap())
                .is_err(),
            "{field}"
        );
        value.as_object_mut().unwrap().remove(field);
        assert!(
            config()
                .validate_discovery(&serde_json::to_vec(&value).unwrap())
                .is_err(),
            "missing {field}"
        );
    }
}

#[test]
fn metadata_byte_and_array_limits_precede_protocol_deserialization() {
    assert!(config().validate_discovery(&vec![b' '; 65537]).is_err());
    let mut value = discovery();
    value["scopes_supported"] = serde_json::json!(vec!["openid"; 65]);
    assert!(
        config()
            .validate_discovery(&serde_json::to_vec(&value).unwrap())
            .is_err()
    );
    let mut value = discovery();
    value["scopes_supported"] = serde_json::json!(["openid", 1]);
    assert!(
        config()
            .validate_discovery(&serde_json::to_vec(&value).unwrap())
            .is_err()
    );
}

#[test]
fn duplicate_and_excessively_nested_provider_metadata_is_refused() {
    let valid = serde_json::to_string(&discovery()).unwrap();
    assert!(config().validate_discovery(valid.as_bytes()).is_ok());
    let duplicate = valid.replacen(
        '{',
        r#"{"issuer":"https://identity.example/realms/apex","#,
        1,
    );
    assert!(config().validate_discovery(duplicate.as_bytes()).is_err());
    let nested = format!(
        "{{\"extra\":{}0{},{}",
        "[".repeat(65),
        "]".repeat(65),
        &valid[1..]
    );
    assert!(config().validate_discovery(nested.as_bytes()).is_err());
}
