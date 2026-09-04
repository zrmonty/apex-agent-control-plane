// Startup tests for credentials.

/// The agent workload credential table follows the operator table's rules:
/// pick one source, never two.
#[test]
fn two_configured_agent_credential_sources_are_refused() {
    assert!(agent_token_source_value(Some("/run/secrets/agents"), Some("inline|..."),).is_err());
    assert_eq!(
        agent_token_source_value(Some("/run/secrets/agents"), None).unwrap(),
        AgentTokenSource::File(PathBuf::from("/run/secrets/agents"))
    );
    assert_eq!(
        agent_token_source_value(None, Some("inline")).unwrap(),
        AgentTokenSource::Inline("inline".to_owned())
    );
    assert_eq!(
        agent_token_source_value(None, None).unwrap(),
        AgentTokenSource::Unset
    );
}

/// Unset means unset: no file, no tuning, no revocation list built --
/// `APEX_CONTROL_AGENT_TOKENS*` behaves exactly as it did before this feature
/// existed, which is the compatibility guarantee every deployment predating
/// it relies on.
#[test]
fn agent_revocation_env_is_unset_by_default_and_changes_nothing() {
    assert_eq!(agent_revocation_env_value(None, None, None).unwrap(), None);
}

#[test]
fn agent_revocation_env_parses_the_configured_file_with_default_tuning() {
    let parsed = agent_revocation_env_value(Some("/run/secrets/agent-revocations"), None, None)
        .unwrap()
        .unwrap();
    assert_eq!(
        parsed,
        AgentRevocationEnv {
            file: PathBuf::from("/run/secrets/agent-revocations"),
            refresh: std::time::Duration::from_secs(5),
            max_age: std::time::Duration::from_secs(15),
        }
    );
}

#[test]
fn agent_revocation_env_honours_explicit_tuning() {
    let parsed = agent_revocation_env_value(
        Some("/run/secrets/agent-revocations"),
        Some("2"),
        Some("30"),
    )
    .unwrap()
    .unwrap();
    assert_eq!(parsed.refresh, std::time::Duration::from_secs(2));
    assert_eq!(parsed.max_age, std::time::Duration::from_secs(30));
}

/// Setting the refresh interval or the staleness ceiling without the file
/// variable is refused rather than silently ignored -- the same
/// "half-configured reads as a mistake" rule the Keycloak break-glass pair and
/// the token-typ waiver already follow.
#[test]
fn agent_revocation_env_refuses_tuning_without_the_file() {
    assert!(agent_revocation_env_value(None, Some("2"), None).is_err());
    assert!(agent_revocation_env_value(None, None, Some("30")).is_err());
    assert!(agent_revocation_env_value(None, Some("2"), Some("30")).is_err());
}

#[test]
fn agent_revocation_env_bounds_tuning_values() {
    assert!(
        agent_revocation_env_value(Some("/run/secrets/agent-revocations"), Some("0"), None)
            .is_err()
    );
    assert!(
        agent_revocation_env_value(Some("/run/secrets/agent-revocations"), Some("301"), None)
            .is_err()
    );
    assert!(
        agent_revocation_env_value(Some("/run/secrets/agent-revocations"), None, Some("0"))
            .is_err()
    );
    assert!(
        agent_revocation_env_value(Some("/run/secrets/agent-revocations"), None, Some("3601"))
            .is_err()
    );
}

#[test]
fn operator_credential_source_refuses_two_configured_sources() {
    const ISSUER: &str = "https://sso.example.com/realms/apex";
    assert_eq!(
        operator_token_source_value(None, None, None).unwrap(),
        OperatorTokenSource::Unset
    );
    assert_eq!(
        operator_token_source_value(Some("/run/secrets/tokens"), None, None).unwrap(),
        OperatorTokenSource::File(PathBuf::from("/run/secrets/tokens"))
    );
    assert_eq!(
        operator_token_source_value(None, Some("token-value|acme/prod"), None).unwrap(),
        OperatorTokenSource::Inline("token-value|acme/prod".to_owned())
    );
    // The production path is selected by its own explicit variable, never
    // inferred from the absence of a static table.
    assert_eq!(
        operator_token_source_value(None, None, Some(ISSUER)).unwrap(),
        OperatorTokenSource::Keycloak(ISSUER.to_owned())
    );
    // Any two set: one of them would be silently ignored. Fail closed instead.
    assert!(operator_token_source_value(Some("/run/secrets/tokens"), Some("t|*"), None).is_err());
    assert!(operator_token_source_value(Some("/run/secrets/tokens"), None, Some(ISSUER)).is_err());
    assert!(operator_token_source_value(None, Some("t|*"), Some(ISSUER)).is_err());
    assert!(
        operator_token_source_value(Some("/run/secrets/tokens"), Some("t|*"), Some(ISSUER))
            .is_err()
    );
}

/// The `*` break-glass grant must be unreachable unless a human configured it,
/// and half-configuring it must not read as "enabled".
#[test]
fn break_glass_subject_allow_list_parses_exact_subjects_only() {
    assert!(global_subjects_value(None).is_empty());
    assert!(global_subjects_value(Some("")).is_empty());
    assert!(global_subjects_value(Some("  ,  ,")).is_empty());
    let subjects = global_subjects_value(Some(
        " 11111111-1111-4111-8111-111111111111 ,22222222-2222-4222-8222-222222222222 ",
    ));
    assert_eq!(subjects.len(), 2);
    assert!(subjects.contains("11111111-1111-4111-8111-111111111111"));
    // No pattern language: a wildcard is just a subject nobody will ever have.
    let wildcard = global_subjects_value(Some("*"));
    assert!(wildcard.contains("*"));
    assert!(!wildcard.contains("11111111-1111-4111-8111-111111111111"));
}

/// Turning off ID-token/refresh-token confusion protection has to be typed on
/// purpose, exactly, and cannot be reached by a near-miss.
#[test]
fn expected_token_typ_defaults_to_bearer_and_waives_only_on_an_exact_acknowledgement() {
    assert_eq!(
        expected_token_typ_value(None, None).unwrap(),
        Some("Bearer".to_owned())
    );
    assert_eq!(
        expected_token_typ_value(Some("Custom"), None).unwrap(),
        Some("Custom".to_owned())
    );
    assert_eq!(expected_token_typ_value(None, Some("true")).unwrap(), None);
    for near_miss in ["TRUE", "True", "1", "yes", "on", " true", "false", ""] {
        assert!(
            expected_token_typ_value(None, Some(near_miss)).is_err(),
            "{near_miss:?} must not waive the token-type check"
        );
    }
    // Both configured: one is being ignored.
    assert!(expected_token_typ_value(Some("Bearer"), Some("true")).is_err());
}
