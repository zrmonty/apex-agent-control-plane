use super::*;

fn metadata_with_auth(value: &str) -> tonic::metadata::MetadataMap {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert("authorization", value.parse().unwrap());
    metadata
}

#[test]
fn authenticate_accepts_a_registered_token_and_scope() {
    let resolver = StaticOperatorTokenResolver::new().with_token(
        "secret-token",
        OperatorCaller::scoped("operator:zack", ["acme/prod"]).unwrap(),
    );
    let auth = OperatorTokenAuthenticator::new(resolver);
    let caller = auth
        .authenticate(&metadata_with_auth("Bearer secret-token"))
        .unwrap();
    assert!(caller.allows_scope("acme", "prod"));
    assert!(!caller.allows_scope("acme", "staging"));
}

#[test]
fn authenticate_rejects_an_unregistered_token() {
    let resolver = StaticOperatorTokenResolver::new();
    let auth = OperatorTokenAuthenticator::new(resolver);
    let error = auth
        .authenticate(&metadata_with_auth("Bearer nope"))
        .unwrap_err();
    assert_eq!(error.code, crate::errors::CommandErrorCode::Unauthenticated);
}

#[test]
fn authenticate_rejects_a_missing_authorization_header() {
    let resolver = StaticOperatorTokenResolver::new();
    let auth = OperatorTokenAuthenticator::new(resolver);
    let metadata = tonic::metadata::MetadataMap::new();
    assert!(auth.authenticate(&metadata).is_err());
}

#[test]
fn authenticate_rejects_duplicate_authorization_headers() {
    let resolver = StaticOperatorTokenResolver::new().with_token(
        "secret-token",
        OperatorCaller::global("operator:break-glass").unwrap(),
    );
    let auth = OperatorTokenAuthenticator::new(resolver);
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.append("authorization", "Bearer secret-token".parse().unwrap());
    metadata.append("authorization", "Bearer secret-token".parse().unwrap());
    let error = auth.authenticate(&metadata).unwrap_err();
    assert_eq!(
        error.code,
        crate::errors::CommandErrorCode::InvalidAuthorization
    );
}

#[test]
fn authenticate_rate_limits_repeated_failures_for_the_same_token() {
    let resolver = StaticOperatorTokenResolver::new();
    let auth = OperatorTokenAuthenticator::new(resolver);
    for _ in 0..AUTH_FAILURES_PER_WINDOW {
        let _ = auth.authenticate(&metadata_with_auth("Bearer guess"));
    }
    let error = auth
        .authenticate(&metadata_with_auth("Bearer guess"))
        .unwrap_err();
    assert_eq!(error.code, crate::errors::CommandErrorCode::RateLimited);
}

#[test]
fn global_operator_allows_every_well_formed_scope() {
    let caller = OperatorCaller::global("operator:break-glass").unwrap();
    assert!(caller.allows_scope("acme", "prod"));
    assert!(caller.allows_scope("other", "staging"));
    assert!(!caller.allows_scope("bad scope", "prod"));
}

#[test]
fn scoped_construction_rejects_malformed_scope_strings() {
    assert!(OperatorCaller::scoped("operator:zack", ["not-a-scope"]).is_err());
    assert!(OperatorCaller::scoped("operator:zack", ["ac me/prod"]).is_err());
}

#[test]
fn scoped_construction_enforces_the_scope_ceiling_exactly() {
    let at_limit =
        (0..MAX_ALLOWED_SCOPES).map(|index| format!("workspace{index}/prod"));
    assert!(OperatorCaller::scoped("operator:zack", at_limit).is_ok());
    let over_limit =
        (0..=MAX_ALLOWED_SCOPES).map(|index| format!("workspace{index}/prod"));
    assert!(OperatorCaller::scoped("operator:zack", over_limit).is_err());
}

#[test]
fn subject_must_satisfy_the_ingest_actor_identifier_grammar() {
    // These authenticate fine but could never produce an admissible
    // `control` event, because `actor.id` is checked against
    // `is_scope_identifier` at the ingest boundary. Reject them at
    // credential construction instead of at every command.
    for bad in ["operator zack", "operator/zack", "\"operator\"", "", "a..b"] {
        assert!(
            OperatorCaller::global(bad).is_err(),
            "{bad:?} must not be accepted as an operator subject"
        );
    }
    assert!(OperatorCaller::global("operator:break-glass").is_ok());
}

/// The token table is a credential store. Parsing it must never quietly
/// register a *different* credential than the operator configured.
#[test]
fn token_table_preserves_a_token_that_contains_the_separator_character() {
    // A token containing '|' still round-trips whole, because the scope
    // side of an entry provably cannot contain the separator.
    let token = "abcdefgh|ijklmnop|qrstuvwx";
    let resolver = parse_operator_token_table(&format!("{token}|acme/prod"))
        .expect("entry must parse");
    let caller = resolver.resolve(token).expect("the whole token must resolve");
    assert!(caller.allows_scope("acme", "prod"));
    // No prefix of the token may authenticate.
    assert!(resolver.resolve("abcdefgh").is_err());
    assert!(resolver.resolve("abcdefgh|ijklmnop").is_err());
}

#[test]
fn token_table_preserves_a_token_that_contains_colons() {
    // The original ':' separator truncated this token to "session" and
    // granted scope "abcdef0123456789:acme/prod" instead of "acme/prod".
    let token = "session:abcdef0123456789";
    let resolver =
        parse_operator_token_table(&format!("{token}|acme/prod")).expect("entry must parse");
    let caller = resolver.resolve(token).expect("the whole token must resolve");
    assert!(caller.allows_scope("acme", "prod"));
    assert!(!caller.allows_scope("abcdef0123456789:acme", "prod"));
    assert!(resolver.resolve("session").is_err());
}

#[test]
fn token_table_fails_closed_on_every_malformed_entry() {
    for (raw, why) in [
        ("no-separator-here-at-all", "missing separator"),
        ("short|acme/prod", "token under the length floor"),
        ("abcdefgh:acme/prod", "legacy ':' form must not be guessed at"),
        ("abcdefghijklmnop|", "no scopes listed"),
        ("abcdefghijklmnop|not-a-scope", "scope without a '/'"),
        ("abcdefghijklmnop|ac me/prod", "scope with whitespace"),
        (
            "abcdefghijklmnop|acme/prod;abcdefghijklmnop|other/prod",
            "duplicate token",
        ),
    ] {
        assert!(
            parse_operator_token_table(raw).is_err(),
            "{why}: {raw:?} must be refused, not silently skipped"
        );
    }
}

#[test]
fn token_table_parses_scoped_and_global_entries() {
    let resolver = parse_operator_token_table(
        "  scoped-operator-token-1|acme/prod, acme/staging ; global-operator-token-2|*  ",
    )
    .expect("well-formed table must parse");

    let scoped = resolver.resolve("scoped-operator-token-1").unwrap();
    assert!(scoped.allows_scope("acme", "prod"));
    assert!(scoped.allows_scope("acme", "staging"));
    assert!(!scoped.allows_scope("other", "prod"));

    let global = resolver.resolve("global-operator-token-2").unwrap();
    assert!(global.allows_scope("anything", "anywhere"));

    // Subjects are distinct per entry so the audit trail can tell two
    // static operator credentials apart.
    assert_ne!(scoped.subject(), global.subject());
}

#[test]
fn token_table_rejects_a_token_that_could_never_be_sent_in_a_bearer_header() {
    // `extract_bearer_token` refuses whitespace and non-ASCII, so a table
    // entry carrying them would register an unusable credential.
    assert!(parse_operator_token_table("token with spaces|acme/prod").is_err());
    assert!(parse_operator_token_table("t\u{00e9}kenabcdefghijkl|acme/prod").is_err());
}

#[test]
fn empty_token_table_authenticates_nobody() {
    let auth = OperatorTokenAuthenticator::new(
        parse_operator_token_table("").expect("an empty table is valid"),
    );
    assert!(
        auth.authenticate(&metadata_with_auth("Bearer anything-at-all"))
            .is_err()
    );
}
