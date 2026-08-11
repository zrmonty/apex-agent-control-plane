use std::time::{Duration, Instant};

use super::*;
use super::revocation::parse_revocation_list;

fn metadata_with_auth(value: &str) -> tonic::metadata::MetadataMap {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert("authorization", value.parse().unwrap());
    metadata
}

fn peer(byte: u8) -> PeerIdentity {
    PeerIdentity {
        certificate_sha256: [byte; 32],
    }
}

fn hex32(byte: u8) -> String {
    (0..32).map(|_| format!("{byte:02x}")).collect()
}

fn table() -> StaticAgentWorkloadResolver {
    parse_agent_token_table(&format!(
        "agent-a-token-abcdefgh|{}|agent-a|acme/prod;agent-b-token-abcdefgh|{}|agent-b|acme/prod",
        hex32(0xaa),
        hex32(0xbb)
    ))
    .expect("well-formed agent table must parse")
}

#[test]
fn authenticates_an_agent_and_binds_it_to_its_own_identity() {
    let auth = AgentWorkloadAuthenticator::new(table());
    let caller = auth
        .authenticate(
            &metadata_with_auth("Bearer agent-a-token-abcdefgh"),
            Some(&peer(0xaa)),
        )
        .expect("a registered agent credential must authenticate");
    assert_eq!(caller.bound_agent_id(), Some("agent-a"));
    assert_eq!(caller.subject(), Some("spiffe://apex/workload/agent-a"));
    assert!(caller.allows_scope("acme/prod"));
    assert!(!caller.allows_scope("acme/staging"));
}

/// The token alone is not the credential. A leaked agent token presented
/// from a connection holding a different client certificate must not
/// authenticate -- this is the property that makes the mTLS layer
/// load-bearing rather than decorative.
#[test]
fn refuses_a_valid_token_presented_with_the_wrong_client_certificate() {
    let auth = AgentWorkloadAuthenticator::new(table());
    let error = auth
        .authenticate(
            &metadata_with_auth("Bearer agent-a-token-abcdefgh"),
            Some(&peer(0xbb)),
        )
        .expect_err("a token must not authenticate off its pinned certificate");
    assert_eq!(error.code, crate::errors::CommandErrorCode::Unauthenticated);
}

/// Agent B's certificate plus agent B's token authenticates as agent B and
/// nothing else. Combined with the `PollCommands` scoping test in
/// `service.rs`, this is the cross-tenant isolation claim.
#[test]
fn each_credential_authenticates_as_exactly_one_agent() {
    let auth = AgentWorkloadAuthenticator::new(table());
    let caller = auth
        .authenticate(
            &metadata_with_auth("Bearer agent-b-token-abcdefgh"),
            Some(&peer(0xbb)),
        )
        .unwrap();
    assert_eq!(caller.bound_agent_id(), Some("agent-b"));
}

#[test]
fn refuses_a_caller_with_no_peer_certificate() {
    let auth = AgentWorkloadAuthenticator::new(table());
    let error = auth
        .authenticate(&metadata_with_auth("Bearer agent-a-token-abcdefgh"), None)
        .expect_err("strict mode must refuse a caller with no client certificate");
    assert_eq!(error.code, crate::errors::CommandErrorCode::Unauthenticated);
}

#[test]
fn refuses_an_unregistered_token() {
    let auth = AgentWorkloadAuthenticator::new(table());
    let error = auth
        .authenticate(&metadata_with_auth("Bearer not-a-real-token"), Some(&peer(0xaa)))
        .unwrap_err();
    assert_eq!(error.code, crate::errors::CommandErrorCode::Unauthenticated);
}

#[test]
fn refuses_missing_and_duplicate_authorization_headers() {
    let auth = AgentWorkloadAuthenticator::new(table());
    let empty = tonic::metadata::MetadataMap::new();
    assert_eq!(
        auth.authenticate(&empty, Some(&peer(0xaa))).unwrap_err().code,
        crate::errors::CommandErrorCode::Unauthenticated
    );
    let mut duplicate = tonic::metadata::MetadataMap::new();
    duplicate.append("authorization", "Bearer a-token-abcdefghij".parse().unwrap());
    duplicate.append("authorization", "Bearer b-token-abcdefghij".parse().unwrap());
    assert_eq!(
        auth.authenticate(&duplicate, Some(&peer(0xaa)))
            .unwrap_err()
            .code,
        crate::errors::CommandErrorCode::InvalidAuthorization
    );
}

/// The verifier's per-identity failure budget has to actually be reached
/// through this adapter, or a credential-stuffing attempt against the poll
/// endpoint is unthrottled.
#[test]
fn rate_limits_repeated_failures_for_the_same_credential() {
    let auth = AgentWorkloadAuthenticator::new(StaticAgentWorkloadResolver::new());
    let mut saw_rate_limit = false;
    for _ in 0..256 {
        if auth
            .authenticate(&metadata_with_auth("Bearer guess-guess-guess"), Some(&peer(1)))
            .unwrap_err()
            .code
            == crate::errors::CommandErrorCode::RateLimited
        {
            saw_rate_limit = true;
            break;
        }
    }
    assert!(
        saw_rate_limit,
        "repeated agent auth failures must eventually be rate-limited"
    );
}

#[test]
fn table_preserves_a_token_that_contains_the_separator_character() {
    let token = "abcdefgh|ijklmnop|qrstuvwx";
    let resolver =
        parse_agent_token_table(&format!("{token}|{}|agent-a|acme/prod", hex32(0x11)))
            .expect("entry must parse");
    assert!(
        resolver
            .resolve_with_peer(token, Some(&peer(0x11)))
            .is_ok(),
        "the whole token must resolve"
    );
    // No prefix of the token may authenticate.
    assert!(resolver.resolve_with_peer("abcdefgh", Some(&peer(0x11))).is_err());
    assert!(
        resolver
            .resolve_with_peer("abcdefgh|ijklmnop", Some(&peer(0x11)))
            .is_err()
    );
}

#[test]
fn table_fails_closed_on_every_malformed_entry() {
    let good = hex32(0x22);
    for (raw, why) in [
        ("no-separators-at-all".to_owned(), "missing separators"),
        (format!("short|{good}|agent-a|acme/prod"), "token under the floor"),
        (
            format!("agent-token-abcdefgh|{good}|agent-a|not-a-scope"),
            "scope without a '/'",
        ),
        (
            format!("agent-token-abcdefgh|{good}|agent-a|"),
            "no scopes listed",
        ),
        (
            format!("agent-token-abcdefgh|{good}|agent a|acme/prod"),
            "agent id with whitespace",
        ),
        (
            "agent-token-abcdefgh|deadbeef|agent-a|acme/prod".to_owned(),
            "short certificate fingerprint",
        ),
        (
            format!("agent-token-abcdefgh|{good}|*|acme/prod"),
            "wildcard agent id",
        ),
        (
            format!("agent-token-abcdefgh|{good}|agent-a|*"),
            "wildcard scope",
        ),
        (
            format!(
                "agent-token-abcdefgh|{good}|agent-a|acme/prod;agent-token-abcdefgh|{good}|agent-b|acme/prod"
            ),
            "duplicate token",
        ),
        (
            format!("token with spaces|{good}|agent-a|acme/prod"),
            "token that could never be sent in a bearer header",
        ),
    ] {
        assert!(
            parse_agent_token_table(&raw).is_err(),
            "{why}: {raw:?} must be refused, not silently skipped"
        );
    }
}

#[test]
fn an_empty_table_authenticates_nobody() {
    let resolver = parse_agent_token_table("").expect("an empty table is valid");
    assert!(
        resolver
            .resolve_with_peer("anything-at-all-here", Some(&peer(3)))
            .is_err()
    );
}

/// A resolver reached without a peer identity must refuse rather than
/// degrade to bearer-only, whichever entry point is used.
#[test]
fn bare_resolve_never_authenticates() {
    assert!(table().resolve("agent-a-token-abcdefgh").is_err());
}

// -- Revocation ----------------------------------------------------

/// A certificate whose fingerprint is in the revocation list is refused
/// even though its token and certificate still match the credential table
/// exactly -- revocation is checked in addition to, not instead of, every
/// existing check. An unrelated, never-revoked credential is unaffected.
#[test]
fn a_revoked_certificate_is_refused_even_with_a_valid_token_and_matching_certificate() {
    let revocations = AgentRevocationList::with_static_revocations(
        [peer(0xaa).certificate_sha256],
        Duration::from_secs(60),
    );
    let auth =
        AgentWorkloadAuthenticator::new(RevocationAwareAgentResolver::new(table(), revocations));
    let error = auth
        .authenticate(
            &metadata_with_auth("Bearer agent-a-token-abcdefgh"),
            Some(&peer(0xaa)),
        )
        .expect_err("a revoked certificate must be refused even with a valid token");
    assert_eq!(error.code, crate::errors::CommandErrorCode::Unauthenticated);

    assert!(
        auth.authenticate(
            &metadata_with_auth("Bearer agent-b-token-abcdefgh"),
            Some(&peer(0xbb)),
        )
        .is_ok(),
        "revocation must be scoped to the listed fingerprint, not every credential"
    );
}

/// An empty (nothing revoked) but fresh revocation list changes nothing
/// about which credentials authenticate -- the wrapper is only ever a
/// narrowing of what the inner resolver already allows.
#[test]
fn an_empty_revocation_list_does_not_affect_authentication() {
    let revocations =
        AgentRevocationList::with_static_revocations(std::iter::empty(), Duration::from_secs(60));
    let auth =
        AgentWorkloadAuthenticator::new(RevocationAwareAgentResolver::new(table(), revocations));
    let caller = auth
        .authenticate(
            &metadata_with_auth("Bearer agent-a-token-abcdefgh"),
            Some(&peer(0xaa)),
        )
        .expect("an unrevoked credential must still authenticate");
    assert_eq!(caller.bound_agent_id(), Some("agent-a"));
}

/// The fail-closed direction is the whole point of this feature (see
/// `AgentRevocationList`'s doc for the full reasoning): once the cache
/// ages past its staleness ceiling, every agent credential is refused,
/// including one that was never revoked at all.
#[test]
fn a_stale_revocation_cache_refuses_every_agent_credential() {
    // One second, not one millisecond -- the same reasoning
    // `keycloak::tests::resolver::a_stale_key_cache_fails_closed_rather_than_trusting_keys_of_unknown_age`
    // gives: the first assertion below has to land *inside* the window,
    // and that has to be reliable on a loaded CI runner, not just locally.
    let revocations =
        AgentRevocationList::with_static_revocations(std::iter::empty(), Duration::from_secs(1));
    assert!(revocations.is_fresh());
    let auth =
        AgentWorkloadAuthenticator::new(RevocationAwareAgentResolver::new(table(), revocations));
    assert!(
        auth.authenticate(
            &metadata_with_auth("Bearer agent-a-token-abcdefgh"),
            Some(&peer(0xaa)),
        )
        .is_ok(),
        "a fresh, empty revocation cache must not refuse an unrevoked agent"
    );
    std::thread::sleep(Duration::from_millis(1_400));
    let error = auth
        .authenticate(
            &metadata_with_auth("Bearer agent-a-token-abcdefgh"),
            Some(&peer(0xaa)),
        )
        .expect_err("a stale revocation cache must refuse even an agent that was never revoked");
    assert_eq!(error.code, crate::errors::CommandErrorCode::Unauthenticated);
}

#[test]
fn revocation_file_parsing_skips_blank_lines_and_hard_fails_on_malformed_ones() {
    let good = hex32(0xaa);
    let parsed = parse_revocation_list(&format!("\n  \n{good}\n\n"))
        .expect("blank lines must be skipped");
    assert_eq!(parsed.len(), 1);
    assert!(parsed.contains(&[0xaa; 32]));

    let too_short = &good[..63];
    for bad in ["not-hex-at-all", "deadbeef", too_short] {
        assert!(
            parse_revocation_list(bad).is_err(),
            "{bad:?} must be refused, not silently skipped"
        );
    }
}

#[test]
fn revocation_file_parsing_deduplicates_repeated_fingerprints() {
    let good = hex32(0xaa);
    let parsed = parse_revocation_list(&format!("{good}\n{good}\n")).unwrap();
    assert_eq!(parsed.len(), 1);
}

/// A configured-but-missing revocation file must fail startup loudly, not
/// silently come up with revocation disabled -- see `AgentRevocationList::start`'s
/// doc for why this differs from the Keycloak JWKS "warn, don't fail"
/// split.
#[test]
fn revocation_list_start_fails_loudly_on_a_missing_file() {
    let missing = std::env::temp_dir().join(format!(
        "apex-control-agent-revocation-missing-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    assert!(
        AgentRevocationList::start(missing, Duration::from_secs(5), Duration::from_secs(15))
            .is_err(),
        "a configured but unreadable revocation file must fail startup"
    );
}

/// The staleness ceiling must be at least the refresh interval, the same
/// cross-check `KeycloakConfig::validate` applies to its own JWKS
/// refresh/max-age pair.
#[test]
fn revocation_list_start_refuses_a_ceiling_below_the_refresh_interval() {
    let dir = std::env::temp_dir().join(format!(
        "apex-control-agent-revocation-ceiling-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("revoked.txt");
    std::fs::write(&path, "\n").unwrap();
    assert!(
        AgentRevocationList::start(path, Duration::from_secs(10), Duration::from_secs(5))
            .is_err()
    );
}

/// The background refresher replaces the cached set wholesale rather than
/// merging: a fingerprint removed from the file stops being revoked after
/// the next refresh, and a newly added one starts being revoked after it.
#[test]
fn revocation_list_background_refresh_replaces_the_set_wholesale() {
    let dir = std::env::temp_dir().join(format!(
        "apex-control-agent-revocation-refresh-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("revoked.txt");
    let fingerprint = peer(0xaa).certificate_sha256;
    std::fs::write(&path, format!("{}\n", hex32(0xaa))).unwrap();

    let list = AgentRevocationList::start(
        path.clone(),
        Duration::from_millis(200),
        Duration::from_secs(5),
    )
    .expect("a well-formed, readable revocation file must start");
    assert_eq!(
        list.check(&fingerprint),
        Ok(true),
        "the fingerprint present at startup must be revoked immediately"
    );

    // Un-revoke by rewriting the file with no entries.
    std::fs::write(&path, "\n").unwrap();
    std::thread::sleep(Duration::from_millis(1_000));
    assert_eq!(
        list.check(&fingerprint),
        Ok(false),
        "removing a fingerprint from the file must un-revoke it, not leave it \
         stuck from an earlier read"
    );
}

/// The supervisor identity is a distinct, valid agent_id -- registerable
/// in the same credential table as the agent it supervises, with its own
/// entry -- and is never equal to the agent_id it is derived from. Equal
/// would mean "the same identity", which is precisely the property this
/// convention exists to avoid.
#[test]
fn supervisor_agent_id_is_distinct_and_registerable() {
    let agent_id = "agent-1";
    let supervisor_id = supervisor_agent_id(agent_id);
    assert_ne!(supervisor_id, agent_id);
    assert_eq!(supervisor_id, "agent-1.supervisor");
    let table = parse_agent_token_table(&format!(
        "agent-token-abcdefgh|{}|{agent_id}|acme/prod;supervisor-token-abcdefgh|{}|{supervisor_id}|acme/prod",
        hex32(0xaa),
        hex32(0xcc)
    ))
    .expect("an agent entry and its supervisor entry must both parse");
    let agent_caller = table
        .resolve_with_peer("agent-token-abcdefgh", Some(&peer(0xaa)))
        .expect("the agent's own credential must authenticate");
    let supervisor_caller = table
        .resolve_with_peer("supervisor-token-abcdefgh", Some(&peer(0xcc)))
        .expect("the supervisor's own, separate credential must authenticate");
    assert_eq!(agent_caller.bound_agent_id(), Some(agent_id));
    assert_eq!(supervisor_caller.bound_agent_id(), Some(supervisor_id.as_str()));
    // Neither credential authenticates as the other's identity: the
    // supervisor's token is pinned to its own certificate, distinct from
    // the agent's.
    assert!(
        table
            .resolve_with_peer("agent-token-abcdefgh", Some(&peer(0xcc)))
            .is_err()
    );
}
