use super::*;
use std::error::Error as _;

// Public deterministic fixtures, never provider credentials. SHA-256 is over
// canonical ASCII state, not the decoded 32 token bytes or percent-encoded wire.
const STATE: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const STATE_DIGEST: [u8; 32] = [
    0xea, 0x86, 0x6a, 0x75, 0x7e, 0x4c, 0x38, 0xba, 0xbf, 0xa8, 0x12, 0x7c, 0xbe, 0x9a, 0x40, 0x9d,
    0x3e, 0x1f, 0x93, 0xa0, 0x0f, 0xf1, 0x48, 0x8f, 0xf7, 0x35, 0xfc, 0xf9, 0x17, 0xaf, 0xff, 0xd0,
];

fn parse_ok(query: &str) -> CallbackRequest {
    CallbackRequest::parse(Some(query)).expect("valid callback must parse")
}

fn invalid(query: Option<&str>) {
    assert!(matches!(
        CallbackRequest::parse(query),
        Err(BrowserError::InvalidRequest)
    ));
}

fn with_state(fields: &str) -> String {
    format!("state={STATE}&{fields}")
}

fn assert_redacted(rendered: &str) {
    for secret in [
        STATE,
        "CODE_SECRET_CANARY",
        "ERROR_SECRET_CANARY",
        "DESCRIPTION_SECRET_CANARY",
        "URI_SECRET_CANARY",
        "ISSUER_SECRET_CANARY",
        "SESSION_SECRET_CANARY",
        "ea866a757e4c38ba",
        "234, 134, 106, 117",
    ] {
        assert!(
            !rendered.contains(secret),
            "callback output leaked a canary"
        );
    }
}

#[test]
fn code_callback_returns_only_state_lookup_and_zeroizing_code() {
    let request = parse_ok(&with_state("code=CODE_SECRET_CANARY"));
    assert_eq!(request.state.as_bytes(), &STATE_DIGEST);
    let code: &Zeroizing<String> = request.code.as_ref().expect("code retained");
    assert_eq!(code.as_str(), "CODE_SECRET_CANARY");
    assert_eq!(request.issuer, None);
    assert!(!request.denied);
}

#[test]
fn keycloak_callback_decodes_issuer_and_ignores_session_state_in_any_order() {
    let query = format!(
        "session_state=provider-session&iss=https%3A%2F%2Fid.example%2Frealms%2Fapex\
         &code=AUTH.CODE-123_456&state={STATE}"
    );
    let request = parse_ok(&query);
    assert_eq!(request.state.as_bytes(), &STATE_DIGEST);
    assert_eq!(request.code.as_ref().unwrap().as_str(), "AUTH.CODE-123_456");
    assert_eq!(
        request.issuer.as_deref(),
        Some("https://id.example/realms/apex")
    );
    assert!(!request.denied);
}

#[test]
fn provider_denial_preserves_state_for_later_browser_bound_one_use_claim() {
    let request = parse_ok(&with_state("error=access_denied"));
    assert_eq!(request.state.as_bytes(), &STATE_DIGEST);
    assert!(request.denied);
    assert!(request.code.is_none());
    assert!(request.issuer.is_none());
}

#[test]
fn provider_error_names_are_not_an_authorization_allowlist() {
    for error in ["A", "0", "_", "-", "Provider_specific-42"] {
        let request = parse_ok(&with_state(&format!("error={error}")));
        assert!(request.denied);
        assert!(request.code.is_none());
    }
}

#[test]
fn denial_accepts_utf8_description_and_discards_untrusted_error_uri() {
    let request = parse_ok(&with_state(
        "error_description=Acc%C3%A8s+refus%C3%A9+%F0%9F%94%92\
         &error_uri=not-a-url&error=access_denied&iss=untrusted-issuer",
    ));
    assert!(request.denied);
    assert_eq!(request.state.as_bytes(), &STATE_DIGEST);
    assert_eq!(request.issuer.as_deref(), Some("untrusted-issuer"));
    assert!(request.code.is_none());
}

#[test]
fn empty_ignored_error_metadata_is_valid_utf8() {
    assert!(
        parse_ok(&with_state(
            "error=access_denied&error_description=&error_uri="
        ))
        .denied
    );
}

#[test]
fn issuer_is_preserved_without_url_validation_normalization_or_trust_policy() {
    // The caller must claim matching state AND browser binding before comparing
    // this value with its configured issuer. Parsing cannot confer that trust.
    for issuer in [
        "not-a-url",
        "http://untrusted.invalid",
        "HTTPS://ID.EXAMPLE/Realm/",
    ] {
        let request = parse_ok(&with_state(&format!("code=x&iss={issuer}")));
        assert_eq!(request.issuer.as_deref(), Some(issuer));
    }
}

#[test]
fn form_decoding_is_once_only_and_encoded_delimiters_remain_in_code() {
    let request = parse_ok(&with_state("code=a%26code%3Db%3D%25%2b%2520"));
    assert_eq!(request.code.as_ref().unwrap().as_str(), "a&code=b=%+%20");
    let request = parse_ok(&with_state("code=a=b=c"));
    assert_eq!(request.code.as_ref().unwrap().as_str(), "a=b=c");
}

#[test]
fn escaped_keys_and_state_hash_the_canonical_decoded_token() {
    let query = format!("%73tate=%41{}&%63ode=x", &STATE[1..]);
    let request = parse_ok(&query);
    assert_eq!(request.state.as_bytes(), &STATE_DIGEST);
    assert_eq!(request.code.as_ref().unwrap().as_str(), "x");
}

#[test]
fn all_ascii_graphic_code_bytes_are_accepted_after_form_decoding() {
    let encoded: String = (b'!'..=b'~').map(|byte| format!("%{byte:02X}")).collect();
    let request = parse_ok(&with_state(&format!("code={encoded}")));
    assert_eq!(
        request.code.as_ref().unwrap().as_bytes(),
        &(b'!'..=b'~').collect::<Vec<_>>()
    );
}

#[test]
fn missing_query_state_or_response_is_invalid() {
    for query in [None, Some(""), Some("code=x"), Some("error=access_denied")] {
        invalid(query);
    }
    invalid(Some(&format!("state={STATE}")));
    invalid(Some(&with_state("iss=https://id.example")));
}

#[test]
fn state_rejects_empty_wrong_width_padding_and_noncanonical_unused_bits() {
    for state in [
        String::new(),
        "A".repeat(42),
        "A".repeat(44),
        format!("{STATE}="),
        format!("{}9", &STATE[..42]),
        format!("{}_", &STATE[..42]),
        format!("{}%2B", &STATE[..42]),
        format!("{}%2F", &STATE[..42]),
        format!("%2541{}", &STATE[1..]),
    ] {
        invalid(Some(&format!("state={state}&code=x")));
        invalid(Some(&format!("state={state}&error=access_denied")));
    }
}

#[test]
fn code_and_error_are_mutually_exclusive_even_if_one_is_empty() {
    for fields in [
        "code=x&error=access_denied",
        "code=&error=access_denied",
        "code=x&error=",
    ] {
        invalid(Some(&with_state(fields)));
    }
}

fn duplicate_query(key: &str, alias: &str, value: &str) -> String {
    let response = if key == "code" {
        "code=x"
    } else {
        "error=access_denied"
    };
    let base = with_state(response);
    if matches!(key, "state" | "code" | "error") {
        format!("{base}&{alias}={value}")
    } else {
        format!("{base}&{key}={value}&{alias}={value}")
    }
}

const FIELDS: [(&str, &str, &str); 7] = [
    ("state", "%73tate", STATE),
    ("code", "%63ode", "x"),
    ("iss", "%69ss", "issuer"),
    ("session_state", "%73ession_state", "session"),
    ("error", "%65rror", "access_denied"),
    ("error_description", "%65rror_description", "description"),
    ("error_uri", "%65rror_uri", "https://id.example/error"),
];

#[test]
fn every_duplicate_decoded_field_is_rejected_including_ignored_metadata() {
    for (key, _, value) in FIELDS {
        invalid(Some(&duplicate_query(key, key, value)));
    }
}

#[test]
fn escaped_duplicate_keys_are_rejected_in_either_order() {
    for (key, alias, value) in FIELDS {
        let query = duplicate_query(key, alias, value);
        invalid(Some(&query));
        let reversed = query.split('&').rev().collect::<Vec<_>>().join("&");
        invalid(Some(&reversed));
    }
}

#[test]
fn duplicate_values_do_not_use_first_wins_or_last_wins() {
    for fields in [
        "code=x&code=y",
        "code=x&code=",
        "code=&code=x",
        "code=x&code",
        "error=access_denied&error=other_error",
        "error=&error=access_denied",
    ] {
        invalid(Some(&with_state(fields)));
    }
    invalid(Some(&with_state("code=x&state=")));
    invalid(Some(&format!("state=&state={STATE}&code=x")));
}

#[test]
fn unknown_empty_and_case_variant_keys_are_rejected() {
    for field in [
        "unknown=x",
        "aud=apex",
        "audience=apex",
        "scope=openid",
        "id_token=x",
        "State=x",
        "CODE=x",
        "ISS=x",
        "=x",
        "",
        "%00=x",
        "+=x",
        "%C3%A9=x",
        "%2563ode=x",
    ] {
        invalid(Some(&with_state(&format!("code=x&{field}"))));
    }
}

#[test]
fn empty_pairs_and_bare_required_values_are_rejected() {
    for query in [
        format!("&state={STATE}&code=x"),
        format!("state={STATE}&&code=x"),
        with_state("code=x&"),
        with_state("code"),
        with_state("error"),
        with_state("code=x&iss"),
        with_state("code=x&session_state"),
    ] {
        invalid(Some(&query));
    }
}

#[test]
fn error_metadata_is_rejected_without_provider_error() {
    for metadata in [
        "error_description=reason",
        "error_uri=https://id.example/error",
        "error_description=",
    ] {
        invalid(Some(&with_state(&format!("code=x&{metadata}"))));
        invalid(Some(&with_state(metadata)));
    }
}

#[test]
fn raw_query_must_be_ascii_even_for_valid_unicode_error_descriptions() {
    for fields in [
        "code=café",
        "error=access_denied&error_description=refusé",
        "error=access_denied&error_uri=é",
    ] {
        invalid(Some(&with_state(fields)));
    }
}

#[test]
fn malformed_percent_escapes_are_invalid_in_all_values_and_keys() {
    for malformed in ["%", "%0", "%GG", "%G0", "%0G", "%u0041"] {
        for (key, _, _) in FIELDS {
            let query = match key {
                "state" => format!("state={malformed}&code=x"),
                "code" | "error" => with_state(&format!("{key}={malformed}")),
                _ => with_state(&format!("error=access_denied&{key}={malformed}")),
            };
            invalid(Some(&query));
        }
        invalid(Some(&with_state(&format!("code=x&{malformed}=x"))));
    }
}

#[test]
fn invalid_utf8_is_rejected_in_every_field_including_ignored_metadata() {
    for malformed in [
        "%FF",
        "%bad",
        "%C0%AF",
        "%E2%82",
        "%ED%A0%80",
        "%F4%90%80%80",
    ] {
        for (key, _, _) in FIELDS {
            let query = match key {
                "state" => format!("state={malformed}&code=x"),
                "code" | "error" => with_state(&format!("{key}={malformed}")),
                _ => with_state(&format!("error=access_denied&{key}={malformed}")),
            };
            invalid(Some(&query));
        }
        invalid(Some(&with_state(&format!("code=x&{malformed}=x"))));
    }
}

#[test]
fn authority_fields_and_session_state_reject_decoded_non_ascii() {
    for fields in [
        "code=%C3%A9",
        "error=%C3%A9",
        "code=x&iss=%C3%A9",
        "code=x&session_state=%C3%A9",
    ] {
        invalid(Some(&with_state(fields)));
    }
    invalid(Some(&format!("state=%C3%A9{}&code=x", &STATE[2..])));
}

#[test]
fn authority_fields_and_session_state_reject_plus_whitespace_and_controls() {
    for bad in [
        "+", "%20", "%09", "%0A", "%0D", "%00", "%1F", "%7F", " ", "\t", "\n",
    ] {
        for fields in [
            format!("code=a{bad}b"),
            format!("error=a{bad}b"),
            format!("code=x&iss=a{bad}b"),
            format!("code=x&session_state=a{bad}b"),
        ] {
            invalid(Some(&with_state(&fields)));
        }
        invalid(Some(&format!("state={}{}&code=x", &STATE[..42], bad)));
    }
}

#[test]
fn error_values_reject_punctuation_outside_alphanumeric_underscore_hyphen() {
    for error in [
        "",
        "access.denied",
        "access%2Bdenied",
        "access%2Fdenied",
        "denied%3Dyes",
    ] {
        invalid(Some(&with_state(&format!("error={error}"))));
    }
}

#[test]
fn code_accepts_one_and_2048_decoded_bytes() {
    for length in [1, 2048] {
        let request = parse_ok(&with_state(&format!("code={}", "c".repeat(length))));
        assert_eq!(request.code.as_ref().unwrap().len(), length);
    }
}

#[test]
fn code_rejects_empty_and_2049_decoded_bytes() {
    for length in [0, 2049] {
        invalid(Some(&with_state(&format!("code={}", "c".repeat(length)))));
    }
}

#[test]
fn issuer_accepts_one_and_2048_decoded_bytes() {
    for length in [1, 2048] {
        let request = parse_ok(&with_state(&format!("code=x&iss={}", "i".repeat(length))));
        assert_eq!(request.issuer.as_ref().unwrap().len(), length);
    }
}

#[test]
fn issuer_rejects_empty_and_2049_decoded_bytes() {
    for length in [0, 2049] {
        invalid(Some(&with_state(&format!(
            "code=x&iss={}",
            "i".repeat(length)
        ))));
    }
}

#[test]
fn provider_error_accepts_128_bytes_and_rejects_129() {
    assert!(parse_ok(&with_state(&format!("error={}", "e".repeat(128)))).denied);
    invalid(Some(&with_state(&format!("error={}", "e".repeat(129)))));
}

#[test]
fn ignored_session_state_accepts_128_graphic_bytes_and_rejects_129_or_empty() {
    assert!(
        !parse_ok(&with_state(&format!(
            "code=x&session_state={}",
            "s".repeat(128)
        )))
        .denied
    );
    for length in [0, 129] {
        invalid(Some(&with_state(&format!(
            "code=x&session_state={}",
            "s".repeat(length)
        ))));
    }
}

#[test]
fn ignored_error_metadata_accepts_2048_bytes_and_rejects_2049_each() {
    for key in ["error_description", "error_uri"] {
        assert!(
            parse_ok(&with_state(&format!(
                "error=denied&{key}={}",
                "m".repeat(2048)
            )))
            .denied
        );
        invalid(Some(&with_state(&format!(
            "error=denied&{key}={}",
            "m".repeat(2049)
        ))));
    }
}

#[test]
fn unicode_description_limit_counts_decoded_utf8_bytes_not_characters() {
    let good = with_state(&format!(
        "error=denied&error_description={}%C3%A9",
        "a".repeat(2046)
    ));
    assert!(parse_ok(&good).denied);
    let oversized = with_state(&format!(
        "error=denied&error_description={}%C3%A9",
        "a".repeat(2047)
    ));
    invalid(Some(&oversized));
}

fn raw_boundary_query(length: usize) -> String {
    let prefix = with_state(&format!("code={}&iss=", "c".repeat(2048)));
    format!("{prefix}{}", "i".repeat(length - prefix.len()))
}

#[test]
fn raw_query_accepts_exactly_4096_bytes() {
    let query = raw_boundary_query(4096);
    assert_eq!(query.len(), 4096);
    assert_eq!(parse_ok(&query).code.as_ref().unwrap().len(), 2048);
}

#[test]
fn raw_query_rejects_4097_bytes_with_individually_valid_fields() {
    let query = raw_boundary_query(4097);
    assert_eq!(query.len(), 4097);
    invalid(Some(&query));
}

#[test]
fn raw_query_bound_applies_before_percent_decoding_reduces_its_length() {
    let query = with_state(&format!("code={}", "%41".repeat(1400)));
    assert!(query.len() > 4096);
    invalid(Some(&query));
    let compact = with_state(&format!("code={}", "A".repeat(1400)));
    assert_eq!(parse_ok(&compact).code.as_ref().unwrap().len(), 1400);
}

#[test]
fn more_than_eight_raw_pairs_is_invalid() {
    // With seven known keys and exclusive code/error, an eight-pair valid
    // request is impossible. GREEN review must also check counting happens
    // before allocation; this public result cannot reveal allocation order.
    for count in [9, 128] {
        let query = format!("{}{}", with_state("code=x"), "&iss=i".repeat(count - 2));
        assert_eq!(query.split('&').count(), count);
        assert!(query.len() <= 4096);
        invalid(Some(&query));
    }
}

#[test]
fn success_debug_redacts_raw_code_issuer_state_and_digest() {
    let request = parse_ok(&with_state(
        "code=CODE_SECRET_CANARY&iss=ISSUER_SECRET_CANARY&session_state=SESSION_SECRET_CANARY",
    ));
    for debug in [format!("{request:?}"), format!("{request:#?}")] {
        assert_redacted(&debug);
    }
}

#[test]
fn denial_debug_discards_provider_error_description_and_uri_canaries() {
    let request = parse_ok(&with_state(
        "error=ERROR_SECRET_CANARY&error_description=DESCRIPTION_SECRET_CANARY\
         &error_uri=https%3A%2F%2FURI_SECRET_CANARY.invalid&iss=ISSUER_SECRET_CANARY\
         &session_state=SESSION_SECRET_CANARY",
    ));
    for debug in [format!("{request:?}"), format!("{request:#?}")] {
        assert_redacted(&debug);
    }
}

#[test]
fn parse_errors_have_no_raw_fields_or_underlying_error_chain() {
    let query = with_state(
        "code=CODE_SECRET_CANARY&error=ERROR_SECRET_CANARY\
         &error_description=DESCRIPTION_SECRET_CANARY&error_uri=URI_SECRET_CANARY\
         &iss=ISSUER_SECRET_CANARY&session_state=SESSION_SECRET_CANARY",
    );
    let error = CallbackRequest::parse(Some(&query)).unwrap_err();
    assert_eq!(error, BrowserError::InvalidRequest);
    assert!(error.source().is_none());
    for rendered in [
        format!("{error}"),
        format!("{error:?}"),
        format!("{error:#?}"),
    ] {
        assert_redacted(&rendered);
    }
}
