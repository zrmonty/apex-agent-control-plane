use super::*;
use axum::http::{HeaderMap, HeaderValue, header::COOKIE};

const TOKEN: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const OTHER_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const DIGEST: [u8; 32] = [
    0xea, 0x86, 0x6a, 0x75, 0x7e, 0x4c, 0x38, 0xba, 0xbf, 0xa8, 0x12, 0x7c, 0xbe, 0x9a, 0x40, 0x9d,
    0x3e, 0x1f, 0x93, 0xa0, 0x0f, 0xf1, 0x48, 0x8f, 0xf7, 0x35, 0xfc, 0xf9, 0x17, 0xaf, 0xff, 0xd0,
];

fn cookies(values: &[&str]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for value in values {
        headers.append(COOKIE, HeaderValue::from_str(value).unwrap());
    }
    headers
}

fn assert_host_attributes(header: &HeaderValue, expected_pair: &str, max_age: &str) {
    let value = header.to_str().unwrap();
    let parts: Vec<_> = value.split(';').map(str::trim).collect();
    assert_eq!(parts[0], expected_pair);
    for attribute in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/", max_age] {
        assert_eq!(parts.iter().filter(|part| **part == attribute).count(), 1);
    }
    assert!(!value.to_ascii_lowercase().contains("domain"));
    assert!(!value.contains('\r') && !value.contains('\n'));
}

#[test]
fn fixed_session_and_login_cookies_set_all_host_attributes() {
    let token = OpaqueToken::parse(TOKEN).unwrap();
    for (kind, name) in [
        (AppCookie::Session, "__Host-apex_session"),
        (AppCookie::Login, "__Host-apex_login"),
    ] {
        let header = set_cookie(kind, &token, 300).unwrap();
        assert_host_attributes(&header, &format!("{name}={TOKEN}"), "Max-Age=300");
        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains(TOKEN));
        assert!(!format!("{:?}", vec![header]).contains(TOKEN));
    }
}

#[test]
fn deleting_cookies_uses_same_host_attributes_and_immediate_expiry() {
    for (kind, name) in [
        (AppCookie::Session, "__Host-apex_session"),
        (AppCookie::Login, "__Host-apex_login"),
    ] {
        let header = clear_cookie(kind);
        assert_host_attributes(&header, &format!("{name}="), "Max-Age=0");
        assert!(
            header
                .to_str()
                .unwrap()
                .contains("Expires=Thu, 01 Jan 1970 00:00:00 GMT")
        );
        assert!(header.is_sensitive());
    }
}

#[test]
fn cookie_creation_rejects_zero_and_excessive_max_age_without_clamping() {
    let token = OpaqueToken::parse(TOKEN).unwrap();
    for (kind, maximum) in [
        (AppCookie::Session, MAX_SESSION_COOKIE_AGE_SECS),
        (AppCookie::Login, MAX_LOGIN_COOKIE_AGE_SECS),
    ] {
        for valid in [1, maximum] {
            let header = set_cookie(kind, &token, valid).unwrap();
            assert!(
                header
                    .to_str()
                    .unwrap()
                    .contains(&format!("Max-Age={valid}"))
            );
        }
        for invalid in [0, maximum + 1, u64::MAX] {
            assert_eq!(
                set_cookie(kind, &token, invalid),
                Err(SecurityError::InvalidMaxAge)
            );
        }
    }
}

#[test]
fn cookie_parser_returns_only_lookup_digests_and_ignores_unrelated_cookies() {
    let absent = parse_app_cookies(&HeaderMap::new()).unwrap();
    assert_eq!(absent.session, None);
    assert_eq!(absent.login, None);
    let values = cookies(&[
        "theme=dark; theme=light; analytics=a=b; quoted=\"light\"",
        &format!("__Host-apex_session={TOKEN}; __Host-apex_login={OTHER_TOKEN}"),
    ]);
    let parsed = parse_app_cookies(&values).unwrap();
    assert_eq!(parsed.session.unwrap().as_bytes(), &DIGEST);
    assert_eq!(
        parsed.login,
        Some(OpaqueToken::parse(OTHER_TOKEN).unwrap().lookup_digest())
    );
    let debug = format!("{parsed:?}");
    assert!(!debug.contains(TOKEN) && !debug.contains(OTHER_TOKEN));
    assert!(!debug.contains("234, 134, 106, 117"));
}

#[test]
fn cookie_names_are_case_sensitive_and_matching_is_not_by_prefix() {
    let parsed = parse_app_cookies(&cookies(&[
        "__host-apex_session=ignored; __Host-apex_session_extra=ignored",
        "__Host-apex_login_extra=ignored; prefix__Host-apex_session=ignored",
    ]))
    .unwrap();
    assert_eq!(parsed.session, None);
    assert_eq!(parsed.login, None);
}

#[test]
fn same_app_cookie_twice_is_rejected_even_if_identical_or_in_separate_headers() {
    for name in ["__Host-apex_session", "__Host-apex_login"] {
        for second in [TOKEN, OTHER_TOKEN] {
            let first = format!("{name}={TOKEN}");
            let duplicate = format!("{name}={second}");
            assert_eq!(
                parse_app_cookies(&cookies(&[&format!("{first}; {duplicate}")])).unwrap_err(),
                SecurityError::DuplicateCookie
            );
            assert_eq!(
                parse_app_cookies(&cookies(&[&first, "theme=light", &duplicate])).unwrap_err(),
                SecurityError::DuplicateCookie
            );
        }
    }
}

#[test]
fn malformed_app_values_cannot_be_ignored_or_normalized() {
    for name in ["__Host-apex_session", "__Host-apex_login"] {
        for value in [
            "".to_owned(),
            "a".repeat(42),
            "a".repeat(44),
            format!("{TOKEN}="),
            format!("\"{TOKEN}\""),
            format!(" {TOKEN}"),
            format!("{TOKEN} "),
            format!("{}B", &OTHER_TOKEN[..42]),
            format!("{}+", &TOKEN[..42]),
            format!("{}%38", &TOKEN[..42]),
        ] {
            assert_eq!(
                parse_app_cookies(&cookies(&[&format!("{name}={value}")])).unwrap_err(),
                SecurityError::InvalidCookie
            );
        }
    }
}

#[test]
fn cookie_parser_rejects_control_bytes_and_ambiguous_cookie_syntax() {
    for malformed in [
        format!("__Host-apex_session={TOKEN}\t"),
        format!("__Host-apex_session\t={TOKEN}"),
        format!("__Host-apex_session = {TOKEN}"),
        format!("unrelated=\tvalue; __Host-apex_session={TOKEN}"),
        format!("__Host-apex_session={TOKEN}, __Host-apex_login={TOKEN}"),
        format!("unrelated=\"x; __Host-apex_session={TOKEN}\""),
        format!("unrelated; __Host-apex_session={TOKEN}"),
        format!("bad name=value; __Host-apex_session={TOKEN}"),
    ] {
        assert_eq!(
            parse_app_cookies(&cookies(&[&malformed])).unwrap_err(),
            SecurityError::InvalidCookie
        );
    }
    // HeaderValue already rejects CR/LF/NUL at the HTTP boundary. Exercise
    // remaining wire bytes it can represent rather than bypassing that type.
    let mut non_ascii = HeaderMap::new();
    non_ascii.insert(COOKIE, HeaderValue::from_bytes(b"unrelated=\x80").unwrap());
    assert_eq!(
        parse_app_cookies(&non_ascii).unwrap_err(),
        SecurityError::InvalidCookie
    );
}

#[test]
fn aggregate_cookie_bytes_are_bounded_across_all_headers() {
    // Each half fits independently; only the total exceeds the ceiling.
    let half = format!("a={}", "x".repeat(MAX_COOKIE_BYTES / 2 - 2));
    assert!(parse_app_cookies(&cookies(&[&half, &half])).is_ok());
    assert_eq!(
        parse_app_cookies(&cookies(&[&half, &format!("{half}x")])).unwrap_err(),
        SecurityError::CookieLimit
    );
    let oversized = format!("a={}", "x".repeat(MAX_COOKIE_BYTES));
    assert_eq!(
        parse_app_cookies(&cookies(&[&oversized])).unwrap_err(),
        SecurityError::CookieLimit
    );
}

#[test]
fn unrelated_cookie_count_and_header_count_cannot_evade_bounds() {
    let at_limit = vec!["other=x"; MAX_COOKIE_COUNT].join("; ");
    assert!(parse_app_cookies(&cookies(&[&at_limit])).is_ok());
    assert_eq!(
        parse_app_cookies(&cookies(&[&at_limit, "other=x"])).unwrap_err(),
        SecurityError::CookieLimit
    );
    let headers = vec!["other=x"; MAX_COOKIE_HEADERS];
    assert!(parse_app_cookies(&cookies(&headers)).is_ok());
    assert_eq!(
        parse_app_cookies(&cookies(&vec!["other=x"; MAX_COOKIE_HEADERS + 1])).unwrap_err(),
        SecurityError::CookieLimit
    );
}

#[test]
fn malformed_cookie_errors_do_not_disclose_cookie_values() {
    let error = parse_app_cookies(&cookies(&[&format!(
        "__Host-apex_session={TOKEN}=private-marker"
    )]))
    .unwrap_err();
    assert_eq!(error, SecurityError::InvalidCookie);
    let message = format!("{error:?} {error}");
    assert!(!message.contains(TOKEN) && !message.contains("private-marker"));
}
