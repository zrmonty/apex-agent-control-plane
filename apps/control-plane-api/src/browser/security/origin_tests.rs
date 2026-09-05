use super::*;
use axum::http::{HeaderMap, HeaderValue, header::ORIGIN};

fn origin_headers(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(ORIGIN, HeaderValue::from_str(value).unwrap());
    headers
}

#[test]
fn origin_matches_exact_scheme_host_and_effective_port() {
    let configured = ConfiguredOrigin::parse("https://console.example:8443").unwrap();
    assert!(
        configured
            .verify(&origin_headers("https://console.example:8443"))
            .is_ok()
    );
    for different in [
        "https://console.example",
        "https://console.example:443",
        "https://console.example:8444",
        "https://console.example.evil:8443",
        "https://child.console.example:8443",
        "https://console.example.:8443",
        "https://evil.example:8443",
    ] {
        assert_eq!(
            configured.verify(&origin_headers(different)),
            Err(SecurityError::UnexpectedOrigin)
        );
    }
    assert!(
        configured
            .verify(&origin_headers("http://console.example:8443"))
            .is_err()
    );
}

#[test]
fn explicit_and_omitted_default_https_ports_match_in_both_directions() {
    for configured in ["https://console.example", "https://console.example:443"] {
        let origin = ConfiguredOrigin::parse(configured).unwrap();
        for request in ["https://console.example", "https://console.example:443"] {
            assert_eq!(origin.verify(&origin_headers(request)), Ok(()));
        }
        assert!(
            origin
                .verify(&origin_headers("http://console.example:443"))
                .is_err()
        );
        assert!(
            origin
                .verify(&origin_headers("https://console.example:80"))
                .is_err()
        );
    }
}

#[test]
fn origin_uses_url_host_and_scheme_canonicalization() {
    let configured = ConfiguredOrigin::parse("HTTPS://CONSOLE.EXAMPLE:443").unwrap();
    assert_eq!(
        configured.verify(&origin_headers("https://console.example")),
        Ok(())
    );
    let ipv6 = ConfiguredOrigin::parse("https://[::1]:443").unwrap();
    assert_eq!(
        ipv6.verify(&origin_headers("https://[0:0:0:0:0:0:0:1]")),
        Ok(())
    );
    assert!(ipv6.verify(&origin_headers("https://[::2]")).is_err());
}

#[test]
fn origin_requires_one_header_and_never_falls_back_to_forwarding_or_referer() {
    let configured = ConfiguredOrigin::parse("https://console.example").unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "referer",
        HeaderValue::from_static("https://console.example/"),
    );
    headers.insert("host", HeaderValue::from_static("console.example"));
    headers.insert(
        "x-forwarded-host",
        HeaderValue::from_static("console.example"),
    );
    headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    assert_eq!(
        configured.verify(&headers),
        Err(SecurityError::InvalidOrigin)
    );

    for second in ["https://console.example", "https://evil.example"] {
        let mut duplicate = origin_headers("https://console.example");
        duplicate.append(ORIGIN, HeaderValue::from_str(second).unwrap());
        assert_eq!(
            configured.verify(&duplicate),
            Err(SecurityError::InvalidOrigin)
        );
    }
}

#[test]
fn origin_rejects_null_lists_paths_userinfo_and_parser_normalization_tricks() {
    let configured = ConfiguredOrigin::parse("https://console.example").unwrap();
    for malformed in [
        "",
        "null",
        "NULL",
        "console.example",
        "https:console.example",
        "https:///console.example",
        "https://console.example/",
        "https://console.example/../",
        "https://console.example/path",
        "https://console.example?",
        "https://console.example?x=1",
        "https://console.example#",
        "https://console.example#fragment",
        "https://user@console.example",
        "https://@console.example",
        "https://user:password@console.example",
        "https://console.example\\",
        "https://console.example:",
        "https://console.example:65536",
        "https://%63onsole.example",
        "https://console.example\t",
        " https://console.example",
        "https://console.example ",
        "https://console.example https://evil.example",
        "https://console.example,https://evil.example",
        "https://console.example, https://console.example",
    ] {
        assert_eq!(
            configured.verify(&origin_headers(malformed)),
            Err(SecurityError::InvalidOrigin)
        );
    }
}

#[test]
fn configured_origin_rejects_non_https_or_non_authority_configuration() {
    for malformed in [
        "",
        "null",
        "http://console.example",
        "file:///console.example",
        "ftp://console.example",
        "https://",
        "https://:443",
        "https://*",
        "https://*.example",
        "https:///console.example",
        "https:console.example",
        "https://console.example/",
        "https://console.example/auth/callback",
        "https://console.example/..",
        "https://console.example?",
        "https://console.example#",
        "https://console.example:0",
        "https://console.example:",
        "https://console.example:65536",
        "https://secret@console.example",
        "https://@console.example",
        "https://user:secret@console.example",
        "https://console.example\\",
        "https://console.example\n",
        "\thttps://console.example",
        " https://console.example",
        "https://%63onsole.example",
        "https://console.example https://evil.example",
    ] {
        assert_eq!(
            ConfiguredOrigin::parse(malformed).unwrap_err(),
            SecurityError::InvalidConfiguredOrigin
        );
    }
}

#[test]
fn origin_bounds_and_non_ascii_fail_closed_without_disclosing_input() {
    let configured = ConfiguredOrigin::parse("https://console.example").unwrap();
    let oversized = format!("https://{}", "a".repeat(MAX_ORIGIN_BYTES));
    assert_eq!(
        ConfiguredOrigin::parse(&oversized).unwrap_err(),
        SecurityError::InvalidConfiguredOrigin
    );
    assert_eq!(
        configured.verify(&origin_headers(&oversized)),
        Err(SecurityError::InvalidOrigin)
    );
    let mut bytes = HeaderMap::new();
    bytes.insert(
        ORIGIN,
        HeaderValue::from_bytes(b"https://console.\x80example").unwrap(),
    );
    assert_eq!(configured.verify(&bytes), Err(SecurityError::InvalidOrigin));

    let error = ConfiguredOrigin::parse("https://user:private-marker@console.example").unwrap_err();
    assert!(!format!("{error:?} {error}").contains("private-marker"));
}
