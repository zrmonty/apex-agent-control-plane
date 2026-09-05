use super::*;
use axum::http::{HeaderMap, HeaderValue};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

const TOKEN: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const OTHER_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const BINDING: [u8; 32] = [
    0xea, 0x86, 0x6a, 0x75, 0x7e, 0x4c, 0x38, 0xba, 0xbf, 0xa8, 0x12, 0x7c, 0xbe, 0x9a, 0x40, 0x9d,
    0x3e, 0x1f, 0x93, 0xa0, 0x0f, 0xf1, 0x48, 0x8f, 0xf7, 0x35, 0xfc, 0xf9, 0x17, 0xaf, 0xff, 0xd0,
];

fn csrf_headers(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-apex-csrf", HeaderValue::from_str(value).unwrap());
    headers
}

#[test]
fn csrf_accepts_exact_canonical_token_against_restored_session_binding() {
    let token = CsrfToken::parse(TOKEN).unwrap();
    assert_eq!(token.expose_secret(), TOKEN);
    assert_eq!(token.binding().as_bytes(), &BINDING);
    assert_eq!(
        verify_csrf(&csrf_headers(TOKEN), &CsrfBinding::from_bytes(BINDING)),
        Ok(())
    );
    let mut mixed_case = HeaderMap::new();
    mixed_case.insert(
        axum::http::HeaderName::from_bytes(b"X-Apex-Csrf").unwrap(),
        HeaderValue::from_static(TOKEN),
    );
    assert_eq!(verify_csrf(&mixed_case, &token.binding()), Ok(()));
}

#[test]
fn csrf_rejects_missing_and_wrong_binding() {
    let binding = CsrfBinding::from_bytes(BINDING);
    assert_eq!(
        verify_csrf(&HeaderMap::new(), &binding),
        Err(SecurityError::MissingCsrf)
    );
    assert_eq!(
        verify_csrf(&csrf_headers(OTHER_TOKEN), &binding),
        Err(SecurityError::CsrfMismatch)
    );
    // Catch prefix/truncated comparisons, including the last digest byte.
    for index in [0, 15, 31] {
        let mut wrong = BINDING;
        wrong[index] ^= 1;
        assert_eq!(
            verify_csrf(&csrf_headers(TOKEN), &CsrfBinding::from_bytes(wrong)),
            Err(SecurityError::CsrfMismatch)
        );
    }
}

#[test]
fn csrf_rejects_duplicate_headers_even_when_values_are_identical() {
    for second in [TOKEN, OTHER_TOKEN] {
        let mut headers = csrf_headers(TOKEN);
        headers.append("x-apex-csrf", HeaderValue::from_str(second).unwrap());
        assert_eq!(
            verify_csrf(&headers, &CsrfBinding::from_bytes(BINDING)),
            Err(SecurityError::InvalidCsrf)
        );
    }
}

#[test]
fn csrf_rejects_noncanonical_coalesced_and_oversized_headers() {
    let binding = CsrfBinding::from_bytes(BINDING);
    for malformed in [
        String::new(),
        "a".repeat(42),
        "a".repeat(44),
        "a".repeat(8193),
        format!("{TOKEN}="),
        format!("{TOKEN},{TOKEN}"),
        format!("{TOKEN}, {OTHER_TOKEN}"),
        format!("{TOKEN} {OTHER_TOKEN}"),
        format!(" {TOKEN}"),
        format!("{TOKEN}\t"),
        format!("\"{TOKEN}\""),
        format!("{}B", &OTHER_TOKEN[..42]),
        format!("{}+", &TOKEN[..42]),
    ] {
        assert_eq!(
            verify_csrf(&csrf_headers(&malformed), &binding),
            Err(SecurityError::InvalidCsrf)
        );
        assert_eq!(
            CsrfToken::parse(&malformed).unwrap_err(),
            SecurityError::InvalidToken
        );
    }
    let mut non_ascii = HeaderMap::new();
    non_ascii.insert("x-apex-csrf", HeaderValue::from_bytes(&[0x80; 43]).unwrap());
    assert_eq!(
        verify_csrf(&non_ascii, &binding),
        Err(SecurityError::InvalidCsrf)
    );
}

#[test]
fn csrf_does_not_use_cookie_or_authorization_header_as_token_source() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "cookie",
        HeaderValue::from_str(&format!("x-apex-csrf={TOKEN}")).unwrap(),
    );
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {TOKEN}")).unwrap(),
    );
    assert_eq!(
        verify_csrf(&headers, &CsrfBinding::from_bytes(BINDING)),
        Err(SecurityError::MissingCsrf)
    );
}

#[test]
fn generated_csrf_tokens_are_independent_and_debug_is_redacted() {
    let first = CsrfToken::generate().unwrap();
    let second = CsrfToken::generate().unwrap();
    assert_ne!(first.expose_secret(), second.expose_secret());
    assert_eq!(
        URL_SAFE_NO_PAD.decode(first.expose_secret()).unwrap().len(),
        32
    );
    assert_eq!(
        verify_csrf(&csrf_headers(first.expose_secret()), &first.binding()),
        Ok(())
    );
    assert_eq!(
        verify_csrf(&csrf_headers(first.expose_secret()), &second.binding()),
        Err(SecurityError::CsrfMismatch)
    );
    assert!(!format!("{first:?}").contains(first.expose_secret()));
    let known = CsrfToken::parse(TOKEN).unwrap();
    let debug = format!("{known:#?} {:?}", known.binding());
    assert!(!debug.contains(TOKEN));
    assert!(!debug.contains("ea866a757e4c38ba"));
    assert!(!debug.contains("234, 134, 106, 117"));
}
