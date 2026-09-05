use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::collections::HashSet;

// Public, deterministic fixtures; these are not provider credentials.
const TOKEN: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const ZERO_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
// SHA-256 of TOKEN's canonical ASCII wire bytes, independently calculated.
const TOKEN_DIGEST: [u8; 32] = [
    0xea, 0x86, 0x6a, 0x75, 0x7e, 0x4c, 0x38, 0xba, 0xbf, 0xa8, 0x12, 0x7c, 0xbe, 0x9a, 0x40, 0x9d,
    0x3e, 0x1f, 0x93, 0xa0, 0x0f, 0xf1, 0x48, 0x8f, 0xf7, 0x35, 0xfc, 0xf9, 0x17, 0xaf, 0xff, 0xd0,
];

#[test]
fn canonical_opaque_tokens_preserve_wire_value_and_hash_canonical_ascii() {
    let token = OpaqueToken::parse(TOKEN).expect("canonical opaque token");
    assert_eq!(token.expose_secret(), TOKEN);
    assert_eq!(token.lookup_digest().as_bytes(), &TOKEN_DIGEST);
    assert_ne!(token.lookup_digest().as_bytes(), &[0; 32]);
}

#[test]
fn opaque_parser_rejects_wrong_lengths_padding_alphabet_and_injection() {
    for malformed in [
        String::new(),
        "a".repeat(42),
        "a".repeat(44),
        "a".repeat(8193),
        format!("{TOKEN}="),
        format!(" {TOKEN}"),
        format!("{TOKEN}\t"),
        format!("\"{TOKEN}\""),
        format!("{TOKEN}; Path=/"),
        format!("{TOKEN}\r\nX-Injected: yes"),
        format!("{}+", &TOKEN[..42]),
        format!("{}/", &TOKEN[..42]),
        format!("{}%", &TOKEN[..42]),
        format!("{}é", &TOKEN[..41]),
    ] {
        assert_eq!(
            OpaqueToken::parse(&malformed).unwrap_err(),
            SecurityError::InvalidToken
        );
    }
}

#[test]
fn opaque_parser_rejects_nonzero_unused_base64_bits() {
    // 32 zero bytes encode as 43 'A's. B/C/D set unused low bits.
    for final_character in ['B', 'C', 'D'] {
        let alias = format!("{}{final_character}", &ZERO_TOKEN[..42]);
        assert_eq!(
            OpaqueToken::parse(&alias).unwrap_err(),
            SecurityError::InvalidToken
        );
    }
    assert!(OpaqueToken::parse(ZERO_TOKEN).is_ok());
}

#[test]
fn generated_opaque_tokens_are_distinct_canonical_32_byte_values() {
    let mut seen = HashSet::new();
    for _ in 0..32 {
        let token = OpaqueToken::generate().expect("OS randomness");
        let wire = token.expose_secret();
        assert_eq!(wire.len(), 43);
        let bytes = URL_SAFE_NO_PAD.decode(wire).expect("URL-safe no padding");
        assert_eq!(bytes.len(), 32);
        assert_eq!(URL_SAFE_NO_PAD.encode(bytes), wire);
        assert!(seen.insert(wire.to_owned()), "reused opaque value");
        assert_eq!(
            OpaqueToken::parse(wire).unwrap().lookup_digest(),
            token.lookup_digest()
        );
    }
    // This catches constant/reused output, not the strength of an RNG.
    // Production generation must use fallible getrandom, never a custom RNG.
}

#[test]
fn token_and_digest_debug_never_disclose_secrets() {
    let token = OpaqueToken::parse(TOKEN).unwrap();
    let digest = token.lookup_digest();
    let restored = LookupDigest::from_bytes(TOKEN_DIGEST);
    assert_eq!(digest, restored);
    for debug in [
        format!("{token:?}"),
        format!("{token:#?}"),
        format!("{digest:?}"),
        format!("{restored:#?}"),
    ] {
        assert!(!debug.contains(TOKEN));
        assert!(!debug.contains("ea866a757e4c38ba"));
        assert!(!debug.contains("234, 134, 106, 117"));
    }
}

#[test]
fn invalid_input_error_has_no_secret_or_underlying_error_chain() {
    use std::error::Error as _;

    let error = OpaqueToken::parse(&format!("{TOKEN}=provider-secret")).unwrap_err();
    assert_eq!(error, SecurityError::InvalidToken);
    assert!(!format!("{error:?} {error}").contains(TOKEN));
    assert!(!format!("{error:?} {error}").contains("provider-secret"));
    assert!(error.source().is_none());
}
