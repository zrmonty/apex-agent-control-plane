use super::*;

// Sign the exact raw bytes so duplicate and malformed JSON cases reach the
// verifier with real RSA signatures, not merely invalid signature fixtures.
fn signed_raw(header: &str, payload: &str) -> String {
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = jsonwebtoken::crypto::sign(
        message.as_bytes(),
        &signing_key(),
        jsonwebtoken::Algorithm::RS256,
    )
    .expect("raw RSA fixture must sign");
    format!("{message}.{signature}")
}

fn check_raw(header: &str, payload: &str) -> Result<VerifiedLogin, BrowserError> {
    verifier().verify(
        &signed_raw(header, payload),
        ACCESS,
        IdTokenExpectation::Login { nonce: NONCE },
    )
}

fn raw_header() -> String {
    serde_json::to_string(&header()).unwrap()
}

fn prepend_member(object: &str, member: &str) -> String {
    format!(
        "{{{member},{}",
        object.strip_prefix('{').expect("fixture JSON object")
    )
}

#[test]
fn raw_rsa_fixture_and_trailing_json_whitespace_are_valid() {
    let payload = serde_json::to_string(&claims()).unwrap();
    assert!(check_raw(&raw_header(), &payload).is_ok());
    assert!(
        check_raw(
            &format!("{} \r\n\t", raw_header()),
            &format!("{payload} \r\n\t")
        )
        .is_ok()
    );
}

#[test]
fn signed_duplicate_jose_members_are_rejected_including_null_first_and_escapes() {
    let payload = serde_json::to_string(&claims()).unwrap();
    for member in [
        r#""alg":null"#,
        r#""\u0061lg":null"#,
        r#""kid":null"#,
        r#""\u006bid":null"#,
        r#""typ":null"#,
    ] {
        let raw = prepend_member(&raw_header(), member);
        assert_eq!(
            check_raw(&raw, &payload).unwrap_err(),
            BrowserError::Unauthenticated,
            "{member}"
        );
    }
}

#[test]
fn signed_duplicate_claims_and_nested_duplicate_members_are_rejected() {
    let mut value = claims();
    value["nbf"] = json!(value["iat"].as_i64().unwrap() - 60);
    let payload = serde_json::to_string(&value).unwrap();
    assert!(check_raw(&raw_header(), &payload).is_ok());
    for member in [
        r#""iss":null"#,
        r#""\u0069ss":null"#,
        r#""sub":null"#,
        r#""aud":null"#,
        r#""iat":null"#,
        r#""exp":null"#,
        r#""nbf":null"#,
        r#""nonce":null"#,
        r#""at_hash":null"#,
        r#""extra":{"x":null,"\u0078":1}"#,
    ] {
        let raw = prepend_member(&payload, member);
        assert_eq!(
            check_raw(&raw_header(), &raw).unwrap_err(),
            BrowserError::Unauthenticated,
            "{member}"
        );
    }
}

#[test]
fn signed_malformed_json_or_a_second_json_value_is_rejected() {
    let payload = serde_json::to_string(&claims()).unwrap();
    for malformed in ["null", "[]", "{", "{\"iss\":}"] {
        assert_eq!(
            check_raw(&raw_header(), malformed).unwrap_err(),
            BrowserError::Unauthenticated
        );
        assert_eq!(
            check_raw(malformed, &payload).unwrap_err(),
            BrowserError::Unauthenticated
        );
    }
    assert_eq!(
        check_raw(&raw_header(), &format!("{payload} {{}}")).unwrap_err(),
        BrowserError::Unauthenticated
    );
    assert_eq!(
        check_raw(&format!("{} {{}}", raw_header()), &payload).unwrap_err(),
        BrowserError::Unauthenticated
    );
}

#[test]
fn jose_extensions_cannot_introduce_keys_urls_or_critical_processing() {
    let payload = serde_json::to_string(&claims()).unwrap();
    for (name, extension) in [
        ("jku", json!("https://attacker.invalid/jwks")),
        (
            "jwk",
            serde_json::to_value(jwks()).unwrap()["keys"][0].clone(),
        ),
        ("x5u", json!("https://attacker.invalid/cert")),
        ("crit", json!(["b64"])),
        ("b64", json!(false)),
    ] {
        let mut jose = serde_json::to_value(header()).unwrap();
        jose[name] = extension;
        assert_eq!(
            check_raw(&serde_json::to_string(&jose).unwrap(), &payload).unwrap_err(),
            BrowserError::Unauthenticated,
            "{name}"
        );
    }
}

#[test]
fn jose_required_fields_and_present_type_must_be_well_typed() {
    let payload = serde_json::to_string(&claims()).unwrap();
    for field in ["alg", "kid", "typ"] {
        for malformed in [json!(null), json!(1), json!(true), json!([]), json!({})] {
            let mut jose = serde_json::to_value(header()).unwrap();
            jose[field] = malformed;
            assert_eq!(
                check_raw(&serde_json::to_string(&jose).unwrap(), &payload).unwrap_err(),
                BrowserError::Unauthenticated,
                "{field}"
            );
        }
    }
    let mut jose = serde_json::to_value(header()).unwrap();
    jose.as_object_mut().unwrap().remove("typ");
    assert!(check_raw(&serde_json::to_string(&jose).unwrap(), &payload).is_ok());
    for field in ["alg", "kid"] {
        let mut jose = serde_json::to_value(header()).unwrap();
        jose.as_object_mut().unwrap().remove(field);
        assert_eq!(
            check_raw(&serde_json::to_string(&jose).unwrap(), &payload).unwrap_err(),
            BrowserError::Unauthenticated
        );
    }
}

#[test]
fn other_real_rsa_algorithms_and_advertised_none_are_rejected() {
    for algorithm in [
        jsonwebtoken::Algorithm::RS384,
        jsonwebtoken::Algorithm::PS256,
    ] {
        let mut jose = header();
        jose.alg = algorithm;
        let token = sign(&jose, &claims(), &signing_key());
        assert_eq!(
            verifier()
                .verify(&token, ACCESS, IdTokenExpectation::Login { nonce: NONCE })
                .unwrap_err(),
            BrowserError::Unauthenticated
        );
    }
    let mut jose = serde_json::to_value(header()).unwrap();
    jose["alg"] = json!("none");
    assert_eq!(
        check_raw(
            &serde_json::to_string(&jose).unwrap(),
            &serde_json::to_string(&claims()).unwrap()
        )
        .unwrap_err(),
        BrowserError::Unauthenticated
    );
}
