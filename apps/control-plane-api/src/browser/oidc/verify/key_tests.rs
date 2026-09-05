use super::*;

fn check_keys(raw: &[u8]) -> Result<IdTokenVerifier, BrowserError> {
    IdTokenVerifier::new(&config(), &serde_json::to_vec(&discovery()).unwrap(), raw)
}

#[test]
fn duplicate_jwks_properties_reject_null_first_and_escaped_names() {
    let original = serde_json::to_value(jwks()).unwrap();
    let raw = serde_json::to_string(&original).unwrap();
    assert!(check_keys(raw.as_bytes()).is_ok());
    for name in ["keys", r#"\u006beys"#] {
        let duplicate = format!("{{\"{name}\":null,{}", raw.strip_prefix('{').unwrap());
        assert_eq!(
            check_keys(duplicate.as_bytes()).unwrap_err(),
            BrowserError::Unavailable
        );
    }
    let key = serde_json::to_string(&original["keys"][0]).unwrap();
    for name in ["kid", r#"\u006bid"#, "n", "e"] {
        let duplicate = format!(
            "{{\"keys\":[{{\"{name}\":null,{}]}}",
            key.strip_prefix('{').unwrap()
        );
        assert_eq!(
            check_keys(duplicate.as_bytes()).unwrap_err(),
            BrowserError::Unavailable
        );
    }
}

#[test]
fn private_key_fields_are_rejected_even_when_null() {
    for field in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        let mut value = serde_json::to_value(jwks()).unwrap();
        value["keys"][0][field] = Value::Null;
        assert_eq!(
            check_keys(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            BrowserError::Unavailable,
            "{field}"
        );
    }
}

#[test]
fn present_key_operations_must_be_exactly_one_verify_operation() {
    let mut value = serde_json::to_value(jwks()).unwrap();
    value["keys"][0]["key_ops"] = json!(["verify"]);
    assert!(check_keys(&serde_json::to_vec(&value).unwrap()).is_ok());
    for operations in [
        json!(null),
        json!("verify"),
        json!([]),
        json!(["sign"]),
        json!(["verify", "sign"]),
        json!(["verify", "verify"]),
        json!([null]),
    ] {
        value["keys"][0]["key_ops"] = operations;
        assert_eq!(
            check_keys(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            BrowserError::Unavailable
        );
    }
}

#[test]
fn jwks_document_and_key_count_have_exact_upper_bounds() {
    let mut raw = serde_json::to_vec(&jwks()).unwrap();
    raw.resize(65536, b' ');
    assert!(check_keys(&raw).is_ok());
    raw.push(b' ');
    assert_eq!(check_keys(&raw).unwrap_err(), BrowserError::Unavailable);

    let original = serde_json::to_value(jwks()).unwrap()["keys"][0].clone();
    let mut entries = Vec::new();
    for index in 0..64 {
        let mut key = original.clone();
        key["kid"] = json!(format!("key-{index}"));
        entries.push(key);
    }
    assert!(check_keys(&serde_json::to_vec(&json!({"keys": entries.clone()})).unwrap()).is_ok());
    let mut key = original;
    key["kid"] = json!("key-64");
    entries.push(key);
    assert_eq!(
        check_keys(&serde_json::to_vec(&json!({"keys": entries})).unwrap()).unwrap_err(),
        BrowserError::Unavailable
    );
}

#[test]
fn rsa_integer_encodings_and_exponents_reject_invalid_representations() {
    for (field, bad) in [
        ("n", ""),
        ("n", "AA"),
        ("n", "!bad"),
        ("n", "AQAB="),
        ("e", ""),
        ("e", "AQ"),
        ("e", "Ag"),
        ("e", "AAEAAQ"),
        ("e", "AQAB="),
        ("e", "AQAAAAAAAAAAAQ"),
    ] {
        let mut value = serde_json::to_value(jwks()).unwrap();
        value["keys"][0][field] = json!(bad);
        assert_eq!(
            check_keys(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            BrowserError::Unavailable,
            "{field}: {bad}"
        );
    }
}
