use super::*;

#[test]
fn browser_audience_accepts_only_string_or_singleton_with_optional_matching_azp() {
    for audience in [json!("apex-browser"), json!(["apex-browser"])] {
        let mut value = claims();
        value["aud"] = audience;
        assert!(check(&value).is_ok());
        value["azp"] = json!("apex-browser");
        assert!(check(&value).is_ok());
    }
}

#[test]
fn browser_audience_rejects_extra_repeated_empty_and_malformed_arrays() {
    for audience in [
        json!(["apex-browser", "other"]),
        json!(["other", "apex-browser"]),
        json!(["apex-browser", "apex-browser"]),
        json!([]),
        json!([null]),
        json!(["apex-browser", null]),
        json!(null),
        json!(true),
        json!(1),
        json!({"aud": "apex-browser"}),
    ] {
        let mut value = claims();
        value["aud"] = audience.clone();
        value["azp"] = json!("apex-browser");
        assert_eq!(
            check(&value).unwrap_err(),
            BrowserError::Unauthenticated,
            "{audience}"
        );
    }
}

#[test]
fn present_authorized_party_must_be_nonnull_matching_client_string() {
    for audience in [json!("apex-browser"), json!(["apex-browser"])] {
        for azp in [
            json!(null),
            json!("other"),
            json!(""),
            json!(true),
            json!(1),
            json!([]),
            json!({}),
        ] {
            let mut value = claims();
            value["aud"] = audience.clone();
            value["azp"] = azp.clone();
            assert_eq!(
                check(&value).unwrap_err(),
                BrowserError::Unauthenticated,
                "{azp}"
            );
        }
    }
}

#[test]
fn signed_future_not_before_is_rejected_at_login() {
    let mut value = claims();
    assert!(check(&value).is_ok());
    value["nbf"] = json!(value["iat"].as_i64().unwrap() + 120);
    assert_eq!(check(&value).unwrap_err(), BrowserError::Unauthenticated);
}

#[test]
fn signed_future_not_before_is_rejected_at_refresh_without_returned_nonce() {
    let mut value = claims();
    value.as_object_mut().unwrap().remove("nonce");
    let verifier = verifier();
    let refresh = || IdTokenExpectation::Refresh {
        subject: "subject-123",
        original_nonce: NONCE,
    };
    assert!(verifier.verify(&signed(&value), ACCESS, refresh()).is_ok());
    value["nbf"] = json!(value["iat"].as_i64().unwrap() + 120);
    assert_eq!(
        verifier
            .verify(&signed(&value), ACCESS, refresh())
            .unwrap_err(),
        BrowserError::Unauthenticated
    );
}

#[test]
fn signed_not_before_is_optional_and_past_integer_is_accepted() {
    let mut value = claims();
    assert!(check(&value).is_ok());
    value["nbf"] = json!(value["iat"].as_i64().unwrap() - 60);
    assert!(check(&value).is_ok());
}

fn malformed_numeric_dates() -> Vec<Value> {
    vec![
        json!(null),
        json!(true),
        json!("1788480000"),
        json!(1788480000.0),
        json!(1788480000.5),
        json!([]),
        json!({}),
        json!(9223372036854775808_u64),
        serde_json::from_str("-9223372036854775809").unwrap(),
    ]
}

#[test]
fn signed_not_before_rejects_null_wrong_types_and_out_of_i64_range() {
    for malformed in malformed_numeric_dates() {
        let mut value = claims();
        value["nbf"] = malformed.clone();
        assert_eq!(
            check(&value).unwrap_err(),
            BrowserError::Unauthenticated,
            "{malformed}"
        );
    }
}

#[test]
fn signed_issuance_and_expiration_reject_non_integer_and_out_of_range_values() {
    for field in ["iat", "exp"] {
        for malformed in malformed_numeric_dates() {
            let mut value = claims();
            value[field] = malformed.clone();
            assert_eq!(
                check(&value).unwrap_err(),
                BrowserError::Unauthenticated,
                "{field}: {malformed}"
            );
        }
    }
}

#[test]
fn present_nonce_and_access_hash_cannot_be_null_or_wrong_json_type() {
    for field in ["nonce", "at_hash"] {
        for malformed in [json!(null), json!(false), json!(1), json!([]), json!({})] {
            let mut value = claims();
            value[field] = malformed;
            assert_eq!(
                check(&value).unwrap_err(),
                BrowserError::Unauthenticated,
                "{field}"
            );
        }
    }
}
