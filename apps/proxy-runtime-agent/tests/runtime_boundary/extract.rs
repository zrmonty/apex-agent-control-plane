use super::support::*;
use apex_proxy_runtime_agent::parse_inspect_id;

#[test]
fn plan_toy_id_is_extractable_but_not_a_production_identity_claim() {
    assert_eq!(
        parse_inspect_id(r#"[{"Id":"sha256:abc"}]"#),
        Ok("sha256:abc".into())
    );
}

#[test]
fn realistic_inspect_extracts_only_id_not_the_complete_json_or_secrets() {
    let input = document();
    assert!(input.len() > 128 && input.contains(CANARY));
    let id = parse_inspect_id(&input).expect("single inspect element");
    assert_eq!(id, "a".repeat(64));
    assert!(!id.contains(CANARY) && !id.contains('{') && !id.contains('['));
}

#[test]
fn extraction_rejects_missing_empty_multiple_malformed_and_wrong_typed_ids() {
    for input in [
        "",
        " ",
        "[]",
        "{}",
        "null",
        r#"{"Id":"a"}"#,
        "[null]",
        r#"["Id"]"#,
        "[{}]",
        r#"[{"Id":""}]"#,
        r#"[{"Id":null}]"#,
        r#"[{"Id":1}]"#,
        r#"[{"Id":true}]"#,
        r#"[{"Id":[]}]"#,
        r#"[{"Id":"a"},{"Id":"b"}]"#,
        r#"[{"Id":"a"}]{}"#,
        r#"[{"Id":"a"}]CANARY"#,
        r#"[{"id":"a"}]"#,
        r#"[{"Id":"a",}]"#,
        r#"[{"Id":"\uD800"}]"#,
    ] {
        assert!(parse_inspect_id(input).is_err());
    }
}

#[test]
fn extraction_rejects_duplicate_id_even_identical_or_escaped_key() {
    for input in [
        r#"[{"Id":"a","Id":"a"}]"#,
        r#"[{"Id":"a","Id":"b"}]"#,
        r#"[{"Id":"a","\u0049d":"b"}]"#,
    ] {
        assert!(parse_inspect_id(input).is_err());
    }
}

#[test]
fn extraction_id_and_raw_document_bounds_use_utf8_bytes() {
    let id = "a".repeat(128);
    assert_eq!(parse_inspect_id(&format!(r#"[{{"Id":"{id}"}}]"#)), Ok(id));
    for id in ["a".repeat(129), "é".repeat(65)] {
        assert!(parse_inspect_id(&format!(r#"[{{"Id":"{id}"}}]"#)).is_err());
    }
    let base = r#"[{"Id":"sha256:abc"}]"#;
    let exact = format!("{base}{}", " ".repeat(65_536 - base.len()));
    assert_eq!(parse_inspect_id(&exact), Ok("sha256:abc".into()));
    assert!(parse_inspect_id(&format!("{exact} ")).is_err());
}

#[test]
fn ignored_nesting_is_bounded_even_when_id_is_small() {
    for (arrays, valid) in [(30, true), (31, false), (200, false)] {
        let input = format!(
            r#"[{{"Id":"sha256:abc","Ignored":{}0{}}}]"#,
            "[".repeat(arrays),
            "]".repeat(arrays)
        );
        assert_eq!(parse_inspect_id(&input).is_ok(), valid);
    }
}
