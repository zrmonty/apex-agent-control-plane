use crate::{RuntimeManifestEncodingError, runtime_manifest_hash};
use serde::{Serialize, Serializer, ser::Error as _};
use serde_json::{Value, json};
use std::error::Error as _;

// Independent UTF-8 literal, hashed with Node crypto before implementation.
// Numeric-looking keys remain lexically ordered, not numeric JS key order.
const CANONICAL: &str = r#"{"10":"ten","2":"two","configHash":"control","generation":"9007199254740993","nested":{"a":true,"runtimeManifestHash":"nested","z":2},"ordered":["first","second"],"schemaBody":"{\"z\":1,\"a\":2}","u64Max":"18446744073709551615"}"#;
const EXPECTED: &str = "c9250f238964a595069085aafce099a2f0c751cf92ce5b8c77a75ab403000071";
const CANARY: &str = "PRIVATE_MANIFEST_SERIALIZER_CANARY_7C";

fn fixture() -> Value {
    serde_json::from_str(CANONICAL).expect("independent canonical literal")
}

#[test]
fn literal_canonical_json_has_independent_digest_without_input_mutation() {
    let input = fixture();
    let unchanged = input.clone();
    assert_eq!(runtime_manifest_hash(&input).unwrap(), EXPECTED);
    assert_eq!(input, unchanged);
}

#[test]
fn only_root_selfhash_is_excluded_regardless_of_its_value() {
    for selfhash in [
        json!("old"),
        json!(CANARY),
        Value::Null,
        json!({"ignored": true}),
    ] {
        let mut input = fixture();
        input["runtimeManifestHash"] = selfhash;
        assert_eq!(runtime_manifest_hash(&input).unwrap(), EXPECTED);
    }
}

#[test]
fn control_hash_and_nested_self_named_key_are_retained() {
    for (pointer, expected) in [
        (
            "/configHash",
            "40d9dc50376d24ad0ca60a583a99bc32720d53e219230c37773c23efffeb57da",
        ),
        (
            "/nested/runtimeManifestHash",
            "e377e55a57b54e581ba9eee831708522af75893a5c2fae8706c3cdb1c26bcc82",
        ),
    ] {
        let mut input = fixture();
        *input.pointer_mut(pointer).unwrap() = json!("changed");
        assert_eq!(runtime_manifest_hash(&input).unwrap(), expected);
    }
}

#[test]
fn recursively_reordered_generated_object_fields_have_identical_digest() {
    #[derive(Serialize)]
    struct InnerAz {
        a: u8,
        z: u8,
    }
    #[derive(Serialize)]
    struct InnerZa {
        z: u8,
        a: u8,
    }
    #[derive(Serialize)]
    struct OuterAn {
        a: u8,
        nested: InnerAz,
    }
    #[derive(Serialize)]
    struct OuterNa {
        nested: InnerZa,
        a: u8,
    }

    let forward = OuterAn {
        a: 1,
        nested: InnerAz { a: 2, z: 3 },
    };
    let reverse = OuterNa {
        nested: InnerZa { z: 3, a: 2 },
        a: 1,
    };
    assert_ne!(
        serde_json::to_string(&forward).unwrap(),
        serde_json::to_string(&reverse).unwrap()
    );
    // SHA256 of exactly {"a":1,"nested":{"a":2,"z":3}}, prepared with .NET SHA256.
    let expected = "20c32a247a7d821ebbb6a618abb48a6d7856f6be01742e9e602efa6e611cf0fb";
    assert_eq!(runtime_manifest_hash(&forward).unwrap(), expected);
    assert_eq!(runtime_manifest_hash(&reverse).unwrap(), expected);
}

#[test]
fn array_order_changes_the_known_digest() {
    let mut input = fixture();
    input["ordered"] = json!(["second", "first"]);
    assert_eq!(
        runtime_manifest_hash(&input).unwrap(),
        "2614e066a009cdfbbbdd8a20c82d098c9231d5667338eed3f36e6663b9ad2c57"
    );
}

#[test]
fn schema_body_json_is_opaque_text_not_a_recursively_normalized_object() {
    let input = fixture();
    let mut changed = input.clone();
    changed["schemaBody"] = json!(r#"{"a":2,"z":1}"#);
    assert_eq!(
        serde_json::from_str::<Value>(input["schemaBody"].as_str().unwrap()).unwrap(),
        serde_json::from_str::<Value>(changed["schemaBody"].as_str().unwrap()).unwrap()
    );
    assert_eq!(runtime_manifest_hash(&input).unwrap(), EXPECTED);
    assert_ne!(runtime_manifest_hash(&changed).unwrap(), EXPECTED);
}

#[test]
fn quoted_uint64_values_are_neither_rounded_nor_coerced_to_numbers() {
    let mut input = fixture();
    assert_eq!(input["generation"], "9007199254740993");
    assert_eq!(input["u64Max"], "18446744073709551615");
    assert_eq!(runtime_manifest_hash(&input).unwrap(), EXPECTED);
    input["generation"] = json!("9007199254740992");
    assert_eq!(
        runtime_manifest_hash(&input).unwrap(),
        "1d0337e13163240ef3c779c33a321938380b59d3faf4f1a6f5a99bd6677d39e9"
    );
    let mut numeric = fixture();
    numeric["u64Max"] = json!(u64::MAX);
    assert_ne!(runtime_manifest_hash(&numeric).unwrap(), EXPECTED);
}

#[test]
fn nonobject_and_serializer_errors_are_static_redacted_and_have_no_source() {
    struct FailingSerializer;
    impl Serialize for FailingSerializer {
        fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
            Err(S::Error::custom(CANARY))
        }
    }
    for input in [Value::Null, json!([]), json!(CANARY), json!(true), json!(7)] {
        assert_eq!(
            runtime_manifest_hash(&input),
            Err(RuntimeManifestEncodingError)
        );
    }
    let error = runtime_manifest_hash(&FailingSerializer).unwrap_err();
    assert_eq!(error.to_string(), "Runtime manifest cannot be encoded.");
    assert!(error.source().is_none());
    assert!(!format!("{error:?} {error}").contains(CANARY));
}
