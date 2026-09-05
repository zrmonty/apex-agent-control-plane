//! Catalog selection is a provisioning prerequisite, not a signed-image proof.

use apex_proxy_runtime_agent::image_catalog::{ImageCatalog, ImageCatalogError};
use serde_json::{Value, json};

fn image() -> String {
    format!("ghcr.io/example/gateway@sha256:{}", "a".repeat(64))
}

fn entry() -> Value {
    json!({
        "id": "gateway-v1",
        "image_ref": image(),
        "signing": {
            "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
            "certificate_identity": "https://github.com/example/repo/.github/workflows/release.yml@refs/tags/v1"
        }
    })
}

fn catalog() -> Value {
    json!({"schema_version": 1, "images": [entry()]})
}

fn parse(value: &Value) -> Result<ImageCatalog, ImageCatalogError> {
    ImageCatalog::parse(&serde_json::to_vec(value).unwrap())
}

fn refuses(value: Value) {
    assert_eq!(
        parse(&value).unwrap_err(),
        ImageCatalogError::InvalidCatalog
    );
}

#[test]
fn selects_exact_catalog_id_and_published_digest_without_claiming_signature_verification() {
    let catalog = parse(&catalog()).unwrap();
    let selected = catalog.select("gateway-v1", &image()).unwrap();
    assert_eq!(selected.catalog_id, "gateway-v1");
    assert_eq!(selected.image_ref, image());
    assert_eq!(
        selected.certificate_oidc_issuer,
        "https://token.actions.githubusercontent.com"
    );
    assert_eq!(
        selected.certificate_identity,
        "https://github.com/example/repo/.github/workflows/release.yml@refs/tags/v1"
    );
    assert_eq!(
        catalog.select("other", &image()).unwrap_err(),
        ImageCatalogError::UnknownImage
    );
    assert_eq!(
        catalog
            .select("gateway-v1", &image().replace("aaaa", "bbbb"))
            .unwrap_err(),
        ImageCatalogError::ImageMismatch
    );
}

#[test]
fn two_images_remain_distinct_and_ids_or_references_cannot_be_ambiguous() {
    let mut value = catalog();
    let mut second = entry();
    second["id"] = json!("gateway-v2");
    second["image_ref"] = json!(image().replace("aaaa", "bbbb"));
    value["images"].as_array_mut().unwrap().push(second);
    let parsed = parse(&value).unwrap();
    assert_eq!(
        parsed
            .select(
                "gateway-v2",
                value["images"][1]["image_ref"].as_str().unwrap()
            )
            .unwrap()
            .catalog_id,
        "gateway-v2"
    );
    value["images"][1]["id"] = json!("gateway-v1");
    refuses(value);
    let mut duplicate = catalog();
    let mut second = entry();
    second["id"] = json!("different-id");
    duplicate["images"].as_array_mut().unwrap().push(second);
    refuses(duplicate);
}

#[test]
fn schema_shape_counts_and_unknown_or_duplicate_fields_fail_closed() {
    for version in [json!(0), json!(2), json!("1"), Value::Null] {
        let mut value = catalog();
        value["schema_version"] = version;
        refuses(value);
    }
    for pointer in ["", "/images/0", "/images/0/signing"] {
        let mut value = catalog();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), json!(true));
        refuses(value);
    }
    refuses(json!({"schema_version": 1, "images": []}));
    refuses(json!({"schema_version": 1, "images": vec![entry(); 65]}));
    let raw = serde_json::to_string(&catalog()).unwrap();
    let duplicate = raw.replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    );
    assert_eq!(
        ImageCatalog::parse(duplicate.as_bytes()).unwrap_err(),
        ImageCatalogError::InvalidCatalog
    );
    assert_eq!(
        ImageCatalog::parse(&vec![b' '; 65537]).unwrap_err(),
        ImageCatalogError::InvalidCatalog
    );
}

#[test]
fn exact_catalog_limits_and_nested_duplicate_keys_are_enforced() {
    let entries: Vec<_> = (0..64)
        .map(|index| {
            let mut value = entry();
            value["id"] = json!(format!("gateway-{index}"));
            value["image_ref"] = json!(format!("ghcr.io/example/gateway@sha256:{index:064x}"));
            value
        })
        .collect();
    let mut value = json!({"schema_version": 1, "images": entries});
    let mut padded = serde_json::to_vec(&value).unwrap();
    padded.resize(65_536, b' ');
    let parsed = ImageCatalog::parse(&padded).unwrap();
    assert!(
        parsed
            .select(
                "gateway-63",
                value["images"][63]["image_ref"].as_str().unwrap()
            )
            .is_ok()
    );
    padded.push(b' ');
    assert_eq!(
        ImageCatalog::parse(&padded).unwrap_err(),
        ImageCatalogError::InvalidCatalog
    );
    let mut extra = entry();
    extra["id"] = json!("gateway-64");
    extra["image_ref"] = json!(format!("ghcr.io/example/gateway@sha256:{:064x}", 64));
    value["images"].as_array_mut().unwrap().push(extra);
    refuses(value);
    let raw = serde_json::to_string(&catalog()).unwrap();
    for (from, to) in [
        (
            "\"id\":\"gateway-v1\"",
            "\"id\":\"gateway-v1\",\"\\u0069d\":\"gateway-v1\"",
        ),
        (
            "\"certificate_identity\":",
            "\"certificate_identity\":\"other@example.test\",\"certificate_identity\":",
        ),
    ] {
        let duplicate = raw.replacen(from, to, 1);
        assert_ne!(raw, duplicate);
        assert_eq!(
            ImageCatalog::parse(duplicate.as_bytes()).unwrap_err(),
            ImageCatalogError::InvalidCatalog
        );
    }
}

#[test]
fn positional_arrays_cannot_replace_policy_objects() {
    refuses(json!([1, [entry()]]));
    let mut value = catalog();
    value["images"][0] = json!(["gateway-v1", image(), entry()["signing"]]);
    refuses(value);
    let mut value = catalog();
    value["images"][0]["signing"] = json!([
        "https://token.actions.githubusercontent.com",
        "https://github.com/example/repo/.github/workflows/release.yml@refs/tags/v1"
    ]);
    refuses(value);
}

#[test]
fn tag_credentials_path_flags_and_digest_injection_are_not_images() {
    for invalid in [
        "gateway:latest".into(),
        "ghcr.io/example/gateway:latest".into(),
        image().replace("sha256:", "sha512:"),
        image().replace('a', "A"),
        image().replace("ghcr.io", "user:secret@ghcr.io"),
        image().replace("example", "../example"),
        format!("{} --privileged", image()),
        "file:///run/docker.sock".into(),
    ] {
        let mut value = catalog();
        value["images"][0]["image_ref"] = json!(invalid);
        refuses(value);
    }
    for id in ["", "../gateway", "--flag", "has space", "has\nnewline"] {
        let mut value = catalog();
        value["images"][0]["id"] = json!(id);
        refuses(value);
    }
}

#[test]
fn signing_policy_requires_exact_https_issuer_and_identity_without_bypass_switches() {
    for issuer in [
        "",
        "http://issuer.test",
        "https://user:secret@issuer.test",
        "https://issuer.test?q=x",
        "https://issuer.test#x",
        "https://issuer.test\\escape",
    ] {
        let mut value = catalog();
        value["images"][0]["signing"]["certificate_oidc_issuer"] = json!(issuer);
        refuses(value);
    }
    for identity in ["", "--insecure-ignore-tlog", "secret\nCANARY"] {
        let mut value = catalog();
        value["images"][0]["signing"]["certificate_identity"] = json!(identity);
        refuses(value);
    }
    let mut value = catalog();
    value["images"][0]["signing"]["ignore_tlog"] = json!(true);
    refuses(value);
}

#[test]
fn parse_and_debug_never_echo_secret_canaries() {
    let error = ImageCatalog::parse(b"SECRET_CANARY").unwrap_err();
    assert!(!format!("{error} {error:?}").contains("SECRET_CANARY"));
    let mut value = catalog();
    value["images"][0]["signing"]["certificate_identity"] = json!("SECRET_CANARY@example.test");
    let parsed = parse(&value).unwrap();
    let selected = parsed.select("gateway-v1", &image()).unwrap();
    assert!(!format!("{parsed:?} {selected:?}").contains("SECRET_CANARY"));
}
