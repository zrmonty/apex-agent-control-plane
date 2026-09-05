use super::*;
use crate::proto;
use axum::http::{HeaderValue, header};

const ROOT: &str = "/api/apex/v1/McpProxyService/";
const ID: &str = "0199082a-9800-7000-8000-000000000001";

fn json_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers
}

#[test]
fn rust_dispatch_matches_generated_browser_allowlist_exactly() {
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../packages/apex-contracts-ts/src/gen/browser-rpcs.json"
    ))
    .unwrap();
    let actual = serde_json::to_value(descriptors()).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(descriptors().len(), 22);
}

#[test]
fn every_approved_method_has_a_typed_decode_branch() {
    // Flat old methods versus nested-scope additive methods. Only mutation
    // schemas declare request_id; required UUID validation remains generated.
    for entry in serde_json::from_str::<Vec<serde_json::Value>>(include_str!(
        "../../../../../packages/apex-contracts-ts/src/gen/browser-rpcs.json"
    ))
    .unwrap()
    {
        let method = entry["method"].as_str().unwrap();
        let mutation = !method.starts_with("Get") && !method.starts_with("List");
        let body = if mutation {
            format!(r#"{{"requestId":"{ID}"}}"#)
        } else {
            "{}".to_owned()
        };
        let decoded = ManagementRequest::decode(
            entry["path"].as_str().unwrap(),
            &json_headers(),
            body.as_bytes(),
        )
        .unwrap_or_else(|err| panic!("{method}: {err}"));
        assert_eq!(serde_json::to_value(decoded.descriptor()).unwrap(), entry);
    }
}

#[test]
fn paths_are_literal_no_service_escape_decoding_or_aliases() {
    for path in [
        "/api/apex/v1/ControlGateway/SubmitCommand",
        "/api/apex/v1/GovernanceGateway/Evaluate",
        "/api/apex/v1/ProxyRuntimeAgent/EnsureRuntime",
        "/api/apex/v1/McpProxyService/create_proxy",
        "/api/apex/v1/McpProxyService/GetProxy/",
        "/api/apex/v1/McpProxyService/%47etProxy",
        "/api/apex/v1/McpProxyService/GetProxy?other=1",
        "/api/apex/v1/McpProxyService//GetProxy",
        "/apex.v1.McpProxyService/GetProxy",
    ] {
        assert!(
            matches!(
                ManagementRequest::decode(path, &json_headers(), b"{}"),
                Err(BrowserError::NotFound)
            ),
            "{path}"
        );
    }
}

#[test]
fn only_one_json_content_type_and_no_content_encoding_is_accepted() {
    for content_type in [
        "application/json",
        "application/json; charset=utf-8",
        "Application/JSON; Charset=UTF-8",
    ] {
        let mut headers = json_headers();
        headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
        assert!(ManagementRequest::decode(&format!("{ROOT}GetProxy"), &headers, b"{}").is_ok());
    }
    for content_type in [
        None,
        Some("text/plain"),
        Some("application/grpc"),
        Some("application/json; charset=iso-8859-1"),
        Some("application/json, application/json"),
        Some("application/json; x=1"),
    ] {
        let mut headers = HeaderMap::new();
        if let Some(value) = content_type {
            headers.insert(header::CONTENT_TYPE, value.parse().unwrap());
        }
        assert!(matches!(
            ManagementRequest::decode(&format!("{ROOT}GetProxy"), &headers, b"{}"),
            Err(BrowserError::UnsupportedMediaType)
        ));
    }
    let mut headers = json_headers();
    headers.append(header::CONTENT_TYPE, "application/json".parse().unwrap());
    assert!(matches!(
        ManagementRequest::decode(&format!("{ROOT}GetProxy"), &headers, b"{}"),
        Err(BrowserError::UnsupportedMediaType)
    ));
    let mut headers = json_headers();
    headers.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
    assert!(matches!(
        ManagementRequest::decode(&format!("{ROOT}GetProxy"), &headers, b"{}"),
        Err(BrowserError::UnsupportedMediaType)
    ));
}

#[test]
fn request_body_ceiling_and_strict_json_apply_before_forwarding() {
    let mut exact = vec![b' '; MAX_RPC_JSON_BYTES];
    exact[..2].copy_from_slice(b"{}");
    assert!(ManagementRequest::decode(&format!("{ROOT}GetProxy"), &json_headers(), &exact).is_ok());
    exact.push(b' ');
    assert!(matches!(
        ManagementRequest::decode(&format!("{ROOT}GetProxy"), &json_headers(), &exact),
        Err(BrowserError::PayloadTooLarge)
    ));
    for body in [
        r#"{"workspaceId":"a","workspaceId":"b"}"#,
        r#"{"workspaceId":"a","workspace_id":"a"}"#,
        r#"{"authorization":"Bearer attacker"}"#,
        r#"{"unknown":null}"#,
        r#"{"workspaceId": 1}"#,
        "null",
        "[]",
        "{} {}",
        "{",
    ] {
        assert!(
            matches!(
                ManagementRequest::decode(
                    &format!("{ROOT}GetProxy"),
                    &json_headers(),
                    body.as_bytes()
                ),
                Err(BrowserError::InvalidRequest)
            ),
            "{body}"
        );
    }
}

#[test]
fn mutation_uuid_is_not_fabricated_or_coerced() {
    for body in [
        "{}".to_owned(),
        r#"{"requestId":""}"#.to_owned(),
        r#"{"requestId":"11111111-2222-4333-8444-555555555555"}"#.to_owned(),
        format!(r#"{{"requestId":"{}"}}"#, ID.to_uppercase()),
    ] {
        // The fixture contains hex a/b so uppercase is observably noncanonical.
        assert!(matches!(
            ManagementRequest::decode(
                &format!("{ROOT}CreateProxy"),
                &json_headers(),
                body.as_bytes()
            ),
            Err(BrowserError::InvalidRequest)
        ));
    }
}

#[test]
fn decoded_request_debug_never_echoes_configuration() {
    let request = ManagementRequest::decode(
        &format!("{ROOT}CreateProxy"),
        &json_headers(),
        format!(r#"{{"requestId":"{ID}","displayName":"private-marker"}}"#).as_bytes(),
    )
    .unwrap();
    assert!(!format!("{request:?}").contains("private-marker"));
}

#[test]
fn generated_response_preserves_microseconds_above_javascript_safe_range() {
    let response = proto::GetProxyCapabilitiesResponse {
        supported: vec![],
        observed_at_unix_us: 9_007_199_254_740_993,
        contract_version: "v1".to_owned(),
    };
    let bytes = encode_response(&response).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["observedAtUnixUs"], "9007199254740993");
}

#[test]
fn response_serialization_bounds_bytes_without_truncating_success() {
    let exact = "x".repeat(MAX_RPC_RESPONSE_BYTES - 2);
    assert_eq!(
        encode_response(&exact).unwrap().len(),
        MAX_RPC_RESPONSE_BYTES
    );
    let too_big = "x".repeat(MAX_RPC_RESPONSE_BYTES - 1);
    assert_eq!(encode_response(&too_big), Err(BrowserError::Unavailable));
    // Escaping can increase JSON size relative to the protobuf/string size.
    assert_eq!(
        encode_response(&"\u{0001}".repeat(MAX_RPC_RESPONSE_BYTES / 3)),
        Err(BrowserError::Unavailable)
    );
}
