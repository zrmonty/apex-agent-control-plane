use super::*;
use serde_json::json;

fn value() -> serde_json::Value {
    json!({"schema_version":1,"installation_id":"0191b7f1-7f2c-7c13-9a61-2f29f2be1001","worker_id":"controller-a",
        "endpoint":"https://runtime.example:8443","server_name":"runtime.example","ca_file":"ca.pem","client_cert_file":"client.pem",
        "client_key_file":"client.key","scopes":[{"workspace_id":"workspace","namespace_id":"namespace"}]})
}
#[test]
fn deployment_transport_accepts_only_exact_bounded_document() {
    let encoded = serde_json::to_vec(&value()).unwrap();
    assert!(parse(&encoded).is_ok());
    let mut duplicate = String::from_utf8(encoded).unwrap();
    duplicate.insert_str(1, "\"schema_version\":1,");
    assert!(parse(duplicate.as_bytes()).is_err());
    for (key, invalid) in [
        ("schema_version", json!(0)),
        ("endpoint", json!("http://runtime.example")),
        ("endpoint", json!("https://user:password@runtime.example")),
        ("endpoint", json!("https://runtime.example/path")),
        ("endpoint", json!("https://runtime.example/?x=1")),
        ("server_name", json!("runtime.example/other")),
        ("worker_id", json!("a".repeat(129))),
        ("scopes", json!([])),
        (
            "scopes",
            json!([{"workspace_id":"workspace","namespace_id":"namespace","unknown":true}]),
        ),
        (
            "scopes",
            json!([{"workspace_id":"workspace","namespace_id":"namespace"},{"workspace_id":"workspace","namespace_id":"namespace"}]),
        ),
        ("arbitrary_timeout", json!(600)),
    ] {
        let mut changed = value();
        changed[key] = invalid;
        assert!(
            parse(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "must reject {key}"
        );
    }
    assert!(parse(&vec![b' '; 65537]).is_err());
}
