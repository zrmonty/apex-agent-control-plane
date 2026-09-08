use super::*;

mod concurrency;
mod hooks;
mod limits;
mod ownership;
mod real_command;
pub(super) mod spawning;

#[test]
fn network_inspection_batch_requires_exact_complete_unique_ids() {
    let ids = vec!["a".repeat(64), "b".repeat(64)];
    let bytes = serde_json::to_vec(&serde_json::json!([
        {"Id": ids[0], "Name": "one"}, {"Id": ids[1], "Name": "two"}
    ]))
    .unwrap();
    let result = split(&bytes, &ids).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].0, ids[0]);
    assert_eq!(
        inspect::Json::parse(&result[1].1).unwrap().0[0]["Name"],
        "two"
    );
    for invalid in [
        serde_json::json!([]),
        serde_json::json!([{"Id": ids[0]}]),
        serde_json::json!([{"Id": ids[0]}, {"Id": ids[0]}]),
        serde_json::json!([{"Id": ids[0]}, {"Id": "c".repeat(64)}]),
        serde_json::json!([{"Id": ids[1]}, {"Id": ids[0]}]),
        serde_json::json!({"Id": ids[0]}),
    ] {
        assert!(split(&serde_json::to_vec(&invalid).unwrap(), &ids).is_err());
    }
}

#[test]
fn network_inspection_batch_preserves_duplicate_and_size_rejection() {
    let id = "a".repeat(64);
    let duplicate = format!(r#"[{{"Id":"{id}","nested":{{"x":1,"x":2}}}}]"#);
    assert!(split(duplicate.as_bytes(), std::slice::from_ref(&id)).is_err());
    assert!(split(&vec![b' '; 262_145], std::slice::from_ref(&id)).is_err());
    assert!(split(b"[]", &[]).is_err());
    assert!(split(b"[]", &vec![id; BATCH + 1]).is_err());
}
