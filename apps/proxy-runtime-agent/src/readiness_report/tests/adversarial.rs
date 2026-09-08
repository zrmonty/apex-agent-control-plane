use super::{decode_health_stdout, fixture};
use serde_json::{Value, json};
use std::error::Error;

fn value() -> Value {
    serde_json::to_value(fixture::report(&fixture::launch())).unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn refuses(bytes: &[u8]) {
    let error = decode_health_stdout(bytes, &fixture::launch()).unwrap_err();
    assert_eq!(format!("{error}"), "readiness report rejected");
    assert_eq!(format!("{error:?}"), "ReadinessReportError");
    assert!(error.source().is_none());
}

#[test]
fn rejects_nonstring_enum_representations_including_externally_tagged_objects() {
    for (field, name) in [
        ("id", "READINESS_CHECK_ID_CONFIG"),
        ("status", "READINESS_CHECK_STATUS_PASS"),
        ("reason", "READINESS_REASON_OK"),
    ] {
        for invalid in [
            json!(1),
            json!(null),
            json!(true),
            json!([name]),
            json!({name: null}),
        ] {
            let mut input = value();
            input["checks"][0][field] = invalid;
            refuses(&bytes(&input));
        }
    }
}

#[test]
fn rejects_duplicate_escaped_duplicate_alias_unknown_and_missing_fields_at_every_record() {
    for pointer in ["", "/target", "/checks/0", "/stages/0"] {
        let original = value();
        for (key, field_value) in original.pointer(pointer).unwrap().as_object().unwrap() {
            let needle = format!("{}:{}", serde_json::to_string(key).unwrap(), field_value);
            let text = String::from_utf8(bytes(&original)).unwrap();
            assert!(text.contains(&needle));
            refuses(
                text.replacen(&needle, &format!("{needle},{needle}"), 1)
                    .as_bytes(),
            );
            let escaped = format!(
                "\"\\u{:04x}{}\":{}",
                key.as_bytes()[0],
                &key[1..],
                field_value
            );
            refuses(
                text.replacen(&needle, &format!("{escaped},{needle}"), 1)
                    .as_bytes(),
            );
            let mut input = original.clone();
            input
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            refuses(&bytes(&input));
            let alias: String = key
                .chars()
                .flat_map(|c| {
                    if c.is_ascii_uppercase() {
                        vec!['_', c.to_ascii_lowercase()]
                    } else {
                        vec![c]
                    }
                })
                .collect();
            if alias != *key {
                let mut input = original.clone();
                input
                    .pointer_mut(pointer)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert(alias.clone(), field_value.clone());
                refuses(&bytes(&input));
                input
                    .pointer_mut(pointer)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(key);
                refuses(&bytes(&input));
            }
        }
        let mut input = original;
        input
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "REPORT_CANARY_diagnostic".into(),
                json!("REPORT_CANARY-secret://token"),
            );
        refuses(&bytes(&input));
    }
}

#[test]
fn rejects_nulls_wrong_scalar_types_and_positional_records() {
    for pointer in ["", "/target", "/checks/0", "/stages/0"] {
        let original = value();
        for key in original
            .pointer(pointer)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
        {
            for bad in [json!(null), json!([]), json!({})] {
                let mut input = original.clone();
                input.pointer_mut(pointer).unwrap()[key] = bad;
                refuses(&bytes(&input));
            }
        }
        let mut input = original.clone();
        *input.pointer_mut(pointer).unwrap() = json!(
            original
                .pointer(pointer)
                .unwrap()
                .as_object()
                .unwrap()
                .values()
                .collect::<Vec<_>>()
        );
        refuses(&bytes(&input));
    }
    for field in ["live", "ready"] {
        for bad in [json!(false), json!(0), json!(1), json!("true")] {
            let mut input = value();
            input[field] = bad;
            refuses(&bytes(&input));
        }
    }
}

#[test]
fn rejects_noncanonical_and_overflowing_uint64s_in_every_numeric_field() {
    for pointer in [
        "/target/generation",
        "/target/fencingToken",
        "/observedAtUnixUs",
        "/stages/0/startedAtUnixUs",
        "/stages/0/durationUs",
        "/stages/0/durationNs",
        "/stages/0/clockResolutionNs",
        "/stages/0/clockUncertaintyUs",
    ] {
        for invalid in [
            json!(0),
            json!(1),
            json!(-1),
            json!(1.5),
            json!(null),
            json!(""),
            json!("01"),
            json!("+1"),
            json!("-0"),
            json!("-1"),
            json!("1.0"),
            json!("1e3"),
            json!(" 1"),
            json!("1 "),
            json!("١"),
            json!("18446744073709551616"),
        ] {
            let mut input = value();
            input["stages"][0]["clockUncertaintyUs"] = json!("0");
            *input.pointer_mut(pointer).unwrap() = invalid;
            refuses(&bytes(&input));
        }
    }
}

#[test]
fn rejects_nonready_incomplete_duplicate_and_unknown_checks_and_stages() {
    for field in ["checks", "stages"] {
        for count in [0, 8, 10, 16] {
            let mut input = value();
            let entry = input[field][0].clone();
            input[field].as_array_mut().unwrap().resize(count, entry);
            refuses(&bytes(&input));
        }
        let mut input = value();
        input[field][1] = input[field][0].clone();
        refuses(&bytes(&input));
    }
    for (field, invalid) in [
        ("id", "READINESS_CHECK_ID_UNSPECIFIED"),
        ("id", "REPORT_CANARY"),
        ("status", "READINESS_CHECK_STATUS_PENDING"),
        ("status", "READINESS_CHECK_STATUS_FAIL"),
        ("status", "READINESS_CHECK_STATUS_UNSPECIFIED"),
        ("status", "REPORT_CANARY"),
        ("reason", "READINESS_REASON_UNSPECIFIED"),
        ("reason", "READINESS_REASON_UNAVAILABLE"),
        ("reason", "READINESS_REASON_TIMEOUT"),
        ("reason", "REPORT_CANARY"),
    ] {
        for index in 0..9 {
            let mut input = value();
            input["checks"][index][field] = json!(invalid);
            refuses(&bytes(&input));
        }
    }
    let mut input = value();
    input["observedAtUnixUs"] = json!("0");
    refuses(&bytes(&input));
}

#[test]
fn rejects_malformed_timing_for_each_of_the_nine_stages() {
    for index in 0..9 {
        for (field, invalid) in [
            ("name", json!("REPORT_CANARY")),
            ("processInstanceId", json!("REPORT_CANARY")),
            ("startedAtUnixUs", json!("0")),
            ("clockResolutionNs", json!("0")),
            ("durationUs", json!("8")),
            ("durationNs", json!("8000")),
            ("clockSource", json!("")),
            ("clockSource", json!("x".repeat(129))),
            ("clockSource", json!(" padding")),
            ("clockSource", json!("padding ")),
            ("clockSource", json!("REPORT_CANARY\n")),
            ("clockSource", json!("REPORT_CANARY\u{7f}")),
            ("clockSource", json!("REPORT_CANARYé")),
        ] {
            let mut input = value();
            input["stages"][index][field] = invalid;
            refuses(&bytes(&input));
        }
        for field in ["otelTraceId", "spanId", "parentSpanId"] {
            for invalid in [json!(""), json!("REPORT_CANARY"), json!(null)] {
                let mut input = value();
                input["stages"][index][field] = invalid;
                refuses(&bytes(&input));
            }
        }
    }
}

#[test]
fn rejects_null_and_duplicate_optional_values_but_preserves_zero() {
    let mut input = value();
    input["stages"][0]["clockUncertaintyUs"] = json!("0");
    let text = String::from_utf8(bytes(&input)).unwrap();
    let needle = "\"clockUncertaintyUs\":\"0\"";
    for duplicate in [
        needle,
        "\"clockUncertaintyUs\":null",
        "\"clock_uncertainty_us\":\"0\"",
    ] {
        refuses(
            text.replacen(needle, &format!("{duplicate},{needle}"), 1)
                .as_bytes(),
        );
    }
    input["stages"][0]["clockUncertaintyUs"] = Value::Null;
    refuses(&bytes(&input));
}

#[test]
fn bounds_original_utf8_and_requires_exact_single_line_framing() {
    let original = bytes(&value());
    let text = std::str::from_utf8(&original).unwrap();
    for bad in [
        text.trim_end().to_owned(),
        format!("{text}\n"),
        format!("{text}{{}}"),
        format!("prefix{text}"),
        format!(" {text}"),
        text.replace("}\n", "} \n"),
        text.replace('\n', "\r\n"),
        text.replacen('{', "{\n", 1),
        text.replacen('{', "{\r", 1),
        format!("\u{feff}{text}"),
        format!("{}[]\n", text.trim_end()),
    ] {
        refuses(bad.as_bytes());
    }
    for bad in [vec![], vec![b'\n'], vec![b'{', 0xff, b'}', b'\n']] {
        refuses(&bad);
    }
    let padded = text.replacen('{', &format!("{{{}", " ".repeat(8193 - original.len())), 1);
    assert_eq!(padded.len(), 8193);
    assert!(decode_health_stdout(padded.as_bytes(), &fixture::launch()).is_ok());
    refuses(padded.replacen('{', "{ ", 1).as_bytes());
    let deep = format!("{{\"checks\":{}0{}}}\n", "[".repeat(150), "]".repeat(150));
    refuses(deep.as_bytes());
}

#[test]
fn successful_wrapper_debug_is_static_even_for_printable_clock_canaries() {
    let mut input = value();
    input["stages"][0]["clockSource"] = json!("REPORT_CANARY");
    let decoded = decode_health_stdout(&bytes(&input), &fixture::launch()).unwrap();
    assert_eq!(
        format!("{decoded:?}"),
        "HealthReport { [redacted; data only] }"
    );
}
