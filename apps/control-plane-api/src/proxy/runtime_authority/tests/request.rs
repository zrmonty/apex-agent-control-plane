use std::time::Duration;

use super::super::RuntimeAuthorityError;
use super::super::request::RequestClaims;
use super::support::request;

fn refused(value: &tonic::Request<crate::proto::CheckRuntimeAuthorityRequest>) {
    assert!(matches!(
        RequestClaims::parse(value),
        Err(RuntimeAuthorityError::InvalidRequest)
    ));
}

#[test]
fn valid_generated_request_preserves_all_claims_without_becoming_authority() {
    let value = request();
    let claims = RequestClaims::parse(&value).expect("valid component request");
    assert!(claims.message == *value.get_ref());
    assert_eq!(claims.budget, Duration::from_secs(5));
}

#[test]
fn schema_action_required_target_and_exact_pin_length_refuse_before_admission() {
    for schema in [0, 2, u32::MAX] {
        let mut value = request();
        value.get_mut().schema_version = schema;
        refused(&value);
    }
    for action in [0, 2, -1, i32::MAX] {
        let mut value = request();
        value.get_mut().action = action;
        refused(&value);
    }
    let mut value = request();
    value.get_mut().target = None;
    refused(&value);
    for length in [0, 31, 33, 4097] {
        let mut value = request();
        value.get_mut().observed_controller_certificate_sha256 = vec![0x22; length];
        refused(&value);
    }
}

#[test]
fn all_five_claimed_ids_require_lower_rfc_uuid7() {
    for field in 0..5 {
        for invalid in [
            "",
            "018F3D4A-8B9C-7D0E-8F12-3A4B5C6D7E01",
            "018f3d4a-8b9c-4d0e-8f12-3a4b5c6d7e01",
            "018f3d4a-8b9c-7d0e-0f12-3a4b5c6d7e01",
            "018f3d4a8b9c7d0e8f123a4b5c6d7e01",
        ] {
            let mut value = request();
            let message = value.get_mut();
            match field {
                0 => message.operation_id = invalid.into(),
                1 => message.command_id = invalid.into(),
                2 => message.installation_id = invalid.into(),
                3 => message.target.as_mut().unwrap().proxy_id = invalid.into(),
                _ => message.target.as_mut().unwrap().revision_id = invalid.into(),
            }
            refused(&value);
        }
    }
}

#[test]
fn generation_and_fence_preserve_sql_limit_and_refuse_zero_or_overflow() {
    let limit = u64::try_from(i64::MAX).unwrap();
    for generation in [true, false] {
        let mut value = request();
        let target = value.get_mut().target.as_mut().unwrap();
        if generation {
            target.generation = limit;
        } else {
            target.fencing_token = limit;
        }
        let parsed = RequestClaims::parse(&value).expect("exact SQL upper bound");
        assert!(parsed.message == *value.get_ref());
        for invalid in [0, limit + 1, u64::MAX] {
            let target = value.get_mut().target.as_mut().unwrap();
            if generation {
                target.generation = invalid;
            } else {
                target.fencing_token = invalid;
            }
            refused(&value);
        }
    }
}

#[test]
fn exact_scope_byte_bounds_accept_256_and_refuse_aliases_or_257() {
    for workspace in [true, false] {
        let mut value = request();
        let target = value.get_mut().target.as_mut().unwrap();
        if workspace {
            target.workspace_id = "a".repeat(256);
        } else {
            target.namespace_id = "a".repeat(256);
        }
        assert!(RequestClaims::parse(&value).is_ok());
        for invalid in [
            "".into(),
            " leading".into(),
            "a..b".into(),
            "a/b".into(),
            "é".into(),
            "a".repeat(257),
        ] {
            let target = value.get_mut().target.as_mut().unwrap();
            if workspace {
                target.workspace_id = invalid;
            } else {
                target.namespace_id = invalid;
            }
            refused(&value);
        }
    }
}

#[test]
fn grpc_timeout_units_clamp_to_one_five_second_local_budget() {
    for (text, expected) in [
        ("1n", Duration::from_nanos(1)),
        ("1u", Duration::from_micros(1)),
        ("17m", Duration::from_millis(17)),
        ("2S", Duration::from_secs(2)),
        ("1M", Duration::from_secs(5)),
        ("99999999H", Duration::from_secs(5)),
        ("00000001S", Duration::from_secs(1)),
        ("0n", Duration::ZERO),
    ] {
        let mut value = request();
        value
            .metadata_mut()
            .insert("grpc-timeout", text.parse().unwrap());
        assert_eq!(
            RequestClaims::parse(&value)
                .expect("valid timeout grammar")
                .budget,
            expected
        );
    }
}

#[test]
fn malformed_or_duplicate_grpc_timeouts_do_not_silently_restore_a_longer_budget() {
    for invalid in [
        "",
        "1",
        "1s",
        "1U",
        "-1S",
        "+1S",
        "1.5S",
        " 1S",
        "1S ",
        "123456789n",
    ] {
        let mut value = request();
        value
            .metadata_mut()
            .insert("grpc-timeout", invalid.parse().unwrap());
        refused(&value);
    }
    let mut value = request();
    value
        .metadata_mut()
        .append("grpc-timeout", "1S".parse().unwrap());
    value
        .metadata_mut()
        .append("grpc-timeout", "2S".parse().unwrap());
    refused(&value);
}

#[test]
fn request_debug_excludes_observed_pin_and_untrusted_metadata() {
    let mut value = request();
    value
        .metadata_mut()
        .insert("x-private-canary", "PRIVATE-HEADER-CANARY".parse().unwrap());
    let claims = RequestClaims::parse(&value).expect("metadata is not an identity override");
    let debug = format!("{claims:?}");
    assert!(debug.len() < 128);
    assert!(!debug.contains("PRIVATE-HEADER-CANARY"));
    assert!(!debug.contains(&value.get_ref().installation_id));
    assert!(!debug.contains("34, 34"));
}
