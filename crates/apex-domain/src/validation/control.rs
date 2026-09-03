use serde_json::Value;

use super::convert::prost_struct_to_json;
use super::identifiers::is_scope_identifier;
use crate::{GatewayError, GatewayErrorCode};

pub(crate) const MAX_CONTROL_BUDGET_LIMIT: f64 = 1_000_000_000_000_000.0;

/// Matches `apex_sdk.validation.MAX_HOLD_REASON_BYTES`: the SDK enforces this
/// client-side, and this validator is the server-side copy of that same
/// bound, not a differently-tuned one -- the two must agree on what a client
/// is allowed to send.
const MAX_HOLD_REASON_BYTES: usize = 8 * 1024;

pub(crate) fn validate_control_data(data: &prost_types::Struct) -> Result<(), GatewayError> {
    let value = prost_struct_to_json(data)?;
    let object = value
        .as_object()
        .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure))?;
    let required = ["action", "enforcement", "reason_code", "parameters"];
    if object.len() != required.len() || required.iter().any(|key| !object.contains_key(*key)) {
        return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
    }
    let action = object
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure))?;
    if !matches!(
        action,
        "stop" | "pause" | "resume" | "inject" | "set_budget" | "resolve_hold"
    ) {
        return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
    }
    if object.get("enforcement").and_then(Value::as_str) != Some("cooperative") {
        return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
    }
    if let Some(reason_code) = object.get("reason_code")
        && !reason_code.is_null()
        && !reason_code.as_str().is_some_and(is_scope_identifier)
    {
        return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
    }
    let parameters = object
        .get("parameters")
        .and_then(Value::as_object)
        .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure))?;
    match action {
        "stop" | "pause" | "resume" if parameters.is_empty() => {}
        "stop" | "pause" | "resume" => {
            return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
        }
        "inject"
            if parameters.len() == 2
                && matches!(parameters.get("content").and_then(Value::as_str), Some(content) if !content.is_empty() && content.len() <= 32 * 1024)
                && parameters
                    .get("content_classification")
                    .and_then(Value::as_str)
                    == Some("untrusted") => {}
        "inject" => {
            return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
        }
        "set_budget" => {
            let budget_kind = parameters.get("budget_kind").and_then(Value::as_str);
            let limit = parameters.get("limit").and_then(Value::as_f64);
            if parameters.len() != 2
                || !matches!(budget_kind, Some("tokens" | "cost"))
                || !limit.is_some_and(|value| {
                    value.is_finite() && value > 0.0 && value <= MAX_CONTROL_BUDGET_LIMIT
                })
            {
                return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
            }
        }
        // Mirrors `apex_sdk.validation`'s own `resolve_hold` shape exactly:
        // this server-side check exists precisely because a client-side one
        // is not a boundary, it's a courtesy.
        "resolve_hold" => {
            if parameters.len() != 3 {
                return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
            }
            let hold_token_ok = parameters
                .get("hold_token")
                .and_then(Value::as_str)
                .is_some_and(is_scope_identifier);
            let decision_ok = matches!(
                parameters.get("decision").and_then(Value::as_str),
                Some("approved" | "denied")
            );
            let reason_ok = match parameters.get("reason") {
                None => false,
                Some(Value::Null) => true,
                Some(Value::String(reason)) => {
                    !reason.is_empty() && reason.len() <= MAX_HOLD_REASON_BYTES
                }
                Some(_) => false,
            };
            if !hold_token_ok || !decision_ok || !reason_ok {
                return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
            }
        }
        _ => unreachable!("control action was checked against the supported action set"),
    }
    Ok(())
}


