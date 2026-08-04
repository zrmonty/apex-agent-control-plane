use serde_json::Value;

use super::convert::prost_struct_to_json;
use super::identifiers::is_scope_identifier;
use crate::{GatewayError, GatewayErrorCode};

pub(crate) const MAX_CONTROL_BUDGET_LIMIT: f64 = 1_000_000_000_000_000.0;

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
        "stop" | "pause" | "resume" | "inject" | "set_budget"
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
        _ => unreachable!("control action was checked against the supported action set"),
    }
    Ok(())
}
