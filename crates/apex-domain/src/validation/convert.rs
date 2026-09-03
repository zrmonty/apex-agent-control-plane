use serde_json::{Map, Number, Value};

use crate::{GatewayError, GatewayErrorCode};

/// Depth zero is the root object; depth 64 is the deepest accepted level.
pub(crate) const MAX_STRUCT_DEPTH: usize = 64;

pub(crate) fn prost_struct_to_json(value: &prost_types::Struct) -> Result<Value, GatewayError> {
    prost_struct_to_json_at_depth(value, 0)
}

pub(crate) fn prost_struct_to_json_at_depth(
    value: &prost_types::Struct,
    depth: usize,
) -> Result<Value, GatewayError> {
    // Reject only once traversal would enter level 65.
    if depth > MAX_STRUCT_DEPTH {
        return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
    }
    let mut object = Map::new();
    for (key, value) in &value.fields {
        object.insert(key.clone(), prost_value_to_json_at_depth(value, depth + 1)?);
    }
    Ok(Value::Object(object))
}

pub(crate) fn prost_value_to_json_at_depth(
    value: &prost_types::Value,
    depth: usize,
) -> Result<Value, GatewayError> {
    if depth > MAX_STRUCT_DEPTH {
        return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
    }
    match value.kind.as_ref() {
        Some(prost_types::value::Kind::NullValue(_)) => Ok(Value::Null),
        Some(prost_types::value::Kind::NumberValue(number)) => Number::from_f64(*number)
            .map(Value::Number)
            .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure)),
        Some(prost_types::value::Kind::StringValue(string)) => Ok(Value::String(string.clone())),
        Some(prost_types::value::Kind::BoolValue(boolean)) => Ok(Value::Bool(*boolean)),
        Some(prost_types::value::Kind::StructValue(object)) => {
            prost_struct_to_json_at_depth(object, depth + 1)
        }
        Some(prost_types::value::Kind::ListValue(list)) => Ok(Value::Array(
            list.values
                .iter()
                .map(|value| prost_value_to_json_at_depth(value, depth + 1))
                .collect::<Result<_, _>>()?,
        )),
        None => Err(GatewayError::new(GatewayErrorCode::InvalidStructure)),
    }
}


