//! Schema metadata checks only; executable schema/output enforcement belongs to
//! the gateway and policy authority. No reference fetches or schema rewriting.

use std::collections::BTreeSet;

use serde::{
    Deserialize,
    de::{Error, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};

use super::{
    RuntimeDeploymentBindings, invalid, require,
    validation::{hex_hash, identifier},
};
use crate::proxy::{McpProxyRevision, ProxyError};

pub(super) fn validate(
    revision: &McpProxyRevision,
    b: &RuntimeDeploymentBindings,
) -> Result<(), ProxyError> {
    let exposed: BTreeSet<_> = revision
        .spec
        .exposed_tools
        .iter()
        .map(|t| (t.upstream_id.as_str(), t.tool_name.as_str()))
        .collect();
    require(
        b.tool_schemas.len() == exposed.len()
            && b.tool_schemas.len() <= 256
            && b.approved_output_profiles.len() <= 256,
    )?;
    require(b.approved_output_profiles.iter().all(|p| identifier(p)))?;
    let mut seen = BTreeSet::new();
    for schema in &b.tool_schemas {
        let key = (schema.upstream_id.as_str(), schema.tool_name.as_str());
        require(
            exposed.contains(&key)
                && seen.insert(key)
                && identifier(&schema.output_profile_id)
                && b.approved_output_profiles
                    .contains(&schema.output_profile_id)
                && hex_hash(&schema.schema_hash),
        )?;
        schema_json(&schema.input_schema_json)?;
        schema_json(&schema.output_schema_json)?;
    }
    Ok(())
}

fn schema_json(input: &str) -> Result<(), ProxyError> {
    require(!input.is_empty() && input.len() <= 32_768)?;
    let UniqueJson(value) = serde_json::from_str(input).map_err(|_| invalid())?;
    require(value.is_object() && value.get("type").and_then(Value::as_str) == Some("object"))?;
    bounded(&value, 0, &mut 0)
}

fn bounded(value: &Value, depth: usize, count: &mut usize) -> Result<(), ProxyError> {
    *count += 1;
    require(depth <= 32 && *count <= 2048)?;
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                // References, including local/dynamic references, need the
                // later approved resolver. Reject rather than partially resolve.
                require(!matches!(
                    key.as_str(),
                    "$ref" | "$dynamicRef" | "$recursiveRef" | "$id"
                ))?;
                bounded(value, depth + 1, count)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                bounded(value, depth + 1, count)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

/// Preserve duplicate detection before building Value (which would discard
/// duplicate keys). Serde bounds parsing depth; byte/depth/node ceilings above
/// bound accepted schemas. These schema strings remain unchanged in the output.
struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        decoder.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON with unique object keys")
    }
    fn visit_bool<E: Error>(self, value: bool) -> Result<UniqueJson, E> {
        Ok(UniqueJson(Value::Bool(value)))
    }
    fn visit_i64<E: Error>(self, value: i64) -> Result<UniqueJson, E> {
        Ok(UniqueJson(Value::Number(value.into())))
    }
    fn visit_u64<E: Error>(self, value: u64) -> Result<UniqueJson, E> {
        Ok(UniqueJson(Value::Number(value.into())))
    }
    fn visit_f64<E: Error>(self, value: f64) -> Result<UniqueJson, E> {
        Number::from_f64(value)
            .map(|n| UniqueJson(Value::Number(n)))
            .ok_or_else(|| E::custom("invalid JSON number"))
    }
    fn visit_str<E: Error>(self, value: &str) -> Result<UniqueJson, E> {
        Ok(UniqueJson(Value::String(value.into())))
    }
    fn visit_string<E: Error>(self, value: String) -> Result<UniqueJson, E> {
        Ok(UniqueJson(Value::String(value)))
    }
    fn visit_unit<E: Error>(self) -> Result<UniqueJson, E> {
        Ok(UniqueJson(Value::Null))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut entries: A) -> Result<UniqueJson, A::Error> {
        let mut fields = Map::new();
        while let Some(key) = entries.next_key::<String>()? {
            if fields.contains_key(&key) {
                return Err(A::Error::custom("duplicate schema key"));
            }
            let UniqueJson(value) = entries.next_value()?;
            fields.insert(key, value);
        }
        Ok(UniqueJson(Value::Object(fields)))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut entries: A) -> Result<UniqueJson, A::Error> {
        let mut values = Vec::new();
        while let Some(UniqueJson(value)) = entries.next_element()? {
            values.push(value);
        }
        Ok(UniqueJson(Value::Array(values)))
    }
}
