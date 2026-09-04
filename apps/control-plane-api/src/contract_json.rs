//! Strict Apex management ProtoJSON entry point; HTTP callers must use this
//! boundary instead of invoking the generated serde deserializer directly.
use prost::Message;
use prost_types::{DescriptorProto, FileDescriptorSet};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

const MAX_BYTES: usize = 256 * 1024;
const MAX_FIELDS: usize = 8192;
const MAX_DEPTH: usize = 64;
const DESCRIPTORS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/apex-management.binpb"));
type MessageIndex = HashMap<String, DescriptorProto>;
static INDEX: OnceLock<Result<MessageIndex, InvalidContractJson>> = OnceLock::new();
mod unique;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidContractJson;

impl std::fmt::Display for InvalidContractJson {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid or oversized management JSON")
    }
}
impl std::error::Error for InvalidContractJson {}

pub fn decode_management_json<T: DeserializeOwned + prost::Name>(
    input: &[u8],
) -> Result<T, InvalidContractJson> {
    if input.len() > MAX_BYTES {
        return Err(InvalidContractJson);
    }
    // Optional generated fields use Option for presence and cannot detect a
    // null-first duplicate. Check original entries before materializing Value.
    let value = unique::parse(input)?;
    let message = serde_json::from_slice(input).map_err(|_| InvalidContractJson)?;
    validate_message(&T::full_name(), &value, index()?)?;
    Ok(message)
}

fn index() -> Result<&'static MessageIndex, InvalidContractJson> {
    INDEX
        .get_or_init(|| {
            let descriptor =
                FileDescriptorSet::decode(DESCRIPTORS).map_err(|_| InvalidContractJson)?;
            let mut messages = HashMap::new();
            for file in descriptor.file {
                let package = file.package.unwrap_or_default();
                for message in file.message_type {
                    insert_message(&mut messages, &package, message)?;
                }
            }
            Ok(messages)
        })
        .as_ref()
        .map_err(|error| *error)
}

fn insert_message(
    index: &mut MessageIndex,
    parent: &str,
    message: DescriptorProto,
) -> Result<(), InvalidContractJson> {
    let name = format!(
        "{parent}.{}",
        message.name.as_deref().ok_or(InvalidContractJson)?
    );
    for nested in &message.nested_type {
        insert_message(index, &name, nested.clone())?;
    }
    index.insert(name, message);
    Ok(())
}

fn validate_message(
    name: &str,
    value: &Value,
    index: &MessageIndex,
) -> Result<(), InvalidContractJson> {
    if name.starts_with("google.protobuf.") {
        return Ok(());
    }
    let descriptor = index.get(name).ok_or(InvalidContractJson)?;
    let object = value.as_object().ok_or(InvalidContractJson)?;
    if name == "apex.v1.RuntimeConfiguration" {
        validate_runtime(value)?;
    }
    for field in &descriptor.field {
        let field_name = field.name.as_deref().ok_or(InvalidContractJson)?;
        let json_name = field.json_name.as_deref().ok_or(InvalidContractJson)?;
        if field_name != json_name
            && object.contains_key(field_name)
            && object.contains_key(json_name)
        {
            return Err(InvalidContractJson);
        }
        let raw = object.get(json_name).or_else(|| object.get(field_name));
        if field_name == "approval_mode"
            && field.r#type == Some(9)
            && !matches!(
                raw.and_then(Value::as_str),
                Some("none" | "operator" | "dual-operator")
            )
        {
            return Err(InvalidContractJson);
        }
        if field_name == "request_id" {
            let id = raw.and_then(Value::as_str).ok_or(InvalidContractJson)?;
            let uuid = uuid::Uuid::try_parse(id).map_err(|_| InvalidContractJson)?;
            if uuid.get_version_num() != 7
                || uuid.get_variant() != uuid::Variant::RFC4122
                || uuid.to_string() != id
            {
                return Err(InvalidContractJson);
            }
        }
        let Some(raw) = raw else { continue };
        let values = match raw {
            Value::Array(values) if field.label == Some(3) => values.as_slice(),
            _ => std::slice::from_ref(raw),
        };
        for entry in values {
            match field.r#type {
                Some(3 | 16 | 18) => integer64(entry, false)?,
                Some(4 | 6) => integer64(entry, true)?,
                Some(11) if !entry.is_null() => {
                    let nested_name = field.type_name.as_deref().ok_or(InvalidContractJson)?;
                    validate_message(nested_name.trim_start_matches('.'), entry, index)?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn integer64(value: &Value, unsigned: bool) -> Result<(), InvalidContractJson> {
    let text = value.as_str().ok_or(InvalidContractJson)?;
    let canonical = if unsigned {
        text.parse::<u64>()
            .map_err(|_| InvalidContractJson)?
            .to_string()
    } else {
        text.parse::<i64>()
            .map_err(|_| InvalidContractJson)?
            .to_string()
    };
    if canonical == text {
        Ok(())
    } else {
        Err(InvalidContractJson)
    }
}

fn member<'a>(value: &'a Value, camel: &str, snake: &str) -> Option<&'a Value> {
    value.get(camel).or_else(|| value.get(snake))
}

fn validate_runtime(value: &Value) -> Result<(), InvalidContractJson> {
    let version = member(value, "schemaVersion", "schema_version")
        .and_then(|version| version.as_u64().or_else(|| version.as_str()?.parse().ok()));
    let generation = value
        .get("generation")
        .and_then(Value::as_str)
        .and_then(|generation| generation.parse::<u64>().ok());
    if version != Some(1)
        || generation.is_none_or(|generation| generation == 0)
        || !value.get("telemetry").is_some_and(Value::is_object)
        || !value
            .get("spec")
            .and_then(|spec| spec.get("ingress"))
            .is_some_and(Value::is_object)
    {
        return Err(InvalidContractJson);
    }
    let resource = member(value, "resourceUrl", "resource_url")
        .and_then(Value::as_str)
        .ok_or(InvalidContractJson)?;
    let url = reqwest::Url::parse(resource).map_err(|_| InvalidContractJson)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || value
            .get("auth")
            .and_then(|auth| auth.get("audience"))
            .and_then(Value::as_str)
            != Some(resource)
    {
        return Err(InvalidContractJson);
    }
    Ok(())
}
