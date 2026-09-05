//! Parse through serde's JSON grammar while counting original entries and
//! rejecting duplicate decoded object keys, including null-valued occurrences.
use super::{InvalidContractJson, MAX_DEPTH, MAX_FIELDS};
use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

pub(super) fn parse(input: &[u8]) -> Result<Value, InvalidContractJson> {
    let mut decoder = serde_json::Deserializer::from_slice(input);
    let value = Seed {
        depth: 0,
        count: &mut 0,
    }
    .deserialize(&mut decoder)
    .map_err(|_| InvalidContractJson)?;
    decoder.end().map_err(|_| InvalidContractJson)?;
    Ok(value)
}

struct Seed<'a> {
    depth: usize,
    count: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth > MAX_DEPTH || *self.count > MAX_FIELDS {
            return Err(D::Error::custom("management JSON bounds exceeded"));
        }
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded JSON without duplicate keys")
    }
    fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("nonfinite number"))
    }
    fn visit_str<E: Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.into()))
    }
    fn visit_string<E: Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut result = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            *self.count += 1;
            if *self.count > MAX_FIELDS
                || result.contains_key(&key)
                || matches!(key.as_str(), "__proto__" | "prototype" | "constructor")
            {
                return Err(A::Error::custom("duplicate or excessive JSON fields"));
            }
            let value = map.next_value_seed(Seed {
                depth: self.depth + 1,
                count: self.count,
            })?;
            result.insert(key, value);
        }
        Ok(Value::Object(result))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut result = Vec::new();
        while let Some(value) = sequence.next_element_seed(Seed {
            depth: self.depth + 1,
            count: self.count,
        })? {
            *self.count += 1;
            if *self.count > MAX_FIELDS {
                return Err(A::Error::custom("excessive JSON elements"));
            }
            result.push(value);
        }
        Ok(Value::Array(result))
    }
}
