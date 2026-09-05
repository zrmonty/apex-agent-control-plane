//! Bounded, typed Docker projection decoding. Never retain an inspect JSON tree.

use std::{collections::BTreeSet, fmt, marker::PhantomData};

use serde::{
    Deserialize, Deserializer,
    de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor, value::MapAccessDeserializer},
};

use crate::RuntimeError;

pub(super) const LABEL_KEYS: [&str; 11] = [
    "io.apex.runtime.installation-id",
    "io.apex.runtime.workspace-id",
    "io.apex.runtime.namespace-id",
    "io.apex.runtime.proxy-id",
    "io.apex.runtime.revision-id",
    "io.apex.runtime.generation",
    "io.apex.runtime.fencing-token",
    "io.apex.runtime.config-hash",
    "io.apex.runtime.runtime-manifest-hash",
    "io.apex.runtime.launch-context-hash",
    "io.apex.runtime.process-instance-id",
];

pub(super) struct BoundedString<const MAX: usize>(pub(super) String);

impl<'de, const MAX: usize> Deserialize<'de> for BoundedString<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StringVisitor<const MAX: usize>;
        impl<const MAX: usize> Visitor<'_> for StringVisitor<MAX> {
            type Value = BoundedString<MAX>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.len() > MAX {
                    return Err(E::custom("string limit"));
                }
                Ok(BoundedString(value.to_owned()))
            }
        }
        deserializer.deserialize_str(StringVisitor::<MAX>)
    }
}

// Derived structs also accept positional sequences. Require a JSON object
// before delegating to their typed, duplicate-detecting field visitors.
pub(super) struct Object<T>(pub(super) T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
            type Value = Object<T>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("projection object")
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(Object)
            }
        }
        deserializer.deserialize_map(ObjectVisitor(PhantomData))
    }
}

struct Single<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Single<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SingleVisitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for SingleVisitor<T> {
            type Value = Single<T>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("exactly one inspect element")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let value = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::custom("empty inspect"))?;
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("multiple inspect elements"));
                }
                Ok(Single(value))
            }
        }
        deserializer.deserialize_seq(SingleVisitor(PhantomData))
    }
}

pub(super) struct Labels([Option<String>; 11]);

impl Labels {
    pub(super) fn matches(&self, values: &[&str; 11]) -> bool {
        self.0
            .iter()
            .zip(values)
            .all(|(actual, expected)| actual.as_deref() == Some(*expected))
    }
}

impl<'de> Deserialize<'de> for Labels {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct LabelsVisitor;
        impl<'de> Visitor<'de> for LabelsVisitor {
            type Value = Labels;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded unique labels")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut seen = BTreeSet::new();
                let mut values = std::array::from_fn(|_| None);
                while let Some(BoundedString(key)) = map.next_key::<BoundedString<128>>()? {
                    if seen.len() == 64 || key.is_empty() || seen.contains(&key) {
                        return Err(de::Error::custom("label key/count limit or duplicate"));
                    }
                    let index = LABEL_KEYS.iter().position(|expected| *expected == key);
                    seen.insert(key);
                    let BoundedString(value) = map.next_value::<BoundedString<512>>()?;
                    if let Some(index) = index {
                        values[index] = Some(value);
                    }
                    // Unknown values are dropped here. Only bounded keys remain
                    // temporarily, to reject duplicates even among unknown labels.
                }
                if values.iter().any(Option::is_none) {
                    return Err(de::Error::custom("missing ownership label"));
                }
                Ok(Labels(values))
            }
        }
        deserializer.deserialize_map(LabelsVisitor)
    }
}

#[derive(Deserialize)]
struct IdProjection {
    #[serde(rename = "Id")]
    id: BoundedString<128>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct Projection {
    pub(super) id: BoundedString<128>,
    pub(super) name: BoundedString<128>,
    pub(super) image: BoundedString<128>,
    pub(super) config: Object<ConfigProjection>,
    pub(super) state: Object<StateProjection>,
}

#[derive(Deserialize)]
pub(super) struct ConfigProjection {
    #[serde(rename = "Labels")]
    pub(super) labels: Labels,
}

#[derive(Deserialize)]
pub(super) struct StateProjection {
    #[serde(rename = "Status")]
    pub(super) status: BoundedString<512>,
}

pub(super) fn extract_id(input: &str) -> Result<String, RuntimeError> {
    check_bounds(input)?;
    let Single(Object(value)): Single<Object<IdProjection>> =
        serde_json::from_str(input).map_err(|_| RuntimeError::InvalidInspect)?;
    if value.id.0.is_empty() {
        return Err(RuntimeError::InvalidInspect);
    }
    Ok(value.id.0)
}

pub(super) fn projection(input: &str) -> Result<Projection, RuntimeError> {
    check_bounds(input)?;
    if input.trim_start().starts_with('[') {
        let Single(Object(value)): Single<Object<Projection>> =
            serde_json::from_str(input).map_err(|_| RuntimeError::InvalidInspect)?;
        Ok(value)
    } else {
        let Object(value) =
            serde_json::from_str(input).map_err(|_| RuntimeError::InvalidInspect)?;
        Ok(value)
    }
}

// Bound all nesting, including unknown fields, before serde's visitors run.
// This is only a lexical budget check; serde still validates the full grammar,
// Unicode escapes, field types and end-of-input. No JSON tree is constructed.
fn check_bounds(input: &str) -> Result<(), RuntimeError> {
    if input.len() > 65_536 {
        return Err(RuntimeError::InvalidInspect);
    }
    let mut depth = 0_u8;
    let mut quoted = false;
    let mut escaped = false;
    for byte in input.bytes() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'[' | b'{' => {
                    if depth == 32 {
                        return Err(RuntimeError::InvalidInspect);
                    }
                    depth += 1;
                }
                b']' | b'}' => {
                    depth = depth.checked_sub(1).ok_or(RuntimeError::InvalidInspect)?;
                }
                _ => {}
            }
        }
    }
    if depth != 0 || quoted {
        return Err(RuntimeError::InvalidInspect);
    }
    Ok(())
}
