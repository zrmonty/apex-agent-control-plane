//! Duplicate-preserving bounded decode with zeroizing success/error trees.
use serde::{
    Deserialize, Deserializer,
    de::{Error, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};
pub(crate) struct Json(pub Value);
impl Json {
    pub(crate) fn parse(b: &[u8]) -> Result<Self, &'static str> {
        Self::bounded(b, 262_144)
    }
    pub(crate) fn bounded(b: &[u8], limit: usize) -> Result<Self, &'static str> {
        if b.is_empty() || b.len() > limit {
            return Err(super::ERROR);
        }
        let value: Self = serde_json::from_slice(b).map_err(|_| super::ERROR)?;
        fn depth(v: &Value, n: usize) -> bool {
            n <= 32
                && match v {
                    Value::Array(a) => a.iter().all(|v| depth(v, n + 1)),
                    Value::Object(o) => o.values().all(|v| depth(v, n + 1)),
                    _ => true,
                }
        }
        if !depth(&value.0, 0) {
            return Err(super::ERROR);
        }
        Ok(value)
    }
}
impl Drop for Json {
    fn drop(&mut self) {
        fn clear(v: &mut Value) {
            match v {
                Value::String(s) => s.zeroize(),
                Value::Array(a) => a.iter_mut().for_each(clear),
                Value::Object(o) => {
                    for (mut k, mut v) in std::mem::take(o) {
                        k.zeroize();
                        clear(&mut v);
                    }
                }
                _ => {}
            }
        }
        clear(&mut self.0);
    }
}
impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Json;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded JSON")
            }
            fn visit_bool<E: Error>(self, v: bool) -> Result<Json, E> {
                Ok(Json(v.into()))
            }
            fn visit_u64<E: Error>(self, v: u64) -> Result<Json, E> {
                Ok(Json(v.into()))
            }
            fn visit_i64<E: Error>(self, v: i64) -> Result<Json, E> {
                Ok(Json(v.into()))
            }
            fn visit_f64<E: Error>(self, v: f64) -> Result<Json, E> {
                Ok(Json(v.into()))
            }
            fn visit_unit<E: Error>(self) -> Result<Json, E> {
                Ok(Json(Value::Null))
            }
            fn visit_str<E: Error>(self, v: &str) -> Result<Json, E> {
                Ok(Json(v.into()))
            }
            fn visit_string<E: Error>(self, v: String) -> Result<Json, E> {
                Ok(Json(v.into()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Json, A::Error> {
                let mut result = Json(Value::Array(vec![]));
                while let Some(mut v) = a.next_element::<Json>()? {
                    if let Value::Array(list) = &mut result.0 {
                        list.push(std::mem::take(&mut v.0));
                    }
                }
                Ok(result)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Json, A::Error> {
                let mut result = Json(Value::Object(Default::default()));
                while let Some(key) = a.next_key::<String>()? {
                    let key = Zeroizing::new(key);
                    if let Value::Object(map) = &mut result.0 {
                        if map.contains_key(&*key) {
                            return Err(A::Error::custom("duplicate JSON field"));
                        }
                        let mut value = a.next_value::<Json>()?;
                        map.insert(key.to_string(), std::mem::take(&mut value.0));
                    }
                }
                Ok(result)
            }
        }
        d.deserialize_any(V)
    }
}
