use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use std::{fmt, marker::PhantomData};
pub(super) struct Object<T>(pub T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for V<T> {
            type Value = Object<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("object")
            }
            fn visit_map<A: MapAccess<'de>>(self, m: A) -> Result<Self::Value, A::Error> {
                T::deserialize(MapAccessDeserializer::new(m)).map(Object)
            }
        }
        d.deserialize_map(V(PhantomData))
    }
}
pub(super) fn version(v: &str) -> bool {
    v.len() <= 128 && crate::shapes::scope(v)
}
pub(super) fn image_id(v: &str) -> bool {
    (1..=64).contains(&v.len())
        && v.as_bytes()[0].is_ascii_alphanumeric()
        && !v.contains("..")
        && v.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}
pub(super) fn host(v: &str) -> bool {
    (1..=253).contains(&v.len())
        && v != "localhost"
        && !v.ends_with(".localhost")
        && v.parse::<std::net::IpAddr>().is_err()
        // Native resolvers also accept hexadecimal/mixed inet_aton forms. Refuse
        // the complete numeric-looking grammar, including overflowing aliases,
        // without resolving DNS or interpreting a protected host as an address.
        && !v.split('.').all(|part| part.bytes().all(|b| b.is_ascii_digit())
            || part.strip_prefix("0x").is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())))
        && v.split('.').all(|p| {
            !p.is_empty()
                && p.len() <= 63
                && !p.starts_with('-')
                && !p.ends_with('-')
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
