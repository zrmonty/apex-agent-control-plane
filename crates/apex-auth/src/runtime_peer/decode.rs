//! Private, bounded JSON boundary; no untyped tree or raw diagnostic escapes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::marker::PhantomData;

use serde::de::{self, MapAccess, SeqAccess, Visitor, value::MapAccessDeserializer};
use serde::{Deserialize, Deserializer};

use super::{
    Grant, RegisteredPeer, RuntimePeerError, RuntimePeerPolicy, RuntimePeerRole, valid_grant,
};
use RuntimePeerError::InvalidPolicy;

const MAX_BYTES: usize = 65_536;
const MAX_DEPTH: usize = 32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawPolicy {
    schema_version: u32,
    version: Text<128>,
    valid_from_unix_us: Text<20>,
    expires_at_unix_us: Text<20>,
    peers: Items<Object<RawPeer>, 128>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawPeer {
    certificate_sha256: Text<64>,
    identity_id: Text<128>,
    role: Text<10>,
    revoked: bool,
    grants: Items<Object<RawGrant>, 64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawGrant {
    installation_id: Text<36>,
    workspace_id: Text<256>,
    namespace_id: Text<256>,
}

pub(super) fn parse(input: &[u8]) -> Result<RuntimePeerPolicy, RuntimePeerError> {
    // Original bytes and lexical depth are checked without allocations, before
    // serde can allocate decoded strings or any collection entries.
    preflight(input)?;
    let Object(raw) =
        serde_json::from_slice::<Object<RawPolicy>>(input).map_err(|_| InvalidPolicy)?;
    if raw.schema_version != 1 || !apex_domain::is_scope_identifier(&raw.version.0) {
        return Err(InvalidPolicy);
    }
    let valid_from_unix_us = epoch(&raw.valid_from_unix_us.0)?;
    let expires_at_unix_us = epoch(&raw.expires_at_unix_us.0)?;
    if valid_from_unix_us == 0 || expires_at_unix_us <= valid_from_unix_us {
        return Err(InvalidPolicy);
    }
    let mut peers = Vec::new();
    let mut total_grants = 0_usize;
    for Object(peer) in raw.peers.0 {
        total_grants = total_grants
            .checked_add(peer.grants.0.len())
            .ok_or(InvalidPolicy)?;
        if total_grants > 1_024 {
            return Err(InvalidPolicy);
        }
        peers.push(parse_peer(peer)?);
    }
    {
        let mut pins = BTreeSet::new();
        let mut identities: BTreeMap<&str, &RegisteredPeer> = BTreeMap::new();
        for peer in &peers {
            if !pins.insert(peer.certificate_sha256) {
                return Err(InvalidPolicy);
            }
            if let Some(previous) = identities.insert(&peer.identity_id, peer)
                && (previous.role != peer.role || previous.grants != peer.grants)
            {
                return Err(InvalidPolicy);
            }
        }
    }
    Ok(RuntimePeerPolicy {
        version: raw.version.0,
        valid_from_unix_us,
        expires_at_unix_us,
        peers,
    })
}

fn parse_peer(raw: RawPeer) -> Result<RegisteredPeer, RuntimePeerError> {
    if !apex_domain::is_scope_identifier(&raw.identity_id.0) {
        return Err(InvalidPolicy);
    }
    let role = match raw.role.0.as_str() {
        "controller" => RuntimePeerRole::Controller,
        "agent" => RuntimePeerRole::Agent,
        _ => return Err(InvalidPolicy),
    };
    let certificate_sha256 = pin(&raw.certificate_sha256.0)?;
    let mut grants = Vec::new();
    for Object(grant) in raw.grants.0 {
        if !valid_grant(
            &grant.installation_id.0,
            &grant.workspace_id.0,
            &grant.namespace_id.0,
        ) {
            return Err(InvalidPolicy);
        }
        grants.push(Grant {
            installation_id: grant.installation_id.0,
            workspace_id: grant.workspace_id.0,
            namespace_id: grant.namespace_id.0,
        });
    }
    // Grant order carries no authority; compare exact sets across rotation.
    grants.sort_unstable();
    if grants.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(InvalidPolicy);
    }
    Ok(RegisteredPeer {
        certificate_sha256,
        identity_id: raw.identity_id.0,
        role,
        revoked: raw.revoked,
        grants,
    })
}

fn epoch(text: &str) -> Result<u64, RuntimePeerError> {
    if text.is_empty()
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(InvalidPolicy);
    }
    text.parse().map_err(|_| InvalidPolicy)
}

fn pin(text: &str) -> Result<[u8; 32], RuntimePeerError> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(InvalidPolicy);
    }
    let mut pin = [0; 32];
    // ASCII validation above makes every two-byte string boundary valid.
    for (out, index) in pin.iter_mut().zip((0..64).step_by(2)) {
        *out = u8::from_str_radix(&text[index..index + 2], 16).map_err(|_| InvalidPolicy)?;
    }
    Ok(pin)
}

fn preflight(input: &[u8]) -> Result<(), RuntimePeerError> {
    if input.is_empty() || input.len() > MAX_BYTES || std::str::from_utf8(input).is_err() {
        return Err(InvalidPolicy);
    }
    let (mut quoted, mut escaped, mut depth) = (false, false, 0_usize);
    for &byte in input {
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
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return Err(InvalidPolicy);
                    }
                }
                b'}' | b']' => depth = depth.checked_sub(1).ok_or(InvalidPolicy)?,
                _ => {}
            }
        }
    }
    if quoted || depth != 0 {
        return Err(InvalidPolicy);
    }
    // Full JSON grammar (including matching delimiters and trailing bytes) is
    // still checked by serde, never inferred from this allocation-free scan.
    Ok(())
}

// Derive accepts positional sequences for structs. This wrapper dispatches
// maps only, retaining derive's decoded-name duplicate/unknown/missing checks.
struct Object<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
            type Value = Object<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("object")
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(Object)
            }
        }
        deserializer.deserialize_map(ObjectVisitor(PhantomData))
    }
}

struct Text<const MAX: usize>(String);

impl<'de, const MAX: usize> Deserialize<'de> for Text<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TextVisitor<const MAX: usize>;
        impl<const MAX: usize> Visitor<'_> for TextVisitor<MAX> {
            type Value = Text<MAX>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded string")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.is_empty() || value.len() > MAX {
                    return Err(E::custom("string bound"));
                }
                Ok(Text(value.to_owned()))
            }
        }
        deserializer.deserialize_str(TextVisitor)
    }
}

struct Items<T, const MAX: usize>(Vec<T>);

impl<'de, T: Deserialize<'de>, const MAX: usize> Deserialize<'de> for Items<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ItemsVisitor<T, const MAX: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for ItemsVisitor<T, MAX> {
            type Value = Items<T, MAX>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded nonempty array")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut items = Vec::new();
                while items.len() < MAX {
                    match sequence.next_element()? {
                        Some(item) => items.push(item),
                        None if !items.is_empty() => return Ok(Items(items)),
                        None => return Err(de::Error::custom("empty array")),
                    }
                }
                // Do not allocate another peer/grant after the collection cap.
                if sequence.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("array bound"));
                }
                Ok(Items(items))
            }
        }
        deserializer.deserialize_seq(ItemsVisitor(PhantomData))
    }
}
