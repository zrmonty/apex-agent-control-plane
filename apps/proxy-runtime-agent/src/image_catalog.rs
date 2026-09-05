//! Deployment-owned image selection. Selection is not signature verification.

use std::{collections::BTreeSet, fmt, marker::PhantomData};

use serde::de::{MapAccess, Visitor, value::MapAccessDeserializer};
use serde::{Deserialize, Deserializer};

/// Strict, bounded catalog loaded by a trusted deployment owner, never from RPCs.
pub struct ImageCatalog {
    images: Vec<Object<CatalogEntry>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogDocument {
    schema_version: u32,
    images: Vec<Object<CatalogEntry>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogEntry {
    id: String,
    image_ref: String,
    signing: Object<SigningPolicy>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningPolicy {
    certificate_oidc_issuer: String,
    certificate_identity: String,
}

/// Exact signing constraints to supply to a future owned Cosign verifier.
pub struct SelectedImage<'a> {
    pub catalog_id: &'a str,
    pub image_ref: &'a str,
    pub certificate_oidc_issuer: &'a str,
    pub certificate_identity: &'a str,
}

/// Static refusals never retain catalog bytes, identities or parser errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageCatalogError {
    InvalidCatalog,
    UnknownImage,
    ImageMismatch,
}

impl fmt::Display for ImageCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidCatalog => "RUNTIME_IMAGE_CATALOG_INVALID",
            Self::UnknownImage => "RUNTIME_IMAGE_CATALOG_UNKNOWN_IMAGE",
            Self::ImageMismatch => "RUNTIME_IMAGE_CATALOG_IMAGE_MISMATCH",
        })
    }
}

impl std::error::Error for ImageCatalogError {}

impl ImageCatalog {
    /// Parse trusted bytes; this does not establish file ownership or freshness.
    /// Only exact-identity keyless signing policy is supported in schema v1.
    /// A later verifier must verify the signature, chain, issuer, exact identity,
    /// transparency evidence and signed digest; parsing proves none of those.
    ///
    /// # Errors
    /// Refuses malformed, oversized, ambiguous or unsupported policy documents.
    pub fn parse(bytes: &[u8]) -> Result<Self, ImageCatalogError> {
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(ImageCatalogError::InvalidCatalog);
        }
        let Object(document): Object<CatalogDocument> =
            serde_json::from_slice(bytes).map_err(|_| ImageCatalogError::InvalidCatalog)?;
        if document.schema_version != 1 || !(1..=64).contains(&document.images.len()) {
            return Err(ImageCatalogError::InvalidCatalog);
        }
        let mut ids = BTreeSet::new();
        let mut references = BTreeSet::new();
        for Object(entry) in &document.images {
            if !catalog_id(&entry.id)
                || !crate::shapes::image_ref(&entry.image_ref)
                || !issuer(&entry.signing.0.certificate_oidc_issuer)
                || !exact_identity(&entry.signing.0.certificate_identity)
                || !ids.insert(&entry.id)
                || !references.insert(&entry.image_ref)
            {
                return Err(ImageCatalogError::InvalidCatalog);
            }
        }
        Ok(Self {
            images: document.images,
        })
    }

    /// Match an ID and the immutable published image reference exactly.
    ///
    /// This borrowed selection cannot authorize a pull, stage or engine effect.
    /// Loading/currentness, signature verification and the live operation gate
    /// are still required at the future provisioning owner's effect boundary.
    ///
    /// # Errors
    /// Refuses unknown IDs and any mismatch with the published image reference.
    pub fn select(
        &self,
        catalog_id: &str,
        expected_image_ref: &str,
    ) -> Result<SelectedImage<'_>, ImageCatalogError> {
        if !self::catalog_id(catalog_id) {
            return Err(ImageCatalogError::UnknownImage);
        }
        let entry = self
            .images
            .iter()
            .find(|Object(entry)| entry.id == catalog_id)
            .ok_or(ImageCatalogError::UnknownImage)?;
        let Object(entry) = entry;
        if expected_image_ref.len() > 512 || entry.image_ref != expected_image_ref {
            return Err(ImageCatalogError::ImageMismatch);
        }
        Ok(SelectedImage {
            catalog_id: &entry.id,
            image_ref: &entry.image_ref,
            certificate_oidc_issuer: &entry.signing.0.certificate_oidc_issuer,
            certificate_identity: &entry.signing.0.certificate_identity,
        })
    }
}

// Like the shared peer-policy decoder, accept named maps only. Serde's derived
// struct decoder otherwise also accepts positional arrays. Retain derive's
// duplicate decoded-key, unknown-field and missing-field refusals.
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

fn catalog_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && !value.contains("..")
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn exact_identity(value: &str) -> bool {
    (1..=2048).contains(&value.len())
        && !value.starts_with('-')
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn issuer(value: &str) -> bool {
    if !exact_identity(value) || value.contains('\\') {
        return false;
    }
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && (url.as_str() == value || url.as_str() == format!("{value}/"))
}

impl fmt::Debug for ImageCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ImageCatalog([redacted])")
    }
}

impl fmt::Debug for SelectedImage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SelectedImage([redacted; signature verification required])")
    }
}
