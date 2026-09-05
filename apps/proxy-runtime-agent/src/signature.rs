//! Linux Cosign verification boundary; a signature is not a launch permit.
use crate::image_catalog::ImageCatalog;
use std::{fmt, path::Path, sync::atomic::AtomicBool, time::Duration};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod output;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureError {
    Unsupported,
    InvalidConfiguration,
    Catalog,
    Unavailable,
    Overloaded,
    Cancelled,
    Deadline,
    Verification,
}
impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "RUNTIME_SIGNATURE_UNSUPPORTED",
            Self::InvalidConfiguration => "RUNTIME_SIGNATURE_INVALID_CONFIGURATION",
            Self::Catalog => "RUNTIME_SIGNATURE_CATALOG",
            Self::Unavailable => "RUNTIME_SIGNATURE_UNAVAILABLE",
            Self::Overloaded => "RUNTIME_SIGNATURE_OVERLOADED",
            Self::Cancelled => "RUNTIME_SIGNATURE_CANCELLED",
            Self::Deadline => "RUNTIME_SIGNATURE_DEADLINE",
            Self::Verification => "RUNTIME_SIGNATURE_VERIFICATION",
        })
    }
}
impl std::error::Error for SignatureError {}

/// Synchronous, single-flight verifier. A fixed blocking owner must call this,
/// never a Tokio worker. No unbounded queue, caller executable or shell exists.
/// Deployment administrators must protect executable/cache ancestors for their
/// lifetime and install the supported Cosign release (acceptance: v3.1.3).
pub struct SignatureVerifier {
    #[cfg(target_os = "linux")]
    inner: linux::Verifier,
}
impl SignatureVerifier {
    /// Open administrator-owned paths without following symlinks.
    /// # Errors
    /// Refuses unsupported platforms or unsafe deployment paths.
    pub fn open(executable: &Path, cache: &Path) -> Result<Self, SignatureError> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                inner: linux::Verifier::open(executable, cache)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (executable, cache);
            Err(SignatureError::Unsupported)
        }
    }
    /// Select from the deployment catalog, then run real Cosign verification.
    /// Success proves the signature only, not publication, freshness or launch
    /// authority. Private registry credentials are intentionally unsupported.
    /// # Errors
    /// Refuses catalog mismatch, overload, cancellation, deadline or any failed
    /// verification; child output and underlying errors are never exposed.
    pub fn verify(
        &self,
        catalog: &ImageCatalog,
        id: &str,
        image: &str,
        budget: Duration,
        cancelled: &AtomicBool,
    ) -> Result<VerifiedImage, SignatureError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.verify(catalog, id, image, budget, cancelled)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (catalog, id, image, budget, cancelled);
            Err(SignatureError::Unsupported)
        }
    }
}

/// Exact image verified at one point in time; never operation/engine authority.
pub struct VerifiedImage {
    image: String,
}
impl VerifiedImage {
    pub fn image_ref(&self) -> &str {
        &self.image
    }
}
impl fmt::Debug for VerifiedImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedImage { [redacted; not a launch permit] }")
    }
}
impl fmt::Debug for SignatureVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignatureVerifier { [redacted] }")
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests;
