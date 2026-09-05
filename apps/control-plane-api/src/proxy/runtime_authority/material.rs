//! Fixed-path public authority metadata, not private credentials. Deployment
//! ownership/write protection of the files AND ancestors is a precondition;
//! inherited check-then-open confinement is not hostile-filesystem race proof.

use std::path::Path;

use super::RuntimeAuthorityError;

// Reuse the exact binary helper source without copying its confinement policy.
// That source also defines read_credential_table, unused by this metadata loader.
#[allow(dead_code)]
#[path = "../../startup/secrets.rs"]
mod startup_secrets;

pub(super) fn read_document(base: &Path, path: &Path) -> Result<Vec<u8>, RuntimeAuthorityError> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let path = startup_secrets::trusted_secret_path(
        &path,
        base,
        65_536,
        false,
        "runtime authority metadata",
    )
    .map_err(|_| RuntimeAuthorityError::Unavailable)?;
    startup_secrets::read_bounded(&path, 65_536, "runtime authority metadata")
        .map_err(|_| RuntimeAuthorityError::Unavailable)
}
