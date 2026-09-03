use std::fs;
use std::path::Path;

/// Reject private-key material that is readable or writable by group/other.
/// Returns `false` (restricted) on any metadata error, matching the
/// fail-closed convention used at every secret-loading call site.
pub fn private_key_permissions_restricted(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match fs::metadata(path) {
        Ok(metadata) => metadata.permissions().mode() & 0o077 == 0,
        Err(_) => false,
    }
}


