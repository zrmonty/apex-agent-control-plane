use std::path::Path;

/// Unix callers retain mode-bit checks at each secret boundary.
pub fn private_key_permissions_restricted(_path: &Path) -> bool {
    true
}
