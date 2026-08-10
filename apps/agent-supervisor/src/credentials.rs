//! Loads the supervisor's own mTLS identity and bearer credential.
//!
//! Deliberately a small, self-contained copy of the discipline
//! `apps/control-plane-api/src/startup/secrets.rs` and
//! `packages/sdk-python/src/apex_sdk/control_transport.py`'s
//! `_read_credential_file` already apply to the same class of file (bounded
//! size, symlinks refused, owner-only permissions on private material) rather
//! than a dependency on either: `control-plane-api`'s helpers live in that
//! binary's `startup` module, which is not part of the `apex_control_plane_api`
//! library crate and so is not importable from here, and pulling in the whole
//! `apex-control-plane-api` crate as a path dependency just to reuse a few
//! dozen lines would mean this binary -- the one holding the credential that
//! must never leak to a compromised agent -- carries that crate's entire
//! server-side dependency tree (Keycloak/JWKS client, Postgres driver, file
//! outbox) for no benefit to the property it exists to hold. See
//! `build.rs`'s doc comment for the same reasoning applied to the generated
//! proto module.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Bound on any single credential file this process reads. A certificate,
/// key, CA bundle, or bearer token larger than this is a misconfiguration; a
/// mounted file should never decide how much memory this process allocates
/// while loading it.
const MAX_CREDENTIAL_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub struct CredentialError {
    pub label: &'static str,
    pub reason: &'static str,
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.label, self.reason)
    }
}

impl std::error::Error for CredentialError {}

fn fail(label: &'static str, reason: &'static str) -> CredentialError {
    CredentialError { label, reason }
}

/// Reads one credential file: refuses a symlink, refuses anything that is
/// not a regular file, refuses empty or oversized content, and -- for
/// `private` material -- refuses a file readable beyond its own owner on
/// Unix.
///
/// **Windows note, stated honestly rather than silently skipped:** POSIX
/// mode-bit permission checks do not exist on Windows; ACL-based enforcement
/// (as `apex_event_ingest::permissions` implements for the ingest gateway's
/// own private key files, via `icacls`/PowerShell) is not duplicated here.
/// The confinement, symlink-refusal, and size-bound checks below still apply
/// on every platform; only the extra owner-only permission check is
/// Unix-only. Matches this codebase's existing precedent for a stated,
/// honest Windows gap rather than invented parity (see
/// `apps/control-plane-api/src/inbox.rs`'s directory-fsync comment).
pub fn read_credential_file(path: &Path, label: &'static str, private: bool) -> Result<Vec<u8>, CredentialError> {
    if path.is_symlink() {
        return Err(fail(label, "must not be a symbolic link"));
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| fail(label, "is not available at the configured path"))?;
    if !metadata.is_file() {
        return Err(fail(label, "must be a regular file"));
    }
    if metadata.len() == 0 || metadata.len() > MAX_CREDENTIAL_BYTES as u64 {
        return Err(fail(label, "has an invalid size"));
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(fail(
                label,
                "permissions are too broad; it must be readable only by its owner",
            ));
        }
    }
    // `private` has no platform-independent check to perform on Windows (see
    // this function's own doc comment); referenced here only so the
    // parameter is not reported unused on that target.
    #[cfg(not(unix))]
    let _ = private;
    let file = fs::File::open(path).map_err(|_| fail(label, "could not be opened"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize + 1);
    file.take(MAX_CREDENTIAL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| fail(label, "could not be read"))?;
    if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_BYTES {
        return Err(fail(label, "has an invalid size"));
    }
    Ok(bytes)
}

/// Reads and validates the supervisor's own bearer token: non-empty,
/// printable ASCII, no whitespace -- the same grammar
/// `apps/control-plane-api/src/agent_auth.rs`'s credential table requires of
/// every agent workload token, since this is exactly such a token.
pub fn read_token_file(path: &Path) -> Result<String, CredentialError> {
    let bytes = read_credential_file(path, "supervisor token file", true)?;
    let text = String::from_utf8(bytes).map_err(|_| fail("supervisor token file", "is not UTF-8"))?;
    let token = text.trim().to_owned();
    if token.is_empty()
        || token.len() > 4096
        || !token.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(fail(
            "supervisor token file",
            "must contain non-empty printable ASCII with no whitespace",
        ));
    }
    Ok(token)
}

/// The supervisor's complete, distinct mTLS + bearer identity for
/// `PollCommands`/`AckCommand`. Every field here is loaded from a file this
/// process was pointed at through its own configuration, never from -- and
/// never copied into -- the environment the supervised agent child sees (see
/// `crate::child_env`).
pub struct SupervisorCredentials {
    pub server_ca_pem: Vec<u8>,
    pub client_cert_pem: Vec<u8>,
    pub client_key_pem: Vec<u8>,
    pub token: String,
}

impl SupervisorCredentials {
    pub fn load(
        server_ca_file: &Path,
        client_cert_file: &Path,
        client_key_file: &Path,
        token_file: &Path,
    ) -> Result<Self, CredentialError> {
        Ok(Self {
            server_ca_pem: read_credential_file(server_ca_file, "control gateway CA certificate", false)?,
            client_cert_pem: read_credential_file(client_cert_file, "supervisor workload certificate", false)?,
            client_key_pem: read_credential_file(client_key_file, "supervisor workload private key", true)?,
            token: read_token_file(token_file)?,
        })
    }
}

/// Confines a configured path under a trusted base directory, refusing a
/// symlinked base or a target that escapes it -- the same discipline
/// `apps/control-plane-api/src/startup/secrets.rs::trusted_secret_path`
/// applies, restated rather than imported for the reason this module's own
/// doc comment gives.
pub fn confine_to_base(path: &Path, base: &Path) -> Result<PathBuf, CredentialError> {
    let canonical_base = base
        .canonicalize()
        .map_err(|_| fail("APEX_SUPERVISOR_TRUSTED_SECRET_BASE", "is unavailable"))?;
    let canonical = path
        .canonicalize()
        .map_err(|_| fail("a configured supervisor secret path", "is unavailable"))?;
    if !canonical.starts_with(&canonical_base) {
        return Err(fail(
            "a configured supervisor secret path",
            "is outside the trusted secret base",
        ));
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "apex-agent-supervisor-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(path: &Path, contents: &[u8]) {
        let mut file = fs::File::create(path).unwrap();
        file.write_all(contents).unwrap();
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn reads_a_well_formed_public_credential_file() {
        let dir = temp_dir("ca");
        let path = dir.join("ca.pem");
        write_file(&path, b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n");
        let bytes = read_credential_file(&path, "test ca", false).unwrap();
        assert!(bytes.starts_with(b"-----BEGIN CERTIFICATE-----"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_an_empty_file() {
        let dir = temp_dir("empty");
        let path = dir.join("empty.pem");
        write_file(&path, b"");
        assert!(read_credential_file(&path, "test", false).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_a_missing_file() {
        let dir = temp_dir("missing");
        assert!(read_credential_file(&dir.join("nope.pem"), "test", false).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_an_oversized_file() {
        let dir = temp_dir("big");
        let path = dir.join("big.pem");
        write_file(&path, &vec![b'a'; MAX_CREDENTIAL_BYTES + 1]);
        assert!(read_credential_file(&path, "test", false).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_private_material_readable_beyond_its_owner() {
        let dir = temp_dir("perm");
        let path = dir.join("key.pem");
        write_file(&path, b"private-key-bytes");
        set_mode(&path, 0o644);
        assert!(read_credential_file(&path, "test key", true).is_err());
        set_mode(&path, 0o600);
        assert!(read_credential_file(&path, "test key", true).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlink_even_when_the_target_is_well_formed() {
        let dir = temp_dir("symlink");
        let real = dir.join("real.pem");
        write_file(&real, b"real-bytes");
        let link = dir.join("link.pem");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read_credential_file(&link, "test", false).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn token_file_trims_trailing_newline_and_validates_grammar() {
        let dir = temp_dir("token");
        let path = dir.join("token");
        write_file(&path, b"a-well-formed-token-value\n");
        #[cfg(unix)]
        set_mode(&path, 0o600);
        assert_eq!(read_token_file(&path).unwrap(), "a-well-formed-token-value");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn token_file_rejects_whitespace_inside_the_token() {
        let dir = temp_dir("token-bad");
        let path = dir.join("token");
        write_file(&path, b"has a space\n");
        #[cfg(unix)]
        set_mode(&path, 0o600);
        assert!(read_token_file(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn confine_to_base_refuses_a_path_outside_the_base() {
        let base = temp_dir("base");
        let outside = temp_dir("outside");
        let escaping_file = outside.join("secret.pem");
        write_file(&escaping_file, b"bytes");
        assert!(confine_to_base(&escaping_file, &base).is_err());
        let _ = fs::remove_dir_all(&base);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn confine_to_base_accepts_a_path_inside_the_base() {
        let base = temp_dir("base-ok");
        let inside_file = base.join("secret.pem");
        write_file(&inside_file, b"bytes");
        assert!(confine_to_base(&inside_file, &base).is_ok());
        let _ = fs::remove_dir_all(&base);
    }
}
