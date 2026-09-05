//! Confined, bounded browser material loading with zeroizing private ownership.

use crate::startup::secrets;
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};
use zeroize::Zeroizing;

const MAX_MATERIAL_BYTES: usize = 1024 * 1024;

pub(super) fn read_public(
    base: &Path,
    path: &Path,
    max: usize,
    label: &str,
) -> Result<Vec<u8>, io::Error> {
    let (_, max_bytes) = checked_size(max, label)?;
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let path = secrets::trusted_secret_path(&path, base, max_bytes, false, label)?;
    secrets::read_bounded(&path, max, label)
}

pub(super) fn read_private(
    base: &Path,
    path: &Path,
    max: usize,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, io::Error> {
    let (limit, max_bytes) = checked_size(max, label)?;
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let path = secrets::trusted_secret_path(&path, base, max_bytes, true, label)?;
    // Fixed storage avoids reallocating private bytes. Ownership is zeroizing
    // before the first read, including partial I/O errors and a growing file.
    let mut bytes = Zeroizing::new(vec![0; limit]);
    let mut file = File::open(&path).map_err(|_| invalid_material(label))?;
    let mut used = 0;
    while used < limit {
        match file.read(&mut bytes[used..]) {
            Ok(0) => break,
            Ok(count) => used += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(invalid_material(label)),
        }
    }
    // The extra byte detects growth past the bound after the metadata check.
    if used == 0 || used > max {
        return Err(invalid_material(label));
    }
    // The unread tail contains only the zeroes from initialization.
    bytes.truncate(used);
    Ok(bytes)
}

pub(super) fn client_secret(base: &Path, path: &Path) -> Result<Zeroizing<String>, io::Error> {
    const LABEL: &str = "browser client secret";
    let bytes = read_private(base, path, 4098, LABEL)?;
    let value = bytes.as_slice();
    let value = value
        .strip_suffix(b"\r\n")
        .or_else(|| value.strip_suffix(b"\n"))
        .unwrap_or(value);
    if !(16..=4096).contains(&value.len()) || !value.iter().all(u8::is_ascii_graphic) {
        return Err(invalid_material(LABEL));
    }
    // Borrow the guarded bytes; a UTF-8 error never owns a plaintext buffer.
    let value = std::str::from_utf8(value).map_err(|_| invalid_material(LABEL))?;
    let mut secret = Zeroizing::new(String::with_capacity(value.len()));
    secret.push_str(value);
    Ok(secret)
}

pub(super) fn session_key(base: &Path, path: &Path) -> Result<Zeroizing<[u8; 32]>, io::Error> {
    const LABEL: &str = "browser session key";
    let bytes = read_private(base, path, 32, LABEL)?;
    if bytes.len() != 32 {
        return Err(invalid_material(LABEL));
    }
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(bytes.as_slice());
    Ok(key)
}

fn checked_size(max: usize, label: &str) -> Result<(usize, u64), io::Error> {
    if !(1..=MAX_MATERIAL_BYTES).contains(&max) {
        return Err(invalid_material(label));
    }
    let limit = max.checked_add(1).ok_or_else(|| invalid_material(label))?;
    let max_bytes = u64::try_from(max).map_err(|_| invalid_material(label))?;
    Ok((limit, max_bytes))
}

fn invalid_material(label: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid {label} material"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    const SECRET: &str = "0123456789ABCDEF";

    // Only synthetic material is written. Tests observe loading behavior and
    // returned ownership types; they do not claim to inspect erased heap memory.
    // Windows component grammar requires --features postgres,test-support.
    // Its shared permission waiver is NOT production Windows ACL coverage.
    // Unix CI must run the real mode-bit and symlink cases below.
    struct Fixture {
        parent: PathBuf,
        root: PathBuf,
        name: String,
    }

    impl Fixture {
        fn new() -> Self {
            #[cfg(all(windows, not(feature = "test-support")))]
            panic!(
                "Windows material component tests require --features postgres,test-support; \
                 this fixture permission waiver does not test production Windows ACLs"
            );
            let parent = std::env::temp_dir().canonicalize().unwrap();
            let name = format!("apex-browser-material-{}", uuid::Uuid::now_v7().simple());
            let root = parent.join(&name);
            // Never reuse or pre-delete a previous test's directory.
            fs::create_dir(&root).unwrap();
            let fixture = Self { parent, root, name };
            fs::create_dir(fixture.base()).unwrap();
            fixture
        }

        fn base(&self) -> PathBuf {
            self.root.join("trusted")
        }

        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            assert_eq!(
                Path::new(name).file_name(),
                Some(std::ffi::OsStr::new(name))
            );
            let path = self.base().join(name);
            fs::write(&path, bytes).unwrap();
            restrict_private_file(&path);
            path
        }

        fn private_file(&self, bytes: &[u8]) -> PathBuf {
            let path = self.write("private", bytes);
            assert!(
                restricted(&path),
                "private material fixture must satisfy the shared policy"
            );
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // Resolve and compare the exact UUID directory before recursive
            // cleanup; never delete a temp root, replacement symlink or escape.
            let expected = self.parent.join(&self.name);
            let safe = self.root == expected
                && self.root.parent() == Some(self.parent.as_path())
                && fs::symlink_metadata(&self.root)
                    .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
                && self
                    .root
                    .canonicalize()
                    .is_ok_and(|resolved| resolved == expected);
            if !safe {
                eprintln!("refused cleanup of changed browser material fixture directory");
                return;
            }
            if let Err(error) = fs::remove_dir_all(&self.root) {
                eprintln!("unable to clean owned browser material fixture: {error}");
            }
        }
    }

    fn restrict_private_file(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = path;
    }

    fn restricted(path: &Path) -> bool {
        apex_durability::permissions::private_key_permissions_restricted(
            &path.canonicalize().unwrap(),
        )
    }

    fn invalid<T>(result: Result<T, io::Error>) -> io::Error {
        match result {
            Ok(_) => panic!("invalid material was accepted"),
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                error
            }
        }
    }

    #[test]
    fn public_bytes_are_loaded_without_private_permission_requirements() {
        let fixture = Fixture::new();
        let path = fixture.write("certificate", b"public-pem");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert_eq!(
            read_public(&fixture.base(), &path, 10, "certificate").unwrap(),
            b"public-pem"
        );
    }

    #[test]
    fn private_bytes_preserve_binary_content_in_zeroizing_ownership_at_the_size_limit() {
        let fixture = Fixture::new();
        let path = fixture.private_file(b"\0\xff\n\r");
        let bytes: Zeroizing<Vec<u8>> = read_private(&fixture.base(), &path, 4, "key").unwrap();
        assert_eq!(bytes.as_slice(), b"\0\xff\n\r");
    }

    #[test]
    fn material_paths_resolve_from_trusted_base_and_reject_parent_escape() {
        let fixture = Fixture::new();
        let expected = b"0123456789ABCDEF0123456789ABCDEF";
        let absolute = fixture.private_file(expected);
        let base = fixture.base();
        for path in [Path::new("private"), absolute.as_path()] {
            assert_eq!(read_public(&base, path, 32, "material").unwrap(), expected);
            assert_eq!(
                read_private(&base, path, 32, "material")
                    .unwrap()
                    .as_slice(),
                expected,
            );
            assert_eq!(
                client_secret(&base, path).unwrap().as_str(),
                "0123456789ABCDEF0123456789ABCDEF",
            );
            assert_eq!(*session_key(&base, path).unwrap(), *expected);
        }
        let outside = fixture.root.join("outside");
        fs::write(&outside, expected).unwrap();
        restrict_private_file(&outside);
        assert!(restricted(&outside));
        for path in [Path::new("../outside"), outside.as_path()] {
            invalid(read_public(&base, path, 32, "material"));
            invalid(read_private(&base, path, 32, "material"));
            invalid(client_secret(&base, path));
            invalid(session_key(&base, path));
        }
    }

    #[test]
    fn readers_reject_empty_oversized_missing_directory_and_outside_material() {
        let fixture = Fixture::new();
        let empty = fixture.write("empty", b"");
        let oversized = fixture.write("oversized", b"12345");
        let outside = fixture.root.join("outside");
        fs::write(&outside, b"1234").unwrap();
        restrict_private_file(&outside);
        for path in [
            empty,
            oversized,
            fixture.base().join("absent"),
            fixture.base(),
            outside,
        ] {
            invalid(read_public(&fixture.base(), &path, 4, "material"));
            invalid(read_private(&fixture.base(), &path, 4, "material"));
        }
    }

    #[test]
    fn private_size_validation_accepts_the_limit_but_not_the_next_byte() {
        let fixture = Fixture::new();
        let path = fixture.private_file(b"1234");
        assert_eq!(
            read_private(&fixture.base(), &path, 4, "key")
                .unwrap()
                .as_slice(),
            b"1234"
        );
        fs::write(&path, b"12345").unwrap();
        invalid(read_private(&fixture.base(), &path, 4, "key"));
        fs::write(&path, b"").unwrap();
        invalid(read_private(&fixture.base(), &path, 4, "key"));
    }

    #[test]
    fn invalid_bounds_and_missing_trusted_base_are_refused() {
        let fixture = Fixture::new();
        let path = fixture.write("key", b"1234");
        for max in [0, usize::MAX] {
            invalid(read_public(&fixture.base(), &path, max, "material"));
            invalid(read_private(&fixture.base(), &path, max, "material"));
        }
        let absent_base = fixture.root.join("absent-base");
        invalid(read_public(&absent_base, &path, 4, "material"));
        invalid(read_private(&absent_base, &path, 4, "material"));
    }

    #[test]
    fn private_loading_agrees_with_the_shared_platform_permission_policy() {
        let fixture = Fixture::new();
        let path = fixture.write("key", b"1234");
        assert_eq!(
            read_private(&fixture.base(), &path, 4, "key").is_ok(),
            restricted(&path)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(!restricted(&path));
            invalid(read_private(&fixture.base(), &path, 4, "key"));
            assert_eq!(
                read_public(&fixture.base(), &path, 4, "key").unwrap(),
                b"1234"
            );
        }
    }

    // Required Unix CI coverage; Windows symlink privilege is not a test skip.
    #[cfg(unix)]
    #[test]
    fn readers_refuse_a_symlink_even_when_its_target_is_inside_the_base() {
        let fixture = Fixture::new();
        let target = fixture.write("target", b"1234");
        let link = fixture.base().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        invalid(read_public(&fixture.base(), &link, 4, "material"));
        invalid(read_private(&fixture.base(), &link, 4, "material"));
    }

    #[test]
    fn client_secret_accepts_no_ending_or_exactly_one_lf_or_crlf() {
        let fixture = Fixture::new();
        let path = fixture.private_file(SECRET.as_bytes());
        for ending in ["", "\n", "\r\n"] {
            fs::write(&path, format!("{SECRET}{ending}")).unwrap();
            let secret: Zeroizing<String> = client_secret(&fixture.base(), &path).unwrap();
            assert_eq!(secret.as_str(), SECRET);
        }
    }

    #[test]
    fn client_secret_accepts_4096_graphic_bytes_even_with_a_crlf() {
        let fixture = Fixture::new();
        let path = fixture.private_file(SECRET.as_bytes());
        let expected = "x".repeat(4096);
        for ending in ["", "\n", "\r\n"] {
            fs::write(&path, format!("{expected}{ending}")).unwrap();
            let secret = client_secret(&fixture.base(), &path).unwrap();
            assert_eq!(secret.as_str(), expected);
        }
    }

    #[test]
    fn client_secret_refuses_whitespace_extra_endings_controls_non_ascii_and_bad_lengths() {
        let fixture = Fixture::new();
        let path = fixture.private_file(SECRET.as_bytes());
        for bytes in [
            Vec::new(),
            b"123456789ABCDEF".to_vec(),
            vec![b'x'; 4097],
            vec![b'x'; 4099],
            format!(" {SECRET}").into_bytes(),
            format!("{SECRET} ").into_bytes(),
            format!("{SECRET}\r").into_bytes(),
            format!("{SECRET}\n\n").into_bytes(),
            format!("{SECRET}\r\n\r\n").into_bytes(),
            format!("{SECRET}\n\r").into_bytes(),
            b"01234567\n89ABCDEF".to_vec(),
            b"01234567\t89ABCDEF".to_vec(),
            b"01234567\089ABCDEF".to_vec(),
            b"01234567\x7f89ABCDEF".to_vec(),
            b"01234567\xff89ABCDEF".to_vec(),
            "0123456789ABCDEFé".as_bytes().to_vec(),
        ] {
            fs::write(&path, bytes).unwrap();
            invalid(client_secret(&fixture.base(), &path));
        }
    }

    #[test]
    fn session_key_is_exactly_32_raw_bytes_including_non_text_and_line_endings() {
        let fixture = Fixture::new();
        let expected = [
            0, 255, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
            23, 24, 25, 26, 27, 28, 13, 10,
        ];
        let path = fixture.private_file(&expected);
        let key: Zeroizing<[u8; 32]> = session_key(&fixture.base(), &path).unwrap();
        assert_eq!(*key, expected);
    }

    #[test]
    fn session_key_rejects_wrong_lengths_and_encoded_text_without_decoding() {
        let fixture = Fixture::new();
        let path = fixture.private_file(&[7; 32]);
        for bytes in [
            Vec::new(),
            vec![7; 31],
            vec![7; 33],
            vec![b'0'; 64],
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_vec(),
            [vec![7; 32], b"\n".to_vec()].concat(),
            [vec![7; 32], b"\r\n".to_vec()].concat(),
        ] {
            fs::write(&path, bytes).unwrap();
            invalid(session_key(&fixture.base(), &path));
        }
    }

    #[test]
    fn typed_secret_loaders_apply_confinement_and_do_not_echo_rejected_material() {
        let fixture = Fixture::new();
        let path = fixture.private_file(SECRET.as_bytes());
        let outside = fixture.root.join("outside-secret");
        fs::write(&outside, SECRET).unwrap();
        restrict_private_file(&outside);
        invalid(client_secret(&fixture.base(), &outside));
        fs::write(&outside, [7; 32]).unwrap();
        invalid(session_key(&fixture.base(), &outside));
        fs::write(&path, format!("{SECRET} credential-canary\0")).unwrap();
        let error = invalid(client_secret(&fixture.base(), &path));
        assert!(!format!("{error} {error:?}").contains(SECRET));
        assert!(!format!("{error} {error:?}").contains("credential-canary"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::write(&path, SECRET).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            invalid(client_secret(&fixture.base(), &path));
            fs::write(&path, [7; 32]).unwrap();
            invalid(session_key(&fixture.base(), &path));
        }
    }
}
