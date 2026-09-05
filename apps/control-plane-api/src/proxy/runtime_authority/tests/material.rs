use std::{
    fs,
    path::{Path, PathBuf},
};

use super::super::RuntimeAuthorityError;
use super::super::material::read_document;

// Real local files testing the material boundary only, not enrolled authority.
pub(super) struct Fixture {
    root: PathBuf,
    temporary_parent: PathBuf,
}

impl Fixture {
    pub(super) fn new() -> Self {
        let temporary_parent = std::env::temp_dir()
            .canonicalize()
            .expect("owned test temp parent");
        let root = temporary_parent.join(format!(
            "apex-runtime-authority-component-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir(&root).expect("fresh exact owned fixture root");
        fs::create_dir(root.join("base")).expect("owned trusted base");
        Self {
            root,
            temporary_parent,
        }
    }

    pub(super) fn base(&self) -> PathBuf {
        self.root.join("base")
    }

    pub(super) fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.base().join(name);
        fs::write(&path, bytes).expect("owned component material");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        assert!(self.root.is_absolute());
        assert_eq!(self.root.parent(), Some(self.temporary_parent.as_path()));
        assert!(
            self.root
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("apex-runtime-authority-component-")
        );
        assert!(
            !fs::symlink_metadata(&self.root)
                .expect("owned root metadata")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            self.root.canonicalize().expect("owned root resolution"),
            self.root
        );
        fs::remove_dir_all(&self.root)
            .expect("remove only exact owned fixture root, without following symlinks");
    }
}

#[test]
fn configured_relative_and_confined_absolute_files_preserve_exact_original_bytes() {
    let fixture = Fixture::new();
    let expected = b"{\"materialComponentOnly\":true}\r\n";
    let path = fixture.write("metadata.json", expected);
    assert!(read_document(&fixture.base(), &path).expect("confined absolute document") == expected);
    assert!(
        read_document(&fixture.base(), Path::new("metadata.json")).expect("base relative document")
            == expected
    );
}

#[test]
fn material_bound_has_an_exact_65536_byte_positive_control() {
    let fixture = Fixture::new();
    let expected = vec![b'x'; 65_536];
    let path = fixture.write("metadata.json", &expected);
    assert!(read_document(&fixture.base(), &path).expect("exact bounded bytes") == expected);
    fs::write(&path, vec![b'x'; 65_537]).unwrap();
    assert!(matches!(
        read_document(&fixture.base(), &path),
        Err(RuntimeAuthorityError::Unavailable)
    ));
    fs::write(&path, []).unwrap();
    assert!(read_document(&fixture.base(), &path).is_err());
}

#[test]
fn material_refuses_missing_directory_and_outside_paths_without_returning_path_diagnostics() {
    let fixture = Fixture::new();
    let outside = fixture.root.join("PRIVATE-PATH-CANARY.json");
    fs::write(&outside, b"component only").unwrap();
    for path in [
        fixture.base().join("missing.json"),
        fixture.base(),
        outside,
        PathBuf::from("../PRIVATE-PATH-CANARY.json"),
    ] {
        let error = read_document(&fixture.base(), &path).expect_err("invalid confined document");
        assert_eq!(error.code(), "RUNTIME_AUTHORITY_UNAVAILABLE");
        assert!(!format!("{error:?} {error}").contains("PRIVATE-PATH-CANARY"));
    }
}

// Unix CI is required for this symlink case. No Windows privilege-dependent skip.
#[cfg(unix)]
#[test]
fn material_refuses_a_final_symlink_even_to_a_confined_regular_file() {
    let fixture = Fixture::new();
    let target = fixture.write("target.json", b"component only");
    let link = fixture.base().join("link.json");
    std::os::unix::fs::symlink(target, &link).expect("Unix owned fixture symlink");
    assert!(read_document(&fixture.base(), &link).is_err());
}
