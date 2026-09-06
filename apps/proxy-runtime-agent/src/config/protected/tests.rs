use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let path =
            std::path::PathBuf::from("/root").join(format!("apex-task2-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, bytes: &[u8]) {
        fs::write(self.0.join(name), bytes).unwrap();
        fs::set_permissions(self.0.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn descriptor_loader_reads_only_protected_regular_bounded_files() {
    let f = Fixture::new();
    f.write("agent.json", b"{}");
    let dir = Directory::open(&f.0).expect("valid protected root must open");
    assert_eq!(&*dir.read("agent.json", 65536).unwrap(), b"{}");
    for name in ["../agent.json", "/etc/passwd", "a/b", "unknown.pem"] {
        assert!(dir.read(name, 65536).is_err());
    }
    symlink("agent.json", f.0.join("peer-policy.json")).unwrap();
    assert!(dir.read("peer-policy.json", 65536).is_err());
    fs::hard_link(f.0.join("agent.json"), f.0.join("launch-catalog.json")).unwrap();
    assert!(dir.read("agent.json", 65536).is_err());
    fs::remove_file(f.0.join("launch-catalog.json")).unwrap();
    for mode in [0o644, 0o620, 0o666, 0o4600] {
        fs::set_permissions(f.0.join("agent.json"), fs::Permissions::from_mode(mode)).unwrap();
        assert!(dir.read("agent.json", 65536).is_err());
    }
    f.write("agent.json", &vec![b'x'; 65536]);
    assert_eq!(dir.read("agent.json", 65536).unwrap().len(), 65536);
    f.write("agent.json", &vec![b'x'; 65537]);
    assert!(dir.read("agent.json", 65536).is_err());
    f.write("agent.json", b"");
    assert!(dir.read("agent.json", 65536).is_err());
}
#[test]
fn writable_ancestors_symlinks_replaced_paths_and_nonregular_files_refuse() {
    let f = Fixture::new();
    let child = f.0.join("child");
    fs::create_dir(&child).unwrap();
    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
    let dir = Directory::open(&child).expect("protected child");
    fs::set_permissions(&f.0, fs::Permissions::from_mode(0o720)).unwrap();
    assert!(Directory::open(&child).is_err());
    assert!(dir.read("agent.json", 65536).is_err());
    fs::set_permissions(&f.0, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&child, f.0.join("link")).unwrap();
    assert!(Directory::open(&f.0.join("link")).is_err());
    assert!(Directory::open(Path::new("relative")).is_err());
    assert!(Directory::open(Path::new("/tmp")).is_err());
    fs::rename(&child, f.0.join("old")).unwrap();
    fs::create_dir(&child).unwrap();
    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(dir.read("agent.json", 65536).is_err());
    let dir = Directory::open(&child).unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        child.join("agent.json"),
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .unwrap();
    assert!(dir.read("agent.json", 65536).is_err());
}
