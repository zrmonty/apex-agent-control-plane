//! The legacy path helper follows ancestors and cannot provide this boundary.
//! Linux opens one component at a time under held directory descriptors. Other
//! production platforms refuse: no claim of equivalent Windows ACL checks.
use super::EnrollmentError;
use std::path::Path;

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod flags {
    // [O_NOFOLLOW, O_DIRECTORY, O_NONBLOCK]. Keep both ABIs testable on every
    // test host; only the matching ABI is compiled into a production target.
    #[cfg(any(test, target_arch = "x86_64"))]
    pub(super) const X86_64: [i32; 3] = [0x20000, 0x10000, 0x800];
    #[cfg(any(test, target_arch = "aarch64"))]
    pub(super) const AARCH64: [i32; 3] = [0x8000, 0x4000, 0x800];

    pub(super) const fn for_path(flags: [i32; 3], directory: bool) -> i32 {
        let [nofollow, directory_only, nonblock] = flags;
        nofollow | nonblock | if directory { directory_only } else { 0 }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn both_architectures_match_linux_uapi_for_every_custom_open_flag() {
            // Independent oracle: Linux v6.12 include/uapi/asm-generic/fcntl.h
            // (x86_64 defaults) and arch/arm64/include/uapi/asm/fcntl.h overrides.
            // https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/fcntl.h
            // https://github.com/torvalds/linux/blob/v6.12/arch/arm64/include/uapi/asm/fcntl.h
            // Preserve UAPI octal notation to make review against headers direct.
            for (actual, expected, direct, largefile) in [
                (X86_64, [0o400000, 0o200000, 0o4000], 0o40000, 0o100000),
                (AARCH64, [0o100000, 0o40000, 0o4000], 0o200000, 0o400000),
            ] {
                assert_eq!(
                    actual, expected,
                    "each custom flag must match its architecture's UAPI"
                );
                assert_eq!(for_path(actual, false), expected[0] | expected[2]);
                assert_eq!(
                    for_path(actual, true),
                    expected[0] | expected[1] | expected[2]
                );
                for directory in [false, true] {
                    assert_eq!(
                        for_path(actual, directory) & (direct | largefile),
                        0,
                        "never accidentally request O_DIRECT or O_LARGEFILE"
                    );
                }
            }
        }

        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        #[test]
        fn selected_architecture_matches_installed_kernel_uapi_headers() {
            if std::env::var_os("APEX_EVIDENCE_LINUX_TEST_BASE").is_none() {
                eprintln!("SKIP: opt-in Linux UAPI/compiler fixture unset");
                return;
            }
            // Read the platform's actual installed kernel headers using its C
            // preprocessor. No fixture numbers or production constants feed it.
            let output = std::process::Command::new("cc")
                .args([
                    "-dM",
                    "-E",
                    "-include",
                    "asm/fcntl.h",
                    "-x",
                    "c",
                    "/dev/null",
                ])
                .output()
                .expect("Linux verification image must provide cc and UAPI headers");
            assert!(output.status.success(), "UAPI preprocessing failed");
            let macros = String::from_utf8(output.stdout).unwrap();
            let expected = ["O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK"].map(|name| {
                let prefix = format!("#define {name} ");
                let value = macros
                    .lines()
                    .find_map(|line| line.strip_prefix(&prefix))
                    .expect("required UAPI macro");
                i32::from_str_radix(value.trim(), 8).expect("kernel UAPI literal is octal")
            });
            let actual = super::super::linux::OPEN_FLAGS;
            assert_eq!(actual, expected);
            for directory in [false, true] {
                assert_eq!(
                    for_path(actual, directory),
                    expected[0] | expected[2] | if directory { expected[1] } else { 0 }
                );
            }
        }
    }
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub(super) fn read(_path: &Path, _base: &Path) -> Result<Vec<u8>, EnrollmentError> {
    Err(EnrollmentError)
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(super) fn read(path: &Path, base: &Path) -> Result<Vec<u8>, EnrollmentError> {
    linux::read(path, base)
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use super::*;
    use std::{
        fs::{File, Metadata, OpenOptions},
        io::Read,
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        path::{Component, PathBuf},
    };

    #[cfg(target_arch = "aarch64")]
    pub(super) use super::flags::AARCH64 as OPEN_FLAGS;
    #[cfg(target_arch = "x86_64")]
    pub(super) use super::flags::X86_64 as OPEN_FLAGS;

    fn parts(path: &Path) -> Result<Vec<&std::ffi::OsStr>, EnrollmentError> {
        if !path.is_absolute() || path.as_os_str().len() > 4096 {
            return Err(EnrollmentError);
        }
        path.components()
            .filter(|c| !matches!(c, Component::RootDir))
            .map(|c| {
                if let Component::Normal(name) = c {
                    Ok(name)
                } else {
                    Err(EnrollmentError)
                }
            })
            .collect()
    }
    fn open(path: &Path, directory: bool) -> Result<File, EnrollmentError> {
        OpenOptions::new()
            .read(true)
            .custom_flags(super::flags::for_path(OPEN_FLAGS, directory))
            .open(path)
            .map_err(|_| EnrollmentError)
    }
    fn metadata(file: &File) -> Result<Metadata, EnrollmentError> {
        file.metadata().map_err(|_| EnrollmentError)
    }
    fn directory(meta: &Metadata, uid: u32) -> Result<(), EnrollmentError> {
        if !meta.is_dir() || ![0, uid].contains(&meta.uid()) || meta.mode() & 0o022 != 0 {
            return Err(EnrollmentError);
        }
        Ok(())
    }
    fn same(a: &Metadata, b: &Metadata) -> bool {
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.uid() == b.uid()
            && a.mode() == b.mode()
            && a.len() == b.len()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    pub(super) fn read(path: &Path, base: &Path) -> Result<Vec<u8>, EnrollmentError> {
        let path_parts = parts(path)?;
        let base_parts = parts(base)?;
        if base_parts.is_empty()
            || path_parts.len() <= base_parts.len()
            || !path_parts.starts_with(&base_parts)
        {
            return Err(EnrollmentError);
        }
        // /proc/self is kernel-owned. Its UID is the effective service UID;
        // no environment variable or profile field chooses the trusted owner.
        let uid = std::fs::metadata("/proc/self")
            .map_err(|_| EnrollmentError)?
            .uid();
        let mut held = vec![open(Path::new("/"), true)?];
        directory(&metadata(&held[0])?, uid)?;
        for component in &path_parts[..path_parts.len() - 1] {
            let parent = held.last().ok_or(EnrollmentError)?;
            let next =
                PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(component);
            let child = open(&next, true)?;
            directory(&metadata(&child)?, uid)?;
            held.push(child);
        }
        let parent = held.last().ok_or(EnrollmentError)?;
        let leaf = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd()))
            .join(path_parts.last().ok_or(EnrollmentError)?);
        let mut file = open(&leaf, false)?;
        let before = metadata(&file)?;
        if !before.is_file()
            || ![0, uid].contains(&before.uid())
            || before.mode() & 0o177 != 0
            || before.nlink() != 1
            || before.len() == 0
            || before.len() > 262_144
        {
            return Err(EnrollmentError);
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(262_145)
            .read_to_end(&mut bytes)
            .map_err(|_| EnrollmentError)?;
        if bytes.is_empty() || bytes.len() > 262_144 || !same(&before, &metadata(&file)?) {
            return Err(EnrollmentError);
        }
        // Reopen through a fresh confined walk to detect root/ancestor/leaf
        // replacement during the read; immutable snapshots publish afterward.
        let mut current = open(Path::new("/"), true)?;
        for (index, component) in path_parts.iter().enumerate() {
            let last = index + 1 == path_parts.len();
            let next =
                PathBuf::from(format!("/proc/self/fd/{}", current.as_raw_fd())).join(component);
            current = open(&next, !last)?;
            let meta = metadata(&current)?;
            if last {
                if !same(&before, &meta) {
                    return Err(EnrollmentError);
                }
            } else {
                directory(&meta, uid)?;
                let original = metadata(&held[index + 1])?;
                if meta.dev() != original.dev() || meta.ino() != original.ino() {
                    return Err(EnrollmentError);
                }
            }
        }
        Ok(bytes)
    }
}
