//! Agent-only random material. No Serialize, Debug, environment or wire exposure.
use super::*;

pub(crate) struct InstanceProof(Zeroizing<Vec<u8>>);
impl InstanceProof {
    /// Caller must durably record ProofIntent before this one generation attempt.
    pub(crate) fn generate() -> Result<Self, StagingError> {
        let mut bytes = Zeroizing::new(vec![0; 32]);
        let count = rustix::rand::getrandom(&mut bytes[..], rustix::rand::GetRandomFlags::NONBLOCK)
            .map_err(|_| StagingError::Io)?;
        if count != 32 {
            return Err(StagingError::Io);
        }
        Ok(Self(bytes))
    }
    pub(super) fn copy_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_vec())
    }
}

impl Owner {
    /// Reopen only a complete sealed private proof; never regenerate or repair.
    pub(super) fn recover_proof(&self, instance: &str) -> Result<Zeroizing<Vec<u8>>, StagingError> {
        if !crate::shapes::uuid_v7(instance) {
            return Err(StagingError::InvalidTarget);
        }
        let name = format!("apex-runtime-{instance}");
        let directory = fs::openat(
            &self.state.fd,
            name.as_str(),
            roots::DIRECTORY_FLAGS,
            Mode::empty(),
        )
        .map_err(|_| StagingError::InvalidSource)?;
        let dir = fs::fstat(&directory).map_err(|_| StagingError::Io)?;
        if dir.st_uid != 10001 || dir.st_gid != 10001 || dir.st_mode & 0o7777 != 0o500 {
            return Err(StagingError::InvalidSource);
        }
        let fd = fs::openat(
            &directory,
            "instance-proof",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StagingError::InvalidSource)?;
        let before = fs::fstat(&fd).map_err(|_| StagingError::Io)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_size != 32
            || before.st_uid != 10001
            || before.st_gid != 10001
            || before.st_nlink != 1
            || before.st_mode & 0o7777 != 0o400
            || mount_id(&fd)? != mount_id(&directory)?
        {
            return Err(StagingError::InvalidSource);
        }
        let mut bytes = Zeroizing::new(vec![0; 33]);
        let mut file = File::from(fd);
        let mut used = 0;
        while used < bytes.len() {
            let count = file
                .read(&mut bytes[used..])
                .map_err(|_| StagingError::Io)?;
            if count == 0 {
                break;
            }
            used += count;
        }
        if used != 32
            || !unchanged_source(&before, &fs::fstat(&file).map_err(|_| StagingError::Io)?)
        {
            return Err(StagingError::InvalidSource);
        }
        bytes.truncate(32);
        Ok(bytes)
    }
}
