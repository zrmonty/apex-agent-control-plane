//! Complete managed stage, including transport/tool metadata, sealed once.
use super::*;
use crate::{
    execution::metadata::{Selected, tool_filename},
    launch::PreparedLaunch,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
impl Owner {
    pub(crate) fn managed(
        &self,
        launch: &PreparedLaunch,
        selected: &Selected,
        recover: bool,
        expected: Option<&BTreeMap<String, String>>,
        proof: Option<&proof::InstanceProof>,
    ) -> Result<BTreeMap<String, String>, StagingError> {
        let c = launch.context();
        let target = c.target.as_ref().ok_or(StagingError::InvalidTarget)?;
        validation::request(
            target,
            &c.process_instance_id,
            launch.configuration_json(),
            launch.launch_json(),
            launch.materials(),
        )?;
        if selected.tools.len() > 32
            || selected.authority_json.len() > 16_384
            || selected.tools_json.len() > 65_536
        {
            return Err(StagingError::InvalidInput);
        }
        self.state.check(self.uid)?;
        self.state.check_path(self.uid)?;
        self.source.check(self.uid)?;
        let mut files: BTreeMap<String, Zeroizing<Vec<u8>>> = BTreeMap::new();
        if let Some(proof) = proof {
            if recover {
                return Err(StagingError::InvalidInput);
            }
            files.insert("instance-proof".into(), proof.copy_bytes());
        } else if expected.is_some_and(|files| files.contains_key("instance-proof")) {
            if !recover {
                return Err(StagingError::InvalidInput);
            }
            files.insert(
                "instance-proof".into(),
                self.recover_proof(&c.process_instance_id)?,
            );
        }
        files.insert(
            "runtime-revision.json".into(),
            Zeroizing::new(launch.configuration_json().to_vec()),
        );
        files.insert(
            "launch-context.json".into(),
            Zeroizing::new(launch.launch_json().to_vec()),
        );
        files.insert(
            "authority-profile.json".into(),
            Zeroizing::new(selected.authority_json.clone()),
        );
        files.insert(
            "tool-bindings.json".into(),
            Zeroizing::new(selected.tools_json.clone()),
        );
        for m in launch.materials() {
            files.insert(
                validation::filename(m.role)?.into(),
                read_source(&self.source, m, self.uid)?,
            );
        }
        let mut total = 0usize;
        for t in &selected.tools {
            let m = ScopedMaterial {
                workspace_id: target.workspace_id.clone(),
                namespace_id: target.namespace_id.clone(),
                proxy_id: target.proxy_id.clone(),
                reference: t.reference.clone(),
                version: t.version.clone(),
                role: RuntimeMaterialRole::GovernanceToken,
                source_name: t.source_name.clone(),
            };
            let bytes = read_source(&self.source, &m, self.uid)?;
            total = total
                .checked_add(bytes.len())
                .ok_or(StagingError::InvalidSource)?;
            if total > 2_097_152 {
                return Err(StagingError::InvalidSource);
            }
            files.insert(tool_filename(&t.reference), bytes);
        }
        let hashes: BTreeMap<_, _> = files
            .iter()
            .map(|(n, b)| (n.clone(), format!("{:x}", Sha256::digest(&**b))))
            .collect();
        if expected.is_some_and(|e| e != &hashes) {
            return Err(StagingError::InvalidSource);
        }
        if !recover && expected.is_none() {
            return Ok(hashes);
        }
        let name = format!("apex-runtime-{}", c.process_instance_id);
        if recover {
            let directory = fs::openat(
                &self.state.fd,
                name.as_str(),
                roots::DIRECTORY_FLAGS,
                Mode::empty(),
            )
            .map_err(|_| StagingError::Io)?;
            let stat = fs::fstat(&directory).map_err(|_| StagingError::Io)?;
            let mount = mount_id(&directory)?;
            if stat.st_uid != 10001 || stat.st_gid != 10001 || stat.st_mode & 0o7777 != 0o500 {
                return Err(StagingError::InvalidSource);
            }
            let mut seen = 0;
            for entry in fs::Dir::read_from(&directory).map_err(|_| StagingError::Io)? {
                let entry = entry.map_err(|_| StagingError::Io)?;
                let n = entry
                    .file_name()
                    .to_str()
                    .map_err(|_| StagingError::InvalidSource)?;
                if n == "." || n == ".." {
                    continue;
                }
                let expected = files.get(n).ok_or(StagingError::InvalidSource)?;
                let fd = fs::openat(
                    &directory,
                    n,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| StagingError::Io)?;
                let s = fs::fstat(&fd).map_err(|_| StagingError::Io)?;
                if mount_id(&fd)? != mount {
                    return Err(StagingError::InvalidSource);
                }
                if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
                    || s.st_nlink != 1
                    || s.st_uid != 10001
                    || s.st_gid != 10001
                    || s.st_mode & 0o7777 != 0o400
                    || usize::try_from(s.st_size).ok() != Some(expected.len())
                {
                    return Err(StagingError::InvalidSource);
                }
                let mut bytes = Zeroizing::new(vec![0; expected.len() + 1]);
                let mut file = File::from(fd);
                let mut used = 0;
                while used < bytes.len() {
                    let n = file
                        .read(&mut bytes[used..])
                        .map_err(|_| StagingError::Io)?;
                    if n == 0 {
                        break;
                    }
                    used += n;
                }
                if bytes[..used] != **expected
                    || !unchanged_source(&s, &fs::fstat(&file).map_err(|_| StagingError::Io)?)
                {
                    return Err(StagingError::InvalidSource);
                }
                seen += 1;
            }
            if seen != files.len() {
                return Err(StagingError::InvalidSource);
            }
        } else {
            fs::mkdirat(&self.state.fd, name.as_str(), Mode::from_raw_mode(0o700))
                .map_err(|_| StagingError::AlreadyExists)?;
            let directory = fs::openat(
                &self.state.fd,
                name.as_str(),
                roots::DIRECTORY_FLAGS,
                Mode::empty(),
            )
            .map_err(|_| StagingError::Io)?;
            for (n, b) in files {
                write_file(&directory, &n, &b)?;
                #[cfg(test)]
                crate::execution::testing::at(crate::execution::testing::Point::StageFile, None)
                    .map_err(|_| StagingError::Io)?;
            }
            seal(&directory, 0o500)?;
            fs::fsync(&directory).map_err(|_| StagingError::Io)?;
            fs::fsync(&self.state.fd).map_err(|_| StagingError::Io)?;
            #[cfg(test)]
            crate::execution::testing::at(crate::execution::testing::Point::Sealed, None)
                .map_err(|_| StagingError::Io)?;
        }
        self.state.check_path(self.uid)?;
        Ok(hashes)
    }
}
