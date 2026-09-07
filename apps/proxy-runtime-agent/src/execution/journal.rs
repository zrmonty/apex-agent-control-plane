//! One exclusively held installation root; atomic bounded per-proxy records.
use super::{metadata::strict::Object, record::Record};
use crate::{config::Directory, proto};
use rustix::{
    fd::OwnedFd,
    fs::{self, FileType, FlockOperation, Mode, OFlags},
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
const ERROR: &str = "RUNTIME_JOURNAL_QUARANTINED";
const LIMIT: usize = 1_048_576;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    record: Object<Record>,
    digest: String,
}
pub(super) struct Journal {
    root: Directory,
    _lock: OwnedFd,
    network_lock: std::sync::Mutex<network::State>,
    topology_lock: std::sync::Mutex<topology::State>,
}
impl Journal {
    pub(super) fn open(path: &Path) -> Result<Self, &'static str> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(ERROR);
        }
        let root = Directory::open(path)?;
        let lock = fs::openat(
            &root.fd,
            "owner.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| ERROR)?;
        let s = fs::fstat(&lock).map_err(|_| ERROR)?;
        if s.st_uid != 0
            || s.st_nlink != 1
            || s.st_mode & 0o7777 != 0o600
            || FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
        {
            return Err(ERROR);
        }
        fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "RUNTIME_JOURNAL_BUSY")?;
        Ok(Self {
            root,
            _lock: lock,
            network_lock: std::sync::Mutex::default(),
            topology_lock: std::sync::Mutex::default(),
        })
    }
    pub(super) fn key(installation: &str, t: &proto::RuntimeTarget) -> String {
        let mut h = Sha256::new();
        for s in [installation, &t.workspace_id, &t.namespace_id, &t.proxy_id] {
            h.update((s.len() as u64).to_be_bytes());
            h.update(s);
        }
        format!("{:x}.json", h.finalize())
    }
    pub(super) fn load(
        &self,
        installation: &str,
        t: &proto::RuntimeTarget,
    ) -> Result<Option<Record>, &'static str> {
        self.root.check()?;
        let key = Self::key(installation, t);
        let fd = match fs::openat(
            &self.root.fd,
            key.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(ERROR),
        };
        let s = fs::fstat(&fd).map_err(|_| ERROR)?;
        if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
            || s.st_uid != 0
            || s.st_nlink != 1
            || s.st_mode & 0o7777 != 0o600
            || s.st_size <= 0
            || s.st_size > LIMIT as i64
        {
            return Err(ERROR);
        }
        let mut bytes = Vec::new();
        File::from(fd)
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ERROR)?;
        if bytes.len() > LIMIT {
            return Err(ERROR);
        }
        super::engine::inspect::json::Json::bounded(&bytes, LIMIT).map_err(|_| ERROR)?;
        let Object(envelope): Object<Envelope> =
            serde_json::from_slice(&bytes).map_err(|_| ERROR)?;
        let r = envelope.record.0;
        if envelope.digest != digest(&r)? {
            return Err(ERROR);
        }
        let rt = r.claims.target.as_ref().ok_or(ERROR)?;
        if r.schema_version != 1
            || r.installation != installation
            || Self::key(installation, rt) != key
            || !crate::shapes::uuid_v7(&r.instance)
            || r.commands.len() > 64
            || r.commands.is_empty()
            || r.replay_floor.as_ref().is_some_and(|floor| {
                !crate::shapes::uuid_v7(floor) || r.commands.keys().any(|id| id <= floor)
            })
            || r.commands
                .iter()
                .any(|(id, op)| !crate::shapes::uuid_v7(id) || !crate::shapes::uuid_v7(op))
            || r.commands.get(&r.claims.command_id) != Some(&r.claims.operation_id)
            || crate::service::validation::request(&r.claims).is_err()
            || crate::service::validation::request(&r.original).is_err()
        {
            return Err(ERROR);
        }
        for i in [&r.installed, &r.predecessor].into_iter().flatten() {
            if let Some(stage) = &i.gateway_stage {
                stage.validate(installation, i)?;
            }
            if let Some(stage) = &i.guard_stage {
                if stage.root_identity.is_none() {
                    return Err(ERROR);
                }
                stage.validate(installation, i)?;
            }
            if let Some(binding) = &i.network {
                binding.validate(installation, i)?;
                if i.phase != super::record::Phase::Intent
                    || !i.files.is_empty()
                    || !i.container_id.is_empty()
                    || !i.image_id.is_empty()
                {
                    return Err(ERROR);
                }
            }
            if !crate::shapes::uuid_v7(&i.instance)
                || i.files.len() > 50
                || i.instance_proof_version.is_some_and(|version| version != 1)
                || (!matches!(
                    i.phase,
                    super::record::Phase::Intent | super::record::Phase::ProofIntent
                ) && i.instance_proof_version.is_some()
                    != i.files.contains_key("instance-proof"))
                || (i.phase == super::record::Phase::ProofIntent
                    && i.instance_proof_version != Some(1))
                || i.files.values().any(|h| !crate::shapes::hex_hash(h))
                || i.launch_json.len() > 16_384
                || i.configuration_json.len() > 262_144
                || i.authority_json.len() > 16_384
                || i.tools_json.len() > 65_536
                || i.unset_env.len() > 16
                || !crate::shapes::hex_hash(&i.publication_hash)
                || crate::service::validation::request(&i.original).is_err()
                || Self::key(installation, i.original.target.as_ref().ok_or(ERROR)?) != key
            {
                return Err(ERROR);
            }
            let l: proto::RuntimeLaunchContext =
                serde_json::from_str(&i.launch_json).map_err(|_| ERROR)?;
            if l.target != i.original.target
                || l.config_hash != i.original.config_hash
                || l.process_instance_id != i.instance
            {
                return Err(ERROR);
            }
        }
        self.root.check()?;
        Ok(Some(r))
    }
    pub(super) fn save(&self, r: &Record) -> Result<(), &'static str> {
        self.root.check()?;
        let key = Self::key(&r.installation, r.claims.target.as_ref().ok_or(ERROR)?);
        let bytes = serde_json::to_vec(&serde_json::json!({"record":r,"digest":digest(r)?}))
            .map_err(|_| ERROR)?;
        if bytes.len() > LIMIT {
            return Err(ERROR);
        }
        // A crash leaves only this fixed temporary name. It is never adopted as a record.
        let temp = format!("{key}.next");
        let fd = fs::openat(
            &self.root.fd,
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| ERROR)?;
        let s = fs::fstat(&fd).map_err(|_| ERROR)?;
        if s.st_uid != 0
            || s.st_nlink != 1
            || s.st_mode & 0o7777 != 0o600
            || FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
        {
            return Err(ERROR);
        }
        fs::ftruncate(&fd, 0).map_err(|_| ERROR)?;
        let mut file = File::from(fd);
        file.write_all(&bytes).map_err(|_| ERROR)?;
        fs::fsync(&file).map_err(|_| ERROR)?;
        fs::renameat(&self.root.fd, temp.as_str(), &self.root.fd, key.as_str())
            .map_err(|_| ERROR)?;
        fs::fsync(&self.root.fd).map_err(|_| ERROR)?;
        self.root.check()
    }
}
fn digest(r: &Record) -> Result<String, &'static str> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(r).map_err(|_| ERROR)?)
    ))
}
mod network;
#[cfg(test)]
mod tests;
mod topology;
