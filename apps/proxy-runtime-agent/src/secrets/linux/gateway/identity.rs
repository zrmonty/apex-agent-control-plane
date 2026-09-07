use super::*;
use serde::{Deserialize, Serialize};
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GatewayIdentity {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) mount: u64,
    pub(super) files: BTreeMap<String, String>,
    pub(super) directory: Option<String>,
}
impl GatewayIdentity {
    pub(crate) fn validate(
        &self,
        root: &GuardRoot,
        files: &BTreeMap<String, String>,
        sealed: bool,
    ) -> Result<(), StagingError> {
        if self.device != root.device
            || self.mount != root.mount
            || self.inode == 0
            || self.files.keys().ne(files.keys())
            || self.files.values().any(|v| !crate::shapes::hex_hash(v))
            || sealed != self.directory.is_some()
            || self
                .directory
                .as_ref()
                .is_some_and(|v| !crate::shapes::hex_hash(v))
        {
            return Err(StagingError::InvalidSource);
        }
        Ok(())
    }
    pub(super) fn check_directory(&self, stat: &Stat, mount: u64) -> Result<(), StagingError> {
        if (self.device, self.inode, self.mount) != (stat.st_dev, stat.st_ino, mount)
            || self
                .directory
                .as_ref()
                .is_some_and(|v| fingerprint(stat).as_ref() != Ok(v))
        {
            return Err(StagingError::InvalidSource);
        }
        Ok(())
    }
}
