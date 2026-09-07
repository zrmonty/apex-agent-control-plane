//! Exact schema3 assembly; every owned byte buffer is zeroizing.
use super::*;
use crate::{
    execution::metadata::{Selected, tool_filename},
    launch::PreparedLaunch,
};
pub(crate) struct GatewayMaterial {
    pub(super) files: BTreeMap<String, Zeroizing<Vec<u8>>>,
    sources: BTreeMap<String, String>,
    source_root: (u64, u64, u64),
}
pub(crate) fn names(tools_json: &str) -> Result<std::collections::BTreeSet<String>, StagingError> {
    if tools_json.len() > 65_536 {
        return Err(StagingError::InvalidInput);
    }
    let doc: serde_json::Value =
        serde_json::from_str(tools_json).map_err(|_| StagingError::InvalidInput)?;
    let entries = doc["entries"]
        .as_array()
        .ok_or(StagingError::InvalidInput)?;
    if entries.len() > 32 {
        return Err(StagingError::InvalidInput);
    }
    let mut names = std::collections::BTreeSet::from(
        [
            "runtime-revision.json",
            "launch-context.json",
            "authority-profile.json",
            "tool-bindings.json",
            "instance-proof",
            "health-token",
            "governance-ca",
            "governance-cert",
            "governance-key",
            "governance-token",
            "evidence-ca",
            "evidence-cert",
            "evidence-key",
            "evidence-token",
            "inbound-jwks",
            "workload-ca",
            "workload-cert",
            "workload-key",
        ]
        .map(String::from),
    );
    for entry in entries {
        let reference = entry["reference"]
            .as_str()
            .ok_or(StagingError::InvalidInput)?;
        let filename = tool_filename(reference);
        if entry["filename"] != filename || !names.insert(filename) {
            return Err(StagingError::InvalidInput);
        }
    }
    Ok(names)
}
impl GatewayMaterial {
    pub(crate) fn source_identity(&self) -> Result<String, StagingError> {
        let bytes = serde_json::to_vec(&(&self.source_root, &self.sources))
            .map_err(|_| StagingError::InvalidSource)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
    pub(crate) fn hashes(&self) -> BTreeMap<String, String> {
        self.files
            .iter()
            .map(|(n, b)| (n.clone(), format!("{:x}", Sha256::digest(&**b))))
            .collect()
    }
    pub(crate) fn add_proof(&mut self, proof: &proof::InstanceProof) {
        self.files
            .insert("instance-proof".into(), proof.copy_bytes());
    }
}
impl Owner {
    pub(crate) fn gateway_material(
        &self,
        launch: &PreparedLaunch,
        selected: &Selected,
        check: &mut impl FnMut() -> Result<(), &'static str>,
    ) -> Result<GatewayMaterial, StagingError> {
        let c = launch.context();
        let t = c.target.as_ref().ok_or(StagingError::InvalidTarget)?;
        validation::request(
            t,
            &c.process_instance_id,
            launch.configuration_json(),
            launch.launch_json(),
            launch.materials(),
        )?;
        if selected.authority_json.len() > 16_384 {
            return Err(StagingError::InvalidInput);
        }
        let a: serde_json::Value = serde_json::from_slice(&selected.authority_json)
            .map_err(|_| StagingError::InvalidInput)?;
        if a["schema_version"] != 3
            || a["profile"]["mode"] != "managed_ingress"
            || launch.materials().len() != 13
            || selected.tools.len() > 32
        {
            return Err(StagingError::InvalidInput);
        }
        let tools_json =
            std::str::from_utf8(&selected.tools_json).map_err(|_| StagingError::InvalidInput)?;
        let expected = names(tools_json)?;
        self.source.check(self.uid)?;
        self.source.check_path(self.uid)?;
        let stat = fs::fstat(&self.source.fd).map_err(|_| StagingError::InvalidRoot)?;
        let mut material = GatewayMaterial {
            files: BTreeMap::new(),
            sources: BTreeMap::new(),
            source_root: (stat.st_dev, stat.st_ino, mount_id(&self.source.fd)?),
        };
        for (n, b) in [
            ("runtime-revision.json", launch.configuration_json()),
            ("launch-context.json", launch.launch_json()),
            ("authority-profile.json", &selected.authority_json),
            ("tool-bindings.json", &selected.tools_json),
        ] {
            material.files.insert(n.into(), Zeroizing::new(b.to_vec()));
        }
        let tools: Vec<_> = selected
            .tools
            .iter()
            .map(|v| ScopedMaterial {
                workspace_id: t.workspace_id.clone(),
                namespace_id: t.namespace_id.clone(),
                proxy_id: t.proxy_id.clone(),
                reference: v.reference.clone(),
                version: v.version.clone(),
                role: RuntimeMaterialRole::GovernanceToken,
                source_name: v.source_name.clone(),
            })
            .collect();
        self.source.check(self.uid)?;
        self.source.check_path(self.uid)?;
        let source_mount = mount_id(&self.source.fd)?;
        for item in launch
            .materials()
            .iter()
            .map(|m| Ok((m, validation::filename(m.role)?.to_owned())))
            .chain(tools.iter().map(|m| Ok((m, tool_filename(&m.reference)))))
        {
            let (m, n): (&ScopedMaterial, String) = item?;
            check().map_err(|_| StagingError::Io)?;
            let fd = fs::openat(
                &self.source.fd,
                m.source_name.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| StagingError::InvalidSource)?;
            same_mount(&fd, source_mount)?;
            let stat = fs::fstat(&fd).map_err(|_| StagingError::Io)?;
            #[cfg(test)]
            crate::execution::testing::at(
                crate::execution::testing::Point::GatewaySourceChecked,
                None,
            )
            .map_err(|_| StagingError::Io)?;
            let mut file = File::from(fd);
            let bytes = read_source_file(&mut file, &stat, m, self.uid)?;
            #[cfg(test)]
            crate::execution::testing::at(
                crate::execution::testing::Point::GatewaySourceRead,
                None,
            )
            .map_err(|_| StagingError::Io)?;
            named(&self.source.fd, &m.source_name, &stat, source_mount)?;
            material
                .sources
                .insert(m.source_name.clone(), fingerprint(&stat)?);
            if material.files.insert(n, bytes).is_some() {
                return Err(StagingError::InvalidInput);
            }
            check().map_err(|_| StagingError::Io)?;
        }
        if material.files.len() + 1 != expected.len()
            || material.files.keys().any(|n| !expected.contains(n))
            || material.files.values().map(|b| b.len()).sum::<usize>() + 32 > 4_194_304
        {
            return Err(StagingError::InvalidInput);
        }
        self.gateway_sources(&material)?;
        Ok(material)
    }
    pub(super) fn gateway_sources(&self, material: &GatewayMaterial) -> Result<(), StagingError> {
        self.source.check(self.uid)?;
        self.source.check_path(self.uid)?;
        let mount = mount_id(&self.source.fd)?;
        let current = roots::Root::open(&self.source.path, self.uid)?;
        same_mount(&current.fd, mount)?;
        let stat = fs::fstat(&self.source.fd).map_err(|_| StagingError::InvalidRoot)?;
        if material.source_root != (stat.st_dev, stat.st_ino, mount) {
            return Err(StagingError::InvalidRoot);
        }
        for (name, expected) in &material.sources {
            let fd = fs::openat(
                &self.source.fd,
                name.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| StagingError::InvalidSource)?;
            same_mount(&fd, mount)?;
            if fingerprint(&fs::fstat(&fd).map_err(|_| StagingError::Io)?)? != *expected {
                return Err(StagingError::InvalidSource);
            }
        }
        Ok(())
    }
}
